//! Compiles one `field|modifiers: values` item into an expression.

use crate::ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
use crate::regex_engine::{BACKTRACK_LIMIT, CompiledRegex, RegexFlags};
use crate::transform::{self, Val};
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{FieldItem, LogSource, Modifier, RuleValue, SigmaString};

const STRING_TRANSFORMS: &[Modifier] = &[
    Modifier::Contains,
    Modifier::StartsWith,
    Modifier::EndsWith,
    Modifier::Windash,
    Modifier::Base64,
    Modifier::Base64Offset,
    Modifier::Utf16Le,
    Modifier::Utf16Be,
    Modifier::Utf16,
    Modifier::Wide,
];

/// Upper bound on predicates produced by one item.
pub(crate) const MAX_ITEM_PREDICATES: usize = 16_384;

const CMP_MODS: &[Modifier] = &[Modifier::Lt, Modifier::Lte, Modifier::Gt, Modifier::Gte];
const TIME_MODS: &[Modifier] = &[
    Modifier::Minute,
    Modifier::Hour,
    Modifier::Day,
    Modifier::Week,
    Modifier::Month,
    Modifier::Year,
];

pub(crate) fn and(mut v: Vec<Expr>) -> Expr {
    if v.len() == 1 {
        v.remove(0)
    } else {
        Expr::And(v)
    }
}

pub(crate) fn or(mut v: Vec<Expr>) -> Expr {
    if v.len() == 1 {
        v.remove(0)
    } else {
        Expr::Or(v)
    }
}

pub(crate) fn compile_item(
    item: &FieldItem,
    logsource: &LogSource,
    pipelines: &PipelineSet,
    warnings: &mut Vec<String>,
) -> Result<Expr, String> {
    use Modifier::*;
    let mods = &item.modifiers;
    let has = |m: Modifier| mods.contains(&m);

    let flags = RegexFlags {
        insensitive: has(ReInsensitive),
        multiline: has(ReMultiline),
        dot_all: has(ReDotAll),
    };
    if flags != RegexFlags::default() && !has(Re) {
        return Err("regex flags `i`, `m` and `s` require the `re` modifier".into());
    }
    let time_part = mods.iter().find_map(|m| match m {
        Minute => Some(TimePart::Minute),
        Hour => Some(TimePart::Hour),
        Day => Some(TimePart::Day),
        Week => Some(TimePart::Week),
        Month => Some(TimePart::Month),
        Year => Some(TimePart::Year),
        _ => None,
    });
    let cmp = mods.iter().find_map(|m| match m {
        Lt => Some(CmpOp::Lt),
        Lte => Some(CmpOp::Lte),
        Gt => Some(CmpOp::Gt),
        Gte => Some(CmpOp::Gte),
        _ => None,
    });
    // [re, cidr, exists, fieldref, numeric-or-time]
    let families = [
        has(Re),
        has(Cidr),
        has(Exists),
        has(FieldRef),
        time_part.is_some() || cmp.is_some(),
    ];
    if families.iter().filter(|b| **b).count() > 1 {
        let names: Vec<&str> = mods.iter().map(|m| m.name()).collect();
        return Err(format!("incompatible modifiers `{}`", names.join("|")));
    }
    if has(All) && item.values.len() < 2 {
        return Err("`all` needs a list of at least two values".into());
    }
    if item.field.is_none() && families[1..].iter().any(|b| *b) {
        return Err("keyword search supports only string matching and `re`".into());
    }

    let target = match &item.field {
        None => Target::AnyField,
        Some(field) => {
            let mapped = pipelines.map_field(logsource, field);
            if pipelines.has_field_mappings() && !mapped.mapped {
                warnings.push(format!("field `{field}` is not mapped by any pipeline"));
            }
            Target::Fields(mapped.names)
        }
    };
    let pred = |matcher: Matcher| {
        Expr::Pred(Predicate {
            target: target.clone(),
            matcher,
        })
    };
    let case_sensitive = has(Cased);

    let any_transform = mods.iter().any(|m| STRING_TRANSFORMS.contains(m));
    let transform_names = || {
        mods.iter()
            .filter(|m| STRING_TRANSFORMS.contains(m))
            .map(|m| m.name())
            .collect::<Vec<_>>()
            .join("|")
    };
    if has(Exists) && mods.len() > 1 {
        return Err("`exists` cannot be combined with other modifiers".into());
    }
    if mods.iter().filter(|m| CMP_MODS.contains(m)).count() > 1 {
        return Err("only one comparison modifier (`lt`, `lte`, `gt`, `gte`) is allowed".into());
    }
    if mods.iter().filter(|m| TIME_MODS.contains(m)).count() > 1 {
        return Err("only one time modifier is allowed".into());
    }
    let typed_path = has(Re) || has(Cidr) || time_part.is_some() || cmp.is_some();
    if typed_path && any_transform {
        return Err(format!(
            "string modifiers `{}` cannot be combined with `re`, `cidr`, numeric or time modifiers",
            transform_names()
        ));
    }

    let groups = expand_values(&item.values, has(Expand), pipelines)?;
    let flat: Vec<&RuleValue> = groups.iter().flatten().collect();

    let mut total = 0usize;
    // One entry per original value; each holds that value's variants.
    let mut out_groups: Vec<Vec<Expr>> = Vec::new();
    let mut push_group = |g: Vec<Expr>, out: &mut Vec<Vec<Expr>>| -> Result<(), String> {
        total += g.len();
        if total > MAX_ITEM_PREDICATES {
            return Err(format!(
                "item expands to more than {MAX_ITEM_PREDICATES} predicates"
            ));
        }
        out.push(g);
        Ok(())
    };

    if has(Exists) {
        match flat.as_slice() {
            [RuleValue::Bool(b)] => out_groups.push(vec![pred(Matcher::Exists(*b))]),
            _ => return Err("`exists` takes a single boolean value".into()),
        }
    } else if flat.contains(&&RuleValue::Null) {
        if flat.len() > 1 {
            return Err("`null` cannot be part of a list of values".into());
        }
        if mods.iter().any(|m| *m != Neq) {
            return Err("`null` cannot be combined with modifiers other than `neq`".into());
        }
        out_groups.push(vec![pred(Matcher::Null)]);
    } else if has(Re) {
        for g in &groups {
            let mut out = Vec::new();
            for v in g {
                let RuleValue::Str(src) = v else {
                    return Err("`re` needs string values".into());
                };
                let re = CompiledRegex::new(src, flags)?;
                if re.needs_backtracking() {
                    warnings.push(format!(
                        "regex `{src}` needs the backtracking engine (limit {BACKTRACK_LIMIT} steps)"
                    ));
                }
                out.push(pred(Matcher::Regex(re)));
            }
            push_group(out, &mut out_groups)?;
        }
    } else if has(Cidr) {
        for g in &groups {
            let out = g
                .iter()
                .map(|v| match v {
                    RuleValue::Str(s) => parse_net(s.trim())
                        .map(|n| pred(Matcher::Cidr(n)))
                        .map_err(|e| format!("invalid CIDR `{s}`: {e}")),
                    _ => Err("`cidr` needs string values".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            push_group(out, &mut out_groups)?;
        }
    } else if let Some(part) = time_part {
        for g in &groups {
            let out = g
                .iter()
                .map(|v| match v {
                    RuleValue::Int(i) => Ok(pred(Matcher::TimePart {
                        part,
                        op: cmp.unwrap_or(CmpOp::Eq),
                        value: *i,
                    })),
                    _ => Err("time modifiers need integer values".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            push_group(out, &mut out_groups)?;
        }
    } else if let Some(op) = cmp {
        for g in &groups {
            let out = g
                .iter()
                .map(|v| match v {
                    RuleValue::Int(i) => Ok(pred(Matcher::Num {
                        op,
                        value: *i as f64,
                    })),
                    RuleValue::Float(f) => Ok(pred(Matcher::Num { op, value: *f })),
                    _ => Err("numeric modifiers need numeric values".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            push_group(out, &mut out_groups)?;
        }
    } else if has(FieldRef) {
        let ref_mods: Vec<Modifier> = mods
            .iter()
            .copied()
            .filter(|m| matches!(m, Contains | StartsWith | EndsWith))
            .collect();
        if ref_mods.len() > 1 {
            return Err(
                "`fieldref` accepts only one of `contains`, `startswith`, `endswith`".into(),
            );
        }
        if mods
            .iter()
            .any(|m| STRING_TRANSFORMS.contains(m) && !ref_mods.contains(m))
        {
            return Err(format!(
                "`fieldref` cannot be combined with string modifiers other than `contains`, `startswith` and `endswith` (found `{}`)",
                transform_names()
            ));
        }
        let mode = match ref_mods.first() {
            Some(Contains) => RefMode::Contains,
            Some(StartsWith) => RefMode::StartsWith,
            Some(EndsWith) => RefMode::EndsWith,
            _ => RefMode::Equals,
        };
        for g in &groups {
            let out = g
                .iter()
                .map(|v| match v {
                    RuleValue::Str(other) => Ok(pred(Matcher::FieldRef {
                        other: pipelines.map_field(logsource, other).names,
                        mode,
                        case_sensitive,
                    })),
                    _ => Err("`fieldref` needs field names as values".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            push_group(out, &mut out_groups)?;
        }
    } else {
        for g in &groups {
            let mut vals: Vec<Val> = g
                .iter()
                .map(|v| match v {
                    RuleValue::Str(s) => Val::S(SigmaString::parse(s)),
                    other => Val::S(SigmaString::literal(&other.to_text().unwrap_or_default())),
                })
                .collect();
            for m in mods.iter().filter(|m| STRING_TRANSFORMS.contains(m)) {
                vals = transform::apply(*m, vals)?;
            }
            let out = vals
                .into_iter()
                .map(|v| {
                    let mut s = v.into_sigma();
                    if item.field.is_none() {
                        s.prepend_any_many();
                        s.append_any_many();
                    }
                    let pattern = if case_sensitive { s } else { s.to_lowercase() };
                    pred(Matcher::Str {
                        pattern,
                        case_sensitive,
                    })
                })
                .collect();
            push_group(out, &mut out_groups)?;
        }
    }
    let combined = if has(All) {
        and(out_groups.into_iter().map(or).collect())
    } else {
        or(out_groups.into_iter().flatten().collect())
    };
    Ok(if has(Neq) {
        Expr::Not(Box::new(combined))
    } else {
        combined
    })
}

fn parse_net(s: &str) -> Result<ipnet::IpNet, String> {
    match s.parse::<ipnet::IpNet>() {
        Ok(n) => Ok(n),
        Err(e) => s
            .parse::<std::net::IpAddr>()
            .map(ipnet::IpNet::from)
            .map_err(|_| e.to_string()),
    }
}

/// Number of predicate leaves in an expression.
#[cfg(test)]
pub(crate) fn count_preds(e: &Expr) -> usize {
    match e {
        Expr::And(v) | Expr::Or(v) => v.iter().map(count_preds).sum(),
        Expr::Not(e) => count_preds(e),
        Expr::Pred(_) => 1,
    }
}

/// Values grouped per original value; each group holds that value's expansions.
fn expand_values(
    values: &[RuleValue],
    expand: bool,
    pipelines: &PipelineSet,
) -> Result<Vec<Vec<RuleValue>>, String> {
    if !expand {
        return Ok(values.iter().map(|v| vec![v.clone()]).collect());
    }
    let lookup = |name: &str| pipelines.placeholder(name).map(<[String]>::to_vec);
    let mut out = Vec::new();
    let mut count = 0usize;
    for v in values {
        let group: Vec<RuleValue> = match v {
            RuleValue::Str(s) => transform::expand_raw(s, &lookup)?
                .into_iter()
                .map(RuleValue::Str)
                .collect(),
            other => vec![other.clone()],
        };
        count += group.len();
        if count > MAX_ITEM_PREDICATES {
            return Err(format!(
                "item expands to more than {MAX_ITEM_PREDICATES} predicates"
            ));
        }
        out.push(group);
    }
    Ok(out)
}

/// Budget weight of an expression: regex predicates weigh `REGEX_WEIGHT`, all others 1.
pub(crate) fn weight(e: &Expr) -> usize {
    match e {
        Expr::And(v) | Expr::Or(v) => v.iter().map(weight).sum(),
        Expr::Not(e) => weight(e),
        Expr::Pred(p) => match p.matcher {
            Matcher::Regex(_) => crate::rule::REGEX_WEIGHT,
            _ => 1,
        },
    }
}
