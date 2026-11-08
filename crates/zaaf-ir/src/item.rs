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
            if !pipelines.is_empty() && !mapped.mapped {
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
    let values = expand_values(&item.values, has(Expand), pipelines)?;

    let preds: Vec<Expr> = if has(Exists) {
        match values.as_slice() {
            [RuleValue::Bool(b)] => vec![pred(Matcher::Exists(*b))],
            _ => return Err("`exists` takes a single boolean value".into()),
        }
    } else if values.contains(&RuleValue::Null) {
        if values.len() > 1 {
            return Err("`null` cannot be part of a list of values".into());
        }
        if mods.iter().any(|m| *m != Neq) {
            return Err("`null` cannot be combined with modifiers other than `neq`".into());
        }
        vec![pred(Matcher::Null)]
    } else if has(Re) {
        let mut out = Vec::new();
        for v in &values {
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
        out
    } else if has(Cidr) {
        values
            .iter()
            .map(|v| match v {
                RuleValue::Str(s) => s
                    .trim()
                    .parse::<ipnet::IpNet>()
                    .map(|n| pred(Matcher::Cidr(n)))
                    .map_err(|e| format!("invalid CIDR `{s}`: {e}")),
                _ => Err("`cidr` needs string values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else if let Some(part) = time_part {
        values
            .iter()
            .map(|v| match v {
                RuleValue::Int(i) => Ok(pred(Matcher::TimePart {
                    part,
                    op: cmp.unwrap_or(CmpOp::Eq),
                    value: *i,
                })),
                _ => Err("time modifiers need integer values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else if let Some(op) = cmp {
        values
            .iter()
            .map(|v| match v {
                RuleValue::Int(i) => Ok(pred(Matcher::Num {
                    op,
                    value: *i as f64,
                })),
                RuleValue::Float(f) => Ok(pred(Matcher::Num { op, value: *f })),
                _ => Err("numeric modifiers need numeric values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else if has(FieldRef) {
        let mode = if has(Contains) {
            RefMode::Contains
        } else if has(StartsWith) {
            RefMode::StartsWith
        } else if has(EndsWith) {
            RefMode::EndsWith
        } else {
            RefMode::Equals
        };
        values
            .iter()
            .map(|v| match v {
                RuleValue::Str(other) => Ok(pred(Matcher::FieldRef {
                    other: pipelines.map_field(logsource, other).names,
                    mode,
                    case_sensitive,
                })),
                _ => Err("`fieldref` needs field names as values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else {
        let mut vals: Vec<Val> = values
            .iter()
            .map(|v| match v {
                RuleValue::Str(s) => Val::S(SigmaString::parse(s)),
                other => Val::S(SigmaString::literal(&other.to_text().unwrap_or_default())),
            })
            .collect();
        for m in mods.iter().filter(|m| STRING_TRANSFORMS.contains(m)) {
            vals = transform::apply(*m, vals)?;
        }
        vals.into_iter()
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
            .collect()
    };
    let combined = if has(All) { and(preds) } else { or(preds) };
    Ok(if has(Neq) {
        Expr::Not(Box::new(combined))
    } else {
        combined
    })
}

fn expand_values(
    values: &[RuleValue],
    expand: bool,
    pipelines: &PipelineSet,
) -> Result<Vec<RuleValue>, String> {
    if !expand {
        return Ok(values.to_vec());
    }
    let lookup = |name: &str| pipelines.placeholder(name).map(<[String]>::to_vec);
    let mut out = Vec::new();
    for v in values {
        match v {
            RuleValue::Str(s) => out.extend(
                transform::expand_raw(s, &lookup)?
                    .into_iter()
                    .map(RuleValue::Str),
            ),
            other => out.push(other.clone()),
        }
    }
    Ok(out)
}
