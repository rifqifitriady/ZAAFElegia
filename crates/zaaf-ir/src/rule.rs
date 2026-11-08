//! Compiles whole documents: search identifiers, conditions, meta filters and metadata.
//!
//! Work is bounded by predicate budgets. A regex predicate weighs [`REGEX_WEIGHT`] units,
//! every other predicate 1. One rule (or filter) may weigh at most [`MAX_RULE_PREDICATES`]
//! units, and one `compile` call at most [`MAX_TOTAL_WEIGHT`] across all rules and filters;
//! the first document that would cross it and every later one are skipped with a single
//! error. A single item is capped at 16384 plain predicates. The SigmaHQ corpus (about
//! 100k predicates) is far below these limits.

use crate::ir::Expr;
use crate::item::{and, compile_item, or, weight};
use std::collections::HashSet;
use std::path::PathBuf;
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{
    CondExpr, Detection, Diagnostic, Document, FieldItem, Location, LogSource, Quantifier,
    SelTarget, SigmaString,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "informational" => Some(Self::Informational),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// OCSF `severity_id`: 1 Informational … 5 Critical.
    pub fn ocsf_severity_id(self) -> u8 {
        self as u8 + 1
    }
}

#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub id: String,
    pub name: Option<String>,
    pub title: String,
    pub level: Level,
    pub status: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    pub logsource: LogSource,
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub info: RuleInfo,
    pub expr: Expr,
}

#[derive(Debug, Clone)]
pub struct SourcedDocument {
    pub document: Document,
    pub source: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct CompileOutput {
    pub rules: Vec<CompiledRule>,
    pub diagnostics: Vec<Diagnostic>,
    pub filters: usize,
    pub correlations_skipped: usize,
}

/// A compile error or warning and where in the rule file it points.
#[derive(Debug)]
pub(crate) struct Problem {
    location: Location,
    message: String,
}

impl Problem {
    fn item(item: &FieldItem, message: String) -> Self {
        Self {
            location: Location::at(item.line, item.col, item.path.clone()),
            message,
        }
    }
}

/// The start of a document; used for diagnostics about the document as a whole.
fn document_at(line: usize, col: usize) -> Location {
    Location::at(line, col, "")
}

fn located(d: Diagnostic, source: &Option<PathBuf>) -> Diagnostic {
    match source {
        Some(p) => d.with_file(p.clone()),
        None => d,
    }
}

fn error(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::error(location, msg), source)
}

fn warning(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::warning(location, msg), source)
}

/// Weight of a regex predicate in the budgets (other predicates weigh 1).
pub const REGEX_WEIGHT: usize = 16;
/// Upper bound on the weight of one rule (or filter) after condition resolution.
pub const MAX_RULE_PREDICATES: usize = 65_536;
/// Upper bound on the summed weight of all rules and filters in one `compile` call.
pub const MAX_TOTAL_WEIGHT: usize = 1_000_000;

fn budget_error() -> String {
    format!("rule expands to more than {MAX_RULE_PREDICATES} predicates")
}

struct CompiledFilter {
    title: String,
    preds: usize,
    targets: Vec<String>,
    expr: Expr,
    source: Option<PathBuf>,
    line: usize,
    col: usize,
    used: bool,
}

/// Compiles documents into rules. Problems become diagnostics; a broken rule is skipped.
pub fn compile(docs: Vec<SourcedDocument>, pipelines: &PipelineSet) -> CompileOutput {
    let mut out = CompileOutput::default();
    let mut rules = Vec::new();
    let mut filters = Vec::new();
    for SourcedDocument { document, source } in docs {
        match document {
            Document::Rule(r) => rules.push((r, source)),
            Document::Filter(f) => filters.push((f, source)),
            Document::Correlation(c) => {
                out.correlations_skipped += 1;
                out.diagnostics.push(warning(
                    &source,
                    document_at(c.line, c.col),
                    format!("correlation rule `{}` skipped: correlation support arrives in milestone M2", c.title),
                ));
            }
        }
    }
    out.filters = filters.len();

    // Running weight over everything kept; once exceeded, the rest is skipped uncompiled.
    let mut total = 0usize;
    let mut skipped = 0usize;
    let mut first_skip: Option<(Option<PathBuf>, Location)> = None;

    let mut compiled_filters = Vec::new();
    for (f, source) in filters {
        if skipped > 0 {
            skipped += 1;
            continue;
        }
        let mut warnings = Vec::new();
        match compile_detection(
            &f.detection,
            "filter",
            &f.logsource,
            pipelines,
            &mut warnings,
        ) {
            Ok(expr) if total + weight(&expr) > MAX_TOTAL_WEIGHT => {
                skipped = 1;
                first_skip = Some((source.clone(), document_at(f.line, f.col)));
                drop(expr);
            }
            Ok(expr) => {
                let preds = weight(&expr);
                total += preds;
                compiled_filters.push(CompiledFilter {
                    title: f.title.clone(),
                    preds,
                    targets: f.rules.clone(),
                    expr,
                    source: source.clone(),
                    line: f.line,
                    col: f.col,
                    used: false,
                });
            }
            Err(p) => out.diagnostics.push(error(
                &source,
                p.location,
                format!("filter `{}`: {}", f.title, p.message),
            )),
        }
        out.diagnostics.extend(warnings.into_iter().map(|w| {
            warning(
                &source,
                w.location,
                format!("filter `{}`: {}", f.title, w.message),
            )
        }));
    }

    let mut seen = HashSet::new();
    'rules: for (r, source) in rules {
        if skipped > 0 {
            skipped += 1;
            continue;
        }
        let mut warnings = Vec::new();
        let compiled = compile_detection(
            &r.detection,
            "detection",
            &r.logsource,
            pipelines,
            &mut warnings,
        );
        out.diagnostics.extend(warnings.into_iter().map(|w| {
            warning(
                &source,
                w.location,
                format!("rule `{}`: {}", r.meta.title, w.message),
            )
        }));
        let mut expr = match compiled {
            Ok(e) => e,
            Err(p) => {
                out.diagnostics.push(error(
                    &source,
                    p.location,
                    format!("rule `{}`: {}", r.meta.title, p.message),
                ));
                continue;
            }
        };
        let id = r
            .meta
            .id
            .clone()
            .unwrap_or_else(|| format!("title:{}", r.meta.title));
        if !seen.insert(id.clone()) {
            out.diagnostics.push(error(
                &source,
                document_at(r.line, r.col),
                format!("duplicate rule id `{id}`; rule `{}` skipped", r.meta.title),
            ));
            continue;
        }
        for f in &mut compiled_filters {
            let targeted = f.targets.iter().any(|t| {
                r.meta.id.as_deref() == Some(t.as_str())
                    || r.meta.name.as_deref() == Some(t.as_str())
            });
            if targeted {
                f.used = true;
                if weight(&expr) + f.preds > MAX_RULE_PREDICATES {
                    out.diagnostics.push(error(
                        &source,
                        document_at(r.line, r.col),
                        format!("rule `{}`: {}", r.meta.title, budget_error()),
                    ));
                    continue 'rules;
                }
                expr = Expr::And(vec![expr, Expr::Not(Box::new(f.expr.clone()))]);
            }
        }
        let rule_weight = weight(&expr);
        if total + rule_weight > MAX_TOTAL_WEIGHT {
            skipped = 1;
            first_skip = Some((source.clone(), document_at(r.line, r.col)));
            continue;
        }
        total += rule_weight;
        let level = match r.meta.level.as_deref() {
            None => Level::Medium,
            Some(s) => Level::parse(s).unwrap_or_else(|| {
                out.diagnostics.push(warning(
                    &source,
                    document_at(r.line, r.col),
                    format!("rule `{}`: unknown level `{s}`, using medium", r.meta.title),
                ));
                Level::Medium
            }),
        };
        out.rules.push(CompiledRule {
            info: RuleInfo {
                id,
                name: r.meta.name,
                title: r.meta.title,
                level,
                status: r.meta.status,
                description: r.meta.description,
                author: r.meta.author,
                references: r.meta.references,
                tags: r.meta.tags,
                falsepositives: r.meta.falsepositives,
                logsource: r.logsource,
                source,
            },
            expr,
        });
    }
    if let Some((source, location)) = first_skip {
        out.diagnostics.push(error(
            &source,
            location,
            format!(
                "rule set exceeds the total compile budget of {MAX_TOTAL_WEIGHT} units; this and later rules were skipped ({skipped} documents skipped)"
            ),
        ));
    }
    for f in compiled_filters.iter().filter(|f| !f.used) {
        out.diagnostics.push(warning(
            &f.source,
            document_at(f.line, f.col),
            format!("filter `{}` does not match any loaded rule", f.title),
        ));
    }
    out
}

/// `base` is `detection` for rules and `filter` for meta filters (the YAML path of the block).
pub(crate) fn compile_detection(
    det: &Detection,
    base: &str,
    logsource: &LogSource,
    pipelines: &PipelineSet,
    warnings: &mut Vec<Problem>,
) -> Result<Expr, Problem> {
    let mut ids: Vec<(String, Expr, usize)> = Vec::new();
    // Running total over every identifier, referenced or not, so compilation work is bounded.
    let mut built = 0usize;
    for sid in &det.search_ids {
        let mut alternatives = Vec::new();
        for alt in &sid.alternatives {
            let mut items = Vec::new();
            for item in alt {
                let mut item_warnings = Vec::new();
                let compiled = compile_item(item, logsource, pipelines, &mut item_warnings);
                warnings.extend(item_warnings.into_iter().map(|w| Problem::item(item, w)));
                let compiled = compiled.map_err(|e| Problem::item(item, e))?;
                built += weight(&compiled);
                if built > MAX_RULE_PREDICATES {
                    return Err(Problem::item(item, budget_error()));
                }
                items.push(compiled);
            }
            alternatives.push(and(items));
        }
        let expr = or(alternatives);
        let cost = weight(&expr);
        ids.push((sid.name.clone(), expr, cost));
    }
    let mut used = 0usize;
    let conditions = det
        .conditions
        .iter()
        .map(|c| resolve(c, &ids, &mut used))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|message| Problem {
            location: Location::at(
                det.condition_line,
                det.condition_col,
                format!("{base}.condition"),
            ),
            message,
        })?;
    Ok(or(conditions))
}

fn resolve(c: &CondExpr, ids: &[(String, Expr, usize)], used: &mut usize) -> Result<Expr, String> {
    Ok(match c {
        CondExpr::Ident(name) => {
            let (_, e, cost) = ids.iter().find(|(n, _, _)| n == name).ok_or_else(|| {
                format!("condition references unknown search identifier `{name}`")
            })?;
            *used = used.saturating_add(*cost);
            if *used > MAX_RULE_PREDICATES {
                return Err(budget_error());
            }
            e.clone()
        }
        CondExpr::Not(inner) => Expr::Not(Box::new(resolve(inner, ids, used)?)),
        CondExpr::And(v) => and(v
            .iter()
            .map(|x| resolve(x, ids, used))
            .collect::<Result<_, _>>()?),
        CondExpr::Or(v) => or(v
            .iter()
            .map(|x| resolve(x, ids, used))
            .collect::<Result<_, _>>()?),
        CondExpr::Of(q, target) => {
            let matching: Vec<&(String, Expr, usize)> = ids
                .iter()
                .filter(|(n, _, _)| match target {
                    SelTarget::Them => !n.starts_with('_'),
                    SelTarget::Pattern(p) => SigmaString::parse(p).matches(n),
                })
                .collect();
            if matching.is_empty() {
                let what = match target {
                    SelTarget::Them => "them".to_string(),
                    SelTarget::Pattern(p) => p.clone(),
                };
                return Err(format!("`{what}` matches no search identifier"));
            }
            for (_, _, cost) in &matching {
                *used = used.saturating_add(*cost);
            }
            if *used > MAX_RULE_PREDICATES {
                return Err(budget_error());
            }
            let selected: Vec<Expr> = matching.into_iter().map(|(_, e, _)| e.clone()).collect();
            match q {
                Quantifier::One => or(selected),
                Quantifier::All => and(selected),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Matcher, Predicate, Target};
    use zaaf_pipeline::parse_pipeline;
    use zaaf_sigma::SigmaString;

    fn compile_src(src: &str, pipelines: &PipelineSet) -> CompileOutput {
        let parsed = zaaf_sigma::parse_str(src);
        assert!(
            parsed.diagnostics.iter().all(|d| !d.is_error()),
            "{:?}",
            parsed.diagnostics
        );
        compile(
            parsed
                .documents
                .into_iter()
                .map(|document| SourcedDocument {
                    document,
                    source: None,
                })
                .collect(),
            pipelines,
        )
    }

    fn rule_with(detection: &str) -> String {
        format!("title: t\nid: r1\nlogsource:\n    product: windows\ndetection:\n{detection}")
    }

    fn compile_detection_src(detection: &str) -> CompileOutput {
        compile_src(&rule_with(detection), &PipelineSet::default())
    }

    fn first_error(out: &CompileOutput) -> String {
        out.diagnostics
            .iter()
            .find(|d| d.is_error())
            .map(|d| d.message.clone())
            .unwrap_or_default()
    }

    fn first_error_location(out: &CompileOutput) -> Location {
        out.diagnostics
            .iter()
            .find(|d| d.is_error())
            .map(|d| d.location.clone())
            .unwrap_or(Location::Unknown)
    }

    fn only_pred(out: &CompileOutput) -> &Predicate {
        match &out.rules[0].expr {
            Expr::Pred(p) => p,
            other => panic!("expected a single predicate, got {other:?}"),
        }
    }

    #[test]
    fn contains_becomes_lowercased_glob() {
        let out = compile_detection_src(
            "    s:\n        CommandLine|contains: WhoAmI\n    condition: s\n",
        );
        let p = only_pred(&out);
        assert_eq!(p.target, Target::Fields(vec!["CommandLine".into()]));
        match &p.matcher {
            Matcher::Str {
                pattern,
                case_sensitive,
            } => {
                assert!(!case_sensitive);
                assert_eq!(pattern, &SigmaString::parse("*whoami*"));
            }
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn cased_keeps_case_and_ints_become_text() {
        let out = compile_detection_src(
            "    s:\n        A|cased: AbC\n    t:\n        EventID: 4688\n    condition: s and t\n",
        );
        let Expr::And(items) = &out.rules[0].expr else {
            panic!("{:?}", out.rules[0].expr)
        };
        let Expr::Pred(a) = &items[0] else { panic!() };
        assert!(
            matches!(&a.matcher, Matcher::Str { pattern, case_sensitive: true } if pattern == &SigmaString::literal("AbC"))
        );
        let Expr::Pred(b) = &items[1] else { panic!() };
        assert!(
            matches!(&b.matcher, Matcher::Str { pattern, .. } if pattern == &SigmaString::literal("4688"))
        );
    }

    #[test]
    fn all_is_and_and_neq_is_not() {
        let out =
            compile_detection_src("    s:\n        C|contains|all: [a, b]\n    condition: s\n");
        assert!(matches!(&out.rules[0].expr, Expr::And(v) if v.len() == 2));
        let out = compile_detection_src("    s:\n        U|neq: SYSTEM\n    condition: s\n");
        assert!(matches!(&out.rules[0].expr, Expr::Not(_)));
    }

    #[test]
    fn type_modifiers_produce_their_matchers() {
        let out = compile_detection_src("    s:\n        Size|gt: 10\n    condition: s\n");
        assert!(
            matches!(only_pred(&out).matcher, Matcher::Num { op: crate::CmpOp::Gt, value } if value == 10.0)
        );
        let out = compile_detection_src("    s:\n        Ip|cidr: 10.0.0.0/8\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Cidr(_)));
        let out = compile_detection_src("    s:\n        F|exists: false\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Exists(false)));
        let out = compile_detection_src("    s:\n        F: null\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Null));
        let out = compile_detection_src("    s:\n        T|hour|gte: 22\n    condition: s\n");
        assert!(matches!(
            only_pred(&out).matcher,
            Matcher::TimePart {
                part: crate::TimePart::Hour,
                op: crate::CmpOp::Gte,
                value: 22
            }
        ));
        let out =
            compile_detection_src("    s:\n        A|fieldref|contains: B\n    condition: s\n");
        assert!(
            matches!(&only_pred(&out).matcher, Matcher::FieldRef { mode: crate::RefMode::Contains, other, .. } if other == &vec!["B".to_string()])
        );
    }

    #[test]
    fn keyword_values_are_contains_over_any_field() {
        let out = compile_detection_src("    k:\n        - 'event::clear'\n    condition: k\n");
        let p = only_pred(&out);
        assert_eq!(p.target, Target::AnyField);
        assert!(
            matches!(&p.matcher, Matcher::Str { pattern, .. } if pattern == &SigmaString::parse("*event::clear*"))
        );
    }

    #[test]
    fn invalid_items_are_errors() {
        let cases = [
            ("    s:\n        X|all: single\n    condition: s\n", "all"),
            ("    s:\n        X|i: a\n    condition: s\n", "re"),
            (
                "    s:\n        X|re|cidr: a\n    condition: s\n",
                "incompatible",
            ),
            (
                "    s:\n        X|cidr: not-a-net\n    condition: s\n",
                "CIDR",
            ),
            (
                "    s:\n        X|exists: yes-please\n    condition: s\n",
                "boolean",
            ),
            (
                "    s:\n        X|expand: '%Nope%'\n    condition: s\n",
                "Nope",
            ),
            (
                "    k:\n        '|cidr': [10.0.0.0/8]\n    condition: k\n",
                "keyword",
            ),
            (
                "    s:\n        X: a\n    condition: s and missing\n",
                "missing",
            ),
            (
                "    s:\n        X: a\n    condition: 1 of nothing_*\n",
                "nothing_*",
            ),
        ];
        for (det, needle) in cases {
            let out = compile_detection_src(det);
            assert!(out.rules.is_empty(), "{det} should not compile");
            let err = first_error(&out);
            assert!(
                err.contains(needle),
                "{det}: expected `{needle}` in `{err}`"
            );
        }
    }

    #[test]
    fn diagnostics_point_at_the_item_the_condition_and_the_document() {
        let out = compile_detection_src("    s:\n        X|all: single\n    condition: s\n");
        assert_eq!(
            first_error_location(&out),
            Location::at(7, 9, "detection.s.X|all")
        );
        let out = compile_detection_src("    s:\n        X: a\n    condition: s and missing\n");
        assert_eq!(
            first_error_location(&out),
            Location::at(8, 16, "detection.condition")
        );
        let src = format!(
            "{}---\ntitle: again\nid: r1\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n",
            rule_with("    s:\n        A: 1\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(first_error_location(&out), Location::at(10, 1, ""));
    }

    #[test]
    fn them_excludes_underscore_identifiers() {
        let out = compile_detection_src(
            "    a:\n        X: 1\n    _b:\n        Y: 1\n    condition: all of them\n",
        );
        assert!(
            matches!(&out.rules[0].expr, Expr::Pred(_)),
            "{:?}",
            out.rules[0].expr
        );
    }

    #[test]
    fn expand_uses_pipeline_vars() {
        let pipes = PipelineSet::new(vec![
            parse_pipeline("name: v\nvars:\n  Admins: ['adm_*', root]\n").unwrap(),
        ]);
        let out = compile_src(
            &rule_with("    s:\n        User|expand: '%Admins%'\n    condition: s\n"),
            &pipes,
        );
        assert!(
            matches!(&out.rules[0].expr, Expr::Or(v) if v.len() == 2),
            "{:?}",
            out.rules[0].expr
        );
    }

    #[test]
    fn unmapped_fields_warn_when_pipelines_are_loaded() {
        let pipes = PipelineSet::new(vec![parse_pipeline(
            "name: m\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: process.executable\n",
        )
        .unwrap()]);
        let out = compile_src(
            &rule_with("    s:\n        Image: a\n        User: b\n    condition: s\n"),
            &pipes,
        );
        let warnings: Vec<_> = out.diagnostics.iter().filter(|d| !d.is_error()).collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].message.contains("`User`"));
        assert_eq!(warnings[0].location, Location::at(8, 9, "detection.s.User"));
    }

    #[test]
    fn filters_fold_into_targeted_rules() {
        let src = format!(
            "{}---\ntitle: f\nlogsource:\n    product: windows\nfilter:\n    rules: [r1]\n    sel:\n        User|startswith: adm_\n    condition: sel\n---\ntitle: unused\nlogsource:\n    product: windows\nfilter:\n    rules: [other]\n    sel:\n        X: 1\n    condition: sel\n",
            rule_with("    s:\n        Image: a\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(out.filters, 2);
        let Expr::And(parts) = &out.rules[0].expr else {
            panic!("{:?}", out.rules[0].expr)
        };
        assert!(matches!(parts[1], Expr::Not(_)));
        let unused = out
            .diagnostics
            .iter()
            .find(|d| d.message.contains("`unused` does not match"))
            .unwrap();
        assert_eq!(unused.location, Location::at(19, 1, ""));
    }

    #[test]
    fn duplicate_ids_correlations_and_levels() {
        let src = format!(
            "{}---\ntitle: second\nid: r1\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n---\ntitle: corr\ncorrelation:\n    type: event_count\n",
            rule_with("    s:\n        A: 1\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.correlations_skipped, 1);
        assert!(first_error(&out).contains("duplicate rule id `r1`"));
        assert_eq!(out.rules[0].info.level, Level::Medium);
        assert_eq!(Level::parse("Critical"), Some(Level::Critical));
        assert_eq!(Level::Critical.ocsf_severity_id(), 5);
        assert!(Level::High > Level::Medium);
    }

    #[test]
    fn rules_without_id_get_a_title_id() {
        let out = compile_src(
            "title: no id\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n",
            &PipelineSet::default(),
        );
        assert_eq!(out.rules[0].info.id, "title:no id");
    }

    use crate::item::count_preds as preds_in;

    fn big_pipes() -> PipelineSet {
        let vals: Vec<String> = (0..4000).map(|i| format!("v{i}")).collect();
        PipelineSet::new(vec![
            parse_pipeline(&format!("name: v\nvars:\n  Big: [{}]\n", vals.join(", "))).unwrap(),
        ])
    }

    #[test]
    fn unreferenced_identifiers_count_toward_the_rule_budget() {
        let mut det = String::new();
        for i in 0..300 {
            det.push_str(&format!(
                "    s{i}:\n        U|expand: ['%Big%', '%Big%', '%Big%', '%Big%']\n"
            ));
        }
        det.push_str("    condition: s0\n");
        let out = compile_src(&rule_with(&det), &big_pipes());
        assert!(out.rules.is_empty());
        assert!(first_error(&out).contains("rule expands to more than 65536 predicates"));
    }

    #[test]
    fn expansion_stops_at_the_item_cap() {
        let list = vec!["'%Big%'"; 2000].join(", ");
        let out = compile_src(
            &rule_with(&format!(
                "    s:\n        U|expand: [{list}]\n    condition: s\n"
            )),
            &big_pipes(),
        );
        assert!(first_error(&out).contains("item expands to more than 16384 predicates"));
    }

    #[test]
    fn modifier_checks_come_before_expansion() {
        let list = vec!["'%Big%'"; 2000].join(", ");
        let out = compile_src(
            &rule_with(&format!(
                "    s:\n        U|expand|gt|lt: [{list}]\n    condition: s\n"
            )),
            &big_pipes(),
        );
        assert!(
            first_error(&out).contains("comparison"),
            "{}",
            first_error(&out)
        );
    }

    fn group_sizes(e: &Expr) -> Vec<usize> {
        let Expr::And(v) = e else {
            panic!("expected And, got {e:?}")
        };
        v.iter()
            .map(|g| match g {
                Expr::Or(x) => {
                    assert!(x.iter().all(|p| matches!(p, Expr::Pred(_))));
                    x.len()
                }
                _ => panic!("expected Or group, got {g:?}"),
            })
            .collect()
    }

    #[test]
    fn all_ands_original_values_and_ors_variants() {
        let out = compile_detection_src(
            "    s:\n        C|windash|contains|all: ['-a', '-b']\n    condition: s\n",
        );
        assert_eq!(group_sizes(&out.rules[0].expr), vec![5, 5]);
        let out = compile_detection_src(
            "    s:\n        C|base64offset|contains|all: [ab, cd]\n    condition: s\n",
        );
        assert_eq!(group_sizes(&out.rules[0].expr), vec![3, 3]);
    }

    #[test]
    fn expand_groups_per_original_value() {
        let pipes = PipelineSet::new(vec![
            parse_pipeline("name: v\nvars:\n  Admins: [a, b]\n").unwrap(),
        ]);
        let out = compile_src(
            &rule_with("    s:\n        U|expand: '%Admins%'\n    condition: s\n"),
            &pipes,
        );
        assert!(matches!(&out.rules[0].expr, Expr::Or(v) if v.len() == 2));
        let out = compile_src(
            &rule_with("    s:\n        U|all|expand: ['%Admins%', x]\n    condition: s\n"),
            &pipes,
        );
        let Expr::And(v) = &out.rules[0].expr else {
            panic!("{:?}", out.rules[0].expr)
        };
        assert_eq!(v.len(), 2);
        assert!(matches!(&v[0], Expr::Or(x) if x.len() == 2));
        assert!(matches!(&v[1], Expr::Pred(_)));
    }

    #[test]
    fn item_predicate_budget() {
        let vals: Vec<String> = (0..200).map(|i| format!("v{i}")).collect();
        let pipes = PipelineSet::new(vec![
            parse_pipeline(&format!("name: v\nvars:\n  Big: [{}]\n", vals.join(", "))).unwrap(),
        ]);
        let out = compile_src(
            &rule_with(&format!(
                "    s:\n        C|expand|windash|contains: [{}]\n    condition: s\n",
                vec!["'%Big% -x'"; 17].join(", ")
            )),
            &pipes,
        );
        assert!(out.rules.is_empty());
        assert!(
            first_error(&out).contains("item expands to more than 16384 predicates"),
            "{}",
            first_error(&out)
        );
    }

    #[test]
    fn rule_predicate_budget_fails_fast() {
        let vals: Vec<String> = (0..4000).map(|i| format!("v{i}")).collect();
        let det = format!(
            "    a:\n        C|contains: [{}]\n    condition: {}\n",
            vals.join(", "),
            vec!["a"; 20].join(" or ")
        );
        let out = compile_detection_src(&det);
        assert!(out.rules.is_empty());
        assert!(
            first_error(&out).contains("rule expands to more than 65536 predicates"),
            "{}",
            first_error(&out)
        );
        // within budget
        let det = format!(
            "    a:\n        C|contains: [{}]\n    condition: a\n",
            vals.join(", ")
        );
        let out = compile_detection_src(&det);
        assert_eq!(preds_in(&out.rules[0].expr), 4000);
    }

    #[test]
    fn filter_fold_respects_rule_budget() {
        let vals: Vec<String> = (0..4000).map(|i| format!("v{i}")).collect();
        let big = |name: &str| {
            format!(
                "    {name}:\n        C|contains: [{}]\n    condition: {name}\n",
                vals.join(", ")
            )
        };
        let mut src = rule_with(&big("s"));
        for i in 0..17 {
            src.push_str(&format!(
                "---\ntitle: f{i}\nlogsource:\n    product: windows\nfilter:\n    rules: [r1]\n{}",
                big("sel")
            ));
        }
        let out = compile_src(&src, &PipelineSet::default());
        assert!(out.rules.is_empty());
        assert!(first_error(&out).contains("rule expands to more than 65536 predicates"));
    }

    #[test]
    fn dropped_modifiers_are_rejected() {
        let cases = [
            ("C|gt|lt: 5", "comparison"),
            ("C|hour|day: 1", "time modifier"),
            ("C|base64|cidr: 10.0.0.0/8", "base64"),
            ("C|contains|re: a", "contains"),
            ("C|windash|gt: 5", "windash"),
            ("C|contains|hour: 5", "contains"),
            ("C|exists|contains: true", "exists"),
            ("C|exists|neq: true", "exists"),
            ("C|fieldref|base64: X", "base64"),
            ("C|fieldref|startswith|contains: X", "only one"),
        ];
        for (item, needle) in cases {
            let out = compile_detection_src(&format!("    s:\n        {item}\n    condition: s\n"));
            assert!(out.rules.is_empty(), "{item} should not compile");
            let err = first_error(&out);
            assert!(err.contains(needle), "{item}: `{needle}` not in `{err}`");
        }
    }

    #[test]
    fn valid_modifier_combos_still_compile() {
        for item in [
            "C|contains|windash: '-a'",
            "C|wide|base64offset|contains: ab",
            "C|base64|contains: ab",
            "C|re|i: 'a.c'",
            "C|hour|gte: 5",
            "C|fieldref|contains: X",
            "C|cased|contains: ab",
        ] {
            let out = compile_detection_src(&format!("    s:\n        {item}\n    condition: s\n"));
            assert_eq!(out.rules.len(), 1, "{item}: {:?}", out.diagnostics);
        }
    }

    #[test]
    fn cidr_accepts_bare_addresses() {
        let out = compile_detection_src("    s:\n        Ip|cidr: 10.1.2.3\n    condition: s\n");
        assert!(
            matches!(&only_pred(&out).matcher, Matcher::Cidr(n) if n.to_string() == "10.1.2.3/32")
        );
        let out = compile_detection_src("    s:\n        Ip|cidr: '::1'\n    condition: s\n");
        assert!(matches!(&only_pred(&out).matcher, Matcher::Cidr(n) if n.to_string() == "::1/128"));
    }

    #[test]
    fn total_budget_skips_the_rest_with_one_error() {
        // Each rule weighs ~60k (under the rule budget); 20 of them exceed 1M.
        let vals: Vec<String> = (0..3750).map(|i| format!("'v{i}'")).collect();
        let one = |n: usize| {
            format!(
                "title: t{n}\nid: r{n}\nlogsource:\n    product: windows\ndetection:\n    s:\n        C|re: [{}]\n    condition: s\n",
                vals.join(", ")
            )
        };
        let src: Vec<String> = (0..20).map(one).collect();
        let out = compile_src(&src.join("---\n"), &PipelineSet::default());
        let errs: Vec<_> = out.diagnostics.iter().filter(|d| d.is_error()).collect();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].message.contains("total compile budget of 1000000"));
        let kept = MAX_TOTAL_WEIGHT / (3750 * REGEX_WEIGHT);
        assert_eq!(out.rules.len(), kept);
        assert!(
            errs[0]
                .message
                .contains(&format!("({} documents skipped)", 20 - kept))
        );
    }

    #[test]
    fn regex_predicates_are_weighted() {
        let vals: Vec<String> = (0..5000).map(|i| format!("'v{i}'")).collect();
        let out = compile_detection_src(&format!(
            "    s:\n        C|re: [{}]\n    condition: s\n",
            vals.join(", ")
        ));
        assert!(out.rules.is_empty());
        assert!(first_error(&out).contains("rule expands to more than 65536 predicates"));
    }

    #[test]
    fn normal_rule_sets_are_unaffected() {
        let src: Vec<String> = (0..50).map(|n| format!(
            "title: t{n}\nid: r{n}\nlogsource:\n    product: windows\ndetection:\n    s:\n        C|re: 'a{n}'\n    condition: s\n")).collect();
        let out = compile_src(&src.join("---\n"), &PipelineSet::default());
        assert_eq!(out.rules.len(), 50);
        assert!(out.diagnostics.iter().all(|d| !d.is_error()));
    }
}
