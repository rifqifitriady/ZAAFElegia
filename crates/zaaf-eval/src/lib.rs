//! Native evaluator. Its behaviour *is* the ZAAFElegia semantics: every other
//! evaluator (DataFusion, M4) is tested against it.

use chrono::{DateTime, Datelike, Timelike, Utc};
use std::net::IpAddr;
use zaaf_event::{Event, FieldValue, parse_timestamp, timestamp_from_epoch};
use zaaf_ir::{CmpOp, CompiledRule, Expr, Matcher, Predicate, RefMode, Target, TimePart};

pub struct Evaluator {
    rules: Vec<CompiledRule>,
}

impl Evaluator {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// `(rule index, hits)` for every rule whose regexes hit the backtrack limit, in rule order.
    /// Counts are cumulative since the evaluator was built. A limit hit evaluates as "no match"; this reports it so evasion is visible.
    pub fn regex_limit_hits(&self) -> Vec<(usize, u64)> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, r)| (i, r.expr.regex_limit_hits()))
            .filter(|(_, n)| *n > 0)
            .collect()
    }

    /// Indexes (into `rules()`) of every rule that matches `event`, in rule order.
    pub fn matching_rules(&self, event: &dyn Event) -> Vec<usize> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| eval_expr(&r.expr, event))
            .map(|(i, _)| i)
            .collect()
    }
}

pub fn eval_expr(expr: &Expr, event: &dyn Event) -> bool {
    match expr {
        Expr::And(items) => items.iter().all(|e| eval_expr(e, event)),
        Expr::Or(items) => items.iter().any(|e| eval_expr(e, event)),
        Expr::Not(inner) => !eval_expr(inner, event),
        Expr::Pred(p) => eval_predicate(p, event),
    }
}

fn eval_predicate(p: &Predicate, event: &dyn Event) -> bool {
    match &p.target {
        Target::AnyField => event
            .leaf_values()
            .iter()
            .any(|v| value_matches(&p.matcher, v)),
        Target::Fields(fields) => match &p.matcher {
            Matcher::Exists(want) => fields.iter().any(|f| event.get(f).is_some()) == *want,
            // Mirrors `Exists(false)`: true only when EVERY mapped alternative is absent or
            // contains a JSON null (so `["a", null]` counts as null). A field that is
            // present with no null (even `[]` or `{}`) makes the predicate false.
            Matcher::Null => fields.iter().all(|f| match event.get(f) {
                None => true,
                Some(values) => values.iter().any(|v| matches!(v, FieldValue::Null)),
            }),
            Matcher::FieldRef {
                other,
                mode,
                case_sensitive,
            } => fields.iter().any(|f| {
                other
                    .iter()
                    .any(|o| fieldref(event, f, o, *mode, *case_sensitive))
            }),
            m => fields.iter().any(|f| {
                event
                    .get(f)
                    .is_some_and(|values| values.iter().any(|v| value_matches(m, v)))
            }),
        },
    }
}

fn value_matches(m: &Matcher, v: &FieldValue) -> bool {
    match m {
        Matcher::Str {
            pattern,
            case_sensitive,
        } => match v.as_text() {
            Some(t) if *case_sensitive => pattern.matches(&t),
            Some(t) => pattern.matches(&t.to_lowercase()),
            None => false,
        },
        Matcher::Regex(re) => v.as_text().is_some_and(|t| re.is_match(&t)),
        Matcher::Num { op, value } => v.as_f64().is_some_and(|x| compare(*op, x, *value)),
        Matcher::Cidr(net) => v.as_text().and_then(|t| parse_ip(&t)).is_some_and(|ip| {
            // IPv4-mapped IPv6 addresses match both as written and as the IPv4 they wrap.
            net.contains(&ip) || net.contains(&ip.to_canonical())
        }),
        Matcher::TimePart { part, op, value } => timestamp_of(v)
            .is_some_and(|ts| compare(*op, time_part(ts, *part) as f64, *value as f64)),
        Matcher::Exists(_) | Matcher::Null | Matcher::FieldRef { .. } => false,
    }
}

/// Trims, drops an IPv6 `%zone` suffix (only when the text contains `:`) and parses. Leading-zero dotted quads stay rejected.
fn parse_ip(text: &str) -> Option<IpAddr> {
    let t = text.trim();
    // A `%zone` suffix exists only on IPv6 text.
    let t = match t.split_once('%') {
        Some((addr, _zone)) if addr.contains(':') => addr,
        _ => t,
    };
    t.parse().ok()
}

fn compare(op: CmpOp, a: f64, b: f64) -> bool {
    match op {
        CmpOp::Eq => a == b,
        CmpOp::Lt => a < b,
        CmpOp::Lte => a <= b,
        CmpOp::Gt => a > b,
        CmpOp::Gte => a >= b,
    }
}

fn timestamp_of(v: &FieldValue) -> Option<DateTime<Utc>> {
    match v {
        FieldValue::Str(s) => parse_timestamp(s),
        FieldValue::Int(i) => timestamp_from_epoch(*i as f64),
        FieldValue::Float(f) => timestamp_from_epoch(*f),
        FieldValue::Bool(_) | FieldValue::Null => None,
    }
}

fn time_part(ts: DateTime<Utc>, part: TimePart) -> i64 {
    match part {
        TimePart::Minute => ts.minute() as i64,
        TimePart::Hour => ts.hour() as i64,
        TimePart::Day => ts.day() as i64,
        TimePart::Week => ts.iso_week().week() as i64,
        TimePart::Month => ts.month() as i64,
        TimePart::Year => ts.year() as i64,
    }
}

fn fieldref(
    event: &dyn Event,
    field: &str,
    other: &str,
    mode: RefMode,
    case_sensitive: bool,
) -> bool {
    let (Some(left), Some(right)) = (event.get(field), event.get(other)) else {
        return false;
    };
    let norm = |v: &FieldValue| {
        v.as_text().map(|t| {
            if case_sensitive {
                t.into_owned()
            } else {
                t.to_lowercase()
            }
        })
    };
    let rights: Vec<String> = right.iter().filter_map(norm).collect();
    left.iter().filter_map(norm).any(|l| {
        rights.iter().any(|r| match mode {
            RefMode::Equals => &l == r,
            RefMode::Contains => l.contains(r.as_str()),
            RefMode::StartsWith => l.starts_with(r.as_str()),
            RefMode::EndsWith => l.ends_with(r.as_str()),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zaaf_event::JsonEvent;
    use zaaf_ir::{SourcedDocument, compile};
    use zaaf_pipeline::PipelineSet;

    fn evaluator(src: &str) -> Evaluator {
        let parsed = zaaf_sigma::parse_str(src);
        assert!(
            parsed.diagnostics.iter().all(|d| !d.is_error()),
            "{:?}",
            parsed.diagnostics
        );
        let out = compile(
            parsed
                .documents
                .into_iter()
                .map(|document| SourcedDocument {
                    document,
                    source: None,
                })
                .collect(),
            &PipelineSet::default(),
        );
        assert!(
            out.diagnostics.iter().all(|d| !d.is_error()),
            "{:?}",
            out.diagnostics
        );
        Evaluator::new(out.rules)
    }

    /// Quoted so that ids such as `null` stay strings in YAML.
    fn rule(id: &str, detection: &str) -> String {
        format!("title: '{id}'\nid: '{id}'\nlogsource:\n    product: test\ndetection:\n{detection}")
    }

    fn hits(e: &Evaluator, json: &str) -> Vec<String> {
        let event = JsonEvent::new(serde_json::from_str(json).unwrap());
        e.matching_rules(&event)
            .into_iter()
            .map(|i| e.rules()[i].info.id.clone())
            .collect()
    }

    #[test]
    fn case_insensitive_equality_and_int_as_text() {
        let e = evaluator(&rule(
            "r",
            "    s:\n        EventID: 4688\n        Image|endswith: '\\cmd.exe'\n    condition: s\n",
        ));
        assert_eq!(
            hits(
                &e,
                r#"{"EventID": "4688", "Image": "C:\\WINDOWS\\CMD.EXE"}"#
            ),
            vec!["r"]
        );
        assert!(hits(&e, r#"{"EventID": 4689, "Image": "C:\\cmd.exe"}"#).is_empty());
    }

    #[test]
    fn keywords_search_nested_values() {
        let e = evaluator(&rule(
            "k",
            "    k:\n        - 'event::clear'\n    condition: k\n",
        ));
        assert_eq!(
            hits(&e, r#"{"a": {"b": ["x", "Mimikatz EVENT::Clear"]}}"#),
            vec!["k"]
        );
        assert!(hits(&e, r#"{"a": "nothing"}"#).is_empty());
    }

    #[test]
    fn null_exists_and_neq_on_missing_fields() {
        let e = evaluator(&format!(
            "{}---\n{}---\n{}",
            rule("null", "    s:\n        F: null\n    condition: s\n"),
            rule(
                "exists",
                "    s:\n        F|exists: true\n    condition: s\n"
            ),
            rule("neq", "    s:\n        F|neq: x\n    condition: s\n"),
        ));
        assert_eq!(hits(&e, r#"{}"#), vec!["null", "neq"]);
        assert_eq!(hits(&e, r#"{"F": null}"#), vec!["null", "exists", "neq"]);
        assert_eq!(hits(&e, r#"{"F": "X"}"#), vec!["exists"]);
    }

    #[test]
    fn numeric_cidr_regex_time_and_fieldref() {
        let e = evaluator(&format!(
            "{}---\n{}---\n{}---\n{}---\n{}",
            rule("num", "    s:\n        Size|gte: 10\n    condition: s\n"),
            rule(
                "cidr",
                "    s:\n        Ip|cidr: 10.0.0.0/8\n    condition: s\n"
            ),
            rule(
                "re",
                "    s:\n        Name|re: '^(?!svchost).*\\.exe$'\n    condition: s\n"
            ),
            rule("hour", "    s:\n        T|hour: 3\n    condition: s\n"),
            rule(
                "ref",
                "    s:\n        A|fieldref|contains: B\n    condition: s\n"
            ),
        ));
        assert_eq!(
            hits(
                &e,
                r#"{"Size": "12", "Ip": "10.1.2.3", "Name": "evil.exe", "T": "2026-11-07T03:00:00Z", "A": "run as BOB", "B": "bob"}"#
            ),
            vec!["num", "cidr", "re", "hour", "ref"]
        );
        assert!(hits(&e, r#"{"Size": "big", "Ip": "nope", "Name": "svchost.exe", "T": "x", "A": "a", "B": "b"}"#).is_empty());
    }

    #[test]
    fn multiple_mapped_fields_are_ored() {
        use zaaf_ir::{Expr, Matcher, Predicate, Target};
        use zaaf_sigma::SigmaString;
        let expr = Expr::Pred(Predicate {
            target: Target::Fields(vec!["a".into(), "b".into()]),
            matcher: Matcher::Str {
                pattern: SigmaString::literal("x"),
                case_sensitive: false,
            },
        });
        let event = JsonEvent::new(serde_json::json!({"b": "X"}));
        assert!(eval_expr(&expr, &event));
    }

    fn null_expr(fields: &[&str]) -> Expr {
        Expr::Pred(Predicate {
            target: Target::Fields(fields.iter().map(|s| s.to_string()).collect()),
            matcher: Matcher::Null,
        })
    }

    #[test]
    fn null_over_several_fields_requires_every_alternative_absent_or_null() {
        let e = null_expr(&["a", "b"]);
        let ev = |v: serde_json::Value| JsonEvent::new(v);
        assert!(!eval_expr(&e, &ev(serde_json::json!({"a": "x"}))));
        assert!(eval_expr(&e, &ev(serde_json::json!({}))));
        assert!(eval_expr(&e, &ev(serde_json::json!({"a": null}))));
        assert!(!eval_expr(
            &e,
            &ev(serde_json::json!({"a": null, "b": "y"}))
        ));
    }

    #[test]
    fn cidr_handles_mapped_ipv6_zones_and_rejects_outsiders() {
        let cidr = |net: &str| {
            Expr::Pred(Predicate {
                target: Target::Fields(vec!["ip".into()]),
                matcher: Matcher::Cidr(net.parse().unwrap()),
            })
        };
        let hit = |net: &str, ip: &str| {
            eval_expr(&cidr(net), &JsonEvent::new(serde_json::json!({ "ip": ip })))
        };
        assert!(hit("10.0.0.0/8", "::ffff:10.1.2.3"));
        assert!(hit("fe80::/10", "fe80::1%12"));
        assert!(hit("10.0.0.0/8", " 10.1.2.3 "));
        assert!(!hit("10.0.0.0/8", "8.8.8.8"));
        assert!(!hit("10.0.0.0/8", "010.1.2.3"));
        // `%zone` is an IPv6 notion only.
        assert!(!hit("10.0.0.0/8", "10.1.2.3%junk"));
        // A mapped address matches a net that contains the mapped form itself.
        assert!(hit("::ffff:0:0/96", "::ffff:10.1.2.3"));
        assert!(hit("::/0", "::ffff:10.1.2.3"));
        assert!(hit("::/0", "2001:db8::1"));
    }

    #[test]
    fn folded_filter_regex_hits_are_credited_only_to_the_rule_that_ran_it() {
        let src = format!(
            "{}---\n{}---\ntitle: f\nlogsource:\n    product: test\nfilter:\n    rules: [r1, r2]\n    sel:\n        Image|re: '^(a|a)*\\1$'\n    condition: sel\n",
            rule(
                "r1",
                "    s:\n        Image|startswith: aaa\n    condition: s\n"
            ),
            rule("r2", "    s:\n        Other: nope\n    condition: s\n"),
        );
        let e = evaluator(&src);
        assert!(e.regex_limit_hits().is_empty());
        let event = JsonEvent::new(serde_json::json!({"Image": format!("{}b", "a".repeat(40))}));
        // r1's selection matches, so its folded filter regex runs, gives up and the
        // event is not silenced. r2's selection fails, so its regex never runs.
        assert_eq!(e.matching_rules(&event), vec![0]);
        let reported = e.regex_limit_hits();
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert_eq!(reported[0].0, 0);
        assert!(reported[0].1 >= 1);
    }

    #[test]
    fn five_thousand_filters_evaluate_on_the_default_stack() {
        let mut src = rule("r1", "    s:\n        Image: a\n    condition: s\n");
        for i in 0..5000 {
            src.push_str(&format!(
                "---\ntitle: f{i}\nlogsource:\n    product: test\nfilter:\n    rules: [r1]\n    sel:\n        U: v{i}\n    condition: sel\n"
            ));
        }
        let e = evaluator(&src);
        assert_eq!(
            hits(&e, r#"{"Image": "a", "U": "v77"}"#),
            Vec::<String>::new()
        );
        assert_eq!(hits(&e, r#"{"Image": "a", "U": "other"}"#), vec!["r1"]);
    }

    #[test]
    fn regex_limit_hits_are_reported_per_rule() {
        use zaaf_ir::{CompiledRegex, Expr, Matcher, Predicate, RegexFlags, Target};
        use zaaf_ir::{CompiledRule, Level, RuleInfo};
        use zaaf_sigma::LogSource;
        let info = |id: &str| RuleInfo {
            id: id.into(),
            name: None,
            title: id.into(),
            level: Level::Medium,
            status: None,
            description: None,
            author: None,
            references: vec![],
            tags: vec![],
            falsepositives: vec![],
            logsource: LogSource::default(),
            source: None,
        };
        let re =
            CompiledRegex::with_backtrack_limit(r"^(a|a)*\1$", RegexFlags::default(), 10).unwrap();
        let pred = |m| {
            Expr::Pred(Predicate {
                target: Target::Fields(vec!["f".into()]),
                matcher: m,
            })
        };
        let e = Evaluator::new(vec![
            CompiledRule {
                info: info("plain"),
                expr: pred(Matcher::Exists(true)),
            },
            CompiledRule {
                info: info("redos"),
                expr: pred(Matcher::Regex(re)),
            },
        ]);
        assert!(e.regex_limit_hits().is_empty());
        let event = JsonEvent::new(serde_json::json!({"f": format!("{}b", "a".repeat(200))}));
        assert_eq!(e.matching_rules(&event), vec![0]);
        let reported = e.regex_limit_hits();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].0, 1);
        assert!(reported[0].1 >= 1);
    }
}
