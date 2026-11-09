//! The intermediate representation shared by every evaluator.

use crate::regex_engine::{CompiledRegex, LimitCounter};
use std::collections::HashMap;
use zaaf_sigma::SigmaString;

/// A boolean expression over predicates. `And([])` is true, `Or([])` is false.
#[derive(Debug, Clone)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Pred(Predicate),
}

impl Expr {
    /// Total backtrack-limit hits over every regex in the expression. Clones of one
    /// regex share a counter, which is counted once.
    pub fn regex_limit_hits(&self) -> u64 {
        let mut seen = HashMap::new();
        self.collect_hits(&mut seen);
        seen.values().sum()
    }

    /// Handles on the distinct hit counters of every regex in the expression (clones of one
    /// regex share a counter and appear once). Summing their `hits()` equals `regex_limit_hits`.
    pub fn regex_counters(&self) -> Vec<LimitCounter> {
        let mut seen = HashMap::new();
        self.collect_counters(&mut seen);
        seen.into_values().collect()
    }

    fn collect_counters(&self, seen: &mut HashMap<usize, LimitCounter>) {
        match self {
            Expr::And(v) | Expr::Or(v) => v.iter().for_each(|e| e.collect_counters(seen)),
            Expr::Not(e) => e.collect_counters(seen),
            Expr::Pred(p) => {
                if let Matcher::Regex(re) = &p.matcher {
                    seen.entry(re.counter_id())
                        .or_insert_with(|| re.limit_counter());
                }
            }
        }
    }

    /// Deep copy in which every regex has its own zeroed limit-hit counter.
    pub fn with_fresh_regex_counters(&self) -> Expr {
        match self {
            Expr::And(v) => Expr::And(v.iter().map(Expr::with_fresh_regex_counters).collect()),
            Expr::Or(v) => Expr::Or(v.iter().map(Expr::with_fresh_regex_counters).collect()),
            Expr::Not(e) => Expr::Not(Box::new(e.with_fresh_regex_counters())),
            Expr::Pred(p) => {
                let matcher = match &p.matcher {
                    Matcher::Regex(re) => Matcher::Regex(re.with_fresh_counter()),
                    m => m.clone(),
                };
                Expr::Pred(Predicate {
                    target: p.target.clone(),
                    matcher,
                })
            }
        }
    }

    fn collect_hits(&self, seen: &mut HashMap<usize, u64>) {
        match self {
            Expr::And(v) | Expr::Or(v) => v.iter().for_each(|e| e.collect_hits(seen)),
            Expr::Not(e) => e.collect_hits(seen),
            Expr::Pred(p) => {
                if let Matcher::Regex(re) = &p.matcher {
                    seen.insert(re.counter_id(), re.limit_hits());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Predicate {
    pub target: Target,
    pub matcher: Matcher,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Event field paths after pipeline mapping; a match on any of them counts.
    Fields(Vec<String>),
    /// Keyword search across every value of the event.
    AnyField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimePart {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefMode {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
pub enum Matcher {
    /// Glob match. When `case_sensitive` is false the pattern is already lower-case
    /// and evaluators must lower-case the event value.
    Str {
        pattern: SigmaString,
        case_sensitive: bool,
    },
    Regex(CompiledRegex),
    Num {
        op: CmpOp,
        value: f64,
    },
    Cidr(ipnet::IpNet),
    /// Field present (any value, even null or empty) == the flag.
    Exists(bool),
    /// True when every mapped alternative is absent or holds a JSON null; an alternative
    /// whose array contains a null among other values counts as null (mirrors `Exists(false)`).
    Null,
    /// Compares the field with other field(s) of the same event.
    FieldRef {
        other: Vec<String>,
        mode: RefMode,
        case_sensitive: bool,
    },
    /// Extracts a part of a timestamp value and compares it.
    TimePart {
        part: TimePart,
        op: CmpOp,
        value: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regex_engine::RegexFlags;

    fn pred(re: CompiledRegex) -> Expr {
        Expr::Pred(Predicate {
            target: Target::Fields(vec!["f".to_string()]),
            matcher: Matcher::Regex(re),
        })
    }

    #[test]
    fn regex_limit_hits_sum_over_the_tree() {
        let mk = || {
            CompiledRegex::with_backtrack_limit(r"^(a|a)*\1$", RegexFlags::default(), 10).unwrap()
        };
        let (a, b) = (mk(), mk());
        let text = format!("{}b", "a".repeat(200));
        assert!(!a.is_match(&text));
        assert!(!b.is_match(&text));
        assert!(!b.is_match(&text));
        let expected = a.limit_hits() + b.limit_hits();
        assert!(expected >= 2);
        let e = Expr::Or(vec![pred(a), Expr::Not(Box::new(pred(b)))]);
        assert_eq!(e.regex_limit_hits(), expected);
    }

    #[test]
    fn regex_counters_are_distinct_and_sum_to_regex_limit_hits() {
        let mk = || {
            CompiledRegex::with_backtrack_limit(r"^(a|a)*\1$", RegexFlags::default(), 10).unwrap()
        };
        let (a, b) = (mk(), mk());
        let e = Expr::Or(vec![
            pred(a.clone()),
            pred(a.clone()),
            Expr::Not(Box::new(pred(b.clone()))),
        ]);
        let counters = e.regex_counters();
        assert_eq!(counters.len(), 2);
        let text = format!("{}b", "a".repeat(200));
        assert!(!a.is_match(&text));
        assert!(!b.is_match(&text));
        assert!(!b.is_match(&text));
        let summed: u64 = counters.iter().map(|c| c.hits()).sum();
        assert!(summed >= 3);
        assert_eq!(summed, e.regex_limit_hits());
    }

    #[test]
    fn cloned_regex_is_counted_once() {
        let re =
            CompiledRegex::with_backtrack_limit(r"^(a|a)*\1$", RegexFlags::default(), 10).unwrap();
        let text = format!("{}b", "a".repeat(200));
        assert!(!re.is_match(&text));
        let per_counter = re.limit_hits();
        assert!(per_counter >= 1);
        assert_eq!(re.counter_id(), re.clone().counter_id());
        let e = Expr::Or(vec![pred(re.clone()), pred(re)]);
        assert_eq!(e.regex_limit_hits(), per_counter);
    }
}
