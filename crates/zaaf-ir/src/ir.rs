//! The intermediate representation shared by every evaluator.

use crate::regex_engine::CompiledRegex;
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
    /// Total backtrack-limit hits over every regex in the expression.
    pub fn regex_limit_hits(&self) -> u64 {
        match self {
            Expr::And(v) | Expr::Or(v) => v.iter().map(Expr::regex_limit_hits).sum(),
            Expr::Not(e) => e.regex_limit_hits(),
            Expr::Pred(p) => match &p.matcher {
                Matcher::Regex(re) => re.limit_hits(),
                _ => 0,
            },
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
    /// Field absent or JSON null.
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
}
