//! Compiles parsed Sigma documents into the ZAAFElegia intermediate representation.

pub mod ir;
mod item;
pub mod regex_engine;
mod rule;
mod transform;

pub use ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
pub use regex_engine::{BACKTRACK_LIMIT, CompiledRegex, LimitCounter, RegexFlags};
pub use rule::{
    CompileOutput, CompiledRule, Level, MAX_RULE_PREDICATES, MAX_TOTAL_WEIGHT, RuleInfo,
    SourcedDocument, compile,
};
