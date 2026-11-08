//! Compiles parsed Sigma documents into the ZAAFElegia intermediate representation.

pub mod ir;
pub mod regex_engine;
mod transform;

pub use ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
pub use regex_engine::{BACKTRACK_LIMIT, CompiledRegex, RegexFlags};
