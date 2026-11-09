//! Sigma rule parser for ZAAFElegia.

pub mod condition;
pub mod diagnostic;
pub mod document;
pub mod modifier;
pub mod sigma_string;
pub mod value;

pub use condition::{CondExpr, Quantifier, SelTarget, parse_condition};
pub use diagnostic::{Diagnostic, Location, Severity};
pub use document::{
    CorrelationStub, Detection, Document, FieldItem, Filter, LogSource, ParsedFile, Rule, RuleMeta,
    SearchIdentifier, parse_file, parse_str,
};
pub use modifier::{FieldKey, Modifier, parse_field_key};
pub use sigma_string::{SigmaString, Tok};
pub use value::RuleValue;

/// Version of the Sigma specification this crate implements.
pub const SPEC_VERSION: &str = "2.1.0";

#[cfg(test)]
mod tests {
    #[test]
    fn spec_version_is_2_1_0() {
        assert_eq!(super::SPEC_VERSION, "2.1.0");
    }
}
