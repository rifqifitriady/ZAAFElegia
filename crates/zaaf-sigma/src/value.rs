//! Scalar values as written in a Sigma detection.

use saphyr::{MarkedYaml, Scalar, YamlData};

/// A scalar value from a Sigma detection.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl RuleValue {
    /// Converts a YAML scalar. Returns `None` for sequences, mappings, tagged
    /// values, aliases and invalid values.
    pub fn from_yaml(v: &MarkedYaml<'_>) -> Option<Self> {
        match &v.data {
            YamlData::Value(Scalar::Null) => Some(Self::Null),
            YamlData::Value(Scalar::Boolean(b)) => Some(Self::Bool(*b)),
            YamlData::Value(Scalar::Integer(i)) => Some(Self::Int(*i)),
            YamlData::Value(Scalar::FloatingPoint(f)) => Some(Self::Float(f.into_inner())),
            YamlData::Value(Scalar::String(s)) => Some(Self::Str(s.to_string())),
            _ => None,
        }
    }

    /// Text used when a non-string value is matched as a string (`4688`, `true`).
    pub fn to_text(&self) -> Option<String> {
        match self {
            Self::Str(s) => Some(s.clone()),
            Self::Int(i) => Some(i.to_string()),
            Self::Float(f) => Some(f.to_string()),
            Self::Bool(b) => Some(b.to_string()),
            Self::Null => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saphyr::LoadableYamlNode;

    #[test]
    fn converts_yaml_scalars() {
        let docs =
            MarkedYaml::load_from_str("[abc, 4688, 1.5, true, null, '4688', [x], !custom y]")
                .unwrap();
        let s = docs[0].data.as_vec().unwrap();
        assert_eq!(
            RuleValue::from_yaml(&s[0]),
            Some(RuleValue::Str("abc".into()))
        );
        assert_eq!(RuleValue::from_yaml(&s[1]), Some(RuleValue::Int(4688)));
        assert_eq!(RuleValue::from_yaml(&s[2]), Some(RuleValue::Float(1.5)));
        assert_eq!(RuleValue::from_yaml(&s[3]), Some(RuleValue::Bool(true)));
        assert_eq!(RuleValue::from_yaml(&s[4]), Some(RuleValue::Null));
        assert_eq!(
            RuleValue::from_yaml(&s[5]),
            Some(RuleValue::Str("4688".into()))
        );
        assert_eq!(RuleValue::from_yaml(&s[6]), None);
        assert_eq!(RuleValue::from_yaml(&s[7]), None);
    }

    #[test]
    fn text_form_of_non_strings() {
        assert_eq!(RuleValue::Int(4688).to_text().as_deref(), Some("4688"));
        assert_eq!(RuleValue::Bool(false).to_text().as_deref(), Some("false"));
        assert_eq!(RuleValue::Null.to_text(), None);
    }
}
