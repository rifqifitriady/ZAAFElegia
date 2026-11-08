//! Sigma 2.1 value modifiers (`field|mod1|mod2`).

/// Every modifier defined by the Sigma 2.1 modifiers appendix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    // generic
    All,
    StartsWith,
    EndsWith,
    Contains,
    Exists,
    Cased,
    Neq,
    // string
    Windash,
    Re,
    ReInsensitive,
    ReMultiline,
    ReDotAll,
    Base64,
    Base64Offset,
    Utf16Le,
    Utf16Be,
    Utf16,
    Wide,
    // numeric
    Lt,
    Lte,
    Gt,
    Gte,
    // time
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
    // ip
    Cidr,
    // specific
    Expand,
    FieldRef,
}

pub(crate) const TABLE: &[(&str, Modifier)] = &[
    ("all", Modifier::All),
    ("startswith", Modifier::StartsWith),
    ("endswith", Modifier::EndsWith),
    ("contains", Modifier::Contains),
    ("exists", Modifier::Exists),
    ("cased", Modifier::Cased),
    ("neq", Modifier::Neq),
    ("windash", Modifier::Windash),
    ("re", Modifier::Re),
    ("i", Modifier::ReInsensitive),
    ("m", Modifier::ReMultiline),
    ("s", Modifier::ReDotAll),
    ("base64", Modifier::Base64),
    ("base64offset", Modifier::Base64Offset),
    ("utf16le", Modifier::Utf16Le),
    ("utf16be", Modifier::Utf16Be),
    ("utf16", Modifier::Utf16),
    ("wide", Modifier::Wide),
    ("lt", Modifier::Lt),
    ("lte", Modifier::Lte),
    ("gt", Modifier::Gt),
    ("gte", Modifier::Gte),
    ("minute", Modifier::Minute),
    ("hour", Modifier::Hour),
    ("day", Modifier::Day),
    ("week", Modifier::Week),
    ("month", Modifier::Month),
    ("year", Modifier::Year),
    ("cidr", Modifier::Cidr),
    ("expand", Modifier::Expand),
    ("fieldref", Modifier::FieldRef),
];

impl Modifier {
    pub fn parse(s: &str) -> Option<Self> {
        TABLE.iter().find(|(n, _)| *n == s).map(|(_, m)| *m)
    }

    pub fn name(self) -> &'static str {
        TABLE
            .iter()
            .find(|(_, m)| *m == self)
            .map(|(n, _)| *n)
            .expect("every modifier is listed in TABLE")
    }
}

/// A detection key split into its field name and modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldKey {
    /// `None` for keyword keys such as `|all`.
    pub field: Option<String>,
    pub modifiers: Vec<Modifier>,
}

/// Splits `CommandLine|contains|all` into the field and its modifiers.
pub fn parse_field_key(key: &str) -> Result<FieldKey, String> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    let field = (!field.is_empty()).then(|| field.to_string());
    let mut modifiers = Vec::new();
    for p in parts {
        match Modifier::parse(p) {
            Some(m) => modifiers.push(m),
            None => return Err(format!("unknown modifier `{p}`")),
        }
    }
    Ok(FieldKey { field, modifiers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_field_and_modifiers() {
        let k = parse_field_key("CommandLine|contains|all").unwrap();
        assert_eq!(k.field.as_deref(), Some("CommandLine"));
        assert_eq!(k.modifiers, vec![Modifier::Contains, Modifier::All]);
    }

    #[test]
    fn keyword_key_has_no_field() {
        let k = parse_field_key("|all").unwrap();
        assert_eq!(k.field, None);
        assert_eq!(k.modifiers, vec![Modifier::All]);
    }

    #[test]
    fn plain_field_and_regex_flags() {
        assert!(parse_field_key("Image").unwrap().modifiers.is_empty());
        let k = parse_field_key("x|re|i|m|s").unwrap();
        assert_eq!(
            k.modifiers,
            vec![
                Modifier::Re,
                Modifier::ReInsensitive,
                Modifier::ReMultiline,
                Modifier::ReDotAll
            ]
        );
    }

    #[test]
    fn unknown_modifier_is_an_error() {
        let err = parse_field_key("x|bogus").unwrap_err();
        assert!(err.contains("bogus"), "{err}");
    }

    #[test]
    fn every_modifier_round_trips() {
        for (name, m) in TABLE {
            assert_eq!(Modifier::parse(name), Some(*m));
            assert_eq!(m.name(), *name);
        }
    }
}
