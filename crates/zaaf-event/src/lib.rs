//! Event abstraction used by every ZAAFElegia evaluator.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::borrow::Cow;

/// A scalar value read from an event.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'a> {
    Str(&'a str),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl<'a> FieldValue<'a> {
    pub fn as_text(&self) -> Option<Cow<'a, str>> {
        match self {
            Self::Str(s) => Some(Cow::Borrowed(*s)),
            Self::Int(i) => Some(Cow::Owned(i.to_string())),
            Self::Float(f) => Some(Cow::Owned(f.to_string())),
            Self::Bool(b) => Some(Cow::Owned(b.to_string())),
            Self::Null => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Int(i) => Some(*i as f64),
            Self::Float(f) => Some(*f),
            Self::Str(s) => s.trim().parse().ok(),
            Self::Bool(_) | Self::Null => None,
        }
    }
}

/// A log event that rules can be evaluated against.
pub trait Event {
    /// `None` when the field is absent; otherwise its scalar values (arrays flattened).
    fn get(&self, path: &str) -> Option<Vec<FieldValue<'_>>>;
    /// Every scalar value in the event (keyword search).
    fn leaf_values(&self) -> Vec<FieldValue<'_>>;
    fn timestamp(&self) -> Option<DateTime<Utc>>;
    fn to_json(&self) -> Value;
}

const TIMESTAMP_FIELDS: &[&str] = &[
    "@timestamp",
    "timestamp",
    "time",
    "eventTime",
    "EventTime",
    "UtcTime",
    "TimeCreated",
    "ts",
];

/// An event backed by a JSON value.
#[derive(Debug, Clone)]
pub struct JsonEvent {
    value: Value,
    ts: Option<DateTime<Utc>>,
}

impl JsonEvent {
    pub fn new(value: Value) -> Self {
        let ts = TIMESTAMP_FIELDS
            .iter()
            .find_map(|f| value.get(*f).and_then(json_timestamp));
        Self { value, ts }
    }

    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl Event for JsonEvent {
    fn get(&self, path: &str) -> Option<Vec<FieldValue<'_>>> {
        let segs: Vec<&str> = path.split('.').collect();
        let mut found = Vec::new();
        if !lookup(&self.value, &segs, &mut found) {
            return None;
        }
        let mut out = Vec::new();
        for v in found {
            flatten(v, &mut out);
        }
        Some(out)
    }

    fn leaf_values(&self) -> Vec<FieldValue<'_>> {
        let mut out = Vec::new();
        leaves(&self.value, &mut out);
        out
    }

    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.ts
    }

    fn to_json(&self) -> Value {
        self.value.clone()
    }
}

fn lookup<'a>(v: &'a Value, segs: &[&str], found: &mut Vec<&'a Value>) -> bool {
    if segs.is_empty() {
        found.push(v);
        return true;
    }
    match v {
        Value::Object(map) => {
            for k in (1..=segs.len()).rev() {
                let key = segs[..k].join(".");
                if let Some(child) = map.get(&key)
                    && lookup(child, &segs[k..], found)
                {
                    return true;
                }
            }
            false
        }
        Value::Array(items) => {
            let mut any = false;
            for item in items {
                any |= lookup(item, segs, found);
            }
            any
        }
        _ => false,
    }
}

fn flatten<'a>(v: &'a Value, out: &mut Vec<FieldValue<'a>>) {
    match v {
        Value::Null => out.push(FieldValue::Null),
        Value::Bool(b) => out.push(FieldValue::Bool(*b)),
        Value::Number(n) => out.push(match n.as_i64() {
            Some(i) => FieldValue::Int(i),
            None => FieldValue::Float(n.as_f64().unwrap_or(f64::NAN)),
        }),
        Value::String(s) => out.push(FieldValue::Str(s)),
        Value::Array(items) => {
            for item in items {
                flatten(item, out);
            }
        }
        Value::Object(_) => {}
    }
}

fn leaves<'a>(v: &'a Value, out: &mut Vec<FieldValue<'a>>) {
    match v {
        Value::Object(map) => {
            for child in map.values() {
                leaves(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                leaves(item, out);
            }
        }
        scalar => flatten(scalar, out),
    }
}

fn json_timestamp(v: &Value) -> Option<DateTime<Utc>> {
    match v {
        Value::String(s) => parse_timestamp(s),
        Value::Number(n) => n.as_f64().and_then(timestamp_from_epoch),
        _ => None,
    }
}

/// RFC 3339, `YYYY-MM-DD HH:MM:SS[.f]` (UTC, e.g. Sysmon `UtcTime`), or epoch seconds/millis.
pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(n.and_utc());
        }
    }
    s.parse::<f64>().ok().and_then(timestamp_from_epoch)
}

/// Epoch seconds, or milliseconds when the value is ≥ 1e11.
pub fn timestamp_from_epoch(x: f64) -> Option<DateTime<Utc>> {
    if !x.is_finite() {
        return None;
    }
    let millis = if x.abs() >= 1e11 { x } else { x * 1000.0 };
    DateTime::from_timestamp_millis(millis as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(v: serde_json::Value) -> JsonEvent {
        JsonEvent::new(v)
    }

    #[test]
    fn resolves_flat_dotted_and_nested_paths() {
        let e =
            ev(json!({"user.name": "a", "process": {"parent": {"name": "x"}}, "o": {"b.c": 1}}));
        assert_eq!(e.get("user.name"), Some(vec![FieldValue::Str("a")]));
        assert_eq!(
            e.get("process.parent.name"),
            Some(vec![FieldValue::Str("x")])
        );
        assert_eq!(e.get("o.b.c"), Some(vec![FieldValue::Int(1)]));
        assert_eq!(e.get("missing"), None);
        assert_eq!(e.get("process.nope"), None);
    }

    #[test]
    fn arrays_fan_out_and_flatten() {
        let e = ev(json!({"tags": ["a", ["b"]], "p": [{"n": "x"}, {"n": "y"}, {"m": 1}]}));
        assert_eq!(
            e.get("tags"),
            Some(vec![FieldValue::Str("a"), FieldValue::Str("b")])
        );
        assert_eq!(
            e.get("p.n"),
            Some(vec![FieldValue::Str("x"), FieldValue::Str("y")])
        );
    }

    #[test]
    fn null_and_object_presence() {
        let e = ev(json!({"n": null, "o": {"k": 1}}));
        assert_eq!(e.get("n"), Some(vec![FieldValue::Null]));
        assert_eq!(e.get("o"), Some(vec![]));
    }

    #[test]
    fn leaf_values_cover_the_whole_event() {
        let e = ev(json!({"a": "x", "b": {"c": [1, true]}}));
        assert_eq!(
            e.leaf_values(),
            vec![
                FieldValue::Str("x"),
                FieldValue::Int(1),
                FieldValue::Bool(true)
            ]
        );
    }

    #[test]
    fn text_and_number_views() {
        assert_eq!(FieldValue::Int(4688).as_text().as_deref(), Some("4688"));
        assert_eq!(FieldValue::Bool(true).as_text().as_deref(), Some("true"));
        assert_eq!(FieldValue::Null.as_text(), None);
        assert_eq!(FieldValue::Str(" 10 ").as_f64(), Some(10.0));
        assert_eq!(FieldValue::Str("x").as_f64(), None);
    }

    #[test]
    fn timestamps() {
        let e = ev(json!({"@timestamp": "2026-11-07T03:15:00Z"}));
        assert_eq!(
            e.timestamp().unwrap().to_rfc3339(),
            "2026-11-07T03:15:00+00:00"
        );
        let e = ev(json!({"UtcTime": "2026-11-07 03:15:00.123"}));
        assert_eq!(e.timestamp().unwrap().timestamp_millis(), 1_794_021_300_123);
        let e = ev(json!({"ts": 1_794_021_300}));
        assert_eq!(e.timestamp().unwrap().timestamp(), 1_794_021_300);
        let e = ev(json!({"ts": 1_794_021_300_123_i64}));
        assert_eq!(e.timestamp().unwrap().timestamp_millis(), 1_794_021_300_123);
        assert!(ev(json!({"x": 1})).timestamp().is_none());
        assert!(parse_timestamp("not a date").is_none());
    }
}
