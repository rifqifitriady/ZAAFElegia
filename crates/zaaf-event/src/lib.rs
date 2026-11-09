//! Event abstraction used by every ZAAFElegia evaluator.
//!
//! # Hostile input
//!
//! `lookup`, `leaves` and `flatten` recurse over the JSON tree. They rely on
//! `serde_json`'s built-in recursion limit of 128 levels (enforced when the event
//! is parsed) to bound the stack depth; a `Value` built by other means with
//! deeper nesting is outside that guarantee.
//!
//! # Timestamp heuristics
//!
//! Timestamps are detected leniently, because log sources disagree:
//!
//! - strings are tried as RFC 3339, then `YYYY-MM-DD HH:MM:SS[.f]` and
//!   `YYYY-MM-DDTHH:MM:SS[.f]` (both taken as UTC);
//! - a string that is none of those but parses as a number is taken as an epoch,
//!   so a bare numeric string such as `"20261107"` is read as epoch seconds;
//! - an epoch with magnitude below 1e11 is seconds, otherwise milliseconds
//!   (1e11 seconds is year 5138, 1e11 milliseconds is March 1973, so the cutoff
//!   misreads only milliseconds before 1973 and seconds after year 5138);
//! - non-finite or out-of-range values give no timestamp.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::borrow::Cow;

/// A scalar value read from an event.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'a> {
    Str(&'a str),
    Int(i64),
    /// An integer above `i64::MAX`, kept exact so its text form is not rounded.
    Uint(u64),
    /// A non-integer number.
    ///
    /// Its text form is Rust's shortest round-trip form, so a whole-valued float
    /// such as `1.0` renders as `"1"`, not `"1.0"`. This is deliberate: it makes
    /// `1`, `1.0` and `"1"` compare equal as text.
    Float(f64),
    Bool(bool),
    Null,
}

impl<'a> FieldValue<'a> {
    /// The value as text. `Null` has none. See [`FieldValue::Float`] for float rendering.
    pub fn as_text(&self) -> Option<Cow<'a, str>> {
        match self {
            Self::Str(s) => Some(Cow::Borrowed(*s)),
            Self::Int(i) => Some(Cow::Owned(i.to_string())),
            Self::Uint(u) => Some(Cow::Owned(u.to_string())),
            Self::Float(f) => Some(Cow::Owned(f.to_string())),
            Self::Bool(b) => Some(Cow::Owned(b.to_string())),
            Self::Null => None,
        }
    }

    /// The value as a finite number. Text such as `"inf"` or `"NaN"` is rejected.
    pub fn as_f64(&self) -> Option<f64> {
        let x = match self {
            Self::Int(i) => *i as f64,
            Self::Uint(u) => *u as f64,
            Self::Float(f) => *f,
            Self::Str(s) => s.trim().parse().ok()?,
            Self::Bool(_) | Self::Null => return None,
        };
        x.is_finite().then_some(x)
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
        let mut found = Vec::new();
        if !lookup(&self.value, Some(path), &mut found) {
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

/// Resolves `rest` (the not-yet-consumed part of a dotted path; `None` once the whole
/// path is consumed). At each object level the candidate keys are the prefixes of
/// `rest` ending before a `.` (or at its end), longest first, so a flat dotted key
/// wins over nesting. Candidates are slices of `rest`; nothing is allocated.
fn lookup<'a>(v: &'a Value, rest: Option<&str>, found: &mut Vec<&'a Value>) -> bool {
    let Some(rest) = rest else {
        found.push(v);
        return true;
    };
    match v {
        Value::Object(map) => {
            // Longest prefix first: the whole of `rest`, then each `.` from the right.
            let ends = std::iter::once(rest.len()).chain(rest.rmatch_indices('.').map(|(i, _)| i));
            for end in ends {
                if let Some(child) = map.get(&rest[..end]) {
                    let next = rest.get(end + 1..);
                    if lookup(child, next, found) {
                        return true;
                    }
                }
            }
            false
        }
        Value::Array(items) => {
            let mut any = false;
            for item in items {
                any |= lookup(item, Some(rest), found);
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
        Value::Number(n) => out.push(match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => FieldValue::Int(i),
            (None, Some(u)) => FieldValue::Uint(u),
            (None, None) => FieldValue::Float(n.as_f64().unwrap_or(f64::NAN)),
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
    fn large_unsigned_integers_keep_their_exact_text() {
        let e = ev(json!({"id": 18_446_744_073_709_551_615_u64, "neg": -5}));
        assert_eq!(
            e.get("id"),
            Some(vec![FieldValue::Uint(18_446_744_073_709_551_615)])
        );
        let v = &e.get("id").unwrap()[0];
        assert_eq!(v.as_text().as_deref(), Some("18446744073709551615"));
        assert!(v.as_f64().is_some());
        // values that fit i64 stay Int
        let e = ev(json!({"id": 9_223_372_036_854_775_807_u64}));
        assert_eq!(
            e.get("id"),
            Some(vec![FieldValue::Int(9_223_372_036_854_775_807)])
        );
    }

    #[test]
    fn as_f64_rejects_non_finite_text() {
        for s in [
            "inf",
            "-inf",
            "infinity",
            "-Infinity",
            "nan",
            "NaN",
            "1e999",
        ] {
            assert_eq!(FieldValue::Str(s).as_f64(), None, "{s}");
        }
        assert_eq!(FieldValue::Float(f64::NAN).as_f64(), None);
        assert_eq!(FieldValue::Str("1e3").as_f64(), Some(1000.0));
    }

    #[test]
    fn hostile_epoch_values_do_not_panic() {
        for s in [
            "NaN",
            "inf",
            "-inf",
            "1e308",
            "-1e308",
            "99999999999999999999",
        ] {
            assert!(parse_timestamp(s).is_none(), "{s}");
        }
        assert!(timestamp_from_epoch(f64::NAN).is_none());
        assert!(timestamp_from_epoch(f64::INFINITY).is_none());
        assert!(timestamp_from_epoch(1e300).is_none());
        // a negative epoch is before 1970 but valid
        let t = parse_timestamp("-86400").unwrap();
        assert_eq!(t.timestamp(), -86400);
        let e = ev(json!({"ts": -1}));
        assert_eq!(e.timestamp().unwrap().timestamp(), -1);
        let e = ev(json!({"ts": 1e300}));
        assert!(e.timestamp().is_none());
    }

    #[test]
    fn odd_paths_are_safe() {
        let e = ev(json!({"a": {"b": 1}, "s": "str", "": 7, "x": {"": 8}}));
        // deep path against a shallow event
        assert_eq!(e.get("a.b.c.d.e.f"), None);
        assert_eq!(e.get("q.w.e.r.t.y.u.i.o.p"), None);
        // path through a scalar
        assert_eq!(e.get("s.len"), None);
        assert_eq!(e.get("a.b.c"), None);
        // the empty path addresses the empty key only
        assert_eq!(e.get(""), Some(vec![FieldValue::Int(7)]));
        assert_eq!(e.get("x."), Some(vec![FieldValue::Int(8)]));
        assert_eq!(ev(json!({"a": 1})).get(""), None);
        assert_eq!(e.get("."), None);
        assert_eq!(e.get("a..b"), None);
    }

    #[test]
    fn dotted_keys_prefer_the_longest_prefix_then_backtrack() {
        let e = ev(json!({"a.b": {"c": 1}, "a": {"b.c": 2, "b": {"c": 3}}}));
        assert_eq!(e.get("a.b.c"), Some(vec![FieldValue::Int(1)]));
        let e = ev(json!({"a.b": {"zz": 1}, "a": {"b.c": 2}}));
        assert_eq!(e.get("a.b.c"), Some(vec![FieldValue::Int(2)]));
        let e = ev(json!({"a.b.c": 1, "a.b": {"c": 2}, "a": {"b": {"c": 3}}}));
        assert_eq!(e.get("a.b.c"), Some(vec![FieldValue::Int(1)]));
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
