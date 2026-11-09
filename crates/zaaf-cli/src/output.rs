//! Alert rendering: OCSF Detection Finding (class 2004) and table/CSV views.

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde_json::{Value, json};
use std::io::{self, Write};
use zaaf_event::Event;
use zaaf_ir::{CompiledRule, Level};

pub const OCSF_VERSION: &str = "1.5.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Ndjson,
    Csv,
}

fn severity_name(level: Level) -> &'static str {
    match level {
        Level::Informational => "Informational",
        Level::Low => "Low",
        Level::Medium => "Medium",
        Level::High => "High",
        Level::Critical => "Critical",
    }
}

/// One OCSF Detection Finding per (rule, event) match. `author` and `references`
/// are always included (DRL 1.1 attribution).
///
/// `finding_info.uid` is `{rule_id}:{hash}`, where `hash` is 16 hex digits of an
/// FNV-1a 64-bit hash of the event's canonical JSON (object keys sorted). It is
/// deterministic across runs, inputs and key order, so the same rule matching the same
/// event content always gets the same uid. It is an identifier, not a cryptographic
/// digest, and identical events (even from different files) share a uid.
pub fn detection_finding(rule: &CompiledRule, event: &dyn Event, source: &str) -> Value {
    let info = &rule.info;
    let evidence = event.to_json();
    let time = event
        .timestamp()
        .unwrap_or_else(Utc::now)
        .timestamp_millis();
    json!({
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": info.level.ocsf_severity_id(),
        "severity": severity_name(info.level),
        "status_id": 1,
        "status": "New",
        "time": time,
        "message": info.title,
        "finding_info": {
            "uid": format!("{}:{:016x}", info.id, event_hash(&evidence)),
            "title": info.title,
            "desc": info.description,
            "types": info.tags,
            "analytic": { "uid": info.id, "name": info.title, "type_id": 1, "type": "Rule" }
        },
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "ZAAFElegia",
                "vendor_name": "ZAAFElegia project",
                "version": env!("CARGO_PKG_VERSION")
            }
        },
        "evidences": [ { "data": evidence } ],
        "unmapped": {
            "source": source,
            "sigma": {
                "level": info.level.as_str(),
                "status": info.status,
                "author": info.author,
                "references": info.references,
                "falsepositives": info.falsepositives,
                "logsource": {
                    "category": info.logsource.category,
                    "product": info.logsource.product,
                    "service": info.logsource.service
                },
                "rule_file": info.source.as_ref().map(|p| p.display().to_string())
            }
        }
    })
}

/// Appends `v` as JSON with object keys sorted, so equal values hash equally whatever
/// their key order (the workspace enables serde_json's `preserve_order`).
fn canonical_json(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(Value::String(k.clone()).to_string().as_bytes());
                out.push(b':');
                canonical_json(&m[k], out);
            }
            out.push(b'}');
        }
        scalar => out.extend_from_slice(scalar.to_string().as_bytes()),
    }
}

/// FNV-1a 64-bit hash of the event's canonical JSON. Hand-rolled because it must stay
/// stable across Rust releases (`DefaultHasher` makes no such promise).
fn event_hash(event: &Value) -> u64 {
    let mut bytes = Vec::new();
    canonical_json(event, &mut bytes);
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Writes findings. NDJSON and CSV stream; table and JSON are buffered until `finish`.
pub struct Sink<W: Write> {
    format: OutputFormat,
    out: W,
    buffered: Vec<Value>,
    rows: Vec<[String; 7]>,
    wrote_header: bool,
}

impl<W: Write> Sink<W> {
    pub fn new(format: OutputFormat, out: W) -> Self {
        Self {
            format,
            out,
            buffered: Vec::new(),
            rows: Vec::new(),
            wrote_header: false,
        }
    }

    pub fn write(&mut self, finding: Value) -> io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => {
                serde_json::to_writer(&mut self.out, &finding)?;
                self.out.write_all(b"\n")
            }
            OutputFormat::Json => {
                self.buffered.push(finding);
                Ok(())
            }
            OutputFormat::Table => {
                self.rows.push(row(&finding));
                Ok(())
            }
            OutputFormat::Csv => {
                if !self.wrote_header {
                    writeln!(
                        self.out,
                        "time,level,rule_id,title,author,references,source"
                    )?;
                    self.wrote_header = true;
                }
                let cells: Vec<String> = row(&finding)
                    .iter()
                    .map(|c| csv_field(&sanitize(c)))
                    .collect();
                writeln!(self.out, "{}", cells.join(","))
            }
        }
    }

    pub fn finish(mut self) -> io::Result<()> {
        match self.format {
            OutputFormat::Json => {
                serde_json::to_writer_pretty(&mut self.out, &self.buffered)?;
                writeln!(self.out)?;
            }
            OutputFormat::Table if !self.rows.is_empty() => {
                let mut table = comfy_table::Table::new();
                table.set_header(vec!["Time", "Level", "Rule", "Title", "Author", "Source"]);
                for r in &self.rows {
                    // References are too long for a table; use json/ndjson/csv for them.
                    table.add_row(
                        [0, 1, 2, 3, 4, 6]
                            .iter()
                            .map(|&i| sanitize(&r[i]))
                            .collect::<Vec<_>>(),
                    );
                }
                writeln!(self.out, "{table}")?;
            }
            _ => {}
        }
        self.out.flush()
    }
}

fn row(f: &Value) -> [String; 7] {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let time = f["time"]
        .as_i64()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    [
        time,
        s(&f["unmapped"]["sigma"]["level"]),
        s(&f["finding_info"]["analytic"]["uid"]),
        s(&f["finding_info"]["title"]),
        s(&f["unmapped"]["sigma"]["author"]),
        f["unmapped"]["sigma"]["references"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .unwrap_or_default(),
        s(&f["unmapped"]["source"]),
    ]
}

/// Every Unicode general-category Cf (format) range as of Unicode 16, which covers
/// soft hyphen, Arabic marks, zero-width and directional marks, bidi controls, word
/// joiner and invisible operators, BOM/ZWNBSP, interlinear annotation and tag
/// characters, plus the line/paragraph separators U+2028/2029 (categories Zl/Zp).
/// std has no category API, hence the table; ranges are sorted and inclusive.
const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

fn is_invisible_format(c: char) -> bool {
    let c = c as u32;
    INVISIBLE_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Replaces control characters with visible `\xNN` escapes, and invisible Unicode
/// format characters (bidi controls, zero-width characters, U+2028/2029) with
/// `\u{XXXX}`, so rule-controlled text (table and CSV cells, warnings) cannot inject
/// terminal escape sequences or visually reorder or hide text.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                format!("\\x{:02x}", c as u32)
            } else if is_invisible_format(c) {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn csv_field(s: &str) -> String {
    // Neutralise spreadsheet formula injection, then apply RFC 4180 quoting.
    let cell = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zaaf_event::JsonEvent;
    use zaaf_ir::{Expr, RuleInfo};

    fn rule() -> CompiledRule {
        CompiledRule {
            info: RuleInfo {
                id: "r1".into(),
                name: None,
                title: "T, \"quoted\"".into(),
                level: Level::High,
                status: Some("test".into()),
                description: None,
                author: Some("Ann".into()),
                references: vec!["https://x".into()],
                tags: vec!["attack.t1059".into()],
                falsepositives: vec![],
                logsource: Default::default(),
                source: None,
            },
            expr: Expr::And(vec![]),
        }
    }

    #[test]
    fn finding_has_ocsf_core_fields_and_attribution() {
        let ev = JsonEvent::new(serde_json::json!({"@timestamp": "2026-11-07T03:15:00Z"}));
        let f = detection_finding(&rule(), &ev, "a.ndjson");
        assert_eq!(f["class_uid"], 2004);
        assert_eq!(f["type_uid"], 200401);
        assert_eq!(f["severity_id"], 4);
        assert_eq!(f["finding_info"]["uid"], "r1:8ba72a9f57120243");
        assert_eq!(f["finding_info"]["analytic"]["uid"], "r1");
        assert_eq!(f["unmapped"]["sigma"]["author"], "Ann");
        assert_eq!(f["unmapped"]["sigma"]["references"][0], "https://x");
        assert_eq!(f["unmapped"]["source"], "a.ndjson");
        assert_eq!(f["time"], 1_794_021_300_000_i64);
    }

    #[test]
    fn uid_is_deterministic_and_content_based() {
        let uid = |v: serde_json::Value| {
            detection_finding(&rule(), &JsonEvent::new(v), "s")["finding_info"]["uid"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let a = uid(serde_json::json!({"x": 1, "y": {"b": [1, 2], "a": "q"}}));
        // Same content, different key order, same uid.
        assert_eq!(
            a,
            uid(serde_json::json!({"y": {"a": "q", "b": [1, 2]}, "x": 1}))
        );
        assert_ne!(
            a,
            uid(serde_json::json!({"x": 2, "y": {"b": [1, 2], "a": "q"}}))
        );
        assert_ne!(
            a,
            uid(serde_json::json!({"x": 1, "y": {"b": [2, 1], "a": "q"}}))
        );
        // Pinned so the uid stays stable across releases.
        assert_eq!(uid(serde_json::json!({})), "r1:08f44b07b5901a25");
    }

    #[test]
    fn csv_has_header_and_escapes() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Csv, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s")).unwrap();
            sink.finish().unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.starts_with("time,level,rule_id,title,author,references,source\n"),
            "{text}"
        );
        assert!(text.contains(",Ann,https://x,s\n"), "{text}");
        assert!(text.contains("\"T, \"\"quoted\"\"\""), "{text}");
    }

    #[test]
    fn csv_neutralises_formulas_and_quotes_cr() {
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("@x"), "'@x");
        assert_eq!(csv_field("-1"), "'-1");
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("\tx"), "'\tx");
        assert_eq!(csv_field("a\rb"), "\"a\rb\"");
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn csv_cells_escape_control_chars() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut r = rule();
        r.info.title = "T\u{1b}]0;x\u{7}".to_string();
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Csv, &mut buf);
            sink.write(detection_finding(&r, &ev, "s")).unwrap();
            sink.finish().unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{7}'),
            "{text:?}"
        );
        assert!(text.contains("T\\x1b]0;x\\x07"), "{text:?}");
    }

    #[test]
    fn table_cells_escape_control_chars() {
        assert_eq!(sanitize("a\u{1b}[31m\rb\tc é"), "a\\x1b[31m\\x0db\\x09c é");
    }

    #[test]
    fn unicode_format_characters_are_escaped() {
        for c in ('\u{200b}'..='\u{200f}')
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}')
            .chain(['\u{2028}', '\u{2029}'])
        {
            let out = sanitize(&format!("a{c}b"));
            assert_eq!(
                out,
                format!("a\\u{{{:04x}}}b", c as u32),
                "U+{:04X}",
                c as u32
            );
        }
        assert_eq!(sanitize("é日本\u{200a}"), "é日本\u{200a}");
        for (c, esc) in [
            ('\u{feff}', "\\u{feff}"),
            ('\u{061c}', "\\u{061c}"),
            ('\u{2060}', "\\u{2060}"),
            ('\u{00ad}', "\\u{00ad}"),
            ('\u{e0041}', "\\u{e0041}"),
        ] {
            assert_eq!(sanitize(&format!("a{c}b")), format!("a{esc}b"));
        }
    }

    #[test]
    fn table_shows_author() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Table, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s")).unwrap();
            sink.finish().unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("Author") && text.contains("Ann"), "{text}");
    }

    #[test]
    fn json_output_is_one_array() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Json, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s")).unwrap();
            sink.write(detection_finding(&rule(), &ev, "s")).unwrap();
            sink.finish().unwrap();
        }
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
    }
}
