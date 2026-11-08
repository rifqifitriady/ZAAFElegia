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
pub fn detection_finding(rule: &CompiledRule, event: &dyn Event, source: &str, seq: u64) -> Value {
    let info = &rule.info;
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
            "uid": format!("{}:{seq}", info.id),
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
        "evidences": [ { "data": event.to_json() } ],
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
                let cells: Vec<String> = row(&finding).iter().map(|c| csv_field(c)).collect();
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
                            .map(|&i| sanitize_cell(&r[i]))
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

/// Replaces control characters with visible `\xNN` escapes so table cells cannot
/// inject terminal escape sequences.
fn sanitize_cell(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                format!("\\x{:02x}", c as u32)
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
        let f = detection_finding(&rule(), &ev, "a.ndjson", 7);
        assert_eq!(f["class_uid"], 2004);
        assert_eq!(f["type_uid"], 200401);
        assert_eq!(f["severity_id"], 4);
        assert_eq!(f["finding_info"]["uid"], "r1:7");
        assert_eq!(f["finding_info"]["analytic"]["uid"], "r1");
        assert_eq!(f["unmapped"]["sigma"]["author"], "Ann");
        assert_eq!(f["unmapped"]["sigma"]["references"][0], "https://x");
        assert_eq!(f["unmapped"]["source"], "a.ndjson");
        assert_eq!(f["time"], 1_794_021_300_000_i64);
    }

    #[test]
    fn csv_has_header_and_escapes() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Csv, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s", 1)).unwrap();
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
    fn table_cells_escape_control_chars() {
        assert_eq!(
            sanitize_cell("a\u{1b}[31m\rb\tc é"),
            "a\\x1b[31m\\x0db\\x09c é"
        );
    }

    #[test]
    fn table_shows_author() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Table, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s", 1)).unwrap();
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
            sink.write(detection_finding(&rule(), &ev, "s", 1)).unwrap();
            sink.write(detection_finding(&rule(), &ev, "s", 2)).unwrap();
            sink.finish().unwrap();
        }
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
    }
}
