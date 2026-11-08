//! Readers that turn log files into events. M1: NDJSON and JSON arrays.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use zaaf_event::JsonEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// 1-based line in the input (0 when unknown).
    pub line: usize,
    pub message: String,
}

pub type EventResult = Result<JsonEvent, InputError>;

/// Reads NDJSON (streaming) or a single top-level JSON array.
pub fn read_json_events<R: BufRead + 'static>(
    mut reader: R,
) -> Box<dyn Iterator<Item = EventResult>> {
    let mut skipped_lines = 0usize;
    let first = loop {
        let (consumed, found, newlines) = match reader.fill_buf() {
            Err(e) => {
                return Box::new(std::iter::once(Err(InputError {
                    line: 0,
                    message: format!("read error: {e}"),
                })));
            }
            Ok([]) => break None,
            Ok(buf) => match buf.iter().position(|b| !b.is_ascii_whitespace()) {
                Some(pos) => (
                    pos,
                    Some(buf[pos]),
                    buf[..pos].iter().filter(|b| **b == b'\n').count(),
                ),
                None => (buf.len(), None, buf.iter().filter(|b| **b == b'\n').count()),
            },
        };
        reader.consume(consumed);
        skipped_lines += newlines;
        if found.is_some() {
            break found;
        }
    };
    match first {
        None => Box::new(std::iter::empty()),
        Some(b'[') => {
            let mut data = Vec::new();
            if let Err(e) = reader.read_to_end(&mut data) {
                return Box::new(std::iter::once(Err(InputError {
                    line: 0,
                    message: format!("read error: {e}"),
                })));
            }
            match serde_json::from_slice::<Vec<Value>>(&data) {
                Ok(items) => Box::new(items.into_iter().map(|v| Ok(JsonEvent::new(v)))),
                Err(e) => Box::new(std::iter::once(Err(InputError {
                    line: skipped_lines + e.line(),
                    message: format!("invalid JSON array: {e}"),
                }))),
            }
        }
        Some(_) => Box::new(reader.lines().enumerate().filter_map(move |(i, line)| {
            let line_no = skipped_lines + i + 1;
            match line {
                Err(e) => Some(Err(InputError {
                    line: line_no,
                    message: format!("read error: {e}"),
                })),
                Ok(l) if l.trim().is_empty() => None,
                Ok(l) => Some(
                    serde_json::from_str::<Value>(&l)
                        .map(JsonEvent::new)
                        .map_err(|e| InputError {
                            line: line_no,
                            message: format!("invalid JSON: {e}"),
                        }),
                ),
            }
        })),
    }
}

pub fn open_path(path: &Path) -> std::io::Result<Box<dyn Iterator<Item = EventResult>>> {
    let file = File::open(path)?;
    Ok(read_json_events(BufReader::new(file)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zaaf_event::Event;

    fn read(s: &str) -> Vec<EventResult> {
        read_json_events(Cursor::new(s.as_bytes().to_vec())).collect()
    }

    #[test]
    fn ndjson_with_blank_and_bad_lines() {
        let items = read("\n\n{\"a\": 1}\n\nnot json\n{\"a\": 2}\n");
        assert_eq!(items.len(), 3);
        assert!(items[0].is_ok());
        let err = items[1].as_ref().unwrap_err();
        assert_eq!(err.line, 5);
        assert!(err.message.contains("invalid JSON"));
        assert_eq!(
            items[2].as_ref().unwrap().get("a"),
            Some(vec![zaaf_event::FieldValue::Int(2)])
        );
    }

    #[test]
    fn json_array() {
        let items = read("  [ {\"a\": 1}, {\"a\": 2} ]");
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(Result::is_ok));
    }

    #[test]
    fn broken_json_array_is_one_error() {
        let items = read("[ {\"a\": 1}, ");
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }

    #[test]
    fn empty_input() {
        assert!(read("").is_empty());
        assert!(read("  \n \n").is_empty());
    }

    #[test]
    fn open_path_reads_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.ndjson");
        std::fs::write(&p, "{\"x\": true}\n").unwrap();
        assert_eq!(open_path(&p).unwrap().count(), 1);
        assert!(open_path(&dir.path().join("missing")).is_err());
    }
}
