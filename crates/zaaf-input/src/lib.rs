//! Readers that turn log files into events. M1: NDJSON and JSON arrays.
//!
//! Format is detected from the first non-blank byte (after an optional UTF-8
//! BOM): `[` means a single JSON array, anything else is NDJSON.
//!
//! NDJSON is streamed line by line; each line is capped at [`MAX_LINE_BYTES`].
//! JSON array input is **fully buffered** in memory before parsing and is
//! capped at [`MAX_ARRAY_BYTES`]; use NDJSON for large inputs.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::Path;
use zaaf_event::JsonEvent;

/// Maximum accepted length of one NDJSON line; longer lines are reported as
/// errors and skipped.
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum accepted size of a JSON array input (it is fully buffered).
pub const MAX_ARRAY_BYTES: usize = 256 * 1024 * 1024;

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// 1-based line in the input (0 when unknown).
    pub line: usize,
    pub message: String,
}

pub type EventResult = Result<JsonEvent, InputError>;

fn err_once(line: usize, message: String) -> Box<dyn Iterator<Item = EventResult>> {
    Box::new(std::iter::once(Err(InputError { line, message })))
}

/// Reads NDJSON (streaming) or a single top-level JSON array (buffered).
pub fn read_json_events<R: BufRead + 'static>(reader: R) -> Box<dyn Iterator<Item = EventResult>> {
    read_with_limits(reader, MAX_LINE_BYTES, MAX_ARRAY_BYTES)
}

fn read_with_limits<R: BufRead + 'static>(
    mut reader: R,
    max_line_bytes: usize,
    max_array_bytes: usize,
) -> Box<dyn Iterator<Item = EventResult>> {
    let mut skipped_lines = 0usize;
    let mut bom_seen = 0usize;
    let first = loop {
        let (consumed, found, newlines, is_bom) = match reader.fill_buf() {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return err_once(0, format!("read error: {e}")),
            Ok([]) => break None,
            Ok(buf) => {
                if bom_seen < BOM.len() && buf[0] == BOM[bom_seen] {
                    (1, None, 0, true)
                } else {
                    match buf.iter().position(|b| !b.is_ascii_whitespace()) {
                        Some(pos) => (
                            pos,
                            Some(buf[pos]),
                            buf[..pos].iter().filter(|b| **b == b'\n').count(),
                            false,
                        ),
                        None => (
                            buf.len(),
                            None,
                            buf.iter().filter(|b| **b == b'\n').count(),
                            false,
                        ),
                    }
                }
            }
        };
        reader.consume(consumed);
        skipped_lines += newlines;
        if found.is_some() {
            break found;
        }
        // Only the very first bytes may be a BOM; once anything else is seen
        // (or the BOM is complete) stop matching.
        bom_seen = if is_bom { bom_seen + 1 } else { BOM.len() };
    };
    match first {
        None => Box::new(std::iter::empty()),
        Some(b'[') => {
            let mut data = Vec::new();
            let limit = u64::try_from(max_array_bytes).unwrap_or(u64::MAX - 1) + 1;
            if let Err(e) = reader.by_ref().take(limit).read_to_end(&mut data) {
                return err_once(0, format!("read error: {e}"));
            }
            if data.len() > max_array_bytes {
                return err_once(
                    0,
                    format!(
                        "JSON array input exceeds {max_array_bytes} bytes; use NDJSON for large inputs"
                    ),
                );
            }
            match serde_json::from_slice::<Vec<Value>>(&data) {
                Ok(items) => Box::new(items.into_iter().map(|v| Ok(JsonEvent::new(v)))),
                Err(e) => err_once(skipped_lines + e.line(), format!("invalid JSON array: {e}")),
            }
        }
        Some(_) => Box::new(Lines {
            reader,
            max: max_line_bytes,
            line_no: skipped_lines,
            done: false,
            buf: Vec::new(),
        }),
    }
}

/// Bounded, streaming NDJSON line reader.
struct Lines<R> {
    reader: R,
    max: usize,
    /// Number of lines fully read so far (including skipped leading ones).
    line_no: usize,
    done: bool,
    buf: Vec<u8>,
}

impl<R: BufRead> Iterator for Lines<R> {
    type Item = EventResult;

    fn next(&mut self) -> Option<EventResult> {
        loop {
            if self.done {
                return None;
            }
            self.buf.clear();
            let mut overflow = false;
            let mut got_any = false;
            loop {
                let chunk = match self.reader.fill_buf() {
                    Ok(c) => c,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => {
                        self.done = true;
                        return Some(Err(InputError {
                            line: self.line_no + 1,
                            message: format!("read error: {e}"),
                        }));
                    }
                };
                if chunk.is_empty() {
                    self.done = true;
                    break;
                }
                got_any = true;
                let nl = chunk.iter().position(|b| *b == b'\n');
                let part = &chunk[..nl.unwrap_or(chunk.len())];
                if !overflow {
                    if self.buf.len() + part.len() > self.max {
                        overflow = true;
                        self.buf = Vec::new();
                    } else {
                        self.buf.extend_from_slice(part);
                    }
                }
                let used = nl.map_or(part.len(), |p| p + 1);
                self.reader.consume(used);
                if nl.is_some() {
                    break;
                }
            }
            if !got_any {
                return None;
            }
            self.line_no += 1;
            if overflow {
                return Some(Err(InputError {
                    line: self.line_no,
                    message: format!("line exceeds {} bytes", self.max),
                }));
            }
            if self.buf.last() == Some(&b'\r') {
                self.buf.pop();
            }
            if self.buf.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            return Some(
                serde_json::from_slice::<Value>(&self.buf)
                    .map(JsonEvent::new)
                    .map_err(|e| InputError {
                        line: self.line_no,
                        message: format!("invalid JSON: {e}"),
                    }),
            );
        }
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

    fn read_lim(bytes: &[u8], line: usize, arr: usize) -> Vec<EventResult> {
        read_with_limits(Cursor::new(bytes.to_vec()), line, arr).collect()
    }

    #[test]
    fn over_long_line_errors_and_numbering_continues() {
        let mut input = b"{\"a\": 1}\n".to_vec();
        input.extend_from_slice(b"{\"pad\": \"");
        input.extend(std::iter::repeat_n(b'x', 200));
        input.extend_from_slice(b"\"}\n{\"a\": 3}\nnot json\n");
        let items = read_lim(&input, 64, MAX_ARRAY_BYTES);
        assert_eq!(items.len(), 4);
        assert!(items[0].is_ok());
        let e = items[1].as_ref().unwrap_err();
        assert_eq!(e.line, 2);
        assert_eq!(e.message, "line exceeds 64 bytes");
        assert!(items[2].is_ok());
        assert_eq!(items[3].as_ref().unwrap_err().line, 4);
    }

    #[test]
    fn over_long_final_line_without_newline() {
        let input = vec![b'x'; 100];
        let items = read_lim(&input, 64, MAX_ARRAY_BYTES);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_ref().unwrap_err().line, 1);
    }

    #[test]
    fn crlf_with_leading_blank_lines() {
        let items = read("\r\n\r\n{\"a\": 1}\r\nbad\r\n");
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert_eq!(items[1].as_ref().unwrap_err().line, 4);
    }

    #[test]
    fn invalid_utf8_line_is_invalid_json_and_iteration_continues() {
        let items = read_lim(b"{\"a\": 1}\n\xff\xfe\n{\"a\": 2}\n", 1024, 1024);
        assert_eq!(items.len(), 3);
        assert!(items[0].is_ok());
        let e = items[1].as_ref().unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.message.contains("invalid JSON"));
        assert!(items[2].is_ok());
    }

    #[test]
    fn array_error_reports_true_line_after_blank_lines() {
        let items = read("\n\n[\n{\"a\": 1},\n{\"a\": }\n]");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_ref().unwrap_err().line, 5);
    }

    #[test]
    fn bom_ndjson_and_array() {
        let items = read_lim(b"\xEF\xBB\xBF{\"a\": 1}\n{\"a\": 2}\n", 1024, 1024);
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(Result::is_ok));
        let items = read_lim(b"\xEF\xBB\xBF[{\"a\": 1}, {\"a\": 2}]", 1024, 1024);
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(Result::is_ok));
    }

    #[test]
    fn array_over_cap_is_one_error() {
        let items = read_lim(b"[{\"a\": 1}, {\"a\": 2}, {\"a\": 3}]", 1024, 16);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].as_ref().unwrap_err().message,
            "JSON array input exceeds 16 bytes; use NDJSON for large inputs"
        );
    }

    /// Serves `data`, then panics (or errors forever) when read further.
    struct Trap {
        data: Vec<u8>,
        pos: usize,
        panic_after: bool,
    }

    impl std::io::Read for Trap {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            unreachable!("only fill_buf/consume are used")
        }
    }

    impl BufRead for Trap {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.pos < self.data.len() {
                Ok(&self.data[self.pos..])
            } else if self.panic_after {
                panic!("read past the first line");
            } else {
                Err(std::io::Error::other("boom"))
            }
        }
        fn consume(&mut self, n: usize) {
            self.pos += n;
        }
    }

    #[test]
    fn streaming_does_not_read_ahead() {
        let trap = Trap {
            data: b"{\"a\": 1}\n".to_vec(),
            pos: 0,
            panic_after: true,
        };
        let mut it = read_json_events(trap);
        assert!(it.next().unwrap().is_ok());
    }

    #[test]
    fn persistent_io_error_ends_after_one() {
        let trap = Trap {
            data: Vec::new(),
            pos: 0,
            panic_after: false,
        };
        assert_eq!(read_json_events(trap).count(), 1);
        let trap = Trap {
            data: b"{\"a\": 1}\n".to_vec(),
            pos: 0,
            panic_after: false,
        };
        let items: Vec<_> = read_json_events(trap).collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
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
