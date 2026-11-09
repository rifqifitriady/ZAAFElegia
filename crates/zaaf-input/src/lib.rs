//! Readers that turn log files into events. M1: NDJSON and JSON arrays.
//!
//! Format is detected from the first non-blank byte (after an optional UTF-8
//! BOM): `[` means a single JSON array, anything else is NDJSON.
//!
//! NDJSON is streamed line by line; each line is capped at [`MAX_LINE_BYTES`].
//! A JSON array is streamed element by element: only the element being read is held in
//! memory, never the whole array. The array as a whole is capped at [`MAX_ARRAY_BYTES`]
//! (every byte from the `[` counts). Elements before a problem are still delivered; an
//! invalid array or one over the cap then ends with a single fatal error (the rest of the
//! input is unreadable). Error lines are absolute, even for multi-line elements.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use zaaf_event::JsonEvent;

/// Maximum accepted length of one NDJSON line; longer lines are reported as
/// errors and skipped.
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum accepted size of a JSON array input, counted from its opening `[`.
pub const MAX_ARRAY_BYTES: usize = 256 * 1024 * 1024;

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// 1-based line in the input (0 when unknown).
    pub line: usize,
    pub message: String,
    /// True for I/O read errors and array failures (invalid or over the cap): the input is unreadable and iteration ends.
    /// False for malformed NDJSON records (invalid JSON, oversized line),
    /// which can be skipped.
    pub fatal: bool,
}

pub type EventResult = Result<JsonEvent, InputError>;

fn err_once(line: usize, message: String, fatal: bool) -> Box<dyn Iterator<Item = EventResult>> {
    Box::new(std::iter::once(Err(InputError {
        line,
        message,
        fatal,
    })))
}

/// Reads NDJSON or a single top-level JSON array, both streaming.
pub fn read_json_events<R: BufRead + 'static>(reader: R) -> Box<dyn Iterator<Item = EventResult>> {
    read_with_limits(reader, MAX_LINE_BYTES, MAX_ARRAY_BYTES)
}

/// Like [`read_json_events`] with caller-chosen caps: `max_line_bytes` for one NDJSON
/// line and `max_array_bytes` for a whole JSON array input. This is a supported API
/// (it backs `zaaf hunt --max-line-bytes`); the defaults are [`MAX_LINE_BYTES`] and
/// [`MAX_ARRAY_BYTES`].
pub fn read_json_events_with_limits<R: BufRead + 'static>(
    reader: R,
    max_line_bytes: usize,
    max_array_bytes: usize,
) -> Box<dyn Iterator<Item = EventResult>> {
    read_with_limits(reader, max_line_bytes, max_array_bytes)
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
            Err(e) => return err_once(0, format!("read error: {e}"), true),
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
        Some(b'[') => Box::new(ArrayItems::new(reader, max_array_bytes, skipped_lines + 1)),
        Some(_) => Box::new(Lines {
            reader,
            max: max_line_bytes,
            line_no: skipped_lines,
            done: false,
            buf: Vec::new(),
        }),
    }
}

/// Where the array reader is in the document.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArrayState {
    /// Between or inside elements, before the closing `]`.
    Elements,
    /// After the closing `]`: only whitespace may follow.
    Trailing,
    Done,
}

/// Streaming reader for a top-level JSON array. A small byte-level splitter finds
/// each element's end (tracking string, escape and bracket depth), and every element
/// is parsed on its own with `serde_json::from_slice`, so only one element is held in
/// memory at a time (never the whole array). Every byte from the opening `[` counts
/// against `max`.
struct ArrayItems<R> {
    reader: R,
    max: usize,
    /// Bytes consumed so far, counted from the opening `[`.
    total: usize,
    /// 1-based line of the next unread byte.
    line: usize,
    /// Bytes of the element being read (no leading whitespace).
    buf: Vec<u8>,
    /// Line on which the current element starts.
    elem_line: usize,
    depth: usize,
    in_string: bool,
    escaped: bool,
    /// A comma was read and an element must follow it.
    after_comma: bool,
    state: ArrayState,
}

/// What one pass over a chunk produced.
enum ArrayStep {
    Item(Value),
    Cap,
    Fail(usize, String),
}

impl<R: BufRead> ArrayItems<R> {
    /// `reader` is positioned at the opening `[`; `first_line` is that byte's line.
    fn new(mut reader: R, max: usize, first_line: usize) -> Self {
        reader.consume(1);
        Self {
            reader,
            max,
            total: 1,
            line: first_line,
            buf: Vec::new(),
            elem_line: first_line,
            depth: 0,
            in_string: false,
            escaped: false,
            after_comma: false,
            state: ArrayState::Elements,
        }
    }

    fn fatal(&mut self, line: usize, message: String) -> Option<EventResult> {
        self.state = ArrayState::Done;
        Some(Err(InputError {
            line,
            message,
            fatal: true,
        }))
    }

    /// Parses the finished element in `buf` and resets the per-element state.
    fn finish_element(&mut self) -> ArrayStep {
        let parsed = serde_json::from_slice::<Value>(&self.buf);
        if self.buf.capacity() > 1 << 20 {
            self.buf = Vec::new();
        } else {
            self.buf.clear();
        }
        match parsed {
            Ok(v) => ArrayStep::Item(v),
            Err(e) => {
                // serde's position is relative to this element; ours is absolute.
                let text = e.to_string();
                let text = text
                    .rsplit_once(" at line ")
                    .map_or(text.as_str(), |(m, _)| m);
                ArrayStep::Fail(self.elem_line + e.line() - 1, text.to_string())
            }
        }
    }
}

impl<R: BufRead> Iterator for ArrayItems<R> {
    type Item = EventResult;

    fn next(&mut self) -> Option<EventResult> {
        loop {
            if self.state == ArrayState::Done {
                return None;
            }
            let chunk = match self.reader.fill_buf() {
                Ok(c) => c,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    let line = self.line;
                    return self.fatal(line, format!("read error: {e}"));
                }
            };
            if chunk.is_empty() {
                if self.state == ArrayState::Trailing {
                    self.state = ArrayState::Done;
                    return None;
                }
                let line = self.line;
                return self.fatal(
                    line,
                    "invalid JSON array: unexpected end of input".to_string(),
                );
            }
            let mut used = 0;
            let mut step = None;
            for &b in chunk {
                used += 1;
                self.total += 1;
                if self.total > self.max {
                    step = Some(ArrayStep::Cap);
                    break;
                }
                let newline = b == b'\n';
                if self.state == ArrayState::Trailing {
                    if !b.is_ascii_whitespace() {
                        step = Some(ArrayStep::Fail(
                            self.line,
                            "trailing characters after the array".to_string(),
                        ));
                        break;
                    }
                } else if self.in_string {
                    self.buf.push(b);
                    if self.escaped {
                        self.escaped = false;
                    } else if b == b'\\' {
                        self.escaped = true;
                    } else if b == b'"' {
                        self.in_string = false;
                    }
                } else if self.buf.is_empty() && b.is_ascii_whitespace() {
                    // Whitespace before an element.
                } else if self.depth == 0 && (b == b',' || b == b']') {
                    if self.buf.is_empty() {
                        if b == b']' && !self.after_comma {
                            self.state = ArrayState::Trailing;
                        } else {
                            step = Some(ArrayStep::Fail(self.line, "expected a value".to_string()));
                            break;
                        }
                    } else {
                        let closes = b == b']';
                        let r = self.finish_element();
                        if closes && matches!(r, ArrayStep::Item(_)) {
                            self.state = ArrayState::Trailing;
                        }
                        self.after_comma = !closes;
                        step = Some(r);
                        if newline {
                            self.line += 1;
                        }
                        break;
                    }
                } else {
                    if self.buf.is_empty() {
                        self.elem_line = self.line;
                    }
                    match b {
                        b'"' => self.in_string = true,
                        b'{' | b'[' => self.depth += 1,
                        b'}' | b']' => self.depth = self.depth.saturating_sub(1),
                        _ => {}
                    }
                    self.buf.push(b);
                }
                if newline {
                    self.line += 1;
                }
            }
            self.reader.consume(used);
            match step {
                Some(ArrayStep::Item(v)) => return Some(Ok(JsonEvent::new(v))),
                Some(ArrayStep::Cap) => {
                    let line = self.line;
                    let message = format!(
                        "JSON array input exceeds {} bytes; use NDJSON for large inputs",
                        self.max
                    );
                    return self.fatal(line, message);
                }
                Some(ArrayStep::Fail(line, m)) => {
                    return self.fatal(line, format!("invalid JSON array: {m}"));
                }
                None => {}
            }
        }
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
                            fatal: true,
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
                    fatal: false,
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
                        fatal: false,
                    }),
            );
        }
    }
}

/// Opens `path` with the default caps.
pub fn open_path(path: &Path) -> std::io::Result<Box<dyn Iterator<Item = EventResult>>> {
    open_path_with_limits(path, MAX_LINE_BYTES, MAX_ARRAY_BYTES)
}

/// Opens `path` with caller-chosen caps; see [`read_json_events_with_limits`].
pub fn open_path_with_limits(
    path: &Path,
    max_line_bytes: usize,
    max_array_bytes: usize,
) -> std::io::Result<Box<dyn Iterator<Item = EventResult>>> {
    // Check before opening: on Windows, opening a directory already fails with
    // "Access is denied", which would hide the clearer message below.
    if std::fs::metadata(path)?.is_dir() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "is a directory",
        ));
    }
    let file = File::open(path)?;
    Ok(read_json_events_with_limits(
        BufReader::new(file),
        max_line_bytes,
        max_array_bytes,
    ))
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
    fn broken_json_array_ends_with_one_fatal_error() {
        // Elements are streamed, so those before the break are still delivered.
        let items = read("[ {\"a\": 1}, ");
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].as_ref().unwrap_err().fatal);
    }

    #[test]
    fn array_elements_are_streamed_not_buffered() {
        // The trap panics when read past its data: the first element must come out
        // before anything after its separating comma is requested.
        let trap = Trap {
            data: b"[{\"a\": 1},".to_vec(),
            pos: 0,
            panic_after: true,
        };
        let mut it = read_json_events(trap);
        assert!(it.next().unwrap().is_ok());
    }

    #[test]
    fn array_edge_shapes() {
        let ok = |s: &str| read(s).iter().filter(|r| r.is_ok()).count();
        assert_eq!(ok("[]"), 0);
        assert_eq!(ok("[ ]  \n"), 0);
        assert_eq!(ok(r#"[1, "a]", [2, 3], {"k": "\"],"}, null]"#), 5);
        assert_eq!(ok("[{\"a\":1},{\"a\":2}]\n\n"), 2);
        for bad in [
            "[,]",
            "[1,]",
            "[1 2]",
            "[1] x",
            "[{\"a\": 1]",
            "[\"abc",
            "[{]",
        ] {
            let items = read(bad);
            let err = items.last().unwrap().as_ref().unwrap_err();
            assert!(err.fatal, "{bad}");
            assert!(
                err.message.starts_with("invalid JSON array"),
                "{bad}: {}",
                err.message
            );
            assert_eq!(items.iter().filter(|r| r.is_err()).count(), 1, "{bad}");
        }
    }

    #[test]
    fn array_error_line_counts_multiline_elements() {
        let items = read("\n[\n{\n\"a\": 1\n},\n{\n\"b\":\n}\n]");
        assert!(items[0].is_ok());
        // The second element spans lines 6 to 8; serde reports its end.
        assert_eq!(items[1].as_ref().unwrap_err().line, 8);
        let items = read("[1,\n2,\n3 4]");
        assert_eq!(items.last().unwrap().as_ref().unwrap_err().line, 3);
        let items = read("[1,\n2,\n");
        assert_eq!(items.last().unwrap().as_ref().unwrap_err().line, 3);
    }

    #[test]
    fn array_cap_counts_all_bytes_and_keeps_earlier_elements() {
        // The first element ends before the cap; the cap trips inside the second.
        let items = read_lim(b"[{\"a\": 1}, {\"a\": 2}, {\"a\": 3}]", 1024, 16);
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        let e = items[1].as_ref().unwrap_err();
        assert!(e.fatal);
        assert_eq!(
            e.message,
            "JSON array input exceeds 16 bytes; use NDJSON for large inputs"
        );
        // Exactly at the cap is accepted; one byte over is not.
        let exact = b"[{\"a\": 1}]";
        assert!(read_lim(exact, 1024, exact.len()).iter().all(Result::is_ok));
        assert!(
            read_lim(exact, 1024, exact.len() - 1)
                .last()
                .unwrap()
                .is_err()
        );
        // Trailing whitespace after `]` counts too.
        assert!(read_lim(b"[1]    ", 1024, 5).last().unwrap().is_err());
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
    fn public_limits_wrapper_enforces_both_caps() {
        let mut long = b"{\"pad\": \"".to_vec();
        long.extend(std::iter::repeat_n(b'x', 100));
        long.extend_from_slice(b"\"}\n");
        let items: Vec<_> =
            read_json_events_with_limits(Cursor::new(long), 64, MAX_ARRAY_BYTES).collect();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].as_ref().unwrap_err().message,
            "line exceeds 64 bytes"
        );

        let mut arr = b"[".to_vec();
        arr.extend(std::iter::repeat_n(b' ', 300));
        arr.extend_from_slice(b"{\"a\": 1}]");
        let items: Vec<_> =
            read_json_events_with_limits(Cursor::new(arr), MAX_LINE_BYTES, 256).collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
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
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert_eq!(items[1].as_ref().unwrap_err().line, 5);
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
        let items: Vec<_> = read_json_events(trap).collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].as_ref().unwrap_err().fatal);
        let trap = Trap {
            data: b"{\"a\": 1}\n".to_vec(),
            pos: 0,
            panic_after: false,
        };
        let items: Vec<_> = read_json_events(trap).collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].as_ref().unwrap_err().fatal);
    }

    #[test]
    fn malformed_records_are_not_fatal() {
        let items = read("not json\n");
        assert!(!items[0].as_ref().unwrap_err().fatal);
        let items = read_lim(&[b'x'; 100], 64, MAX_ARRAY_BYTES);
        assert!(!items[0].as_ref().unwrap_err().fatal);
    }

    #[test]
    fn whole_array_failures_are_fatal() {
        let items = read("[ {\"a\": 1}, ");
        assert!(items.last().unwrap().as_ref().unwrap_err().fatal);
        let items = read_lim(b"[{\"a\": 1}, {\"a\": 2}]", 1024, 4);
        assert!(items[0].as_ref().unwrap_err().fatal);
    }

    #[test]
    fn directory_is_an_open_error() {
        let dir = tempfile::tempdir().unwrap();
        let e = open_path(dir.path())
            .err()
            .expect("directory must not open");
        assert!(e.to_string().contains("is a directory"), "{e}");
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
