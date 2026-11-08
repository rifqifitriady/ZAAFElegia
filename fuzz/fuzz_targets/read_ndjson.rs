#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{BufRead, Read};

/// Yields at most `n` bytes per `fill_buf`, to exercise cross-chunk paths.
struct Chunked {
    data: Vec<u8>,
    pos: usize,
    n: usize,
}

impl Read for Chunked {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let chunk = self.fill_buf()?;
        let len = chunk.len().min(buf.len());
        buf[..len].copy_from_slice(&chunk[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl BufRead for Chunked {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let end = (self.pos + self.n).min(self.data.len());
        Ok(&self.data[self.pos..end])
    }
    fn consume(&mut self, amt: usize) {
        self.pos += amt;
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    let reader = Chunked {
        data: rest.to_vec(),
        pos: 0,
        n: usize::from(first % 7) + 1,
    };
    for _ in zaaf_input::read_json_events_with_limits(reader, 64, 256) {}
});
