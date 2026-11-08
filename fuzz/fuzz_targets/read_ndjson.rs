#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for _ in zaaf_input::read_json_events(std::io::Cursor::new(data.to_vec())) {}
});
