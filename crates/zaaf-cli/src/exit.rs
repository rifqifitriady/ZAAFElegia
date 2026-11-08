//! Process exit codes (design spec §4).

pub const OK: u8 = 0;
pub const MATCHES: u8 = 1;
/// Rule errors. Usage errors share this code, as with clap.
pub const RULE_ERRORS: u8 = 2;
pub const INPUT_ERRORS: u8 = 3;
pub const INTERNAL: u8 = 4;

/// Maps a failed write to stdout to an exit code. A closed pipe (`zaaf ... | head`) is
/// not an error.
pub fn write_failed(e: std::io::Error) -> u8 {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        OK
    } else {
        eprintln!("error: cannot write output: {e}");
        INTERNAL
    }
}
