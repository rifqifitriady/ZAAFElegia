//! Process exit codes (design spec §4).

pub const OK: u8 = 0;
/// Rule errors. Usage errors share this code, as with clap.
pub const RULE_ERRORS: u8 = 2;
pub const INTERNAL: u8 = 4;
