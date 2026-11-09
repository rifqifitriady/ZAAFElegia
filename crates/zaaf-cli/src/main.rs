//! `zaaf`: the ZAAFElegia command-line interface.

mod check;
mod exit;
mod hunt;
mod output;
mod rules;

use clap::{Parser, Subcommand};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "zaaf",
    version,
    about = "ZAAFElegia: Sigma-native detection engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse, compile and lint Sigma rules
    Check(check::CheckArgs),
    /// Run Sigma rules over log events and emit OCSF Detection Findings
    Hunt(hunt::HuntArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = catch_unwind(AssertUnwindSafe(|| {
        // Test hook for the exit-code-4 contract. It exists only when `debug_assertions`
        // is on, so it is compiled out of `--release` builds and the exit-4 test
        // (`internal_panic_exits_four`, also `#[cfg(debug_assertions)]`) does not run
        // under `cargo test --release`.
        #[cfg(debug_assertions)]
        if std::env::var_os("ZAAF_INTERNAL_PANIC_TEST").is_some_and(|v| v == "1") {
            panic!("zaaf internal panic test");
        }
        match cli.command {
            Command::Check(args) => check::run(args),
            Command::Hunt(args) => hunt::run(args),
        }
    }))
    .unwrap_or(exit::INTERNAL);
    ExitCode::from(code)
}
