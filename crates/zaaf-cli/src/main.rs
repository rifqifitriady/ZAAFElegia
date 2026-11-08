//! `zaaf`: the ZAAFElegia command-line interface.

mod check;
mod exit;
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = catch_unwind(AssertUnwindSafe(|| match cli.command {
        Command::Check(args) => check::run(args),
    }))
    .unwrap_or(exit::INTERNAL);
    ExitCode::from(code)
}
