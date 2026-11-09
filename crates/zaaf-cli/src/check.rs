//! `zaaf check`: parse, compile and lint rules.

use crate::exit;
use crate::output::sanitize;
use crate::rules::load_rules;
use clap::{Args, ValueEnum};
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::PathBuf;
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{Diagnostic, Location};

#[derive(Args)]
pub struct CheckArgs {
    /// Rule files or directories (searched recursively for .yml/.yaml)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    /// Processing pipeline files, applied in priority order
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,
    /// Diagnostics format
    #[arg(long, value_enum, default_value_t = DiagFormat::Text)]
    pub format: DiagFormat,
    /// Do not print warnings
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum DiagFormat {
    Text,
    Json,
}

/// One diagnostic as JSON. `line`, `col` and `path` are null when unknown; `path`
/// is also null when the position has no YAML path (syntax errors, whole documents).
pub fn diagnostic_json(d: &Diagnostic) -> Value {
    let (line, col, path) = match &d.location {
        Location::Unknown => (None, None, None),
        Location::At { line, col, path } => (
            Some(*line),
            Some(*col),
            (!path.is_empty()).then_some(path.as_str()),
        ),
    };
    json!({
        "severity": if d.is_error() { "error" } else { "warning" },
        "file": d.file.as_ref().map(|p| p.display().to_string()),
        "line": line,
        "col": col,
        "path": path,
        "message": d.message,
    })
}

pub fn run(args: CheckArgs) -> u8 {
    let pipelines = match PipelineSet::load(&args.pipelines) {
        Ok(p) => p,
        Err(d) => {
            eprintln!("{}", sanitize(&d.to_string()));
            return exit::RULE_ERRORS;
        }
    };
    let loaded = load_rules(&args.paths, &pipelines);
    let errors = loaded.diagnostics.iter().filter(|d| d.is_error()).count();
    let warnings = loaded.diagnostics.len() - errors;
    let shown = loaded
        .diagnostics
        .iter()
        .filter(|d| d.is_error() || !args.quiet);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let written = match args.format {
        DiagFormat::Text => (|| {
            for d in shown {
                writeln!(out, "{}", sanitize(&d.to_string()))?;
            }
            writeln!(
                out,
                "checked {} files: {} rules, {} filters, {} correlations skipped, {errors} errors, {warnings} warnings",
                loaded.files,
                loaded.output.rules.len(),
                loaded.output.filters,
                loaded.output.correlations_skipped
            )
        })(),
        DiagFormat::Json => {
            let report = json!({
                "files": loaded.files,
                "rules": loaded.output.rules.len(),
                "filters": loaded.output.filters,
                "correlations_skipped": loaded.output.correlations_skipped,
                "errors": errors,
                "warnings": warnings,
                "diagnostics": shown.map(diagnostic_json).collect::<Vec<_>>(),
            });
            writeln!(
                out,
                "{}",
                serde_json::to_string_pretty(&report).expect("a JSON value always serializes")
            )
        }
    };
    if let Err(e) = written.and_then(|()| out.flush()) {
        let code = exit::write_failed(e);
        // A closed pipe must not hide rule errors (`zaaf check | head` under pipefail).
        return if errors > 0 && code == exit::OK {
            exit::RULE_ERRORS
        } else {
            code
        };
    }
    if errors > 0 {
        exit::RULE_ERRORS
    } else {
        exit::OK
    }
}
