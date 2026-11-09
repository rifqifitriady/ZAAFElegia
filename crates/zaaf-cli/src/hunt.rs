//! `zaaf hunt`: run rules over log events.

use crate::exit;
use crate::output::{OutputFormat, Sink, detection_finding, sanitize};
use crate::rules::load_rules;
use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use zaaf_eval::Evaluator;
use zaaf_event::Event;
use zaaf_input::{
    EventResult, MAX_ARRAY_BYTES, MAX_LINE_BYTES, open_path_with_limits,
    read_json_events_with_limits,
};
use zaaf_ir::{CompiledRule, Level};
use zaaf_pipeline::PipelineSet;

#[derive(Clone, Copy, ValueEnum)]
pub enum LevelArg {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl From<LevelArg> for Level {
    fn from(l: LevelArg) -> Self {
        match l {
            LevelArg::Informational => Level::Informational,
            LevelArg::Low => Level::Low,
            LevelArg::Medium => Level::Medium,
            LevelArg::High => Level::High,
            LevelArg::Critical => Level::Critical,
        }
    }
}

#[derive(Args)]
pub struct HuntArgs {
    /// Log files (NDJSON or a JSON array); `-` or none reads stdin
    pub inputs: Vec<PathBuf>,
    /// Rule files or directories (repeatable)
    #[arg(short = 'r', long = "rules", required = true)]
    pub rules: Vec<PathBuf>,
    /// Processing pipeline files, applied in priority order
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,
    /// Output format [default: table on a terminal, ndjson otherwise]. `ndjson` and `csv`
    /// stream; `json` and `table` hold every finding in memory until the end of the run
    /// (`json` is one array)
    #[arg(short = 'o', long = "output", value_enum)]
    pub output: Option<OutputFormat>,
    /// Only run rules at or above this level
    #[arg(long, value_enum)]
    pub min_level: Option<LevelArg>,
    /// Only run rules with these statuses (comma-separated, e.g. stable,test)
    #[arg(long, value_delimiter = ',')]
    pub status: Vec<String>,
    /// Skip events whose timestamp is before this time (RFC 3339)
    #[arg(long)]
    pub from: Option<String>,
    /// Skip events whose timestamp is after this time (RFC 3339)
    #[arg(long)]
    pub to: Option<String>,
    /// Exit with code 1 when anything matches
    #[arg(long)]
    pub fail_on_match: bool,
    /// Abort on any rule error (exit 2); fail on any malformed record (exit 3)
    #[arg(long)]
    pub strict: bool,
    /// Abort after this many malformed records (exit 3)
    #[arg(long, default_value_t = 1000)]
    pub max_errors: usize,
    /// Longest accepted NDJSON line in bytes; longer lines are malformed records
    #[arg(
        long,
        default_value_t = MAX_LINE_BYTES,
        value_parser = positive_usize
    )]
    pub max_line_bytes: usize,
    /// Also print rule warnings
    #[arg(short, long)]
    pub verbose: bool,
}

fn positive_usize(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(0) => Err("must be at least 1".to_string()),
        Ok(n) => Ok(n),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Default)]
struct Stats {
    events: u64,
    input_errors: usize,
    open_errors: usize,
    out_of_range: u64,
    matches: u64,
}

fn bound(value: &Option<String>, flag: &str) -> Result<Option<DateTime<Utc>>, String> {
    match value {
        None => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| Some(t.with_timezone(&Utc)))
            .map_err(|_| {
                format!(
                    "--{flag}: `{s}` is not an RFC 3339 timestamp (for example 2026-11-07T01:00:00Z)"
                )
            }),
    }
}

fn keep(rule: &CompiledRule, min: Option<Level>, statuses: &[String]) -> bool {
    min.is_none_or(|m| rule.info.level >= m)
        && (statuses.is_empty()
            || rule
                .info
                .status
                .as_deref()
                .is_some_and(|s| statuses.iter().any(|w| w.eq_ignore_ascii_case(s))))
}

pub fn run(args: HuntArgs) -> u8 {
    let (from, to) = match (bound(&args.from, "from"), bound(&args.to, "to")) {
        (Ok(f), Ok(t)) => (f, t),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("error: {e}");
            return exit::RULE_ERRORS;
        }
    };
    let pipelines = match PipelineSet::load(&args.pipelines) {
        Ok(p) => p,
        Err(d) => {
            eprintln!("{d}");
            return exit::RULE_ERRORS;
        }
    };
    let loaded = load_rules(&args.rules, &pipelines);
    let rule_errors = loaded.diagnostics.iter().filter(|d| d.is_error()).count();
    for d in &loaded.diagnostics {
        if d.is_error() || args.verbose {
            eprintln!("{}", sanitize(&d.to_string()));
        }
    }
    if rule_errors > 0 && args.strict {
        eprintln!("error: {rule_errors} rule errors (--strict)");
        return exit::RULE_ERRORS;
    }
    let rules_before = loaded.output.rules.len();
    let min = args.min_level.map(Level::from);
    let rules: Vec<CompiledRule> = loaded
        .output
        .rules
        .into_iter()
        .filter(|r| keep(r, min, &args.status))
        .collect();
    if rules.is_empty() {
        if rules_before > 0 {
            eprintln!("error: no rules left after --min-level/--status filters");
        } else {
            eprintln!("error: no rules to run");
        }
        return exit::RULE_ERRORS;
    }
    let rule_count = rules.len();
    let evaluator = Evaluator::new(rules);
    let code = scan(&args, &evaluator, from, to, rule_count);
    warn_regex_limits(&evaluator);
    code
}

fn warn_regex_limits(evaluator: &Evaluator) {
    for (idx, hits) in evaluator.regex_limit_hits() {
        let info = &evaluator.rules()[idx].info;
        eprintln!(
            "warning: rule `{}` ({}): {hits} regex evaluation(s) hit the backtracking limit and were treated as no match",
            sanitize(&info.title),
            sanitize(&info.id)
        );
    }
}

/// Exit-code precedence when several conditions hold: 4 > 3 > 2 > 1 > 0.
/// Unreadable inputs always give 3; malformed records give 3 only with
/// `--strict` (or past `--max-errors`); `--fail-on-match` (1) loses to both.
///
/// Two cases sit outside that ordering. Exit 2 (rule or usage errors) is returned by
/// `run` before any input is scanned, so it never competes with 3 or 1. A broken
/// output pipe returns 0 immediately, mid-scan, and skips the remaining inputs and
/// every other condition (so it also hides 3 and 1).
fn scan(
    args: &HuntArgs,
    evaluator: &Evaluator,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    rule_count: usize,
) -> u8 {
    let format = args.output.unwrap_or(if io::stdout().is_terminal() {
        OutputFormat::Table
    } else {
        OutputFormat::Ndjson
    });
    let mut sink = Sink::new(format, io::stdout().lock());

    let inputs: Vec<Option<PathBuf>> = if args.inputs.is_empty() {
        vec![None]
    } else {
        args.inputs
            .iter()
            .map(|p| (p.as_os_str() != "-").then(|| p.clone()))
            .collect()
    };
    let mut stats = Stats::default();
    for input in inputs {
        let (name, events): (String, io::Result<Box<dyn Iterator<Item = EventResult>>>) =
            match &input {
                None => (
                    "<stdin>".to_string(),
                    Ok(read_json_events_with_limits(
                        io::stdin().lock(),
                        args.max_line_bytes,
                        MAX_ARRAY_BYTES,
                    )),
                ),
                Some(p) => (
                    p.display().to_string(),
                    open_path_with_limits(p, args.max_line_bytes, MAX_ARRAY_BYTES),
                ),
            };
        let events = match events {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {name}: {e}");
                stats.open_errors += 1;
                continue;
            }
        };
        for item in events {
            let event = match item {
                Ok(ev) => ev,
                Err(e) if e.fatal => {
                    eprintln!("error: {name}: {}", e.message);
                    stats.open_errors += 1;
                    break;
                }
                Err(e) => {
                    stats.input_errors += 1;
                    if stats.input_errors <= 5 {
                        eprintln!("warning: {name}:{}: {}", e.line, e.message);
                    }
                    if stats.input_errors > args.max_errors {
                        eprintln!(
                            "error: more than {} malformed records, aborting",
                            args.max_errors
                        );
                        if let Err(e) = sink.finish() {
                            return exit::write_failed(e);
                        }
                        return exit::INPUT_ERRORS;
                    }
                    continue;
                }
            };
            stats.events += 1;
            if let Some(ts) = event.timestamp()
                && (from.is_some_and(|f| ts < f) || to.is_some_and(|t| ts > t))
            {
                stats.out_of_range += 1;
                continue;
            }
            for idx in evaluator.matching_rules(&event) {
                stats.matches += 1;
                let finding = detection_finding(&evaluator.rules()[idx], &event, &name);
                if let Err(e) = sink.write(finding) {
                    return exit::write_failed(e);
                }
            }
        }
    }
    if let Err(e) = sink.finish() {
        return exit::write_failed(e);
    }
    let range_note = if stats.out_of_range > 0 {
        format!(" ({} outside time range)", stats.out_of_range)
    } else {
        String::new()
    };
    eprintln!(
        "{} events{range_note}, {} malformed records, {} unreadable inputs, {rule_count} rules, {} matches",
        stats.events, stats.input_errors, stats.open_errors, stats.matches
    );
    if stats.open_errors > 0 || (args.strict && stats.input_errors > 0) {
        return exit::INPUT_ERRORS;
    }
    if args.fail_on_match && stats.matches > 0 {
        exit::MATCHES
    } else {
        exit::OK
    }
}
