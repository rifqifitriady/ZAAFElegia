# ZAAFElegia

A Sigma-native detection engine written in Rust. ZAAFElegia runs
[Sigma](https://github.com/SigmaHQ/sigma) rules directly over your logs.
It does not convert them to another query language first.

> **Status: 0.0.1 pre-release (milestone M1).** Single-event rules over JSON/NDJSON.
> Planned, not yet available: correlation rules (M2), EVTX and cloud logs (M3),
> Parquet (M4) and the AI-attack rule pack (M5).
> See the [design spec](docs/superpowers/specs/2026-11-07-zaafelegia-v0.1-design.md).

## Why ZAAFElegia

- **Conformance you can check.**
  - A public, language-neutral [conformance suite](conformance/README.md) for Sigma 2.1 (29 cases).
  - A CI run that parses and compiles the whole SigmaHQ corpus (pinned to commit `53b90df`, see `scripts/sigmahq-corpus.sh`), with the bundled placeholder pipeline (`tests/sigmahq/placeholders.yml`): SigmaHQ corpus: 3807/3807 files parse and compile (100.00%). This measures parse and compile only, not detection accuracy.
- **One rule, live and historical (planned, M4).** The same rule should give identical results on a stream and on Parquet.
- **Detection for the AI era (planned, M5).** Logsources and rules for LLM gateways and MCP tool calls.
- **Apache-2.0.** No copyleft dependencies, enforced by `cargo-deny`.

## Install from source

You need Rust 1.89 or newer (the minimum supported version). Install it with [rustup](https://rustup.rs/).

```bash
git clone https://github.com/rifqifitriady/ZAAFElegia
cd ZAAFElegia
cargo install --path crates/zaaf-cli
```

## Quick start

```bash
# Lint rules (exit 2 on errors)
zaaf check path/to/sigma/rules

# Hunt over NDJSON: a table on a terminal, OCSF NDJSON when piped
zaaf hunt -r path/to/sigma/rules logs/*.ndjson

# Stream from stdin and fail a CI job on any match
tail -f app.ndjson | zaaf hunt -r rules/ --fail-on-match -
```

`zaaf check` reports each diagnostic as `file:line:col: path: message` (prefixed with its
severity, `error:` or `warning:`), where `path` is the location inside the rule's YAML.

Sigma rules use Windows/Sysmon field names (`Image`, `CommandLine`). If your logs
use other names, map them with a pipeline:

```yaml
# ecs-windows.yml
name: ecs-windows
transformations:
  - type: field_name_mapping
    mapping:
      Image: process.executable
      CommandLine: process.command_line
    rule_conditions:
      - product: windows
```

```bash
zaaf hunt -r rules/ -p ecs-windows.yml logs.ndjson
```

## Output

Each match is an [OCSF](https://schema.ocsf.io/) Detection Finding (class 2004).
That is the `json` and `ndjson` output (`-o json|ndjson`). The rule's `author` and
`references` are always included under `unmapped.sigma`, as the Detection Rule License
(DRL 1.1) requires for SigmaHQ rules.

`-o csv` and `-o table` are summaries, not OCSF. CSV has the columns
`time,level,rule_id,title,author,references,source` (references joined with ` | `).
The table shows the author but not the references, which are too long for it; use
`-o json`, `ndjson` or `csv` to see them.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Matches found (only with `--fail-on-match`) |
| 2 | Rule errors (with `--strict`), no rules left to run, or usage errors |
| 3 | Input errors: an unreadable input file always; malformed records (including oversized lines) only with `--strict` or above `--max-errors` |
| 4 | Internal error |

When several conditions hold, the highest-precedence code wins (4 > 3 > 2 > 1 > 0).
A broken output pipe (for example `zaaf hunt ... | head`) exits 0.

## Input

`zaaf hunt` reads NDJSON, a JSON array, or stdin. NDJSON lines over 8 MiB and JSON arrays
over 256 MiB are reported as input errors. An oversized NDJSON line counts as a malformed
record, so it exits 3 only with `--strict` or above `--max-errors`. JSON arrays are buffered in memory in full, so
prefer NDJSON for large inputs.

## Limits

To keep rules from exhausting memory or time, ZAAFElegia enforces these limits:

- Condition nesting depth: at most 64.
- Value expansion (for example a modifier chain over a list): at most 4,096 variants.
- Predicates per detection item: at most 16,384.
- Per rule: at most 65,536 weight units (a regular expression counts as 16).
- Per run: at most 1,000,000 weight units across all loaded rules.
- Regular expressions use a linear-time engine. Patterns it cannot run fall back to a
  backtracking engine capped at 1,000,000 steps. Hitting that cap counts as no match, and
  `zaaf hunt` prints a warning naming the rule.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). ZAAFElegia does not bundle
the SigmaHQ rules; they are licensed separately under DRL 1.1.
