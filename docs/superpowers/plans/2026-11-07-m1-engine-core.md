# ZAAFElegia M1: Engine Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship pre-release `0.0.1` of ZAAFElegia. It is a Rust workspace whose `zaaf` CLI parses, lints and evaluates single-event Sigma v2.1 rules over JSON/NDJSON logs. Correctness is proven by a public conformance suite and by a parse/compile run over the whole SigmaHQ corpus.

**Architecture:**
- `zaaf-sigma` parses YAML into a typed AST.
- `zaaf-pipeline` maps fields and placeholders.
- `zaaf-ir` compiles the AST and pipelines into an immutable boolean expression tree, the IR. Every modifier is resolved there.
- `zaaf-eval` evaluates the IR against `zaaf-event::Event`. It is the semantic reference for every later evaluator (DataFusion arrives in M4).
- `zaaf-input` turns JSON/NDJSON into events.
- `zaaf-cli` wires everything into `zaaf check` and `zaaf hunt`.
- `zaaf-testkit` runs the language-neutral conformance suite.

**Tech Stack:**
- Rust (edition 2024, MSRV 1.89).
- Libraries: serde, saphyr, serde-saphyr, serde_json, regex, fancy-regex, base64, ipnet, chrono, clap, comfy-table, walkdir.
- Tests: assert_cmd/predicates/tempfile, cargo-fuzz.
- Supply chain: cargo-deny.

**Spec:** [docs/superpowers/specs/2026-11-07-zaafelegia-v0.1-design.md](../specs/2026-11-07-zaafelegia-v0.1-design.md), milestone M1.

## Global Constraints

- **License:** Apache-2.0. `cargo-deny` must reject AGPL, GPL, SSPL, Elastic License and unlicensed dependencies.
- **No copied code:** nothing is copied from Hayabusa, Chainsaw, Velociraptor, Security Onion, elastic/detection-rules or any copyleft or source-available project.
- **Toolchain:** Rust stable, `edition = "2024"`, `rust-version = "1.89"` (the floor set by `serde-saphyr` 2.1; `comfy-table` 8.0 already needs 1.88). Rust 1.88+ has `let` chains, so clippy's `collapsible_if` expects them; the code below uses them.
- **Names:** crates are `zaaf-*`; the binary is `zaaf`.
- **Sigma version:** Sigma specification 2.1.0, covering rules, the modifiers appendix and filters.
- **Semantic reference:** `zaaf-eval` defines the semantics. Every interpretation of an ambiguous spec point is recorded in a conformance case's `spec_ref` and `description`.
- **Alerts:** OCSF Detection Finding, `class_uid: 2004`. Every alert carries the rule's `author` and `references` (DRL 1.1 attribution).
- **Exit codes:**
  - `0` OK
  - `1` matches found (only with `--fail-on-match`)
  - `2` rule errors
  - `3` input errors (with `--strict`, or above `--max-errors`)
  - `4` internal error
- **No panics on data:** the engine must not panic on any rule text or log input.
- **Every task ends with:**
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - all three passing, then a commit.
- **Commit messages** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Third-party APIs:** versions are pinned in the workspace `Cargo.toml`. If a third-party API differs slightly from the code shown, adapt minimally, keep the behaviour, and mention it in the commit body.

## Scope notes for M1 (agreed narrowing of the spec)

- **Correlation documents** are parsed as stubs and skipped with a warning. The correlator is M2.
- **Deferred `zaaf check` lints:** the ATT&CK/ATLAS tag existence lint needs bundled STIX data and moves to M5 with `coverage`. The correlation-reference lint moves to M2.
- **Input formats:** NDJSON or a top-level JSON array. CloudTrail `Records[]`, EVTX and Parquet are M3/M4.
- **Rule selection:** every rule runs against every event. Indexing rules by logsource needs typed inputs (M3).

## File Structure

```
ZAAFElegia/
├── Cargo.toml                      # workspace, shared dependency versions
├── rust-toolchain.toml             # stable + clippy + rustfmt
├── deny.toml                       # cargo-deny license and source policy
├── LICENSE  NOTICE                 # Apache-2.0; DRL 1.1 + MITRE attribution notes
├── .github/workflows/ci.yml        # fmt, clippy, test (3 OS), cargo-deny, SigmaHQ corpus
├── .github/workflows/fuzz.yml      # short fuzz on PR, long fuzz nightly
├── crates/
│   ├── zaaf-sigma/src/
│   │   ├── lib.rs                  # re-exports
│   │   ├── diagnostic.rs           # Diagnostic, Location, Severity
│   │   ├── value.rs                # RuleValue (YAML scalars)
│   │   ├── modifier.rs             # Modifier enum, parse_field_key
│   │   ├── sigma_string.rs         # wildcard/escape-aware strings + glob matching
│   │   ├── condition.rs            # condition grammar → CondExpr
│   │   └── document.rs             # YAML documents → Rule / Filter / CorrelationStub
│   ├── zaaf-pipeline/src/lib.rs    # Pipeline YAML, PipelineSet, field mapping, vars
│   ├── zaaf-ir/src/
│   │   ├── lib.rs                  # re-exports
│   │   ├── ir.rs                   # Expr, Predicate, Target, Matcher, CmpOp, TimePart, RefMode
│   │   ├── regex_engine.rs         # CompiledRegex (linear first, backtracking fallback)
│   │   ├── transform.rs            # windash, base64, base64offset, utf16*, placeholders
│   │   ├── item.rs                 # one `field|mods: values` item → Expr
│   │   └── rule.rs                 # documents → CompiledRule; conditions, filters, metadata
│   ├── zaaf-event/src/lib.rs       # Event trait, FieldValue, JsonEvent, timestamp parsing
│   ├── zaaf-eval/src/lib.rs        # Evaluator, eval_expr
│   ├── zaaf-input/src/lib.rs       # NDJSON / JSON array reader
│   ├── zaaf-testkit/
│   │   ├── src/lib.rs              # conformance case runner
│   │   └── tests/conformance.rs    # runs conformance/cases in `cargo test`
│   └── zaaf-cli/
│       ├── src/{main,exit,rules,check,hunt,output}.rs
│       └── tests/{check,hunt}.rs
├── conformance/
│   ├── README.md                   # format, invitation to other engines
│   ├── known-unsupported.txt       # SigmaHQ files we knowingly reject, with reasons
│   └── cases/NNN-name/{case.yml, rules/*.yml, events.ndjson[, pipeline.yml]}
├── tests/sigmahq/placeholders.yml  # dummy vars so placeholder rules compile in CI
├── scripts/sigmahq-corpus.sh       # clone SigmaHQ, run zaaf check, compare
├── scripts/compare_known_unsupported.py
├── fuzz/                           # cargo-fuzz targets (not a workspace member)
└── README.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md .github/ISSUE_TEMPLATE/ .github/PULL_REQUEST_TEMPLATE.md
```

---

### Task 0: Toolchain, workspace skeleton, CI and license

**Files:**
- Create: `rust-toolchain.toml`, `Cargo.toml`, `.gitignore`, `deny.toml`, `LICENSE`, `NOTICE`, `.github/workflows/ci.yml`
- Create: `crates/zaaf-sigma/Cargo.toml`, `crates/zaaf-sigma/src/lib.rs`

**Interfaces:**
- Produces: a compiling workspace with member `zaaf-sigma` and the shared `[workspace.dependencies]` table every later task uses.

- [ ] **Step 1: Install the Rust toolchain (ask Rifqi before installing system software)**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component clippy,rustfmt
source "$HOME/.cargo/env"
cargo --version && rustc --version
cargo install cargo-deny --locked
```
Expected: `cargo 1.x` and `rustc 1.x` with x ≥ 89, and `cargo deny --version` prints a version.

- [ ] **Step 2: Write the workspace files**

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt"]
```

`Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["crates/*"]
exclude = ["fuzz"]

[workspace.package]
version = "0.0.1"
edition = "2024"
license = "Apache-2.0"
repository = "https://github.com/rifqifitriady/ZAAFElegia"
rust-version = "1.89"

[workspace.dependencies]
anyhow = "1.0"
base64 = "0.23"
chrono = { version = "0.4.45", default-features = false, features = ["std", "clock"] }
clap = { version = "4.6", features = ["derive"] }
comfy-table = "8.0"
fancy-regex = "0.20"
indexmap = { version = "2.14", features = ["serde"] }
ipnet = "2.12"
regex = "1.13"
saphyr = "0.3"
serde = { version = "1.0", features = ["derive"] }
serde-saphyr = "2.1"
serde_json = { version = "1.0", features = ["preserve_order"] }
walkdir = "2.5"
assert_cmd = "2.2"
predicates = "3.1"
tempfile = "3.27"
zaaf-sigma = { path = "crates/zaaf-sigma", version = "0.0.1" }
zaaf-pipeline = { path = "crates/zaaf-pipeline", version = "0.0.1" }
zaaf-ir = { path = "crates/zaaf-ir", version = "0.0.1" }
zaaf-event = { path = "crates/zaaf-event", version = "0.0.1" }
zaaf-eval = { path = "crates/zaaf-eval", version = "0.0.1" }
zaaf-input = { path = "crates/zaaf-input", version = "0.0.1" }
zaaf-testkit = { path = "crates/zaaf-testkit", version = "0.0.1" }

[profile.release]
lto = "thin"
codegen-units = 1
```

YAML is read with two pure-Rust crates: `saphyr` parses Sigma rule files into nodes that carry their line and column, and `serde-saphyr` (`#![forbid(unsafe_code)]`) deserializes the serde-derived config files (pipelines, conformance `case.yml`). `serde_yaml_ng` is deliberately not used: it depends on `unsafe-libyaml`, which is unmaintained (RUSTSEC-2024-0449).

`.gitignore`:
```
/target
/fuzz/target
/fuzz/corpus
/fuzz/artifacts
```

`deny.toml`:
```toml
[graph]
all-features = true

[licenses]
version = 2
confidence-threshold = 0.9
allow = [
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "BSL-1.0",
    "CC0-1.0",
    "MPL-2.0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
]

[bans]
multiple-versions = "warn"

[advisories]
version = 2
yanked = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

`NOTICE`:
```
ZAAFElegia
Copyright 2026 Rifqi Fitriady and ZAAFElegia contributors

This product is licensed under the Apache License, Version 2.0 (see LICENSE).

Sigma rules
-----------
ZAAFElegia executes Sigma rules but does not bundle the SigmaHQ rule corpus.
Rules from https://github.com/SigmaHQ/sigma are licensed under the Detection
Rule License (DRL) 1.1. When you run them, DRL 1.1 requires that the rule
author and references remain visible; ZAAFElegia includes both in every alert
(`unmapped.sigma.author` and `unmapped.sigma.references`).
The Sigma specification and logo are public domain.

MITRE ATT&CK and ATLAS
----------------------
ATT&CK and ATLAS identifiers used in tags and coverage reports are
© The MITRE Corporation, used under the ATT&CK and ATLAS terms of use.
```

`.github/workflows/ci.yml`:
```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

`crates/zaaf-sigma/Cargo.toml`:
```toml
[package]
name = "zaaf-sigma"
description = "Sigma v2 rule, filter and correlation parser for ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
saphyr.workspace = true
```

`crates/zaaf-sigma/src/lib.rs`:
```rust
//! Sigma rule parser for ZAAFElegia.

/// Version of the Sigma specification this crate implements.
pub const SPEC_VERSION: &str = "2.1.0";

#[cfg(test)]
mod tests {
    #[test]
    fn spec_version_is_2_1() {
        assert_eq!(super::SPEC_VERSION, "2.1.0");
    }
}
```

- [ ] **Step 3: Add the Apache-2.0 license text**

```bash
curl -sSf https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
head -3 LICENSE
```
Expected: the first lines read `Apache License` / `Version 2.0, January 2004`.

- [ ] **Step 4: Verify**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check && cargo deny check`
Expected: `test tests::spec_version_is_2_1 ... ok`, no clippy warnings, and `cargo deny` reports `advisories ok, bans ok, licenses ok, sources ok`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "build: workspace skeleton, CI, cargo-deny policy, Apache-2.0 license

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1: zaaf-sigma: diagnostics, rule values, modifiers

**Files:**
- Create: `crates/zaaf-sigma/src/diagnostic.rs`, `crates/zaaf-sigma/src/value.rs`, `crates/zaaf-sigma/src/modifier.rs`
- Modify: `crates/zaaf-sigma/src/lib.rs`

**Interfaces:**
- Produces:
  - `Diagnostic { severity: Severity, file: Option<PathBuf>, location: Location, message: String }`
    - `Diagnostic::error(Location, impl Into<String>)`
    - `Diagnostic::warning(..)`
    - `.with_file(impl Into<PathBuf>)`
    - `.is_error()`
    - `Display`
  - `Location::{Unknown, At { line, col, path }}`: 1-based line and column plus the dotted YAML path of the node (empty when no path applies)
    - `Location::at(line, col, impl Into<String>)`
  - `Severity::{Error, Warning}`
  - `RuleValue::{Str(String), Int(i64), Float(f64), Bool(bool), Null}`
    - `RuleValue::from_yaml(&saphyr::MarkedYaml) -> Option<RuleValue>`: `None` for sequences, mappings, tagged values, aliases and bad values
    - `RuleValue::to_text(&self) -> Option<String>`
  - `Modifier` (one variant per Sigma 2.1 modifier)
    - `Modifier::parse(&str) -> Option<Modifier>`
    - `Modifier::name(self) -> &'static str`
  - `FieldKey { field: Option<String>, modifiers: Vec<Modifier> }`
  - `parse_field_key(&str) -> Result<FieldKey, String>`

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-sigma/src/diagnostic.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_line_and_column() {
        let d = Diagnostic::error(Location::at(3, 7, ""), "bad").with_file("r.yml");
        assert_eq!(d.to_string(), "error: r.yml:3:7: bad");
    }

    #[test]
    fn displays_position_and_yaml_path() {
        let d = Diagnostic::warning(Location::at(12, 9, "detection.sel.Image"), "unmapped");
        assert_eq!(d.to_string(), "warning: <input>:12:9: detection.sel.Image: unmapped");
        assert_eq!(d.location, Location::At { line: 12, col: 9, path: "detection.sel.Image".into() });
    }

    #[test]
    fn displays_unknown_location() {
        let d = Diagnostic::error(Location::Unknown, "boom").with_file("x.yml");
        assert_eq!(d.to_string(), "error: x.yml: boom");
        assert!(d.is_error());
    }
}
```

`crates/zaaf-sigma/src/value.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use saphyr::LoadableYamlNode;

    #[test]
    fn converts_yaml_scalars() {
        let docs = MarkedYaml::load_from_str("[abc, 4688, 1.5, true, null, '4688', [x], !custom y]").unwrap();
        let s = docs[0].data.as_vec().unwrap();
        assert_eq!(RuleValue::from_yaml(&s[0]), Some(RuleValue::Str("abc".into())));
        assert_eq!(RuleValue::from_yaml(&s[1]), Some(RuleValue::Int(4688)));
        assert_eq!(RuleValue::from_yaml(&s[2]), Some(RuleValue::Float(1.5)));
        assert_eq!(RuleValue::from_yaml(&s[3]), Some(RuleValue::Bool(true)));
        assert_eq!(RuleValue::from_yaml(&s[4]), Some(RuleValue::Null));
        assert_eq!(RuleValue::from_yaml(&s[5]), Some(RuleValue::Str("4688".into())));
        assert_eq!(RuleValue::from_yaml(&s[6]), None);
        assert_eq!(RuleValue::from_yaml(&s[7]), None);
    }

    #[test]
    fn text_form_of_non_strings() {
        assert_eq!(RuleValue::Int(4688).to_text().as_deref(), Some("4688"));
        assert_eq!(RuleValue::Bool(false).to_text().as_deref(), Some("false"));
        assert_eq!(RuleValue::Null.to_text(), None);
    }
}
```

`crates/zaaf-sigma/src/modifier.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_field_and_modifiers() {
        let k = parse_field_key("CommandLine|contains|all").unwrap();
        assert_eq!(k.field.as_deref(), Some("CommandLine"));
        assert_eq!(k.modifiers, vec![Modifier::Contains, Modifier::All]);
    }

    #[test]
    fn keyword_key_has_no_field() {
        let k = parse_field_key("|all").unwrap();
        assert_eq!(k.field, None);
        assert_eq!(k.modifiers, vec![Modifier::All]);
    }

    #[test]
    fn plain_field_and_regex_flags() {
        assert!(parse_field_key("Image").unwrap().modifiers.is_empty());
        let k = parse_field_key("x|re|i|m|s").unwrap();
        assert_eq!(
            k.modifiers,
            vec![Modifier::Re, Modifier::ReInsensitive, Modifier::ReMultiline, Modifier::ReDotAll]
        );
    }

    #[test]
    fn unknown_modifier_is_an_error() {
        let err = parse_field_key("x|bogus").unwrap_err();
        assert!(err.contains("bogus"), "{err}");
    }

    #[test]
    fn every_modifier_round_trips() {
        for (name, m) in TABLE {
            assert_eq!(Modifier::parse(name), Some(*m));
            assert_eq!(m.name(), *name);
        }
    }
}
```

`crates/zaaf-sigma/src/lib.rs` (replace whole file):
```rust
//! Sigma rule parser for ZAAFElegia.

pub mod diagnostic;
pub mod modifier;
pub mod value;

pub use diagnostic::{Diagnostic, Location, Severity};
pub use modifier::{FieldKey, Modifier, parse_field_key};
pub use value::RuleValue;

/// Version of the Sigma specification this crate implements.
pub const SPEC_VERSION: &str = "2.1.0";
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zaaf-sigma`
Expected: compile errors `cannot find type Diagnostic`, `cannot find type RuleValue`, `cannot find function parse_field_key`.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` block of `diagnostic.rs`:
```rust
//! Diagnostics reported while parsing and compiling rules.

use std::fmt;
use std::path::PathBuf;

/// How serious a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// Where in a file a diagnostic points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    Unknown,
    /// 1-based line and column, plus the dotted YAML path of the node
    /// (e.g. `detection.selection.Image|endswith`). `path` is empty when no
    /// path applies, e.g. for YAML syntax errors or a whole document.
    At { line: usize, col: usize, path: String },
}

impl Location {
    pub fn at(line: usize, col: usize, path: impl Into<String>) -> Self {
        Self::At { line, col, path: path.into() }
    }
}

/// A problem found in a rule, pipeline or input file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub file: Option<PathBuf>,
    pub location: Location,
    pub message: String,
}

impl Diagnostic {
    pub fn error(location: Location, message: impl Into<String>) -> Self {
        Self { severity: Severity::Error, file: None, location, message: message.into() }
    }

    pub fn warning(location: Location, message: impl Into<String>) -> Self {
        Self { severity: Severity::Warning, file: None, location, message: message.into() }
    }

    pub fn with_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let file = self
            .file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<input>".to_string());
        match &self.location {
            Location::Unknown => write!(f, "{sev}: {file}: {}", self.message),
            Location::At { line, col, path } if path.is_empty() => {
                write!(f, "{sev}: {file}:{line}:{col}: {}", self.message)
            }
            Location::At { line, col, path } => write!(f, "{sev}: {file}:{line}:{col}: {path}: {}", self.message),
        }
    }
}
```

Insert above the tests of `value.rs`:
```rust
//! Scalar values as written in a Sigma detection.

use saphyr::{MarkedYaml, Scalar, YamlData};

/// A scalar value from a Sigma detection.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl RuleValue {
    /// Converts a YAML scalar. Returns `None` for sequences, mappings, tagged
    /// values, aliases and invalid values.
    pub fn from_yaml(v: &MarkedYaml<'_>) -> Option<Self> {
        match &v.data {
            YamlData::Value(Scalar::Null) => Some(Self::Null),
            YamlData::Value(Scalar::Boolean(b)) => Some(Self::Bool(*b)),
            YamlData::Value(Scalar::Integer(i)) => Some(Self::Int(*i)),
            YamlData::Value(Scalar::FloatingPoint(f)) => Some(Self::Float(f.into_inner())),
            YamlData::Value(Scalar::String(s)) => Some(Self::Str(s.to_string())),
            _ => None,
        }
    }

    /// Text used when a non-string value is matched as a string (`4688`, `true`).
    pub fn to_text(&self) -> Option<String> {
        match self {
            Self::Str(s) => Some(s.clone()),
            Self::Int(i) => Some(i.to_string()),
            Self::Float(f) => Some(f.to_string()),
            Self::Bool(b) => Some(b.to_string()),
            Self::Null => None,
        }
    }
}
```

Insert above the tests of `modifier.rs`:
```rust
//! Sigma 2.1 value modifiers (`field|mod1|mod2`).

/// Every modifier defined by the Sigma 2.1 modifiers appendix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    // generic
    All,
    StartsWith,
    EndsWith,
    Contains,
    Exists,
    Cased,
    Neq,
    // string
    Windash,
    Re,
    ReInsensitive,
    ReMultiline,
    ReDotAll,
    Base64,
    Base64Offset,
    Utf16Le,
    Utf16Be,
    Utf16,
    Wide,
    // numeric
    Lt,
    Lte,
    Gt,
    Gte,
    // time
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
    // ip
    Cidr,
    // specific
    Expand,
    FieldRef,
}

pub(crate) const TABLE: &[(&str, Modifier)] = &[
    ("all", Modifier::All),
    ("startswith", Modifier::StartsWith),
    ("endswith", Modifier::EndsWith),
    ("contains", Modifier::Contains),
    ("exists", Modifier::Exists),
    ("cased", Modifier::Cased),
    ("neq", Modifier::Neq),
    ("windash", Modifier::Windash),
    ("re", Modifier::Re),
    ("i", Modifier::ReInsensitive),
    ("m", Modifier::ReMultiline),
    ("s", Modifier::ReDotAll),
    ("base64", Modifier::Base64),
    ("base64offset", Modifier::Base64Offset),
    ("utf16le", Modifier::Utf16Le),
    ("utf16be", Modifier::Utf16Be),
    ("utf16", Modifier::Utf16),
    ("wide", Modifier::Wide),
    ("lt", Modifier::Lt),
    ("lte", Modifier::Lte),
    ("gt", Modifier::Gt),
    ("gte", Modifier::Gte),
    ("minute", Modifier::Minute),
    ("hour", Modifier::Hour),
    ("day", Modifier::Day),
    ("week", Modifier::Week),
    ("month", Modifier::Month),
    ("year", Modifier::Year),
    ("cidr", Modifier::Cidr),
    ("expand", Modifier::Expand),
    ("fieldref", Modifier::FieldRef),
];

impl Modifier {
    pub fn parse(s: &str) -> Option<Self> {
        TABLE.iter().find(|(n, _)| *n == s).map(|(_, m)| *m)
    }

    pub fn name(self) -> &'static str {
        TABLE
            .iter()
            .find(|(_, m)| *m == self)
            .map(|(n, _)| *n)
            .expect("every modifier is listed in TABLE")
    }
}

/// A detection key split into its field name and modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldKey {
    /// `None` for keyword keys such as `|all`.
    pub field: Option<String>,
    pub modifiers: Vec<Modifier>,
}

/// Splits `CommandLine|contains|all` into the field and its modifiers.
pub fn parse_field_key(key: &str) -> Result<FieldKey, String> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    let field = (!field.is_empty()).then(|| field.to_string());
    let mut modifiers = Vec::new();
    for p in parts {
        match Modifier::parse(p) {
            Some(m) => modifiers.push(m),
            None => return Err(format!("unknown modifier `{p}`")),
        }
    }
    Ok(FieldKey { field, modifiers })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zaaf-sigma`
Expected: all tests pass (`converts_yaml_scalars`, `splits_field_and_modifiers`, `every_modifier_round_trips`, …).

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(sigma): diagnostics, rule values and Sigma 2.1 modifiers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: zaaf-sigma: wildcard strings and glob matching

**Files:**
- Create: `crates/zaaf-sigma/src/sigma_string.rs`
- Modify: `crates/zaaf-sigma/src/lib.rs`, adding `pub mod sigma_string;` and `pub use sigma_string::{SigmaString, Tok};`

**Interfaces:**
- Produces:
  - `Tok::{Lit(String), AnyOne, AnyMany}`
  - `SigmaString`, with:
    - `parse(&str)`: Sigma escape rules.
    - `literal(&str)`: no wildcard interpretation.
    - `from_toks(Vec<Tok>)`
    - `toks() -> &[Tok]`
    - `push(Tok)`, `push_lit(&str)`
    - `prepend_any_many()`, `append_any_many()`
    - `has_wildcards()`
    - `as_plain() -> Option<String>`
    - `to_lowercase()`
    - `concat(&SigmaString)`
    - `matches(&str) -> bool`: exact-case glob match. Callers lowercase both sides for case-insensitive matching.

- [ ] **Step 1: Write the failing tests** in `crates/zaaf-sigma/src/sigma_string.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> Tok {
        Tok::Lit(s.to_string())
    }

    #[test]
    fn parses_wildcards() {
        assert_eq!(SigmaString::parse("prog?.exe").toks(), &[lit("prog"), Tok::AnyOne, lit(".exe")]);
        assert_eq!(SigmaString::parse(r"*\cmd.exe").toks(), &[Tok::AnyMany, lit(r"\cmd.exe")]);
    }

    #[test]
    fn escaping_follows_the_spec_table() {
        let plain = |s: &str| SigmaString::parse(s).as_plain();
        assert_eq!(plain(r"C:\Windows").as_deref(), Some(r"C:\Windows"));
        assert_eq!(plain(r"C:\\Windows").as_deref(), Some(r"C:\Windows"));
        assert_eq!(plain(r"a\*b").as_deref(), Some("a*b"));
        assert_eq!(SigmaString::parse(r"a\\*").toks(), &[lit(r"a\"), Tok::AnyMany]);
        assert_eq!(plain(r"a\\\*").as_deref(), Some(r"a\*"));
        assert_eq!(plain(r"a\\\b").as_deref(), Some(r"a\\b"));
        assert_eq!(plain(r"a\\\\b").as_deref(), Some(r"a\\b"));
        assert_eq!(plain(r"dir\").as_deref(), Some(r"dir\"));
        assert_eq!(plain("").as_deref(), Some(""));
    }

    #[test]
    fn matches_fast_paths_and_general_globs() {
        let m = |p: &str, t: &str| SigmaString::parse(p).matches(t);
        assert!(m("abc", "abc"));
        assert!(!m("abc", "abcd"));
        assert!(m("*bc", "abc"));
        assert!(m("ab*", "abc"));
        assert!(m("*b*", "abc"));
        assert!(m("*", ""));
        assert!(m("", ""));
        assert!(!m("", "x"));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(m("a*c*e", "abcde"));
        assert!(!m("a*c*e", "abcdef"));
        assert!(m("*a*a*a*", "xaxaxax"));
        assert!(m("?", "é"));
    }

    #[test]
    fn helpers() {
        let mut s = SigmaString::literal("x");
        s.prepend_any_many();
        s.prepend_any_many();
        s.append_any_many();
        s.append_any_many();
        assert_eq!(s.toks(), &[Tok::AnyMany, lit("x"), Tok::AnyMany]);
        assert!(s.has_wildcards());
        assert_eq!(s.as_plain(), None);
        assert_eq!(SigmaString::literal("A*").to_lowercase().as_plain().as_deref(), Some("a*"));
        assert_eq!(
            SigmaString::literal("ab").concat(&SigmaString::parse("c*")).toks(),
            &[lit("abc"), Tok::AnyMany]
        );
        assert_eq!(
            SigmaString::from_toks(vec![lit("a"), lit("b"), Tok::AnyMany, Tok::AnyMany]).toks(),
            &[lit("ab"), Tok::AnyMany]
        );
    }
}
```

Add to `lib.rs`: `pub mod sigma_string;` and `pub use sigma_string::{SigmaString, Tok};`

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-sigma sigma_string`
Expected: compile error `cannot find type SigmaString`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Sigma string values with `*` / `?` wildcards and backslash escaping
//! (Sigma rules specification, "String Wildcard" and "Escape Character").

/// One token of a Sigma string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tok {
    Lit(String),
    /// `?`: exactly one character.
    AnyOne,
    /// `*`: any number of characters.
    AnyMany,
}

/// A Sigma string value: literal text interleaved with wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SigmaString {
    toks: Vec<Tok>,
}

impl SigmaString {
    /// Parses a rule value. `\` escapes `*`, `?` and `\`; before any other
    /// character it is a plain backslash.
    pub fn parse(s: &str) -> Self {
        let mut out = Self::default();
        let mut lit = String::new();
        let mut escaped = false;
        for c in s.chars() {
            if escaped {
                if c != '*' && c != '?' && c != '\\' {
                    lit.push('\\');
                }
                lit.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '*' || c == '?' {
                out.push_lit(&lit);
                lit.clear();
                out.push(if c == '*' { Tok::AnyMany } else { Tok::AnyOne });
            } else {
                lit.push(c);
            }
        }
        if escaped {
            lit.push('\\');
        }
        out.push_lit(&lit);
        out
    }

    /// A string whose characters are all literal.
    pub fn literal(s: &str) -> Self {
        let mut out = Self::default();
        out.push_lit(s);
        out
    }

    pub fn from_toks(toks: Vec<Tok>) -> Self {
        let mut out = Self::default();
        for t in toks {
            out.push(t);
        }
        out
    }

    pub fn toks(&self) -> &[Tok] {
        &self.toks
    }

    pub fn push_lit(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        if let Some(Tok::Lit(prev)) = self.toks.last_mut() {
            prev.push_str(s);
        } else {
            self.toks.push(Tok::Lit(s.to_string()));
        }
    }

    pub fn push(&mut self, t: Tok) {
        match t {
            Tok::Lit(s) => self.push_lit(&s),
            Tok::AnyMany if matches!(self.toks.last(), Some(Tok::AnyMany)) => {}
            other => self.toks.push(other),
        }
    }

    pub fn prepend_any_many(&mut self) {
        if !matches!(self.toks.first(), Some(Tok::AnyMany)) {
            self.toks.insert(0, Tok::AnyMany);
        }
    }

    pub fn append_any_many(&mut self) {
        self.push(Tok::AnyMany);
    }

    pub fn has_wildcards(&self) -> bool {
        self.toks.iter().any(|t| !matches!(t, Tok::Lit(_)))
    }

    /// The text if the string has no wildcards.
    pub fn as_plain(&self) -> Option<String> {
        let mut out = String::new();
        for t in &self.toks {
            match t {
                Tok::Lit(s) => out.push_str(s),
                _ => return None,
            }
        }
        Some(out)
    }

    pub fn to_lowercase(&self) -> Self {
        Self {
            toks: self
                .toks
                .iter()
                .map(|t| match t {
                    Tok::Lit(s) => Tok::Lit(s.to_lowercase()),
                    other => other.clone(),
                })
                .collect(),
        }
    }

    pub fn concat(&self, other: &SigmaString) -> SigmaString {
        let mut out = self.clone();
        for t in &other.toks {
            out.push(t.clone());
        }
        out
    }

    /// Exact-case glob match of the whole `text`.
    pub fn matches(&self, text: &str) -> bool {
        match self.toks.as_slice() {
            [] => text.is_empty(),
            [Tok::Lit(l)] => text == l,
            [Tok::AnyMany] => true,
            [Tok::AnyMany, Tok::Lit(l)] => text.ends_with(l.as_str()),
            [Tok::Lit(l), Tok::AnyMany] => text.starts_with(l.as_str()),
            [Tok::AnyMany, Tok::Lit(l), Tok::AnyMany] => text.contains(l.as_str()),
            toks => glob(toks, text),
        }
    }
}

/// Iterative wildcard matching with single-star backtracking (linear memory).
fn glob(toks: &[Tok], text: &str) -> bool {
    #[derive(Clone, Copy)]
    enum P {
        C(char),
        One,
        Many,
    }
    let pat: Vec<P> = toks
        .iter()
        .flat_map(|t| match t {
            Tok::Lit(s) => s.chars().map(P::C).collect::<Vec<_>>(),
            Tok::AnyOne => vec![P::One],
            Tok::AnyMany => vec![P::Many],
        })
        .collect();
    let txt: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while t < txt.len() {
        let step = p < pat.len()
            && match pat[p] {
                P::C(c) => c == txt[t],
                P::One => true,
                P::Many => false,
            };
        if step {
            p += 1;
            t += 1;
        } else if p < pat.len() && matches!(pat[p], P::Many) {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && matches!(pat[p], P::Many) {
        p += 1;
    }
    p == pat.len()
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-sigma sigma_string`
Expected: 4 tests pass.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(sigma): wildcard-aware SigmaString with spec escaping and glob matching

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: zaaf-sigma: condition grammar

**Files:**
- Create: `crates/zaaf-sigma/src/condition.rs`
- Modify: `crates/zaaf-sigma/src/lib.rs`, adding `pub mod condition;` and `pub use condition::{CondExpr, Quantifier, SelTarget, parse_condition};`

**Interfaces:**
- Produces:
  - `CondExpr::{Ident(String), Not(Box<CondExpr>), And(Vec<CondExpr>), Or(Vec<CondExpr>), Of(Quantifier, SelTarget)}`
  - `Quantifier::{One, All}`
  - `SelTarget::{Them, Pattern(String)}`
  - `parse_condition(&str) -> Result<CondExpr, String>`
- Operator precedence, from least to most binding: `or`, `and`, `not`, `x of`, `( )`.

- [ ] **Step 1: Write the failing tests** in `crates/zaaf-sigma/src/condition.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> CondExpr {
        CondExpr::Ident(s.into())
    }

    #[test]
    fn precedence_or_and_not() {
        assert_eq!(
            parse_condition("a or b and not c").unwrap(),
            CondExpr::Or(vec![id("a"), CondExpr::And(vec![id("b"), CondExpr::Not(Box::new(id("c")))])])
        );
    }

    #[test]
    fn parentheses_and_newlines() {
        assert_eq!(
            parse_condition("(a or b)\n  and c").unwrap(),
            CondExpr::And(vec![CondExpr::Or(vec![id("a"), id("b")]), id("c")])
        );
    }

    #[test]
    fn quantifiers() {
        assert_eq!(
            parse_condition("1 of selection_*").unwrap(),
            CondExpr::Of(Quantifier::One, SelTarget::Pattern("selection_*".into()))
        );
        assert_eq!(parse_condition("all of them").unwrap(), CondExpr::Of(Quantifier::All, SelTarget::Them));
        assert_eq!(
            parse_condition("sel and not 1 of filter_*").unwrap(),
            CondExpr::And(vec![
                id("sel"),
                CondExpr::Not(Box::new(CondExpr::Of(Quantifier::One, SelTarget::Pattern("filter_*".into()))))
            ])
        );
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(parse_condition("a AND NOT b").unwrap(), parse_condition("a and not b").unwrap());
    }

    #[test]
    fn errors() {
        for bad in ["", "a and", "(a", "a b", "and a", "1 of", "a)"] {
            assert!(parse_condition(bad).is_err(), "should reject {bad:?}");
        }
        let agg = parse_condition("sel | count() > 5").unwrap_err();
        assert!(agg.contains("correlation rule"), "{agg}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-sigma condition`
Expected: compile error `cannot find function parse_condition`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Sigma condition grammar.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quantifier {
    One,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelTarget {
    /// All search identifiers not starting with `_`.
    Them,
    /// A pattern with `*` wildcards, e.g. `selection_*`.
    Pattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondExpr {
    Ident(String),
    Not(Box<CondExpr>),
    And(Vec<CondExpr>),
    Or(Vec<CondExpr>),
    Of(Quantifier, SelTarget),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum T {
    LParen,
    RParen,
    Word(String),
}

fn tokenize(s: &str) -> Result<Vec<T>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    fn flush(cur: &mut String, out: &mut Vec<T>) {
        if !cur.is_empty() {
            out.push(T::Word(std::mem::take(cur)));
        }
    }
    for c in s.chars() {
        match c {
            '(' => {
                flush(&mut cur, &mut out);
                out.push(T::LParen);
            }
            ')' => {
                flush(&mut cur, &mut out);
                out.push(T::RParen);
            }
            '|' => {
                return Err("aggregation expressions (`| count() ...`) were removed in Sigma 2.0; \
                            use a correlation rule instead"
                    .into());
            }
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            c => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    Ok(out)
}

struct Parser {
    toks: Vec<T>,
    pos: usize,
}

impl Parser {
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.toks.get(self.pos), Some(T::Word(w)) if w.eq_ignore_ascii_case(kw))
    }

    fn expr(&mut self) -> Result<CondExpr, String> {
        let mut items = vec![self.and_expr()?];
        while self.is_kw("or") {
            self.pos += 1;
            items.push(self.and_expr()?);
        }
        Ok(if items.len() == 1 { items.remove(0) } else { CondExpr::Or(items) })
    }

    fn and_expr(&mut self) -> Result<CondExpr, String> {
        let mut items = vec![self.not_expr()?];
        while self.is_kw("and") {
            self.pos += 1;
            items.push(self.not_expr()?);
        }
        Ok(if items.len() == 1 { items.remove(0) } else { CondExpr::And(items) })
    }

    fn not_expr(&mut self) -> Result<CondExpr, String> {
        if self.is_kw("not") {
            self.pos += 1;
            return Ok(CondExpr::Not(Box::new(self.not_expr()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<CondExpr, String> {
        match self.toks.get(self.pos).cloned() {
            Some(T::LParen) => {
                self.pos += 1;
                let e = self.expr()?;
                if self.toks.get(self.pos) == Some(&T::RParen) {
                    self.pos += 1;
                    Ok(e)
                } else {
                    Err("missing closing parenthesis".into())
                }
            }
            Some(T::RParen) => Err("unexpected `)`".into()),
            Some(T::Word(w)) => {
                let lower = w.to_ascii_lowercase();
                let next_is_of =
                    matches!(self.toks.get(self.pos + 1), Some(T::Word(o)) if o.eq_ignore_ascii_case("of"));
                if (lower == "1" || lower == "all") && next_is_of {
                    self.pos += 2;
                    let q = if lower == "all" { Quantifier::All } else { Quantifier::One };
                    let target = match self.toks.get(self.pos).cloned() {
                        Some(T::Word(t)) => {
                            self.pos += 1;
                            if t.eq_ignore_ascii_case("them") { SelTarget::Them } else { SelTarget::Pattern(t) }
                        }
                        _ => return Err(format!("`{w} of` must be followed by `them` or a pattern")),
                    };
                    return Ok(CondExpr::Of(q, target));
                }
                if ["and", "or", "not", "of", "them"].contains(&lower.as_str()) {
                    return Err(format!("unexpected keyword `{w}`"));
                }
                self.pos += 1;
                Ok(CondExpr::Ident(w))
            }
            None => Err("unexpected end of condition".into()),
        }
    }
}

/// Parses one condition string.
pub fn parse_condition(s: &str) -> Result<CondExpr, String> {
    let toks = tokenize(s)?;
    if toks.is_empty() {
        return Err("empty condition".into());
    }
    let mut p = Parser { toks, pos: 0 };
    let e = p.expr()?;
    if p.pos != p.toks.len() {
        return Err(format!("unexpected token after position {}", p.pos));
    }
    Ok(e)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-sigma condition`
Expected: 5 tests pass.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(sigma): condition grammar with spec precedence and x-of quantifiers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: zaaf-sigma: documents (rules, filters, correlation stubs)

**Files:**
- Create: `crates/zaaf-sigma/src/document.rs`
- Modify: `crates/zaaf-sigma/src/lib.rs` (final form shown in Step 1)

**Interfaces:**
- Consumes: `parse_field_key`, `RuleValue::from_yaml`, `parse_condition`, `Diagnostic` (Tasks 1–3).
- Produces:
  - `LogSource { category, product, service: Option<String> }`
  - `FieldItem { field: Option<String>, modifiers: Vec<Modifier>, values: Vec<RuleValue>, path: String, line: usize, col: usize }`. `line`/`col` are the 1-based position of the item's key (of the search identifier's key for keyword lists).
  - `SearchIdentifier { name: String, alternatives: Vec<Vec<FieldItem>> }`. Alternatives are OR'd; the items inside one alternative are AND'd.
  - `Detection { search_ids: Vec<SearchIdentifier>, conditions: Vec<CondExpr>, condition_line: usize, condition_col: usize }`. Multiple conditions are OR'd; `condition_line`/`condition_col` are the 1-based position of the `condition` value.
  - `RuleMeta { title, id, name, status, level, description, author, references, tags, falsepositives, date, modified }`
  - `Rule { meta, logsource, detection, line, col }`
  - `Filter { title, id, name, logsource, rules: Vec<String>, detection, line, col }`
  - `CorrelationStub { title, id, line, col }`
  - `Rule`, `Filter` and `CorrelationStub` `line`/`col`: 1-based start of the document (its first key).
  - `Document::{Rule, Filter, Correlation}`
  - `ParsedFile { documents: Vec<Document>, diagnostics: Vec<Diagnostic> }`
  - `parse_str(&str) -> ParsedFile`
  - `parse_file(&Path) -> ParsedFile`. Every diagnostic carries the file.
- Every parse diagnostic is `Location::At` with the offending node's position and YAML path. Invalid YAML (a syntax error or a duplicated key) rejects the whole file: `saphyr` fails the entire stream, so `parse_str` returns no documents and one `Location::At` diagnostic with an empty path.

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-sigma/src/lib.rs` (final form):
```rust
//! Sigma rule parser for ZAAFElegia.

pub mod condition;
pub mod diagnostic;
pub mod document;
pub mod modifier;
pub mod sigma_string;
pub mod value;

pub use condition::{CondExpr, Quantifier, SelTarget, parse_condition};
pub use diagnostic::{Diagnostic, Location, Severity};
pub use document::{
    CorrelationStub, Detection, Document, FieldItem, Filter, LogSource, ParsedFile, Rule, RuleMeta,
    SearchIdentifier, parse_file, parse_str,
};
pub use modifier::{FieldKey, Modifier, parse_field_key};
pub use sigma_string::{SigmaString, Tok};
pub use value::RuleValue;

/// Version of the Sigma specification this crate implements.
pub const SPEC_VERSION: &str = "2.1.0";
```

`crates/zaaf-sigma/src/document.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modifier::Modifier;

    const QUICKASSIST: &str = r#"
title: QuickAssist Execution
id: e20b5b14-ce93-4230-88af-981983ef6e74
status: experimental
description: Detects QuickAssist.exe
references:
    - https://example.com/a
author: Muhammad Faisal (@faisalusuf)
date: 2024-12-19
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\QuickAssist.exe'
    condition: selection
falsepositives:
    - Legitimate use of Quick Assist in the environment.
level: low
"#;

    fn rule_with(detection: &str) -> String {
        format!("title: t\nid: r1\nlogsource:\n    product: test\ndetection:\n{detection}")
    }

    fn only_rule(src: &str) -> Rule {
        let parsed = parse_str(src);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        match parsed.documents.into_iter().next() {
            Some(Document::Rule(r)) => r,
            other => panic!("expected a rule, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_sigmahq_rule() {
        let r = only_rule(QUICKASSIST);
        assert_eq!(r.meta.title, "QuickAssist Execution");
        assert_eq!(r.meta.id.as_deref(), Some("e20b5b14-ce93-4230-88af-981983ef6e74"));
        assert_eq!(r.meta.level.as_deref(), Some("low"));
        assert_eq!(r.meta.date.as_deref(), Some("2024-12-19"));
        assert_eq!(r.meta.tags, vec!["attack.command-and-control", "attack.t1219.002"]);
        assert_eq!(r.meta.references, vec!["https://example.com/a"]);
        assert_eq!(r.meta.author.as_deref(), Some("Muhammad Faisal (@faisalusuf)"));
        assert_eq!(r.logsource.product.as_deref(), Some("windows"));
        assert_eq!(r.logsource.category.as_deref(), Some("process_creation"));
        assert_eq!(r.detection.conditions, vec![CondExpr::Ident("selection".into())]);
        let item = &r.detection.search_ids[0].alternatives[0][0];
        assert_eq!(item.field.as_deref(), Some("Image"));
        assert_eq!(item.modifiers, vec![Modifier::EndsWith]);
        assert_eq!(item.values, vec![RuleValue::Str(r"\QuickAssist.exe".into())]);
        assert_eq!(item.path, "detection.selection.Image|endswith");
        assert_eq!((item.line, item.col), (18, 9));
        assert_eq!((r.detection.condition_line, r.detection.condition_col), (19, 16));
        assert_eq!((r.line, r.col), (2, 1));
    }

    #[test]
    fn quoted_numbers_stay_strings() {
        let r = only_rule(&rule_with("    s:\n        EventID: '4688'\n        Other: 4688\n    condition: s\n"));
        let items = &r.detection.search_ids[0].alternatives[0];
        assert_eq!(items[0].values, vec![RuleValue::Str("4688".into())]);
        assert_eq!(items[1].values, vec![RuleValue::Int(4688)]);
    }

    #[test]
    fn list_of_maps_becomes_alternatives() {
        let r = only_rule(&rule_with(
            "    selection:\n        - A: 1\n        - B: 2\n          C: 3\n    condition: selection\n",
        ));
        let alts = &r.detection.search_ids[0].alternatives;
        assert_eq!(alts.len(), 2);
        assert_eq!(alts[1].len(), 2);
        assert_eq!(alts[1][0].path, "detection.selection[1].B");
        assert_eq!((alts[1][0].line, alts[1][0].col), (8, 11));
    }

    #[test]
    fn keyword_lists_have_no_field() {
        let r = only_rule(&rule_with(
            "    keywords:\n        - 'event::clear'\n        - 'event::drop'\n    kw_all:\n        '|all':\n            - a\n            - b\n    condition: keywords or kw_all\n",
        ));
        let kw = &r.detection.search_ids[0].alternatives[0][0];
        assert_eq!(kw.field, None);
        assert_eq!(kw.values.len(), 2);
        assert_eq!((kw.line, kw.col), (6, 5));
        let all = &r.detection.search_ids[1].alternatives[0][0];
        assert_eq!(all.field, None);
        assert_eq!(all.modifiers, vec![Modifier::All]);
    }

    #[test]
    fn block_scalar_condition() {
        let r = only_rule(&rule_with(
            "    a:\n        X: 1\n    b:\n        Y: 1\n    condition: |\n        a\n        or b\n",
        ));
        assert_eq!(r.detection.conditions.len(), 1);
    }

    #[test]
    fn condition_list_is_kept() {
        let r = only_rule(&rule_with("    a:\n        X: 1\n    condition:\n        - a\n        - not a\n"));
        assert_eq!(r.detection.conditions.len(), 2);
    }

    #[test]
    fn parses_filter_document() {
        let src = "title: Filter admins\nlogsource:\n    product: windows\nfilter:\n    rules:\n        - 6f3e2987-db24-4c78-a860-b4f4095a7095\n    selection:\n        User|startswith: 'adm_'\n    condition: selection\n";
        let parsed = parse_str(src);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let Some(Document::Filter(f)) = parsed.documents.first() else { panic!("expected a filter") };
        assert_eq!(f.rules, vec!["6f3e2987-db24-4c78-a860-b4f4095a7095"]);
        assert_eq!(f.detection.search_ids.len(), 1);
        assert_eq!(f.detection.search_ids[0].name, "selection");
        assert_eq!((f.line, f.col), (1, 1));
    }

    #[test]
    fn multi_document_with_correlation_stub() {
        let src = format!(
            "{}---\ntitle: many\nid: c1\ncorrelation:\n    type: event_count\n    rules: [r1]\n    timespan: 1h\n",
            rule_with("    sel:\n        A: 1\n    condition: sel\n")
        );
        let parsed = parse_str(&src);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        assert_eq!(parsed.documents.len(), 2);
        let Document::Correlation(c) = &parsed.documents[1] else { panic!("{:?}", parsed.documents[1]) };
        assert_eq!((c.line, c.col), (10, 1));
    }

    #[test]
    fn reports_errors_with_positions_and_yaml_paths() {
        let parsed = parse_str(&rule_with(
            "    sel:\n        A|bogus: 1\n        B:\n            - ''\n            - null\n    condition: sel\n",
        ));
        let msgs: Vec<String> = parsed.diagnostics.iter().map(|d| d.to_string()).collect();
        assert!(
            msgs.iter().any(|m| m.contains("<input>:7:9: detection.sel.A|bogus: unknown modifier")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m.contains("<input>:10:15: detection.sel.B: `null`")), "{msgs:?}");
        assert!(parsed.documents.is_empty());
    }

    #[test]
    fn semantic_error_reports_the_right_line() {
        let parsed = parse_str(&rule_with("    sel:\n        A: 1\n    condition: sel and\n"));
        assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
        assert_eq!(parsed.diagnostics[0].location, Location::at(8, 16, "detection.condition"));
        assert!(parsed.diagnostics[0].message.contains("invalid condition"));
    }

    #[test]
    fn rejects_missing_title_aggregations_and_actions() {
        let p = parse_str("logsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s | count() > 5\n");
        let all = p.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>().join("\n");
        assert!(all.contains("title"), "{all}");
        assert!(all.contains("correlation rule"), "{all}");
        let p = parse_str("title: x\naction: global\n");
        assert!(p.diagnostics[0].message.contains("action"));
        assert_eq!(p.diagnostics[0].location, Location::at(2, 1, "action"));
    }

    #[test]
    fn yaml_syntax_error_has_line_and_column() {
        let p = parse_str("title: x\ndetection: [unclosed\n");
        assert_eq!(p.diagnostics[0].location, Location::at(3, 1, ""), "{:?}", p.diagnostics);
        assert!(p.diagnostics[0].message.starts_with("invalid YAML"), "{:?}", p.diagnostics);
    }

    #[test]
    fn duplicate_key_is_an_error() {
        let p = parse_str("title: a\ntitle: b\nlogsource: {product: x}\ndetection: {s: {A: 1}, condition: s}\n");
        assert!(p.documents.is_empty());
        assert_eq!(p.diagnostics[0].location, Location::at(2, 1, ""), "{:?}", p.diagnostics);
        assert!(p.diagnostics[0].message.contains("duplicated key"), "{:?}", p.diagnostics);
    }

    #[test]
    fn parse_file_attaches_the_path() {
        let p = parse_file(std::path::Path::new("/nonexistent/rule.yml"));
        assert_eq!(p.diagnostics[0].file.as_deref(), Some(std::path::Path::new("/nonexistent/rule.yml")));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-sigma document`
Expected: compile errors for the missing `parse_str`, `Rule` and `Document`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Sigma YAML documents: rules, meta filters and (stubbed) correlation rules.

use crate::condition::{CondExpr, parse_condition};
use crate::diagnostic::{Diagnostic, Location};
use crate::modifier::{Modifier, parse_field_key};
use crate::value::RuleValue;
use saphyr::{AnnotatedMapping, LoadableYamlNode, MarkedYaml, Scalar, YamlData};
use std::path::Path;

type Node<'a> = MarkedYaml<'a>;
type Map<'a> = AnnotatedMapping<'a, MarkedYaml<'a>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// One `field|modifiers: values` entry. `field` is `None` for keyword search.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldItem {
    pub field: Option<String>,
    pub modifiers: Vec<Modifier>,
    pub values: Vec<RuleValue>,
    /// YAML path used in diagnostics, e.g. `detection.selection.Image|endswith`.
    pub path: String,
    /// 1-based position of the item's key (of the search identifier for keyword lists).
    pub line: usize,
    pub col: usize,
}

/// A named search identifier. Alternatives are OR'd; items in one alternative are AND'd.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchIdentifier {
    pub name: String,
    pub alternatives: Vec<Vec<FieldItem>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub search_ids: Vec<SearchIdentifier>,
    /// Several conditions are OR'd.
    pub conditions: Vec<CondExpr>,
    /// 1-based position of the `condition` value.
    pub condition_line: usize,
    pub condition_col: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleMeta {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub meta: RuleMeta,
    pub logsource: LogSource,
    pub detection: Detection,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub logsource: LogSource,
    /// Ids or names of the rules the filter applies to.
    pub rules: Vec<String>,
    pub detection: Detection,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

/// Placeholder until correlation rules are implemented (milestone M2).
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationStub {
    pub title: String,
    pub id: Option<String>,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    Rule(Rule),
    Filter(Filter),
    Correlation(CorrelationStub),
}

#[derive(Debug, Default)]
pub struct ParsedFile {
    pub documents: Vec<Document>,
    pub diagnostics: Vec<Diagnostic>,
}

type Diags = Vec<Diagnostic>;

/// 1-based line and column where `node` starts.
fn line_col(node: &Node) -> (usize, usize) {
    (node.span.start.line(), node.span.start.col() + 1)
}

fn err(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::error(Location::at(line, col, path), msg)
}

/// The key and value nodes of `key` in a mapping.
fn entry<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<(&'n Node<'a>, &'n Node<'a>)> {
    map.iter().find(|(k, _)| k.data.as_str() == Some(key))
}

fn get<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<&'n Node<'a>> {
    entry(map, key).map(|(_, v)| v)
}

/// Parses a (possibly multi-document) Sigma YAML string.
pub fn parse_str(src: &str) -> ParsedFile {
    let mut out = ParsedFile::default();
    let docs = match MarkedYaml::load_from_str(src) {
        Ok(docs) => docs,
        Err(e) => {
            let m = e.marker();
            out.diagnostics.push(Diagnostic::error(
                Location::at(m.line(), m.col() + 1, ""),
                format!("invalid YAML: {}", e.info()),
            ));
            return out;
        }
    };
    for doc in &docs {
        if doc.data.is_null() {
            continue;
        }
        match parse_document(doc) {
            Ok(d) => out.documents.push(d),
            Err(mut d) => out.diagnostics.append(&mut d),
        }
    }
    out
}

/// Reads and parses a rule file; every diagnostic carries `path`.
pub fn parse_file(path: &Path) -> ParsedFile {
    let mut parsed = match std::fs::read_to_string(path) {
        Ok(src) => parse_str(&src),
        Err(e) => ParsedFile {
            documents: Vec::new(),
            diagnostics: vec![Diagnostic::error(Location::Unknown, format!("cannot read file: {e}"))],
        },
    };
    for d in &mut parsed.diagnostics {
        d.file = Some(path.to_path_buf());
    }
    parsed
}

fn parse_document(doc: &Node) -> Result<Document, Diags> {
    let YamlData::Mapping(map) = &doc.data else {
        return Err(vec![err(doc, "", "document is not a YAML mapping")]);
    };
    if let Some((key, _)) = entry(map, "action") {
        return Err(vec![err(
            key,
            "action",
            "Sigma 1.x collection actions (`action: global|reset|repeat`) are not supported; \
             split the collection into standalone rules",
        )]);
    }
    let (line, col) = line_col(doc);
    let has = |key: &str| entry(map, key).is_some();
    if has("correlation") {
        return Ok(Document::Correlation(CorrelationStub {
            title: get_str(map, "title").unwrap_or_default(),
            id: get_str(map, "id"),
            line,
            col,
        }));
    }
    if has("filter") && !has("detection") {
        return parse_filter(doc, map).map(Document::Filter);
    }
    if has("detection") {
        return parse_rule(doc, map).map(Document::Rule);
    }
    Err(vec![err(
        doc,
        "",
        "document is not a Sigma rule, filter or correlation (no `detection`, `filter` or `correlation` key)",
    )])
}

fn get_str(map: &Map, key: &str) -> Option<String> {
    match &get(map, key)?.data {
        YamlData::Value(Scalar::String(s)) => Some(s.to_string()),
        YamlData::Value(Scalar::Integer(i)) => Some(i.to_string()),
        YamlData::Value(Scalar::FloatingPoint(f)) => Some(f.into_inner().to_string()),
        _ => None,
    }
}

fn get_str_list(map: &Map, key: &str) -> Vec<String> {
    match get(map, key).map(|n| &n.data) {
        Some(YamlData::Sequence(seq)) => seq.iter().filter_map(|v| v.data.as_str().map(str::to_string)).collect(),
        Some(YamlData::Value(Scalar::String(s))) => vec![s.to_string()],
        _ => Vec::new(),
    }
}

fn parse_logsource(doc: &Node, map: &Map) -> Result<LogSource, Diags> {
    match entry(map, "logsource") {
        Some((_, Node { data: YamlData::Mapping(ls), .. })) => Ok(LogSource {
            category: get_str(ls, "category"),
            product: get_str(ls, "product"),
            service: get_str(ls, "service"),
        }),
        other => Err(vec![err(other.map_or(doc, |(_, v)| v), "logsource", "missing mandatory `logsource` mapping")]),
    }
}

fn parse_rule(doc: &Node, map: &Map) -> Result<Rule, Diags> {
    let mut diags = Vec::new();
    let title = get_str(map, "title");
    if title.is_none() {
        diags.push(err(doc, "title", "missing mandatory `title`"));
    }
    let logsource = parse_logsource(doc, map).map_err(|mut d| diags.append(&mut d)).ok();
    let detection = match entry(map, "detection") {
        Some((key, Node { data: YamlData::Mapping(dm), .. })) => {
            parse_detection("detection", key, dm, &[]).map_err(|mut d| diags.append(&mut d)).ok()
        }
        other => {
            diags.push(err(other.map_or(doc, |(_, v)| v), "detection", "`detection` must be a mapping"));
            None
        }
    };
    let (line, col) = line_col(doc);
    match (title, logsource, detection) {
        (Some(title), Some(logsource), Some(detection)) if diags.is_empty() => Ok(Rule {
            meta: RuleMeta {
                title,
                id: get_str(map, "id"),
                name: get_str(map, "name"),
                status: get_str(map, "status"),
                level: get_str(map, "level"),
                description: get_str(map, "description"),
                author: get_str(map, "author"),
                references: get_str_list(map, "references"),
                tags: get_str_list(map, "tags"),
                falsepositives: get_str_list(map, "falsepositives"),
                date: get_str(map, "date"),
                modified: get_str(map, "modified"),
            },
            logsource,
            detection,
            line,
            col,
        }),
        _ => Err(diags),
    }
}

fn parse_filter(doc: &Node, map: &Map) -> Result<Filter, Diags> {
    let mut diags = Vec::new();
    let title = get_str(map, "title");
    if title.is_none() {
        diags.push(err(doc, "title", "missing mandatory `title`"));
    }
    let logsource = parse_logsource(doc, map).map_err(|mut d| diags.append(&mut d)).ok();
    let mut rules = Vec::new();
    let detection = match entry(map, "filter") {
        Some((key, Node { data: YamlData::Mapping(fm), .. })) => {
            rules = get_str_list(fm, "rules");
            if rules.is_empty() {
                let at = entry(fm, "rules").map_or(key, |(k, _)| k);
                diags.push(err(at, "filter.rules", "`filter.rules` must list at least one rule id or name"));
            }
            parse_detection("filter", key, fm, &["rules"]).map_err(|mut d| diags.append(&mut d)).ok()
        }
        other => {
            diags.push(err(other.map_or(doc, |(_, v)| v), "filter", "`filter` must be a mapping"));
            None
        }
    };
    let (line, col) = line_col(doc);
    match (title, logsource, detection) {
        (Some(title), Some(logsource), Some(detection)) if diags.is_empty() => Ok(Filter {
            title,
            id: get_str(map, "id"),
            name: get_str(map, "name"),
            logsource,
            rules,
            detection,
            line,
            col,
        }),
        _ => Err(diags),
    }
}

/// `key` is the `detection:` / `filter:` key node, `dm` its mapping.
fn parse_detection(base: &str, key: &Node, dm: &Map, reserved: &[&str]) -> Result<Detection, Diags> {
    let mut diags = Vec::new();
    let mut search_ids = Vec::new();
    let mut conditions = Vec::new();
    let mut condition_at = None;
    for (k, v) in dm {
        let Some(name) = k.data.as_str() else {
            diags.push(err(k, base, "search identifier names must be strings"));
            continue;
        };
        let path = format!("{base}.{name}");
        match name {
            "condition" => {
                condition_at = Some(line_col(v));
                let sources: Vec<(&str, &Node)> = match &v.data {
                    YamlData::Value(Scalar::String(s)) => vec![(s.as_ref(), v)],
                    YamlData::Sequence(seq) => seq.iter().filter_map(|x| x.data.as_str().map(|s| (s, x))).collect(),
                    _ => {
                        diags.push(err(v, &path, "`condition` must be a string or a list of strings"));
                        continue;
                    }
                };
                for (s, node) in sources {
                    match parse_condition(s) {
                        Ok(c) => conditions.push(c),
                        Err(e) => diags.push(err(node, &path, format!("invalid condition: {e}"))),
                    }
                }
            }
            "timeframe" => diags.push(err(
                k,
                &path,
                "`timeframe` inside `detection` was removed in Sigma 2.0; use a correlation rule",
            )),
            n if reserved.contains(&n) => {}
            _ => match parse_search_id(&path, name, k, v) {
                Ok(s) => search_ids.push(s),
                Err(mut d) => diags.append(&mut d),
            },
        }
    }
    if conditions.is_empty() && diags.is_empty() {
        diags.push(err(key, base, "missing `condition`"));
    }
    if !diags.is_empty() {
        return Err(diags);
    }
    let (condition_line, condition_col) = condition_at.unwrap_or_else(|| line_col(key));
    Ok(Detection { search_ids, conditions, condition_line, condition_col })
}

fn parse_search_id(path: &str, name: &str, key: &Node, v: &Node) -> Result<SearchIdentifier, Diags> {
    let (line, col) = line_col(key);
    let keyword_item =
        |values| FieldItem { field: None, modifiers: Vec::new(), values, path: path.to_string(), line, col };
    let alternatives = match &v.data {
        YamlData::Mapping(m) => vec![parse_map(path, v, m)?],
        YamlData::Sequence(seq) if !seq.is_empty() && seq.iter().all(|x| x.data.is_mapping()) => {
            let mut alts = Vec::new();
            for (i, item) in seq.iter().enumerate() {
                if let YamlData::Mapping(m) = &item.data {
                    alts.push(parse_map(&format!("{path}[{i}]"), item, m)?);
                }
            }
            alts
        }
        YamlData::Sequence(seq) if !seq.is_empty() => vec![vec![keyword_item(parse_values(path, v)?)]],
        YamlData::Value(Scalar::String(_) | Scalar::Integer(_) | Scalar::FloatingPoint(_)) => {
            vec![vec![keyword_item(parse_values(path, v)?)]]
        }
        _ => {
            return Err(vec![err(
                v,
                path,
                "a search identifier must be a mapping, a list of mappings or a list of keywords",
            )]);
        }
    };
    Ok(SearchIdentifier { name: name.to_string(), alternatives })
}

/// `node` is the mapping node itself, `m` its entries.
fn parse_map(path: &str, node: &Node, m: &Map) -> Result<Vec<FieldItem>, Diags> {
    let mut items = Vec::new();
    let mut diags = Vec::new();
    if m.is_empty() {
        diags.push(err(node, path, "empty selection"));
    }
    for (k, v) in m {
        let Some(key) = k.data.as_str() else {
            diags.push(err(k, path, "field names must be strings"));
            continue;
        };
        let item_path = format!("{path}.{key}");
        let fk = match parse_field_key(key) {
            Ok(fk) => fk,
            Err(msg) => {
                diags.push(err(k, &item_path, msg));
                continue;
            }
        };
        let (line, col) = line_col(k);
        match parse_values(&item_path, v) {
            Ok(values) => {
                items.push(FieldItem { field: fk.field, modifiers: fk.modifiers, values, path: item_path, line, col })
            }
            Err(mut d) => diags.append(&mut d),
        }
    }
    if diags.is_empty() { Ok(items) } else { Err(diags) }
}

fn parse_values(path: &str, v: &Node) -> Result<Vec<RuleValue>, Diags> {
    let scalars: Vec<&Node> = match &v.data {
        YamlData::Sequence(seq) => seq.iter().collect(),
        _ => vec![v],
    };
    if scalars.is_empty() {
        return Err(vec![err(v, path, "empty value list")]);
    }
    let mut out = Vec::new();
    for s in &scalars {
        match RuleValue::from_yaml(s) {
            Some(rv) => out.push(rv),
            None => {
                return Err(vec![err(s, path, "values must be scalars (string, number, boolean or null)")]);
            }
        }
    }
    if out.len() > 1
        && let Some(null) = scalars.iter().find(|s| s.data.is_null())
    {
        return Err(vec![err(null, path, "`null` cannot be part of a list of values; use a separate selection")]);
    }
    Ok(out)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-sigma`
Expected: all zaaf-sigma tests pass (14 document tests plus earlier ones, 33 in total).

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(sigma): parse rules, meta filters and correlation stubs with positioned diagnostics

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: zaaf-pipeline: field mapping and placeholder variables

**Files:**
- Create: `crates/zaaf-pipeline/Cargo.toml`, `crates/zaaf-pipeline/src/lib.rs`

**Interfaces:**
- Consumes: `zaaf_sigma::{LogSource, Diagnostic, Location}`.
- Produces:
  - `Pipeline { name, priority: i32, vars: IndexMap<String, Vec<String>>, transformations: Vec<Transformation> }`
  - `Transformation::FieldNameMapping { mapping: IndexMap<String, OneOrMany>, rule_conditions: Vec<LogSourceCondition> }`
  - `parse_pipeline(&str) -> Result<Pipeline, String>`
  - `PipelineSet`:
    - `PipelineSet::new(Vec<Pipeline>)`: sorted by priority ascending, stable.
    - `PipelineSet::default()`: empty.
    - `PipelineSet::load(&[PathBuf]) -> Result<PipelineSet, Diagnostic>`: an invalid pipeline's diagnostic carries `Location::At` (line and column from `serde-saphyr`) when the position is known.
    - `is_empty()`
    - `map_field(&LogSource, &str) -> MappedField { names: Vec<String>, mapped: bool }`
    - `placeholder(&str) -> Option<&[String]>`: the later pipeline wins.

Pipeline YAML format (documented in the crate docs):
```yaml
name: ecs-windows
priority: 10            # lower runs first; default 0
vars:                   # values for `|expand` placeholders, e.g. %Admins%
  Admins: ['adm_*', root]
transformations:
  - type: field_name_mapping
    mapping:
      Image: process.executable
      CommandLine: [process.command_line, process.args]   # one-to-many = OR
    rule_conditions:    # optional; any matching condition enables the mapping
      - product: windows
```

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-pipeline/Cargo.toml`:
```toml
[package]
name = "zaaf-pipeline"
description = "Field mapping and placeholder pipelines for ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
indexmap.workspace = true
serde.workspace = true
serde-saphyr.workspace = true
zaaf-sigma.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/zaaf-pipeline/src/lib.rs` (tests module only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ls(product: &str) -> LogSource {
        LogSource { product: Some(product.into()), ..Default::default() }
    }

    const ECS: &str = "name: ecs\npriority: 10\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: process.executable\n      CommandLine: [process.command_line, process.args]\n    rule_conditions:\n      - product: windows\n";

    #[test]
    fn maps_one_to_one_and_one_to_many() {
        let set = PipelineSet::new(vec![parse_pipeline(ECS).unwrap()]);
        assert_eq!(
            set.map_field(&ls("windows"), "Image"),
            MappedField { names: vec!["process.executable".into()], mapped: true }
        );
        assert_eq!(
            set.map_field(&ls("Windows"), "CommandLine").names,
            vec!["process.command_line", "process.args"]
        );
    }

    #[test]
    fn unmatched_condition_or_field_passes_through() {
        let set = PipelineSet::new(vec![parse_pipeline(ECS).unwrap()]);
        assert_eq!(
            set.map_field(&ls("linux"), "Image"),
            MappedField { names: vec!["Image".into()], mapped: false }
        );
        assert!(!set.map_field(&ls("windows"), "User").mapped);
    }

    #[test]
    fn pipelines_chain_in_priority_order() {
        let late = parse_pipeline(
            "name: late\npriority: 20\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      process.executable: proc.exe\n",
        )
        .unwrap();
        let set = PipelineSet::new(vec![late, parse_pipeline(ECS).unwrap()]);
        assert_eq!(set.map_field(&ls("windows"), "Image").names, vec!["proc.exe"]);
    }

    #[test]
    fn later_pipeline_vars_override_earlier() {
        let a = parse_pipeline("name: a\npriority: 1\nvars:\n  Admins: [root]\n").unwrap();
        let b = parse_pipeline("name: b\npriority: 2\nvars:\n  Admins: ['adm_*']\n").unwrap();
        let set = PipelineSet::new(vec![b, a]);
        assert_eq!(set.placeholder("Admins"), Some(&["adm_*".to_string()][..]));
        assert_eq!(set.placeholder("Missing"), None);
    }

    #[test]
    fn rejects_unknown_transformation_and_fields() {
        let err = parse_pipeline("name: x\ntransformations:\n  - type: drop_everything\n").unwrap_err();
        assert!(err.contains("drop_everything"), "{err}");
        assert!(parse_pipeline("name: x\nbogus: 1\n").is_err());
    }

    #[test]
    fn load_reports_missing_file_with_path() {
        let err = PipelineSet::load(&[PathBuf::from("/nonexistent/p.yml")]).unwrap_err();
        assert!(err.is_error());
        assert_eq!(err.file.as_deref(), Some(std::path::Path::new("/nonexistent/p.yml")));
    }

    #[test]
    fn load_reports_the_position_of_an_invalid_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.yml");
        std::fs::write(&p, "name: x\ntransformations:\n  - type: drop_everything\n").unwrap();
        let err = PipelineSet::load(&[p]).unwrap_err();
        assert!(matches!(err.location, Location::At { line: 3, .. }), "{err:?}");
        assert!(err.message.contains("drop_everything"), "{err}");
    }

    #[test]
    fn empty_set_maps_nothing() {
        let set = PipelineSet::default();
        assert!(set.is_empty());
        assert_eq!(set.map_field(&ls("windows"), "Image").names, vec!["Image"]);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-pipeline`
Expected: compile errors for the missing `PipelineSet` and `parse_pipeline`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Processing pipelines: field-name mapping and placeholder variables.
//!
//! See the module-level YAML example in the M1 plan / README.

use indexmap::IndexMap;
use serde::Deserialize;
use std::path::PathBuf;
use zaaf_sigma::{Diagnostic, Location, LogSource};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pipeline {
    pub name: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub vars: IndexMap<String, Vec<String>>,
    #[serde(default)]
    pub transformations: Vec<Transformation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transformation {
    FieldNameMapping {
        mapping: IndexMap<String, OneOrMany>,
        #[serde(default)]
        rule_conditions: Vec<LogSourceCondition>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn targets(&self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSourceCondition {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

impl LogSourceCondition {
    pub fn matches(&self, ls: &LogSource) -> bool {
        fn eq(want: &Option<String>, have: &Option<String>) -> bool {
            match want {
                None => true,
                Some(w) => have.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(w)),
            }
        }
        eq(&self.category, &ls.category) && eq(&self.product, &ls.product) && eq(&self.service, &ls.service)
    }
}

/// Field names a rule field maps to, and whether any pipeline mapped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedField {
    pub names: Vec<String>,
    pub mapped: bool,
}

pub fn parse_pipeline(src: &str) -> Result<Pipeline, String> {
    parse_located(src).map_err(|(_, msg)| msg)
}

/// Parses a pipeline; an error carries its 1-based position when the YAML library knows it.
fn parse_located(src: &str) -> Result<Pipeline, (Location, String)> {
    serde_saphyr::from_str(src).map_err(|e| {
        let location = e
            .location()
            .map_or(Location::Unknown, |l| Location::at(l.line() as usize, l.column() as usize, ""));
        (location, e.without_snippet().to_string())
    })
}

/// Pipelines applied in ascending priority order.
#[derive(Debug, Clone, Default)]
pub struct PipelineSet {
    pipelines: Vec<Pipeline>,
}

impl PipelineSet {
    pub fn new(mut pipelines: Vec<Pipeline>) -> Self {
        pipelines.sort_by_key(|p| p.priority);
        Self { pipelines }
    }

    pub fn load(paths: &[PathBuf]) -> Result<Self, Diagnostic> {
        let mut pipelines = Vec::new();
        for p in paths {
            let src = std::fs::read_to_string(p).map_err(|e| {
                Diagnostic::error(Location::Unknown, format!("cannot read pipeline: {e}")).with_file(p)
            })?;
            let pipeline = parse_located(&src).map_err(|(location, e)| {
                Diagnostic::error(location, format!("invalid pipeline: {e}")).with_file(p)
            })?;
            pipelines.push(pipeline);
        }
        Ok(Self::new(pipelines))
    }

    pub fn is_empty(&self) -> bool {
        self.pipelines.is_empty()
    }

    pub fn map_field(&self, ls: &LogSource, field: &str) -> MappedField {
        let mut names = vec![field.to_string()];
        let mut mapped = false;
        for p in &self.pipelines {
            for t in &p.transformations {
                let Transformation::FieldNameMapping { mapping, rule_conditions } = t;
                if !rule_conditions.is_empty() && !rule_conditions.iter().any(|c| c.matches(ls)) {
                    continue;
                }
                let mut next: Vec<String> = Vec::new();
                for n in &names {
                    match mapping.get(n) {
                        Some(targets) => {
                            mapped = true;
                            for t in targets.targets() {
                                if !next.contains(&t) {
                                    next.push(t);
                                }
                            }
                        }
                        None => {
                            if !next.contains(n) {
                                next.push(n.clone());
                            }
                        }
                    }
                }
                names = next;
            }
        }
        MappedField { names, mapped }
    }

    pub fn placeholder(&self, name: &str) -> Option<&[String]> {
        self.pipelines.iter().rev().find_map(|p| p.vars.get(name).map(Vec::as_slice))
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-pipeline`
Expected: 8 tests pass.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(pipeline): field-name mapping with logsource conditions and placeholder vars

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: zaaf-ir: IR types, regex engine, value transformations

**Files:**
- Create: `crates/zaaf-ir/Cargo.toml`, `crates/zaaf-ir/src/lib.rs`, `crates/zaaf-ir/src/ir.rs`, `crates/zaaf-ir/src/regex_engine.rs`, `crates/zaaf-ir/src/transform.rs`

**Interfaces:**
- Consumes: `zaaf_sigma::{SigmaString, Tok, Modifier}`.
- Produces:
  - `Expr::{And(Vec<Expr>), Or(Vec<Expr>), Not(Box<Expr>), Pred(Predicate)}`
  - `Predicate { target: Target, matcher: Matcher }`
  - `Target::{Fields(Vec<String>) /* OR across names */, AnyField /* keyword search */}`
  - `Matcher`:
    - `Str { pattern: SigmaString, case_sensitive: bool }`
    - `Regex(CompiledRegex)`
    - `Num { op: CmpOp, value: f64 }`
    - `Cidr(ipnet::IpNet)`
    - `Exists(bool)`
    - `Null`
    - `FieldRef { other: Vec<String>, mode: RefMode, case_sensitive: bool }`
    - `TimePart { part: TimePart, op: CmpOp, value: i64 }`
  - `CmpOp::{Eq, Lt, Lte, Gt, Gte}`
  - `TimePart::{Minute, Hour, Day, Week, Month, Year}`
  - `RefMode::{Equals, Contains, StartsWith, EndsWith}`
  - `RegexFlags { insensitive, multiline, dot_all }`
  - `CompiledRegex`:
    - `CompiledRegex::new(&str, RegexFlags) -> Result<_, String>`
    - `.is_match(&str)`
    - `.needs_backtracking()`
    - `.source()`
    - `.flags()`
  - `BACKTRACK_LIMIT`
  - crate-private, in `transform`:
    - `Val::{S(SigmaString), B(Vec<u8>)}`
    - `Val::into_sigma()`
    - `apply(Modifier, Vec<Val>) -> Result<Vec<Val>, String>`
    - `base64_offsets(&[u8]) -> Vec<String>`
    - `utf16(&str, big_endian, bom) -> Vec<u8>`
    - `windash(&SigmaString) -> Vec<SigmaString>`
    - `expand_raw(&str, &dyn Fn(&str) -> Option<Vec<String>>) -> Result<Vec<String>, String>`

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-ir/Cargo.toml`:
```toml
[package]
name = "zaaf-ir"
description = "Compiles Sigma rules into the ZAAFElegia intermediate representation"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
base64.workspace = true
fancy-regex.workspace = true
ipnet.workspace = true
regex.workspace = true
zaaf-pipeline.workspace = true
zaaf-sigma.workspace = true
```

`crates/zaaf-ir/src/lib.rs`:
```rust
//! Compiles parsed Sigma documents into the ZAAFElegia intermediate representation.

pub mod ir;
pub mod regex_engine;
mod transform;

pub use ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
pub use regex_engine::{BACKTRACK_LIMIT, CompiledRegex, RegexFlags};
```

`crates/zaaf-ir/src/regex_engine.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_engine_with_case_flag() {
        let re = CompiledRegex::new("^admin$", RegexFlags { insensitive: true, ..Default::default() }).unwrap();
        assert!(re.is_match("ADMIN"));
        assert!(!re.needs_backtracking());
    }

    #[test]
    fn lookaround_falls_back_to_backtracking() {
        let re = CompiledRegex::new(r"^(?!svchost).*\.exe$", RegexFlags::default()).unwrap();
        assert!(re.needs_backtracking());
        assert!(re.is_match("evil.exe"));
        assert!(!re.is_match("svchost.exe"));
    }

    #[test]
    fn multiline_and_dot_all() {
        let m = CompiledRegex::new("^evil$", RegexFlags { multiline: true, ..Default::default() }).unwrap();
        assert!(m.is_match("a\nevil\nb"));
        let plain = CompiledRegex::new("^evil$", RegexFlags::default()).unwrap();
        assert!(!plain.is_match("a\nevil\nb"));
        let s = CompiledRegex::new("a.b", RegexFlags { dot_all: true, ..Default::default() }).unwrap();
        assert!(s.is_match("a\nb"));
        assert!(!CompiledRegex::new("a.b", RegexFlags::default()).unwrap().is_match("a\nb"));
    }

    #[test]
    fn invalid_regex_is_an_error() {
        let err = CompiledRegex::new("(unclosed", RegexFlags::default()).unwrap_err();
        assert!(err.contains("(unclosed"), "{err}");
    }
}
```

`crates/zaaf-ir/src/transform.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64offset_matches_pysigma_vectors() {
        assert_eq!(base64_offsets(b"ping"), vec!["cGluZ", "Bpbm", "waW5n"]);
        assert_eq!(base64_offsets(&utf16("cmd", false, false)), vec!["YwBtAGQA", "MAbQBkA", "jAG0AZA"]);
    }

    #[test]
    fn base64offset_drops_empty_variants() {
        assert!(base64_offsets(b"a").iter().all(|s| !s.is_empty()));
    }

    #[test]
    fn utf16_variants() {
        assert_eq!(utf16("ab", false, false), vec![0x61, 0, 0x62, 0]);
        assert_eq!(utf16("ab", true, false), vec![0, 0x61, 0, 0x62]);
        assert_eq!(utf16("ab", false, true), vec![0xFF, 0xFE, 0x61, 0, 0x62, 0]);
    }

    #[test]
    fn windash_permutes_flag_dashes_only() {
        let v = windash(&SigmaString::parse(" -s "));
        assert_eq!(v.len(), 5);
        assert!(v.contains(&SigmaString::literal(" /s ")));
        assert!(v.contains(&SigmaString::literal(" \u{2015}s ")));
        assert_eq!(windash(&SigmaString::parse("foo-bar")), vec![SigmaString::literal("foo-bar")]);
    }

    #[test]
    fn windash_keeps_wildcards() {
        let v = windash(&SigmaString::parse("* -a -b*"));
        assert_eq!(v.len(), 25);
        assert!(v.iter().all(|s| s.has_wildcards()));
    }

    #[test]
    fn expand_raw_placeholders() {
        let lookup = |n: &str| (n == "Admins").then(|| vec!["adm_*".to_string(), "root".to_string()]);
        assert_eq!(expand_raw("%Admins%", &lookup).unwrap(), vec!["adm_*", "root"]);
        assert_eq!(expand_raw("x-%Admins%-y", &lookup).unwrap(), vec!["x-adm_*-y", "x-root-y"]);
        assert_eq!(expand_raw(r"\%Admins%", &lookup).unwrap(), vec!["%Admins%"]);
        assert_eq!(expand_raw("100%", &lookup).unwrap(), vec!["100%"]);
        let err = expand_raw("%Nope%", &lookup).unwrap_err();
        assert!(err.contains("Nope"), "{err}");
    }

    #[test]
    fn apply_contains_then_base64_errors_on_wildcards() {
        let vals = apply(Modifier::Contains, vec![Val::S(SigmaString::literal("x"))]).unwrap();
        let err = apply(Modifier::Base64, vals).unwrap_err();
        assert!(err.contains("base64"), "{err}");
    }

    #[test]
    fn apply_wide_then_base64() {
        let vals = apply(Modifier::Wide, vec![Val::S(SigmaString::literal("ab"))]).unwrap();
        let vals = apply(Modifier::Base64, vals).unwrap();
        assert_eq!(vals.into_iter().next().unwrap().into_sigma(), SigmaString::literal("YQBiAA=="));
    }
}
```

`crates/zaaf-ir/src/ir.rs` has no tests of its own; Task 7 exercises it.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-ir`
Expected: compile errors for the missing `CompiledRegex` and `base64_offsets`, and because `ir.rs` does not exist yet.

- [ ] **Step 3: Implement**

`crates/zaaf-ir/src/ir.rs`:
```rust
//! The intermediate representation shared by every evaluator.

use crate::regex_engine::CompiledRegex;
use zaaf_sigma::SigmaString;

/// A boolean expression over predicates. `And([])` is true, `Or([])` is false.
#[derive(Debug, Clone)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Pred(Predicate),
}

#[derive(Debug, Clone)]
pub struct Predicate {
    pub target: Target,
    pub matcher: Matcher,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Event field paths after pipeline mapping; a match on any of them counts.
    Fields(Vec<String>),
    /// Keyword search across every value of the event.
    AnyField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimePart {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefMode {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
pub enum Matcher {
    /// Glob match. When `case_sensitive` is false the pattern is already lower-case
    /// and evaluators must lower-case the event value.
    Str { pattern: SigmaString, case_sensitive: bool },
    Regex(CompiledRegex),
    Num { op: CmpOp, value: f64 },
    Cidr(ipnet::IpNet),
    /// Field present (any value, even null or empty) == the flag.
    Exists(bool),
    /// Field absent or JSON null.
    Null,
    /// Compares the field with other field(s) of the same event.
    FieldRef { other: Vec<String>, mode: RefMode, case_sensitive: bool },
    /// Extracts a part of a timestamp value and compares it.
    TimePart { part: TimePart, op: CmpOp, value: i64 },
}
```

`crates/zaaf-ir/src/regex_engine.rs` (insert above the tests):
```rust
//! Regular expressions: linear-time `regex` first, `fancy-regex` with a
//! backtracking limit only for patterns that need lookaround or backreferences.

use std::fmt;

/// Maximum backtracking steps for patterns that need the backtracking engine.
pub const BACKTRACK_LIMIT: usize = 1_000_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegexFlags {
    pub insensitive: bool,
    pub multiline: bool,
    pub dot_all: bool,
}

#[derive(Clone)]
enum Engine {
    Linear(regex::Regex),
    Backtracking(fancy_regex::Regex),
}

#[derive(Clone)]
pub struct CompiledRegex {
    source: String,
    flags: RegexFlags,
    engine: Engine,
}

impl CompiledRegex {
    pub fn new(source: &str, flags: RegexFlags) -> Result<Self, String> {
        let linear = regex::RegexBuilder::new(source)
            .case_insensitive(flags.insensitive)
            .multi_line(flags.multiline)
            .dot_matches_new_line(flags.dot_all)
            .build();
        match linear {
            Ok(re) => Ok(Self { source: source.to_string(), flags, engine: Engine::Linear(re) }),
            Err(linear_err) => {
                let mut inline = String::new();
                if flags.insensitive {
                    inline.push('i');
                }
                if flags.multiline {
                    inline.push('m');
                }
                if flags.dot_all {
                    inline.push('s');
                }
                let pattern =
                    if inline.is_empty() { source.to_string() } else { format!("(?{inline}){source}") };
                fancy_regex::RegexBuilder::new(&pattern)
                    .backtrack_limit(BACKTRACK_LIMIT)
                    .build()
                    .map(|re| Self { source: source.to_string(), flags, engine: Engine::Backtracking(re) })
                    .map_err(|_| format!("invalid regular expression `{source}`: {linear_err}"))
            }
        }
    }

    /// Unanchored search. A pattern that exceeds the backtracking limit does not match.
    pub fn is_match(&self, text: &str) -> bool {
        match &self.engine {
            Engine::Linear(re) => re.is_match(text),
            Engine::Backtracking(re) => re.is_match(text).unwrap_or(false),
        }
    }

    pub fn needs_backtracking(&self) -> bool {
        matches!(self.engine, Engine::Backtracking(_))
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn flags(&self) -> RegexFlags {
        self.flags
    }
}

impl fmt::Debug for CompiledRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}/{:?}", self.source, self.flags)
    }
}
```

`crates/zaaf-ir/src/transform.rs` (insert above the tests). The first line keeps clippy quiet until Task 7 uses these functions; Task 7 deletes it:
```rust
#![allow(dead_code)] // used by the compiler added in Task 7

//! Value transformation modifiers (Sigma modifiers appendix).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use regex::Regex;
use std::sync::OnceLock;
use zaaf_sigma::{Modifier, SigmaString, Tok};

/// A value during transformation: a Sigma string, or raw bytes after `utf16*`.
#[derive(Debug, Clone)]
pub(crate) enum Val {
    S(SigmaString),
    B(Vec<u8>),
}

impl Val {
    /// Bytes are mapped one-to-one to chars (latin-1), so `wide` without
    /// `base64` yields `c\0m\0d\0` like pySigma.
    pub(crate) fn into_sigma(self) -> SigmaString {
        match self {
            Val::S(s) => s,
            Val::B(b) => SigmaString::literal(&b.iter().map(|&c| c as char).collect::<String>()),
        }
    }

    fn bytes(&self, m: Modifier) -> Result<Vec<u8>, String> {
        match self {
            Val::B(b) => Ok(b.clone()),
            Val::S(s) => s
                .as_plain()
                .map(String::into_bytes)
                .ok_or_else(|| format!("`{}` cannot be applied to a value with wildcards", m.name())),
        }
    }

    fn text(&self, m: Modifier) -> Result<String, String> {
        match self {
            Val::S(s) => s
                .as_plain()
                .ok_or_else(|| format!("`{}` cannot be applied to a value with wildcards", m.name())),
            Val::B(_) => Err(format!("`{}` needs a text value", m.name())),
        }
    }
}

/// Applies one string transformation modifier to every value.
pub(crate) fn apply(m: Modifier, vals: Vec<Val>) -> Result<Vec<Val>, String> {
    let mut out = Vec::new();
    for v in vals {
        match m {
            Modifier::Contains => {
                let mut s = v.into_sigma();
                s.prepend_any_many();
                s.append_any_many();
                out.push(Val::S(s));
            }
            Modifier::StartsWith => {
                let mut s = v.into_sigma();
                s.append_any_many();
                out.push(Val::S(s));
            }
            Modifier::EndsWith => {
                let mut s = v.into_sigma();
                s.prepend_any_many();
                out.push(Val::S(s));
            }
            Modifier::Base64 => out.push(Val::S(SigmaString::literal(&STANDARD.encode(v.bytes(m)?)))),
            Modifier::Base64Offset => {
                for s in base64_offsets(&v.bytes(m)?) {
                    out.push(Val::S(SigmaString::literal(&s)));
                }
            }
            Modifier::Utf16Le | Modifier::Wide => out.push(Val::B(utf16(&v.text(m)?, false, false))),
            Modifier::Utf16Be => out.push(Val::B(utf16(&v.text(m)?, true, false))),
            Modifier::Utf16 => out.push(Val::B(utf16(&v.text(m)?, false, true))),
            Modifier::Windash => out.extend(windash(&v.into_sigma()).into_iter().map(Val::S)),
            other => return Err(format!("`{}` is not a string transformation", other.name())),
        }
    }
    Ok(out)
}

/// The three base64 representations of `value` at byte offsets 0, 1 and 2,
/// trimmed to the characters that do not depend on surrounding bytes.
pub(crate) fn base64_offsets(value: &[u8]) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END_STRIP: [usize; 3] = [0, 3, 2];
    (0..3)
        .filter_map(|i| {
            let mut input = vec![b' '; i];
            input.extend_from_slice(value);
            let enc = STANDARD.encode(&input);
            let end = enc.len().saturating_sub(END_STRIP[(value.len() + i) % 3]);
            (START[i] < end).then(|| enc[START[i]..end].to_string())
        })
        .collect()
}

pub(crate) fn utf16(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if bom {
        out.extend_from_slice(if big_endian { &[0xFE, 0xFF] } else { &[0xFF, 0xFE] });
    }
    for unit in text.encode_utf16() {
        let b = if big_endian { unit.to_be_bytes() } else { unit.to_le_bytes() };
        out.extend_from_slice(&b);
    }
    out
}

const DASHES: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

fn windash_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\B[-/]\b").expect("static regex"))
}

/// All permutations of command-line flag dashes (`-x`, `/x`, `–x`, `—x`, `―x`).
pub(crate) fn windash(s: &SigmaString) -> Vec<SigmaString> {
    let mut results = vec![SigmaString::default()];
    for tok in s.toks() {
        match tok {
            Tok::Lit(text) => {
                let mut variants = vec![String::new()];
                let mut last = 0;
                for m in windash_regex().find_iter(text) {
                    let seg = &text[last..m.start()];
                    variants = variants
                        .into_iter()
                        .flat_map(|v| DASHES.iter().map(move |d| format!("{v}{seg}{d}")))
                        .collect();
                    last = m.end();
                }
                let tail = &text[last..];
                for v in &mut variants {
                    v.push_str(tail);
                }
                results = results
                    .into_iter()
                    .flat_map(|r| {
                        variants.iter().map(move |v| {
                            let mut r2 = r.clone();
                            r2.push_lit(v);
                            r2
                        })
                    })
                    .collect();
            }
            other => {
                for r in &mut results {
                    r.push(other.clone());
                }
            }
        }
    }
    results
}

enum Piece {
    Text(String),
    Var(String),
}

/// `%name%` is a placeholder, `\%` a literal percent; a lone `%` stays literal.
fn split_placeholders(text: &str) -> Vec<Piece> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && chars.get(i + 1) == Some(&'%') {
            buf.push('%');
            i += 2;
            continue;
        }
        if chars[i] == '%'
            && let Some(rel) = chars[i + 1..].iter().position(|&c| c == '%')
        {
            let name: String = chars[i + 1..i + 1 + rel].iter().collect();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                if !buf.is_empty() {
                    out.push(Piece::Text(std::mem::take(&mut buf)));
                }
                out.push(Piece::Var(name));
                i += rel + 2;
                continue;
            }
        }
        buf.push(chars[i]);
        i += 1;
    }
    if !buf.is_empty() {
        out.push(Piece::Text(buf));
    }
    out
}

/// Expands placeholders in a raw rule value into every combination of values.
pub(crate) fn expand_raw(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<Vec<String>>,
) -> Result<Vec<String>, String> {
    let mut results = vec![String::new()];
    for piece in split_placeholders(text) {
        match piece {
            Piece::Text(t) => {
                for r in &mut results {
                    r.push_str(&t);
                }
            }
            Piece::Var(name) => {
                let vals = lookup(&name).filter(|v| !v.is_empty()).ok_or_else(|| {
                    format!("placeholder `%{name}%` has no value; define it under `vars:` in a pipeline")
                })?;
                results = results
                    .into_iter()
                    .flat_map(|r| vals.iter().map(move |v| format!("{r}{v}")))
                    .collect();
            }
        }
    }
    Ok(results)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-ir`
Expected: 12 tests pass (4 regex_engine, 8 transform).

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(ir): IR types, two-tier regex engine and Sigma value transformations

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: zaaf-ir: compile items, conditions, filters and rule metadata

**Files:**
- Create: `crates/zaaf-ir/src/item.rs`, `crates/zaaf-ir/src/rule.rs`
- Modify: `crates/zaaf-ir/src/lib.rs`, `crates/zaaf-ir/src/transform.rs` (delete the `#![allow(dead_code)]` line)

**Interfaces:**
- Consumes:
  - from Task 6: `transform::{apply, expand_raw, Val}`, `CompiledRegex`, the IR types;
  - from Task 5: `PipelineSet::{map_field, placeholder, is_empty}`;
  - from Task 4: the `zaaf_sigma` document types.
- Produces:
  - `Level::{Informational, Low, Medium, High, Critical}`, ordered
    - `Level::parse(&str) -> Option<Level>`
    - `.as_str()`
    - `.ocsf_severity_id() -> u8` (1–5)
  - `RuleInfo { id: String, name, title, level: Level, status, description, author, references, tags, falsepositives, logsource: LogSource, source: Option<PathBuf> }`. A rule without an id gets `id = "title:<title>"`.
  - `CompiledRule { info: RuleInfo, expr: Expr }`
  - `SourcedDocument { document: Document, source: Option<PathBuf> }`
  - `CompileOutput { rules: Vec<CompiledRule>, diagnostics: Vec<Diagnostic>, filters: usize, correlations_skipped: usize }`
  - `compile(Vec<SourcedDocument>, &PipelineSet) -> CompileOutput`
  - crate-private `Problem { location: Location, message: String }`: a compile error or warning with its position.
- Diagnostic positions: item errors and warnings point at the `FieldItem` (its key and YAML path); condition errors at the `condition` value (`detection.condition` or `filter.condition`); duplicate ids, unknown levels, skipped correlations and unused filters at the start of their document (empty path).

Semantics fixed in this task (each one is tested here and again in the conformance suite):
- **String values:** case-insensitive by default; `cased` makes them case-sensitive.
- **Non-string values:** numbers and booleans match their text form.
- **Keyword search:** keyword values (no field) are `contains` matches over every value of the event.
- **`all`:** turns the OR between values into AND. It needs at least two values.
- **`neq`:** wraps the item in `Not`, so a missing field satisfies `neq`.
- **`null`:** matches a field that is absent or JSON null. `exists` checks presence only.
- **`expand`:** expands raw text before anything else. An unknown placeholder is a compile error, as the spec requires the rule to be rejected.
- **`fieldref`:** accepts `contains`, `startswith` and `endswith` as comparison modes.
- **Time modifiers:** they extract a number from a timestamp value and can be combined with `lt`/`lte`/`gt`/`gte`.
- **Regex flags:** `i`, `m` and `s` without `re` are errors.
- **Type modifiers:** `re`, `cidr`, `exists`, `fieldref`, the numeric modifiers and the time modifiers are mutually exclusive.
- **Meta filters:** they fold into the rules they target as `rule AND NOT filter`. Targets match the rule `id` or `name`.
- **Duplicate ids:** a duplicate rule id is an error, and the later rule is skipped.
- **`1 of them` / `all of them`:** both exclude identifiers that start with `_`.
- **Unmapped fields:** when pipelines are loaded, a field no pipeline mapped produces a warning.

- [ ] **Step 1: Write the failing tests** in `crates/zaaf-ir/src/rule.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Matcher, Predicate, Target};
    use zaaf_pipeline::parse_pipeline;
    use zaaf_sigma::SigmaString;

    fn compile_src(src: &str, pipelines: &PipelineSet) -> CompileOutput {
        let parsed = zaaf_sigma::parse_str(src);
        assert!(parsed.diagnostics.iter().all(|d| !d.is_error()), "{:?}", parsed.diagnostics);
        compile(
            parsed.documents.into_iter().map(|document| SourcedDocument { document, source: None }).collect(),
            pipelines,
        )
    }

    fn rule_with(detection: &str) -> String {
        format!("title: t\nid: r1\nlogsource:\n    product: windows\ndetection:\n{detection}")
    }

    fn compile_detection_src(detection: &str) -> CompileOutput {
        compile_src(&rule_with(detection), &PipelineSet::default())
    }

    fn first_error(out: &CompileOutput) -> String {
        out.diagnostics.iter().find(|d| d.is_error()).map(|d| d.message.clone()).unwrap_or_default()
    }

    fn first_error_location(out: &CompileOutput) -> Location {
        out.diagnostics.iter().find(|d| d.is_error()).map(|d| d.location.clone()).unwrap_or(Location::Unknown)
    }

    fn only_pred(out: &CompileOutput) -> &Predicate {
        match &out.rules[0].expr {
            Expr::Pred(p) => p,
            other => panic!("expected a single predicate, got {other:?}"),
        }
    }

    #[test]
    fn contains_becomes_lowercased_glob() {
        let out = compile_detection_src("    s:\n        CommandLine|contains: WhoAmI\n    condition: s\n");
        let p = only_pred(&out);
        assert_eq!(p.target, Target::Fields(vec!["CommandLine".into()]));
        match &p.matcher {
            Matcher::Str { pattern, case_sensitive } => {
                assert!(!case_sensitive);
                assert_eq!(pattern, &SigmaString::parse("*whoami*"));
            }
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn cased_keeps_case_and_ints_become_text() {
        let out = compile_detection_src("    s:\n        A|cased: AbC\n    t:\n        EventID: 4688\n    condition: s and t\n");
        let Expr::And(items) = &out.rules[0].expr else { panic!("{:?}", out.rules[0].expr) };
        let Expr::Pred(a) = &items[0] else { panic!() };
        assert!(matches!(&a.matcher, Matcher::Str { pattern, case_sensitive: true } if pattern == &SigmaString::literal("AbC")));
        let Expr::Pred(b) = &items[1] else { panic!() };
        assert!(matches!(&b.matcher, Matcher::Str { pattern, .. } if pattern == &SigmaString::literal("4688")));
    }

    #[test]
    fn all_is_and_and_neq_is_not() {
        let out = compile_detection_src("    s:\n        C|contains|all: [a, b]\n    condition: s\n");
        assert!(matches!(&out.rules[0].expr, Expr::And(v) if v.len() == 2));
        let out = compile_detection_src("    s:\n        U|neq: SYSTEM\n    condition: s\n");
        assert!(matches!(&out.rules[0].expr, Expr::Not(_)));
    }

    #[test]
    fn type_modifiers_produce_their_matchers() {
        let out = compile_detection_src("    s:\n        Size|gt: 10\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Num { op: crate::CmpOp::Gt, value } if value == 10.0));
        let out = compile_detection_src("    s:\n        Ip|cidr: 10.0.0.0/8\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Cidr(_)));
        let out = compile_detection_src("    s:\n        F|exists: false\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Exists(false)));
        let out = compile_detection_src("    s:\n        F: null\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::Null));
        let out = compile_detection_src("    s:\n        T|hour|gte: 22\n    condition: s\n");
        assert!(matches!(only_pred(&out).matcher, Matcher::TimePart { part: crate::TimePart::Hour, op: crate::CmpOp::Gte, value: 22 }));
        let out = compile_detection_src("    s:\n        A|fieldref|contains: B\n    condition: s\n");
        assert!(matches!(&only_pred(&out).matcher, Matcher::FieldRef { mode: crate::RefMode::Contains, other, .. } if other == &vec!["B".to_string()]));
    }

    #[test]
    fn keyword_values_are_contains_over_any_field() {
        let out = compile_detection_src("    k:\n        - 'event::clear'\n    condition: k\n");
        let p = only_pred(&out);
        assert_eq!(p.target, Target::AnyField);
        assert!(matches!(&p.matcher, Matcher::Str { pattern, .. } if pattern == &SigmaString::parse("*event::clear*")));
    }

    #[test]
    fn invalid_items_are_errors() {
        let cases = [
            ("    s:\n        X|all: single\n    condition: s\n", "all"),
            ("    s:\n        X|i: a\n    condition: s\n", "re"),
            ("    s:\n        X|re|cidr: a\n    condition: s\n", "incompatible"),
            ("    s:\n        X|cidr: not-a-net\n    condition: s\n", "CIDR"),
            ("    s:\n        X|exists: yes-please\n    condition: s\n", "boolean"),
            ("    s:\n        X|expand: '%Nope%'\n    condition: s\n", "Nope"),
            ("    k:\n        '|cidr': [10.0.0.0/8]\n    condition: k\n", "keyword"),
            ("    s:\n        X: a\n    condition: s and missing\n", "missing"),
            ("    s:\n        X: a\n    condition: 1 of nothing_*\n", "nothing_*"),
        ];
        for (det, needle) in cases {
            let out = compile_detection_src(det);
            assert!(out.rules.is_empty(), "{det} should not compile");
            let err = first_error(&out);
            assert!(err.contains(needle), "{det}: expected `{needle}` in `{err}`");
        }
    }

    #[test]
    fn diagnostics_point_at_the_item_the_condition_and_the_document() {
        let out = compile_detection_src("    s:\n        X|all: single\n    condition: s\n");
        assert_eq!(first_error_location(&out), Location::at(7, 9, "detection.s.X|all"));
        let out = compile_detection_src("    s:\n        X: a\n    condition: s and missing\n");
        assert_eq!(first_error_location(&out), Location::at(8, 16, "detection.condition"));
        let src = format!(
            "{}---\ntitle: again\nid: r1\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n",
            rule_with("    s:\n        A: 1\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(first_error_location(&out), Location::at(10, 1, ""));
    }

    #[test]
    fn them_excludes_underscore_identifiers() {
        let out = compile_detection_src("    a:\n        X: 1\n    _b:\n        Y: 1\n    condition: all of them\n");
        assert!(matches!(&out.rules[0].expr, Expr::Pred(_)), "{:?}", out.rules[0].expr);
    }

    #[test]
    fn expand_uses_pipeline_vars() {
        let pipes = PipelineSet::new(vec![parse_pipeline("name: v\nvars:\n  Admins: ['adm_*', root]\n").unwrap()]);
        let out = compile_src(&rule_with("    s:\n        User|expand: '%Admins%'\n    condition: s\n"), &pipes);
        assert!(matches!(&out.rules[0].expr, Expr::Or(v) if v.len() == 2), "{:?}", out.rules[0].expr);
    }

    #[test]
    fn unmapped_fields_warn_when_pipelines_are_loaded() {
        let pipes = PipelineSet::new(vec![parse_pipeline(
            "name: m\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: process.executable\n",
        )
        .unwrap()]);
        let out = compile_src(&rule_with("    s:\n        Image: a\n        User: b\n    condition: s\n"), &pipes);
        let warnings: Vec<_> = out.diagnostics.iter().filter(|d| !d.is_error()).collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].message.contains("`User`"));
        assert_eq!(warnings[0].location, Location::at(8, 9, "detection.s.User"));
    }

    #[test]
    fn filters_fold_into_targeted_rules() {
        let src = format!(
            "{}---\ntitle: f\nlogsource:\n    product: windows\nfilter:\n    rules: [r1]\n    sel:\n        User|startswith: adm_\n    condition: sel\n---\ntitle: unused\nlogsource:\n    product: windows\nfilter:\n    rules: [other]\n    sel:\n        X: 1\n    condition: sel\n",
            rule_with("    s:\n        Image: a\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(out.filters, 2);
        let Expr::And(parts) = &out.rules[0].expr else { panic!("{:?}", out.rules[0].expr) };
        assert!(matches!(parts[1], Expr::Not(_)));
        let unused = out.diagnostics.iter().find(|d| d.message.contains("`unused` does not match")).unwrap();
        assert_eq!(unused.location, Location::at(19, 1, ""));
    }

    #[test]
    fn duplicate_ids_correlations_and_levels() {
        let src = format!(
            "{}---\ntitle: second\nid: r1\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n---\ntitle: corr\ncorrelation:\n    type: event_count\n",
            rule_with("    s:\n        A: 1\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.correlations_skipped, 1);
        assert!(first_error(&out).contains("duplicate rule id `r1`"));
        assert_eq!(out.rules[0].info.level, Level::Medium);
        assert_eq!(Level::parse("Critical"), Some(Level::Critical));
        assert_eq!(Level::Critical.ocsf_severity_id(), 5);
        assert!(Level::High > Level::Medium);
    }

    #[test]
    fn rules_without_id_get_a_title_id() {
        let out = compile_src(
            "title: no id\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n",
            &PipelineSet::default(),
        );
        assert_eq!(out.rules[0].info.id, "title:no id");
    }
}
```

Replace `crates/zaaf-ir/src/lib.rs` with:
```rust
//! Compiles parsed Sigma documents into the ZAAFElegia intermediate representation.

pub mod ir;
mod item;
pub mod regex_engine;
mod rule;
mod transform;

pub use ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
pub use regex_engine::{BACKTRACK_LIMIT, CompiledRegex, RegexFlags};
pub use rule::{CompileOutput, CompiledRule, Level, RuleInfo, SourcedDocument, compile};
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-ir`
Expected: compile errors for the missing `compile`, `Level` and `SourcedDocument`, and for the missing module `item`.

- [ ] **Step 3: Implement**

Delete the line `#![allow(dead_code)] // used by the compiler added in Task 7` from `transform.rs`.

`crates/zaaf-ir/src/item.rs`:
```rust
//! Compiles one `field|modifiers: values` item into an expression.

use crate::ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
use crate::regex_engine::{BACKTRACK_LIMIT, CompiledRegex, RegexFlags};
use crate::transform::{self, Val};
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{FieldItem, LogSource, Modifier, RuleValue, SigmaString};

const STRING_TRANSFORMS: &[Modifier] = &[
    Modifier::Contains,
    Modifier::StartsWith,
    Modifier::EndsWith,
    Modifier::Windash,
    Modifier::Base64,
    Modifier::Base64Offset,
    Modifier::Utf16Le,
    Modifier::Utf16Be,
    Modifier::Utf16,
    Modifier::Wide,
];

pub(crate) fn and(mut v: Vec<Expr>) -> Expr {
    if v.len() == 1 { v.remove(0) } else { Expr::And(v) }
}

pub(crate) fn or(mut v: Vec<Expr>) -> Expr {
    if v.len() == 1 { v.remove(0) } else { Expr::Or(v) }
}

pub(crate) fn compile_item(
    item: &FieldItem,
    logsource: &LogSource,
    pipelines: &PipelineSet,
    warnings: &mut Vec<String>,
) -> Result<Expr, String> {
    use Modifier::*;
    let mods = &item.modifiers;
    let has = |m: Modifier| mods.contains(&m);

    let flags = RegexFlags { insensitive: has(ReInsensitive), multiline: has(ReMultiline), dot_all: has(ReDotAll) };
    if flags != RegexFlags::default() && !has(Re) {
        return Err("regex flags `i`, `m` and `s` require the `re` modifier".into());
    }
    let time_part = mods.iter().find_map(|m| match m {
        Minute => Some(TimePart::Minute),
        Hour => Some(TimePart::Hour),
        Day => Some(TimePart::Day),
        Week => Some(TimePart::Week),
        Month => Some(TimePart::Month),
        Year => Some(TimePart::Year),
        _ => None,
    });
    let cmp = mods.iter().find_map(|m| match m {
        Lt => Some(CmpOp::Lt),
        Lte => Some(CmpOp::Lte),
        Gt => Some(CmpOp::Gt),
        Gte => Some(CmpOp::Gte),
        _ => None,
    });
    // [re, cidr, exists, fieldref, numeric-or-time]
    let families = [has(Re), has(Cidr), has(Exists), has(FieldRef), time_part.is_some() || cmp.is_some()];
    if families.iter().filter(|b| **b).count() > 1 {
        let names: Vec<&str> = mods.iter().map(|m| m.name()).collect();
        return Err(format!("incompatible modifiers `{}`", names.join("|")));
    }
    if has(All) && item.values.len() < 2 {
        return Err("`all` needs a list of at least two values".into());
    }
    if item.field.is_none() && families[1..].iter().any(|b| *b) {
        return Err("keyword search supports only string matching and `re`".into());
    }

    let target = match &item.field {
        None => Target::AnyField,
        Some(field) => {
            let mapped = pipelines.map_field(logsource, field);
            if !pipelines.is_empty() && !mapped.mapped {
                warnings.push(format!("field `{field}` is not mapped by any pipeline"));
            }
            Target::Fields(mapped.names)
        }
    };
    let pred = |matcher: Matcher| Expr::Pred(Predicate { target: target.clone(), matcher });
    let case_sensitive = has(Cased);
    let values = expand_values(&item.values, has(Expand), pipelines)?;

    let preds: Vec<Expr> = if has(Exists) {
        match values.as_slice() {
            [RuleValue::Bool(b)] => vec![pred(Matcher::Exists(*b))],
            _ => return Err("`exists` takes a single boolean value".into()),
        }
    } else if values.contains(&RuleValue::Null) {
        if values.len() > 1 {
            return Err("`null` cannot be part of a list of values".into());
        }
        if mods.iter().any(|m| *m != Neq) {
            return Err("`null` cannot be combined with modifiers other than `neq`".into());
        }
        vec![pred(Matcher::Null)]
    } else if has(Re) {
        let mut out = Vec::new();
        for v in &values {
            let RuleValue::Str(src) = v else { return Err("`re` needs string values".into()) };
            let re = CompiledRegex::new(src, flags)?;
            if re.needs_backtracking() {
                warnings.push(format!("regex `{src}` needs the backtracking engine (limit {BACKTRACK_LIMIT} steps)"));
            }
            out.push(pred(Matcher::Regex(re)));
        }
        out
    } else if has(Cidr) {
        values
            .iter()
            .map(|v| match v {
                RuleValue::Str(s) => s
                    .trim()
                    .parse::<ipnet::IpNet>()
                    .map(|n| pred(Matcher::Cidr(n)))
                    .map_err(|e| format!("invalid CIDR `{s}`: {e}")),
                _ => Err("`cidr` needs string values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else if let Some(part) = time_part {
        values
            .iter()
            .map(|v| match v {
                RuleValue::Int(i) => Ok(pred(Matcher::TimePart { part, op: cmp.unwrap_or(CmpOp::Eq), value: *i })),
                _ => Err("time modifiers need integer values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else if let Some(op) = cmp {
        values
            .iter()
            .map(|v| match v {
                RuleValue::Int(i) => Ok(pred(Matcher::Num { op, value: *i as f64 })),
                RuleValue::Float(f) => Ok(pred(Matcher::Num { op, value: *f })),
                _ => Err("numeric modifiers need numeric values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else if has(FieldRef) {
        let mode = if has(Contains) {
            RefMode::Contains
        } else if has(StartsWith) {
            RefMode::StartsWith
        } else if has(EndsWith) {
            RefMode::EndsWith
        } else {
            RefMode::Equals
        };
        values
            .iter()
            .map(|v| match v {
                RuleValue::Str(other) => Ok(pred(Matcher::FieldRef {
                    other: pipelines.map_field(logsource, other).names,
                    mode,
                    case_sensitive,
                })),
                _ => Err("`fieldref` needs field names as values".to_string()),
            })
            .collect::<Result<_, _>>()?
    } else {
        let mut vals: Vec<Val> = values
            .iter()
            .map(|v| match v {
                RuleValue::Str(s) => Val::S(SigmaString::parse(s)),
                other => Val::S(SigmaString::literal(&other.to_text().unwrap_or_default())),
            })
            .collect();
        for m in mods.iter().filter(|m| STRING_TRANSFORMS.contains(m)) {
            vals = transform::apply(*m, vals)?;
        }
        vals.into_iter()
            .map(|v| {
                let mut s = v.into_sigma();
                if item.field.is_none() {
                    s.prepend_any_many();
                    s.append_any_many();
                }
                let pattern = if case_sensitive { s } else { s.to_lowercase() };
                pred(Matcher::Str { pattern, case_sensitive })
            })
            .collect()
    };
    let combined = if has(All) { and(preds) } else { or(preds) };
    Ok(if has(Neq) { Expr::Not(Box::new(combined)) } else { combined })
}

fn expand_values(values: &[RuleValue], expand: bool, pipelines: &PipelineSet) -> Result<Vec<RuleValue>, String> {
    if !expand {
        return Ok(values.to_vec());
    }
    let lookup = |name: &str| pipelines.placeholder(name).map(<[String]>::to_vec);
    let mut out = Vec::new();
    for v in values {
        match v {
            RuleValue::Str(s) => out.extend(transform::expand_raw(s, &lookup)?.into_iter().map(RuleValue::Str)),
            other => out.push(other.clone()),
        }
    }
    Ok(out)
}
```

`crates/zaaf-ir/src/rule.rs` (insert above the tests):
```rust
//! Compiles whole documents: search identifiers, conditions, meta filters and metadata.

use crate::ir::Expr;
use crate::item::{and, compile_item, or};
use std::collections::HashSet;
use std::path::PathBuf;
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{
    CondExpr, Detection, Diagnostic, Document, FieldItem, Location, LogSource, Quantifier, SelTarget, SigmaString,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "informational" => Some(Self::Informational),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// OCSF `severity_id`: 1 Informational … 5 Critical.
    pub fn ocsf_severity_id(self) -> u8 {
        self as u8 + 1
    }
}

#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub id: String,
    pub name: Option<String>,
    pub title: String,
    pub level: Level,
    pub status: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    pub logsource: LogSource,
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub info: RuleInfo,
    pub expr: Expr,
}

#[derive(Debug, Clone)]
pub struct SourcedDocument {
    pub document: Document,
    pub source: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct CompileOutput {
    pub rules: Vec<CompiledRule>,
    pub diagnostics: Vec<Diagnostic>,
    pub filters: usize,
    pub correlations_skipped: usize,
}

/// A compile error or warning and where in the rule file it points.
#[derive(Debug)]
pub(crate) struct Problem {
    location: Location,
    message: String,
}

impl Problem {
    fn item(item: &FieldItem, message: String) -> Self {
        Self { location: Location::at(item.line, item.col, item.path.clone()), message }
    }
}

/// The start of a document; used for diagnostics about the document as a whole.
fn document_at(line: usize, col: usize) -> Location {
    Location::at(line, col, "")
}

fn located(d: Diagnostic, source: &Option<PathBuf>) -> Diagnostic {
    match source {
        Some(p) => d.with_file(p.clone()),
        None => d,
    }
}

fn error(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::error(location, msg), source)
}

fn warning(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::warning(location, msg), source)
}

struct CompiledFilter {
    title: String,
    targets: Vec<String>,
    expr: Expr,
    source: Option<PathBuf>,
    line: usize,
    col: usize,
    used: bool,
}

/// Compiles documents into rules. Problems become diagnostics; a broken rule is skipped.
pub fn compile(docs: Vec<SourcedDocument>, pipelines: &PipelineSet) -> CompileOutput {
    let mut out = CompileOutput::default();
    let mut rules = Vec::new();
    let mut filters = Vec::new();
    for SourcedDocument { document, source } in docs {
        match document {
            Document::Rule(r) => rules.push((r, source)),
            Document::Filter(f) => filters.push((f, source)),
            Document::Correlation(c) => {
                out.correlations_skipped += 1;
                out.diagnostics.push(warning(
                    &source,
                    document_at(c.line, c.col),
                    format!("correlation rule `{}` skipped: correlation support arrives in milestone M2", c.title),
                ));
            }
        }
    }
    out.filters = filters.len();

    let mut compiled_filters = Vec::new();
    for (f, source) in filters {
        let mut warnings = Vec::new();
        match compile_detection(&f.detection, "filter", &f.logsource, pipelines, &mut warnings) {
            Ok(expr) => compiled_filters.push(CompiledFilter {
                title: f.title.clone(),
                targets: f.rules.clone(),
                expr,
                source: source.clone(),
                line: f.line,
                col: f.col,
                used: false,
            }),
            Err(p) => out.diagnostics.push(error(&source, p.location, format!("filter `{}`: {}", f.title, p.message))),
        }
        out.diagnostics.extend(
            warnings
                .into_iter()
                .map(|w| warning(&source, w.location, format!("filter `{}`: {}", f.title, w.message))),
        );
    }

    let mut seen = HashSet::new();
    for (r, source) in rules {
        let mut warnings = Vec::new();
        let compiled = compile_detection(&r.detection, "detection", &r.logsource, pipelines, &mut warnings);
        out.diagnostics.extend(
            warnings
                .into_iter()
                .map(|w| warning(&source, w.location, format!("rule `{}`: {}", r.meta.title, w.message))),
        );
        let mut expr = match compiled {
            Ok(e) => e,
            Err(p) => {
                out.diagnostics.push(error(&source, p.location, format!("rule `{}`: {}", r.meta.title, p.message)));
                continue;
            }
        };
        let id = r.meta.id.clone().unwrap_or_else(|| format!("title:{}", r.meta.title));
        if !seen.insert(id.clone()) {
            out.diagnostics.push(error(
                &source,
                document_at(r.line, r.col),
                format!("duplicate rule id `{id}`; rule `{}` skipped", r.meta.title),
            ));
            continue;
        }
        for f in &mut compiled_filters {
            let targeted = f.targets.iter().any(|t| {
                r.meta.id.as_deref() == Some(t.as_str()) || r.meta.name.as_deref() == Some(t.as_str())
            });
            if targeted {
                f.used = true;
                expr = Expr::And(vec![expr, Expr::Not(Box::new(f.expr.clone()))]);
            }
        }
        let level = match r.meta.level.as_deref() {
            None => Level::Medium,
            Some(s) => Level::parse(s).unwrap_or_else(|| {
                out.diagnostics.push(warning(
                    &source,
                    document_at(r.line, r.col),
                    format!("rule `{}`: unknown level `{s}`, using medium", r.meta.title),
                ));
                Level::Medium
            }),
        };
        out.rules.push(CompiledRule {
            info: RuleInfo {
                id,
                name: r.meta.name,
                title: r.meta.title,
                level,
                status: r.meta.status,
                description: r.meta.description,
                author: r.meta.author,
                references: r.meta.references,
                tags: r.meta.tags,
                falsepositives: r.meta.falsepositives,
                logsource: r.logsource,
                source,
            },
            expr,
        });
    }
    for f in compiled_filters.iter().filter(|f| !f.used) {
        out.diagnostics.push(warning(
            &f.source,
            document_at(f.line, f.col),
            format!("filter `{}` does not match any loaded rule", f.title),
        ));
    }
    out
}

/// `base` is `detection` for rules and `filter` for meta filters (the YAML path of the block).
pub(crate) fn compile_detection(
    det: &Detection,
    base: &str,
    logsource: &LogSource,
    pipelines: &PipelineSet,
    warnings: &mut Vec<Problem>,
) -> Result<Expr, Problem> {
    let mut ids: Vec<(String, Expr)> = Vec::new();
    for sid in &det.search_ids {
        let mut alternatives = Vec::new();
        for alt in &sid.alternatives {
            let mut items = Vec::new();
            for item in alt {
                let mut item_warnings = Vec::new();
                let compiled = compile_item(item, logsource, pipelines, &mut item_warnings);
                warnings.extend(item_warnings.into_iter().map(|w| Problem::item(item, w)));
                items.push(compiled.map_err(|e| Problem::item(item, e))?);
            }
            alternatives.push(and(items));
        }
        ids.push((sid.name.clone(), or(alternatives)));
    }
    let conditions = det
        .conditions
        .iter()
        .map(|c| resolve(c, &ids))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|message| Problem {
            location: Location::at(det.condition_line, det.condition_col, format!("{base}.condition")),
            message,
        })?;
    Ok(or(conditions))
}

fn resolve(c: &CondExpr, ids: &[(String, Expr)]) -> Result<Expr, String> {
    Ok(match c {
        CondExpr::Ident(name) => ids
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.clone())
            .ok_or_else(|| format!("condition references unknown search identifier `{name}`"))?,
        CondExpr::Not(inner) => Expr::Not(Box::new(resolve(inner, ids)?)),
        CondExpr::And(v) => and(v.iter().map(|x| resolve(x, ids)).collect::<Result<_, _>>()?),
        CondExpr::Or(v) => or(v.iter().map(|x| resolve(x, ids)).collect::<Result<_, _>>()?),
        CondExpr::Of(q, target) => {
            let selected: Vec<Expr> = ids
                .iter()
                .filter(|(n, _)| match target {
                    SelTarget::Them => !n.starts_with('_'),
                    SelTarget::Pattern(p) => SigmaString::parse(p).matches(n),
                })
                .map(|(_, e)| e.clone())
                .collect();
            if selected.is_empty() {
                let what = match target {
                    SelTarget::Them => "them".to_string(),
                    SelTarget::Pattern(p) => p.clone(),
                };
                return Err(format!("`{what}` matches no search identifier"));
            }
            match q {
                Quantifier::One => or(selected),
                Quantifier::All => and(selected),
            }
        }
    })
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-ir`
Expected: every zaaf-ir test passes (12 from Task 6 + 13 new).

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(ir): compile items, conditions, meta filters and rule metadata

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: zaaf-event: Event trait and JSON events

**Files:**
- Create: `crates/zaaf-event/Cargo.toml`, `crates/zaaf-event/src/lib.rs`

**Interfaces:**
- Produces:
  - `FieldValue<'a>::{Str(&'a str), Int(i64), Float(f64), Bool(bool), Null}`
    - `.as_text() -> Option<Cow<'a, str>>`: `None` for Null.
    - `.as_f64() -> Option<f64>`: numbers and numeric strings.
  - `trait Event`:
    - `fn get(&self, path: &str) -> Option<Vec<FieldValue<'_>>>`: `None` means the field is absent. Arrays are flattened. An object at the path counts as present with no scalar values.
    - `fn leaf_values(&self) -> Vec<FieldValue<'_>>`
    - `fn timestamp(&self) -> Option<DateTime<Utc>>`
    - `fn to_json(&self) -> serde_json::Value`
  - `JsonEvent::new(serde_json::Value)`: auto-detects the timestamp from `@timestamp`, `timestamp`, `time`, `eventTime`, `EventTime`, `UtcTime`, `TimeCreated`, `ts`.
  - `JsonEvent::value()`
  - `parse_timestamp(&str) -> Option<DateTime<Utc>>`
  - `timestamp_from_epoch(f64) -> Option<DateTime<Utc>>`: values ≥ 1e11 are milliseconds, smaller values are seconds.
- Field path resolution: an exact top-level key wins (`"user.name"`). Otherwise the path is split on `.`, trying the longest key at each level, so `{"user": {"name": ..}}` and `{"a": {"b.c": ..}}` both resolve. Arrays along the path fan out to every element.

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-event/Cargo.toml`:
```toml
[package]
name = "zaaf-event"
description = "Event abstraction for ZAAFElegia evaluators"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
chrono.workspace = true
serde_json.workspace = true
```

`crates/zaaf-event/src/lib.rs` (tests first):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(v: serde_json::Value) -> JsonEvent {
        JsonEvent::new(v)
    }

    #[test]
    fn resolves_flat_dotted_and_nested_paths() {
        let e = ev(json!({"user.name": "a", "process": {"parent": {"name": "x"}}, "o": {"b.c": 1}}));
        assert_eq!(e.get("user.name"), Some(vec![FieldValue::Str("a")]));
        assert_eq!(e.get("process.parent.name"), Some(vec![FieldValue::Str("x")]));
        assert_eq!(e.get("o.b.c"), Some(vec![FieldValue::Int(1)]));
        assert_eq!(e.get("missing"), None);
        assert_eq!(e.get("process.nope"), None);
    }

    #[test]
    fn arrays_fan_out_and_flatten() {
        let e = ev(json!({"tags": ["a", ["b"]], "p": [{"n": "x"}, {"n": "y"}, {"m": 1}]}));
        assert_eq!(e.get("tags"), Some(vec![FieldValue::Str("a"), FieldValue::Str("b")]));
        assert_eq!(e.get("p.n"), Some(vec![FieldValue::Str("x"), FieldValue::Str("y")]));
    }

    #[test]
    fn null_and_object_presence() {
        let e = ev(json!({"n": null, "o": {"k": 1}}));
        assert_eq!(e.get("n"), Some(vec![FieldValue::Null]));
        assert_eq!(e.get("o"), Some(vec![]));
    }

    #[test]
    fn leaf_values_cover_the_whole_event() {
        let e = ev(json!({"a": "x", "b": {"c": [1, true]}}));
        assert_eq!(e.leaf_values(), vec![FieldValue::Str("x"), FieldValue::Int(1), FieldValue::Bool(true)]);
    }

    #[test]
    fn text_and_number_views() {
        assert_eq!(FieldValue::Int(4688).as_text().as_deref(), Some("4688"));
        assert_eq!(FieldValue::Bool(true).as_text().as_deref(), Some("true"));
        assert_eq!(FieldValue::Null.as_text(), None);
        assert_eq!(FieldValue::Str(" 10 ").as_f64(), Some(10.0));
        assert_eq!(FieldValue::Str("x").as_f64(), None);
    }

    #[test]
    fn timestamps() {
        let e = ev(json!({"@timestamp": "2026-11-07T03:15:00Z"}));
        assert_eq!(e.timestamp().unwrap().to_rfc3339(), "2026-11-07T03:15:00+00:00");
        let e = ev(json!({"UtcTime": "2026-11-07 03:15:00.123"}));
        assert_eq!(e.timestamp().unwrap().timestamp_millis(), 1_794_021_300_123);
        let e = ev(json!({"ts": 1_794_021_300}));
        assert_eq!(e.timestamp().unwrap().timestamp(), 1_794_021_300);
        let e = ev(json!({"ts": 1_794_021_300_123_i64}));
        assert_eq!(e.timestamp().unwrap().timestamp_millis(), 1_794_021_300_123);
        assert!(ev(json!({"x": 1})).timestamp().is_none());
        assert!(parse_timestamp("not a date").is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-event`
Expected: compile errors for the missing `JsonEvent`, `FieldValue` and `parse_timestamp`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Event abstraction used by every ZAAFElegia evaluator.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::borrow::Cow;

/// A scalar value read from an event.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'a> {
    Str(&'a str),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl<'a> FieldValue<'a> {
    pub fn as_text(&self) -> Option<Cow<'a, str>> {
        match self {
            Self::Str(s) => Some(Cow::Borrowed(*s)),
            Self::Int(i) => Some(Cow::Owned(i.to_string())),
            Self::Float(f) => Some(Cow::Owned(f.to_string())),
            Self::Bool(b) => Some(Cow::Owned(b.to_string())),
            Self::Null => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Int(i) => Some(*i as f64),
            Self::Float(f) => Some(*f),
            Self::Str(s) => s.trim().parse().ok(),
            Self::Bool(_) | Self::Null => None,
        }
    }
}

/// A log event that rules can be evaluated against.
pub trait Event {
    /// `None` when the field is absent; otherwise its scalar values (arrays flattened).
    fn get(&self, path: &str) -> Option<Vec<FieldValue<'_>>>;
    /// Every scalar value in the event (keyword search).
    fn leaf_values(&self) -> Vec<FieldValue<'_>>;
    fn timestamp(&self) -> Option<DateTime<Utc>>;
    fn to_json(&self) -> Value;
}

const TIMESTAMP_FIELDS: &[&str] =
    &["@timestamp", "timestamp", "time", "eventTime", "EventTime", "UtcTime", "TimeCreated", "ts"];

/// An event backed by a JSON value.
#[derive(Debug, Clone)]
pub struct JsonEvent {
    value: Value,
    ts: Option<DateTime<Utc>>,
}

impl JsonEvent {
    pub fn new(value: Value) -> Self {
        let ts = TIMESTAMP_FIELDS.iter().find_map(|f| value.get(*f).and_then(json_timestamp));
        Self { value, ts }
    }

    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl Event for JsonEvent {
    fn get(&self, path: &str) -> Option<Vec<FieldValue<'_>>> {
        let segs: Vec<&str> = path.split('.').collect();
        let mut found = Vec::new();
        if !lookup(&self.value, &segs, &mut found) {
            return None;
        }
        let mut out = Vec::new();
        for v in found {
            flatten(v, &mut out);
        }
        Some(out)
    }

    fn leaf_values(&self) -> Vec<FieldValue<'_>> {
        let mut out = Vec::new();
        leaves(&self.value, &mut out);
        out
    }

    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.ts
    }

    fn to_json(&self) -> Value {
        self.value.clone()
    }
}

fn lookup<'a>(v: &'a Value, segs: &[&str], found: &mut Vec<&'a Value>) -> bool {
    if segs.is_empty() {
        found.push(v);
        return true;
    }
    match v {
        Value::Object(map) => {
            for k in (1..=segs.len()).rev() {
                let key = segs[..k].join(".");
                if let Some(child) = map.get(&key)
                    && lookup(child, &segs[k..], found)
                {
                    return true;
                }
            }
            false
        }
        Value::Array(items) => {
            let mut any = false;
            for item in items {
                any |= lookup(item, segs, found);
            }
            any
        }
        _ => false,
    }
}

fn flatten<'a>(v: &'a Value, out: &mut Vec<FieldValue<'a>>) {
    match v {
        Value::Null => out.push(FieldValue::Null),
        Value::Bool(b) => out.push(FieldValue::Bool(*b)),
        Value::Number(n) => out.push(match n.as_i64() {
            Some(i) => FieldValue::Int(i),
            None => FieldValue::Float(n.as_f64().unwrap_or(f64::NAN)),
        }),
        Value::String(s) => out.push(FieldValue::Str(s)),
        Value::Array(items) => {
            for item in items {
                flatten(item, out);
            }
        }
        Value::Object(_) => {}
    }
}

fn leaves<'a>(v: &'a Value, out: &mut Vec<FieldValue<'a>>) {
    match v {
        Value::Object(map) => {
            for child in map.values() {
                leaves(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                leaves(item, out);
            }
        }
        scalar => flatten(scalar, out),
    }
}

fn json_timestamp(v: &Value) -> Option<DateTime<Utc>> {
    match v {
        Value::String(s) => parse_timestamp(s),
        Value::Number(n) => n.as_f64().and_then(timestamp_from_epoch),
        _ => None,
    }
}

/// RFC 3339, `YYYY-MM-DD HH:MM:SS[.f]` (UTC, e.g. Sysmon `UtcTime`), or epoch seconds/millis.
pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(n.and_utc());
        }
    }
    s.parse::<f64>().ok().and_then(timestamp_from_epoch)
}

/// Epoch seconds, or milliseconds when the value is ≥ 1e11.
pub fn timestamp_from_epoch(x: f64) -> Option<DateTime<Utc>> {
    if !x.is_finite() {
        return None;
    }
    let millis = if x.abs() >= 1e11 { x } else { x * 1000.0 };
    DateTime::from_timestamp_millis(millis as i64)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-event`
Expected: 6 tests pass. The expected epoch values were computed independently: 2026-11-07T03:15:00Z is 1794021300 s.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(event): Event trait, JSON events, path resolution and timestamp parsing

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: zaaf-eval: the native evaluator (semantic reference)

**Files:**
- Create: `crates/zaaf-eval/Cargo.toml`, `crates/zaaf-eval/src/lib.rs`

**Interfaces:**
- Consumes:
  - from Task 7: `zaaf_ir::{CompiledRule, Expr, Predicate, Target, Matcher, CmpOp, TimePart, RefMode}`;
  - from Task 8: `zaaf_event::{Event, FieldValue, parse_timestamp, timestamp_from_epoch}`.
- Produces:
  - `Evaluator`:
    - `Evaluator::new(Vec<CompiledRule>)`
    - `.rules() -> &[CompiledRule]`
    - `.matching_rules(&dyn Event) -> Vec<usize>`: indexes into `rules()`, in rule order.
  - `eval_expr(&Expr, &dyn Event) -> bool`

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-eval/Cargo.toml`:
```toml
[package]
name = "zaaf-eval"
description = "Native Sigma evaluator, the semantic reference of ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
chrono.workspace = true
zaaf-event.workspace = true
zaaf-ir.workspace = true

[dev-dependencies]
serde_json.workspace = true
zaaf-pipeline.workspace = true
zaaf-sigma.workspace = true
```

`crates/zaaf-eval/src/lib.rs` (tests first):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use zaaf_event::JsonEvent;
    use zaaf_ir::{SourcedDocument, compile};
    use zaaf_pipeline::PipelineSet;

    fn evaluator(src: &str) -> Evaluator {
        let parsed = zaaf_sigma::parse_str(src);
        assert!(parsed.diagnostics.iter().all(|d| !d.is_error()), "{:?}", parsed.diagnostics);
        let out = compile(
            parsed.documents.into_iter().map(|document| SourcedDocument { document, source: None }).collect(),
            &PipelineSet::default(),
        );
        assert!(out.diagnostics.iter().all(|d| !d.is_error()), "{:?}", out.diagnostics);
        Evaluator::new(out.rules)
    }

    /// Quoted so that ids such as `null` stay strings in YAML.
    fn rule(id: &str, detection: &str) -> String {
        format!("title: '{id}'\nid: '{id}'\nlogsource:\n    product: test\ndetection:\n{detection}")
    }

    fn hits(e: &Evaluator, json: &str) -> Vec<String> {
        let event = JsonEvent::new(serde_json::from_str(json).unwrap());
        e.matching_rules(&event).into_iter().map(|i| e.rules()[i].info.id.clone()).collect()
    }

    #[test]
    fn case_insensitive_equality_and_int_as_text() {
        let e = evaluator(&rule("r", "    s:\n        EventID: 4688\n        Image|endswith: '\\cmd.exe'\n    condition: s\n"));
        assert_eq!(hits(&e, r#"{"EventID": "4688", "Image": "C:\\WINDOWS\\CMD.EXE"}"#), vec!["r"]);
        assert!(hits(&e, r#"{"EventID": 4689, "Image": "C:\\cmd.exe"}"#).is_empty());
    }

    #[test]
    fn keywords_search_nested_values() {
        let e = evaluator(&rule("k", "    k:\n        - 'event::clear'\n    condition: k\n"));
        assert_eq!(hits(&e, r#"{"a": {"b": ["x", "Mimikatz EVENT::Clear"]}}"#), vec!["k"]);
        assert!(hits(&e, r#"{"a": "nothing"}"#).is_empty());
    }

    #[test]
    fn null_exists_and_neq_on_missing_fields() {
        let e = evaluator(&format!(
            "{}---\n{}---\n{}",
            rule("null", "    s:\n        F: null\n    condition: s\n"),
            rule("exists", "    s:\n        F|exists: true\n    condition: s\n"),
            rule("neq", "    s:\n        F|neq: x\n    condition: s\n"),
        ));
        assert_eq!(hits(&e, r#"{}"#), vec!["null", "neq"]);
        assert_eq!(hits(&e, r#"{"F": null}"#), vec!["null", "exists", "neq"]);
        assert_eq!(hits(&e, r#"{"F": "X"}"#), vec!["exists"]);
    }

    #[test]
    fn numeric_cidr_regex_time_and_fieldref() {
        let e = evaluator(&format!(
            "{}---\n{}---\n{}---\n{}---\n{}",
            rule("num", "    s:\n        Size|gte: 10\n    condition: s\n"),
            rule("cidr", "    s:\n        Ip|cidr: 10.0.0.0/8\n    condition: s\n"),
            rule("re", "    s:\n        Name|re: '^(?!svchost).*\\.exe$'\n    condition: s\n"),
            rule("hour", "    s:\n        T|hour: 3\n    condition: s\n"),
            rule("ref", "    s:\n        A|fieldref|contains: B\n    condition: s\n"),
        ));
        assert_eq!(
            hits(&e, r#"{"Size": "12", "Ip": "10.1.2.3", "Name": "evil.exe", "T": "2026-11-07T03:00:00Z", "A": "run as BOB", "B": "bob"}"#),
            vec!["num", "cidr", "re", "hour", "ref"]
        );
        assert!(hits(&e, r#"{"Size": "big", "Ip": "nope", "Name": "svchost.exe", "T": "x", "A": "a", "B": "b"}"#).is_empty());
    }

    #[test]
    fn multiple_mapped_fields_are_ored() {
        use zaaf_ir::{Expr, Matcher, Predicate, Target};
        use zaaf_sigma::SigmaString;
        let expr = Expr::Pred(Predicate {
            target: Target::Fields(vec!["a".into(), "b".into()]),
            matcher: Matcher::Str { pattern: SigmaString::literal("x"), case_sensitive: false },
        });
        let event = JsonEvent::new(serde_json::json!({"b": "X"}));
        assert!(eval_expr(&expr, &event));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-eval`
Expected: compile errors for the missing `Evaluator` and `eval_expr`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Native evaluator. Its behaviour *is* the ZAAFElegia semantics: every other
//! evaluator (DataFusion, M4) is tested against it.

use chrono::{DateTime, Datelike, Timelike, Utc};
use std::net::IpAddr;
use zaaf_event::{Event, FieldValue, parse_timestamp, timestamp_from_epoch};
use zaaf_ir::{CmpOp, CompiledRule, Expr, Matcher, Predicate, RefMode, Target, TimePart};

pub struct Evaluator {
    rules: Vec<CompiledRule>,
}

impl Evaluator {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Indexes (into `rules()`) of every rule that matches `event`, in rule order.
    pub fn matching_rules(&self, event: &dyn Event) -> Vec<usize> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| eval_expr(&r.expr, event))
            .map(|(i, _)| i)
            .collect()
    }
}

pub fn eval_expr(expr: &Expr, event: &dyn Event) -> bool {
    match expr {
        Expr::And(items) => items.iter().all(|e| eval_expr(e, event)),
        Expr::Or(items) => items.iter().any(|e| eval_expr(e, event)),
        Expr::Not(inner) => !eval_expr(inner, event),
        Expr::Pred(p) => eval_predicate(p, event),
    }
}

fn eval_predicate(p: &Predicate, event: &dyn Event) -> bool {
    match &p.target {
        Target::AnyField => event.leaf_values().iter().any(|v| value_matches(&p.matcher, v)),
        Target::Fields(fields) => match &p.matcher {
            Matcher::Exists(want) => fields.iter().any(|f| event.get(f).is_some()) == *want,
            Matcher::Null => fields.iter().any(|f| match event.get(f) {
                None => true,
                Some(values) => values.iter().any(|v| matches!(v, FieldValue::Null)),
            }),
            Matcher::FieldRef { other, mode, case_sensitive } => fields
                .iter()
                .any(|f| other.iter().any(|o| fieldref(event, f, o, *mode, *case_sensitive))),
            m => fields
                .iter()
                .any(|f| event.get(f).is_some_and(|values| values.iter().any(|v| value_matches(m, v)))),
        },
    }
}

fn value_matches(m: &Matcher, v: &FieldValue) -> bool {
    match m {
        Matcher::Str { pattern, case_sensitive } => match v.as_text() {
            Some(t) if *case_sensitive => pattern.matches(&t),
            Some(t) => pattern.matches(&t.to_lowercase()),
            None => false,
        },
        Matcher::Regex(re) => v.as_text().is_some_and(|t| re.is_match(&t)),
        Matcher::Num { op, value } => v.as_f64().is_some_and(|x| compare(*op, x, *value)),
        Matcher::Cidr(net) => v
            .as_text()
            .and_then(|t| t.trim().parse::<IpAddr>().ok())
            .is_some_and(|ip| net.contains(&ip)),
        Matcher::TimePart { part, op, value } => {
            timestamp_of(v).is_some_and(|ts| compare(*op, time_part(ts, *part) as f64, *value as f64))
        }
        Matcher::Exists(_) | Matcher::Null | Matcher::FieldRef { .. } => false,
    }
}

fn compare(op: CmpOp, a: f64, b: f64) -> bool {
    match op {
        CmpOp::Eq => a == b,
        CmpOp::Lt => a < b,
        CmpOp::Lte => a <= b,
        CmpOp::Gt => a > b,
        CmpOp::Gte => a >= b,
    }
}

fn timestamp_of(v: &FieldValue) -> Option<DateTime<Utc>> {
    match v {
        FieldValue::Str(s) => parse_timestamp(s),
        FieldValue::Int(i) => timestamp_from_epoch(*i as f64),
        FieldValue::Float(f) => timestamp_from_epoch(*f),
        FieldValue::Bool(_) | FieldValue::Null => None,
    }
}

fn time_part(ts: DateTime<Utc>, part: TimePart) -> i64 {
    match part {
        TimePart::Minute => ts.minute() as i64,
        TimePart::Hour => ts.hour() as i64,
        TimePart::Day => ts.day() as i64,
        TimePart::Week => ts.iso_week().week() as i64,
        TimePart::Month => ts.month() as i64,
        TimePart::Year => ts.year() as i64,
    }
}

fn fieldref(event: &dyn Event, field: &str, other: &str, mode: RefMode, case_sensitive: bool) -> bool {
    let (Some(left), Some(right)) = (event.get(field), event.get(other)) else {
        return false;
    };
    let norm = |v: &FieldValue| v.as_text().map(|t| if case_sensitive { t.into_owned() } else { t.to_lowercase() });
    let rights: Vec<String> = right.iter().filter_map(norm).collect();
    left.iter().filter_map(norm).any(|l| {
        rights.iter().any(|r| match mode {
            RefMode::Equals => &l == r,
            RefMode::Contains => l.contains(r.as_str()),
            RefMode::StartsWith => l.starts_with(r.as_str()),
            RefMode::EndsWith => l.ends_with(r.as_str()),
        })
    })
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-eval`
Expected: 5 tests pass.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(eval): native evaluator as the semantic reference

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: zaaf-input: NDJSON and JSON-array reader

**Files:**
- Create: `crates/zaaf-input/Cargo.toml`, `crates/zaaf-input/src/lib.rs`

**Interfaces:**
- Consumes: `zaaf_event::JsonEvent` (Task 8).
- Produces:
  - `InputError { line: usize, message: String }`
  - `type EventResult = Result<JsonEvent, InputError>`
  - `read_json_events<R: BufRead + 'static>(R) -> Box<dyn Iterator<Item = EventResult>>`: format by the first non-blank byte. `[` means a JSON array; anything else is NDJSON, read line by line and streaming-safe. Blank lines are skipped. Line numbers are 1-based in the original input.
  - `open_path(&Path) -> std::io::Result<Box<dyn Iterator<Item = EventResult>>>`

- [ ] **Step 1: Write the failing tests**

`crates/zaaf-input/Cargo.toml`:
```toml
[package]
name = "zaaf-input"
description = "Log readers for ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
serde_json.workspace = true
zaaf-event.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/zaaf-input/src/lib.rs` (tests first):
```rust
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
        assert_eq!(items[2].as_ref().unwrap().get("a"), Some(vec![zaaf_event::FieldValue::Int(2)]));
    }

    #[test]
    fn json_array() {
        let items = read("  [ {\"a\": 1}, {\"a\": 2} ]");
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(Result::is_ok));
    }

    #[test]
    fn broken_json_array_is_one_error() {
        let items = read("[ {\"a\": 1}, ");
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }

    #[test]
    fn empty_input() {
        assert!(read("").is_empty());
        assert!(read("  \n \n").is_empty());
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-input`
Expected: compile errors for the missing `read_json_events` and `EventResult`.

- [ ] **Step 3: Implement** (insert above the tests):

```rust
//! Readers that turn log files into events. M1: NDJSON and JSON arrays.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use zaaf_event::JsonEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// 1-based line in the input (0 when unknown).
    pub line: usize,
    pub message: String,
}

pub type EventResult = Result<JsonEvent, InputError>;

/// Reads NDJSON (streaming) or a single top-level JSON array.
pub fn read_json_events<R: BufRead + 'static>(mut reader: R) -> Box<dyn Iterator<Item = EventResult>> {
    let mut skipped_lines = 0usize;
    let first = loop {
        let (consumed, found, newlines) = match reader.fill_buf() {
            Err(e) => {
                return Box::new(std::iter::once(Err(InputError { line: 0, message: format!("read error: {e}") })));
            }
            Ok([]) => break None,
            Ok(buf) => match buf.iter().position(|b| !b.is_ascii_whitespace()) {
                Some(pos) => (pos, Some(buf[pos]), buf[..pos].iter().filter(|b| **b == b'\n').count()),
                None => (buf.len(), None, buf.iter().filter(|b| **b == b'\n').count()),
            },
        };
        reader.consume(consumed);
        skipped_lines += newlines;
        if found.is_some() {
            break found;
        }
    };
    match first {
        None => Box::new(std::iter::empty()),
        Some(b'[') => {
            let mut data = Vec::new();
            if let Err(e) = reader.read_to_end(&mut data) {
                return Box::new(std::iter::once(Err(InputError { line: 0, message: format!("read error: {e}") })));
            }
            match serde_json::from_slice::<Vec<Value>>(&data) {
                Ok(items) => Box::new(items.into_iter().map(|v| Ok(JsonEvent::new(v)))),
                Err(e) => Box::new(std::iter::once(Err(InputError {
                    line: skipped_lines + e.line(),
                    message: format!("invalid JSON array: {e}"),
                }))),
            }
        }
        Some(_) => Box::new(reader.lines().enumerate().filter_map(move |(i, line)| {
            let line_no = skipped_lines + i + 1;
            match line {
                Err(e) => Some(Err(InputError { line: line_no, message: format!("read error: {e}") })),
                Ok(l) if l.trim().is_empty() => None,
                Ok(l) => Some(
                    serde_json::from_str::<Value>(&l)
                        .map(JsonEvent::new)
                        .map_err(|e| InputError { line: line_no, message: format!("invalid JSON: {e}") }),
                ),
            }
        })),
    }
}

pub fn open_path(path: &Path) -> std::io::Result<Box<dyn Iterator<Item = EventResult>>> {
    let file = File::open(path)?;
    Ok(read_json_events(BufReader::new(file)))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-input`
Expected: 5 tests pass.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(input): streaming NDJSON and JSON-array reader with line numbers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: zaaf-cli: rule loading and `zaaf check`

**Files:**
- Create: `crates/zaaf-cli/Cargo.toml`, `crates/zaaf-cli/src/main.rs`, `crates/zaaf-cli/src/exit.rs`, `crates/zaaf-cli/src/rules.rs`, `crates/zaaf-cli/src/check.rs`
- Test: `crates/zaaf-cli/tests/check.rs`

**Interfaces:**
- Consumes:
  - `zaaf_sigma::parse_file`
  - `zaaf_ir::{compile, SourcedDocument, CompileOutput}`
  - `PipelineSet::load`
- Produces:
  - `rules::collect_rule_files(&[PathBuf]) -> (Vec<PathBuf>, Vec<Diagnostic>)`: recursive, sorted, `.yml`/`.yaml` only. An explicitly named file is accepted whatever its extension.
  - `rules::load_rules(&[PathBuf], &PipelineSet) -> LoadedRules { output: CompileOutput, files: usize, diagnostics: Vec<Diagnostic> }`
  - `check::diagnostic_json(&Diagnostic) -> serde_json::Value`: `{severity, file, line, col, path, message}`. `line`, `col` and `path` are null for `Location::Unknown`; `path` is also null when the position has no YAML path.
  - The `zaaf check [-p PIPELINE]… [--format text|json] [-q] PATHS…` command. It exits 0 when there are no errors and 2 otherwise.
  - The JSON report: `{files, rules, filters, correlations_skipped, errors, warnings, diagnostics: [{severity, file, line, col, path, message}]}`. Task 14 relies on `files`, `diagnostics[].severity`, `diagnostics[].file` and `diagnostics[].message`.

- [ ] **Step 1: Write the failing integration tests**

`crates/zaaf-cli/Cargo.toml`:
```toml
[package]
name = "zaaf-cli"
description = "The zaaf command-line interface of ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "zaaf"
path = "src/main.rs"

[dependencies]
chrono.workspace = true
clap.workspace = true
comfy-table.workspace = true
serde_json.workspace = true
walkdir.workspace = true
zaaf-eval.workspace = true
zaaf-event.workspace = true
zaaf-input.workspace = true
zaaf-ir.workspace = true
zaaf-pipeline.workspace = true
zaaf-sigma.workspace = true

[dev-dependencies]
assert_cmd.workspace = true
predicates.workspace = true
serde_json.workspace = true
tempfile.workspace = true
```

`crates/zaaf-cli/tests/check.rs`:
```rust
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn zaaf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zaaf"))
}

const GOOD: &str = "title: Whoami\nid: r-whoami\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|contains: whoami\n    condition: sel\n";
const BAD: &str = "title: Bad\nid: r-bad\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|nope: x\n    condition: sel\n";

#[test]
fn valid_rules_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/good.yml"), GOOD).unwrap();
    fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("checked 1 files: 1 rules"));
}

#[test]
fn invalid_rule_exits_two_with_yaml_path() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bad.yml"), BAD).unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path())
        .assert()
        .code(2)
        .stdout(
            predicate::str::contains("bad.yml:7:9: detection.sel.CommandLine|nope")
                .and(predicate::str::contains("unknown modifier")),
        );
}

#[test]
fn json_report_and_correlation_warning() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("r.yml"), format!("{GOOD}---\ntitle: corr\ncorrelation:\n    type: event_count\n")).unwrap();
    let out = zaaf()
        .args(["check", "--format", "json"])
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["files"], 1);
    assert_eq!(report["rules"], 1);
    assert_eq!(report["correlations_skipped"], 1);
    let d = &report["diagnostics"][0];
    assert_eq!(d["severity"], "warning");
    assert_eq!(d["line"], 10);
    assert_eq!(d["col"], 1);
    assert!(d["path"].is_null());
    assert!(d["file"].as_str().unwrap().ends_with("r.yml"));
}

#[test]
fn json_report_carries_positions_and_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bad.yml"), BAD).unwrap();
    let out = zaaf().args(["check", "--format", "json"]).arg(dir.path()).assert().code(2).get_output().stdout.clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let d = &report["diagnostics"][0];
    assert_eq!(d["severity"], "error");
    assert_eq!(d["line"], 7);
    assert_eq!(d["col"], 9);
    assert_eq!(d["path"], "detection.sel.CommandLine|nope");
    assert!(d["message"].as_str().unwrap().contains("unknown modifier"));
}

#[test]
fn missing_path_and_bad_pipeline() {
    zaaf()
        .args(["check", "/nonexistent/rules"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("path does not exist"));
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("good.yml"), GOOD).unwrap();
    fs::write(dir.path().join("p.yml"), "name: [").unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path().join("good.yml"))
        .arg("-p")
        .arg(dir.path().join("p.yml"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid pipeline"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-cli --test check`
Expected: build failure. `src/main.rs` does not exist yet, so the `zaaf` binary target cannot be built.

- [ ] **Step 3: Implement**

`crates/zaaf-cli/src/exit.rs`:
```rust
//! Process exit codes (design spec §4).

pub const OK: u8 = 0;
/// Rule errors. Usage errors share this code, as with clap.
pub const RULE_ERRORS: u8 = 2;
pub const INTERNAL: u8 = 4;
```

`crates/zaaf-cli/src/rules.rs`:
```rust
//! Locating, parsing and compiling rule files.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zaaf_ir::{CompileOutput, SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{Diagnostic, Location};

pub struct LoadedRules {
    pub output: CompileOutput,
    pub files: usize,
    pub diagnostics: Vec<Diagnostic>,
}

fn is_yaml(p: &Path) -> bool {
    matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml"))
}

pub fn collect_rule_files(paths: &[PathBuf]) -> (Vec<PathBuf>, Vec<Diagnostic>) {
    let mut files = Vec::new();
    let mut diags = Vec::new();
    for p in paths {
        if p.is_file() {
            files.push(p.clone());
        } else if p.is_dir() {
            for entry in WalkDir::new(p).sort_by_file_name() {
                match entry {
                    Ok(e) if e.file_type().is_file() && is_yaml(e.path()) => files.push(e.into_path()),
                    Ok(_) => {}
                    Err(e) => diags.push(
                        Diagnostic::error(Location::Unknown, format!("cannot read directory: {e}")).with_file(p.clone()),
                    ),
                }
            }
        } else {
            diags.push(Diagnostic::error(Location::Unknown, "path does not exist").with_file(p.clone()));
        }
    }
    (files, diags)
}

pub fn load_rules(paths: &[PathBuf], pipelines: &PipelineSet) -> LoadedRules {
    let (files, mut diagnostics) = collect_rule_files(paths);
    let mut docs = Vec::new();
    for f in &files {
        let parsed = zaaf_sigma::parse_file(f);
        diagnostics.extend(parsed.diagnostics);
        docs.extend(
            parsed.documents.into_iter().map(|document| SourcedDocument { document, source: Some(f.clone()) }),
        );
    }
    let mut output = compile(docs, pipelines);
    diagnostics.append(&mut output.diagnostics);
    LoadedRules { output, files: files.len(), diagnostics }
}
```

`crates/zaaf-cli/src/check.rs`:
```rust
//! `zaaf check`: parse, compile and lint rules.

use crate::exit;
use crate::rules::load_rules;
use clap::{Args, ValueEnum};
use serde_json::{Value, json};
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
        Location::At { line, col, path } => (Some(*line), Some(*col), (!path.is_empty()).then_some(path.as_str())),
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
            eprintln!("{d}");
            return exit::RULE_ERRORS;
        }
    };
    let loaded = load_rules(&args.paths, &pipelines);
    let errors = loaded.diagnostics.iter().filter(|d| d.is_error()).count();
    let warnings = loaded.diagnostics.len() - errors;
    let shown = loaded.diagnostics.iter().filter(|d| d.is_error() || !args.quiet);
    match args.format {
        DiagFormat::Text => {
            for d in shown {
                println!("{d}");
            }
            println!(
                "checked {} files: {} rules, {} filters, {} correlations skipped, {errors} errors, {warnings} warnings",
                loaded.files,
                loaded.output.rules.len(),
                loaded.output.filters,
                loaded.output.correlations_skipped
            );
        }
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
            println!("{}", serde_json::to_string_pretty(&report).expect("a JSON value always serializes"));
        }
    }
    if errors > 0 { exit::RULE_ERRORS } else { exit::OK }
}
```

`crates/zaaf-cli/src/main.rs`:
```rust
//! `zaaf`: the ZAAFElegia command-line interface.

mod check;
mod exit;
mod rules;

use clap::{Parser, Subcommand};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "zaaf", version, about = "ZAAFElegia: Sigma-native detection engine")]
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-cli --test check`
Expected: 5 tests pass.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(cli): zaaf check with recursive rule loading and JSON report

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: zaaf-cli: `zaaf hunt` and OCSF Detection Finding output

**Files:**
- Create: `crates/zaaf-cli/src/output.rs`, `crates/zaaf-cli/src/hunt.rs`
- Modify: `crates/zaaf-cli/src/exit.rs` (add `MATCHES`, `INPUT_ERRORS`), `crates/zaaf-cli/src/main.rs` (add the `Hunt` subcommand and modules)
- Test: `crates/zaaf-cli/tests/hunt.rs` (unit tests live in `output.rs`)

**Interfaces:**
- Consumes:
  - `Evaluator::{new, rules, matching_rules}` (Task 9)
  - `read_json_events`, `open_path`, `EventResult` (Task 10)
  - `Event::{timestamp, to_json}`, `parse_timestamp` (Task 8)
  - `Level`, `CompiledRule` (Task 7)
  - `load_rules` (Task 11)
- Produces:
  - `output::OutputFormat::{Table, Json, Ndjson, Csv}`
  - `output::detection_finding(&CompiledRule, &dyn Event, source: &str, seq: u64) -> serde_json::Value`
  - `output::Sink<W: Write>`:
    - `Sink::new(OutputFormat, W)`
    - `.write(Value) -> io::Result<()>`
    - `.finish() -> io::Result<()>`
  - `zaaf hunt` with these options: `-r RULES…`, `-p PIPELINE…`, `-o table|json|ndjson|csv`, `--min-level`, `--status a,b`, `--from/--to`, `--fail-on-match`, `--strict`, `--max-errors N` (default 1000), `-v`, and `INPUTS…` (where `-` or no inputs means stdin).
  - Summary on stderr: `<events> events, <n> malformed records, <rules> rules, <m> matches`.

- [ ] **Step 1: Write the failing tests**

Unit tests at the bottom of `crates/zaaf-cli/src/output.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use zaaf_event::JsonEvent;
    use zaaf_ir::{Expr, RuleInfo};

    fn rule() -> CompiledRule {
        CompiledRule {
            info: RuleInfo {
                id: "r1".into(),
                name: None,
                title: "T, \"quoted\"".into(),
                level: Level::High,
                status: Some("test".into()),
                description: None,
                author: Some("Ann".into()),
                references: vec!["https://x".into()],
                tags: vec!["attack.t1059".into()],
                falsepositives: vec![],
                logsource: Default::default(),
                source: None,
            },
            expr: Expr::And(vec![]),
        }
    }

    #[test]
    fn finding_has_ocsf_core_fields_and_attribution() {
        let ev = JsonEvent::new(serde_json::json!({"@timestamp": "2026-11-07T03:15:00Z"}));
        let f = detection_finding(&rule(), &ev, "a.ndjson", 7);
        assert_eq!(f["class_uid"], 2004);
        assert_eq!(f["type_uid"], 200401);
        assert_eq!(f["severity_id"], 4);
        assert_eq!(f["finding_info"]["uid"], "r1:7");
        assert_eq!(f["finding_info"]["analytic"]["uid"], "r1");
        assert_eq!(f["unmapped"]["sigma"]["author"], "Ann");
        assert_eq!(f["unmapped"]["sigma"]["references"][0], "https://x");
        assert_eq!(f["unmapped"]["source"], "a.ndjson");
        assert_eq!(f["time"], 1_794_021_300_000_i64);
    }

    #[test]
    fn csv_has_header_and_escapes() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Csv, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s", 1)).unwrap();
            sink.finish().unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("time,level,rule_id,title,source\n"), "{text}");
        assert!(text.contains("\"T, \"\"quoted\"\"\""), "{text}");
    }

    #[test]
    fn json_output_is_one_array() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
        {
            let mut sink = Sink::new(OutputFormat::Json, &mut buf);
            sink.write(detection_finding(&rule(), &ev, "s", 1)).unwrap();
            sink.write(detection_finding(&rule(), &ev, "s", 2)).unwrap();
            sink.finish().unwrap();
        }
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
    }
}
```

`crates/zaaf-cli/tests/hunt.rs`:
```rust
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;

fn zaaf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zaaf"))
}

const WHOAMI: &str = "title: Whoami\nid: r-whoami\nauthor: Tester\nreferences:\n    - https://example.com/ref\nstatus: test\nlevel: medium\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|contains: whoami\n    condition: sel\n";
const MIMI: &str = "title: Mimikatz\nid: r-mimi\nstatus: stable\nlevel: critical\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|contains: sekurlsa\n    condition: sel\n";
const EVENTS: &str = "{\"@timestamp\": \"2026-11-07T01:00:00Z\", \"CommandLine\": \"cmd /c whoami\"}\n{\"@timestamp\": \"2026-11-07T02:00:00Z\", \"CommandLine\": \"mimikatz sekurlsa::logonpasswords\"}\n{\"@timestamp\": \"2026-11-07T03:00:00Z\", \"CommandLine\": \"dir\"}\n";

fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(dir.path().join("rules/whoami.yml"), WHOAMI).unwrap();
    fs::write(dir.path().join("rules/mimi.yml"), MIMI).unwrap();
    fs::write(dir.path().join("events.ndjson"), EVENTS).unwrap();
    dir
}

fn hunt(dir: &Path) -> Command {
    let mut c = zaaf();
    c.arg("hunt").arg("-r").arg(dir.join("rules")).arg(dir.join("events.ndjson"));
    c
}

#[test]
fn ndjson_findings_with_attribution() {
    let dir = setup();
    let out = hunt(dir.path()).args(["-o", "ndjson"]).assert().success().get_output().stdout.clone();
    let findings: Vec<serde_json::Value> =
        String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(findings.len(), 2);
    let whoami = findings.iter().find(|f| f["finding_info"]["analytic"]["uid"] == "r-whoami").unwrap();
    assert_eq!(whoami["class_uid"], 2004);
    assert_eq!(whoami["unmapped"]["sigma"]["author"], "Tester");
    assert_eq!(whoami["unmapped"]["sigma"]["references"][0], "https://example.com/ref");
    assert_eq!(whoami["evidences"][0]["data"]["CommandLine"], "cmd /c whoami");
}

#[test]
fn fail_on_match_and_rule_and_time_filters() {
    let dir = setup();
    hunt(dir.path()).arg("--fail-on-match").assert().code(1);
    hunt(dir.path())
        .args(["--min-level", "high", "-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("r-mimi").and(predicate::str::contains("r-whoami").not()));
    hunt(dir.path())
        .args(["--status", "test", "-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("r-whoami").and(predicate::str::contains("r-mimi").not()));
    hunt(dir.path())
        .args(["--from", "2026-11-07T01:30:00Z", "-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("r-mimi").and(predicate::str::contains("r-whoami").not()));
}

#[test]
fn reads_stdin_and_renders_a_table() {
    let dir = setup();
    zaaf()
        .arg("hunt")
        .arg("-r")
        .arg(dir.path().join("rules"))
        .args(["-o", "table", "-"])
        .write_stdin("{\"CommandLine\": \"WHOAMI /all\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("r-whoami"))
        .stderr(predicate::str::contains("1 events"));
}

#[test]
fn malformed_input_and_strict_modes() {
    let dir = setup();
    fs::write(dir.path().join("events.ndjson"), "{\"CommandLine\": \"whoami\"}\nnot json\n").unwrap();
    hunt(dir.path()).assert().success().stderr(predicate::str::contains(":2: invalid JSON"));
    hunt(dir.path()).arg("--strict").assert().code(3);
    hunt(dir.path()).args(["--max-errors", "0"]).assert().code(3);
    fs::write(
        dir.path().join("rules/bad.yml"),
        "title: bad\nlogsource:\n    product: x\ndetection:\n    s:\n        A|nope: 1\n    condition: s\n",
    )
    .unwrap();
    hunt(dir.path()).arg("--strict").assert().code(2);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-cli`
Expected: `tests/hunt.rs` fails with `unrecognized subcommand 'hunt'`. The unit tests do not compile yet because `output.rs` is not declared in `main.rs`; Step 3 adds it.

- [ ] **Step 3: Implement**

Replace `crates/zaaf-cli/src/exit.rs`:
```rust
//! Process exit codes (design spec §4).

pub const OK: u8 = 0;
pub const MATCHES: u8 = 1;
/// Rule errors. Usage errors share this code, as with clap.
pub const RULE_ERRORS: u8 = 2;
pub const INPUT_ERRORS: u8 = 3;
pub const INTERNAL: u8 = 4;
```

`crates/zaaf-cli/src/output.rs` (insert above the tests):
```rust
//! Alert rendering: OCSF Detection Finding (class 2004) and table/CSV views.

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde_json::{Value, json};
use std::io::{self, Write};
use zaaf_event::Event;
use zaaf_ir::{CompiledRule, Level};

pub const OCSF_VERSION: &str = "1.5.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Ndjson,
    Csv,
}

fn severity_name(level: Level) -> &'static str {
    match level {
        Level::Informational => "Informational",
        Level::Low => "Low",
        Level::Medium => "Medium",
        Level::High => "High",
        Level::Critical => "Critical",
    }
}

/// One OCSF Detection Finding per (rule, event) match. `author` and `references`
/// are always included (DRL 1.1 attribution).
pub fn detection_finding(rule: &CompiledRule, event: &dyn Event, source: &str, seq: u64) -> Value {
    let info = &rule.info;
    let time = event.timestamp().unwrap_or_else(Utc::now).timestamp_millis();
    json!({
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": info.level.ocsf_severity_id(),
        "severity": severity_name(info.level),
        "status_id": 1,
        "status": "New",
        "time": time,
        "message": info.title,
        "finding_info": {
            "uid": format!("{}:{seq}", info.id),
            "title": info.title,
            "desc": info.description,
            "types": info.tags,
            "analytic": { "uid": info.id, "name": info.title, "type_id": 1, "type": "Rule" }
        },
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "ZAAFElegia",
                "vendor_name": "ZAAFElegia project",
                "version": env!("CARGO_PKG_VERSION")
            }
        },
        "evidences": [ { "data": event.to_json() } ],
        "unmapped": {
            "source": source,
            "sigma": {
                "level": info.level.as_str(),
                "status": info.status,
                "author": info.author,
                "references": info.references,
                "falsepositives": info.falsepositives,
                "logsource": {
                    "category": info.logsource.category,
                    "product": info.logsource.product,
                    "service": info.logsource.service
                },
                "rule_file": info.source.as_ref().map(|p| p.display().to_string())
            }
        }
    })
}

/// Writes findings. NDJSON and CSV stream; table and JSON are buffered until `finish`.
pub struct Sink<W: Write> {
    format: OutputFormat,
    out: W,
    buffered: Vec<Value>,
    rows: Vec<[String; 5]>,
    wrote_header: bool,
}

impl<W: Write> Sink<W> {
    pub fn new(format: OutputFormat, out: W) -> Self {
        Self { format, out, buffered: Vec::new(), rows: Vec::new(), wrote_header: false }
    }

    pub fn write(&mut self, finding: Value) -> io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => {
                serde_json::to_writer(&mut self.out, &finding)?;
                self.out.write_all(b"\n")
            }
            OutputFormat::Json => {
                self.buffered.push(finding);
                Ok(())
            }
            OutputFormat::Table => {
                self.rows.push(row(&finding));
                Ok(())
            }
            OutputFormat::Csv => {
                if !self.wrote_header {
                    writeln!(self.out, "time,level,rule_id,title,source")?;
                    self.wrote_header = true;
                }
                let cells: Vec<String> = row(&finding).iter().map(|c| csv_field(c)).collect();
                writeln!(self.out, "{}", cells.join(","))
            }
        }
    }

    pub fn finish(mut self) -> io::Result<()> {
        match self.format {
            OutputFormat::Json => {
                serde_json::to_writer_pretty(&mut self.out, &self.buffered)?;
                writeln!(self.out)?;
            }
            OutputFormat::Table if !self.rows.is_empty() => {
                let mut table = comfy_table::Table::new();
                table.set_header(vec!["Time", "Level", "Rule", "Title", "Source"]);
                for r in &self.rows {
                    table.add_row(r.to_vec());
                }
                writeln!(self.out, "{table}")?;
            }
            _ => {}
        }
        self.out.flush()
    }
}

fn row(f: &Value) -> [String; 5] {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let time = f["time"]
        .as_i64()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    [
        time,
        s(&f["unmapped"]["sigma"]["level"]),
        s(&f["finding_info"]["analytic"]["uid"]),
        s(&f["finding_info"]["title"]),
        s(&f["unmapped"]["source"]),
    ]
}

fn csv_field(s: &str) -> String {
    if s.contains(&[',', '"', '\n'][..]) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}
```

`crates/zaaf-cli/src/hunt.rs`:
```rust
//! `zaaf hunt`: run rules over log events.

use crate::exit;
use crate::output::{OutputFormat, Sink, detection_finding};
use crate::rules::load_rules;
use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use zaaf_eval::Evaluator;
use zaaf_event::{Event, parse_timestamp};
use zaaf_input::{EventResult, open_path, read_json_events};
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
    /// Output format [default: table on a terminal, ndjson otherwise]
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
    /// Also print rule warnings
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Default)]
struct Stats {
    events: u64,
    input_errors: usize,
    matches: u64,
}

fn bound(value: &Option<String>, flag: &str) -> Result<Option<DateTime<Utc>>, String> {
    match value {
        None => Ok(None),
        Some(s) => parse_timestamp(s).map(Some).ok_or_else(|| format!("--{flag}: cannot parse `{s}` as a timestamp")),
    }
}

fn keep(rule: &CompiledRule, min: Option<Level>, statuses: &[String]) -> bool {
    min.is_none_or(|m| rule.info.level >= m)
        && (statuses.is_empty()
            || rule.info.status.as_deref().is_some_and(|s| statuses.iter().any(|w| w.eq_ignore_ascii_case(s))))
}

fn write_failed(e: io::Error) -> u8 {
    if e.kind() == io::ErrorKind::BrokenPipe {
        exit::OK
    } else {
        eprintln!("error: cannot write output: {e}");
        exit::INTERNAL
    }
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
            eprintln!("{d}");
        }
    }
    if rule_errors > 0 && args.strict {
        eprintln!("error: {rule_errors} rule errors (--strict)");
        return exit::RULE_ERRORS;
    }
    let min = args.min_level.map(Level::from);
    let rules: Vec<CompiledRule> = loaded.output.rules.into_iter().filter(|r| keep(r, min, &args.status)).collect();
    if rules.is_empty() {
        eprintln!("error: no rules to run");
        return exit::RULE_ERRORS;
    }
    let rule_count = rules.len();
    let evaluator = Evaluator::new(rules);
    let format =
        args.output.unwrap_or(if io::stdout().is_terminal() { OutputFormat::Table } else { OutputFormat::Ndjson });
    let mut sink = Sink::new(format, io::stdout().lock());

    let inputs: Vec<Option<PathBuf>> = if args.inputs.is_empty() {
        vec![None]
    } else {
        args.inputs.iter().map(|p| (p.as_os_str() != "-").then(|| p.clone())).collect()
    };
    let mut stats = Stats::default();
    for input in inputs {
        let (name, events): (String, io::Result<Box<dyn Iterator<Item = EventResult>>>) = match &input {
            None => ("<stdin>".to_string(), Ok(read_json_events(io::stdin().lock()))),
            Some(p) => (p.display().to_string(), open_path(p)),
        };
        let events = match events {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {name}: {e}");
                stats.input_errors += 1;
                continue;
            }
        };
        for item in events {
            let event = match item {
                Ok(ev) => ev,
                Err(e) => {
                    stats.input_errors += 1;
                    if stats.input_errors <= 5 {
                        eprintln!("warning: {name}:{}: {}", e.line, e.message);
                    }
                    if stats.input_errors > args.max_errors {
                        eprintln!("error: more than {} malformed records, aborting", args.max_errors);
                        if let Err(e) = sink.finish() {
                            return write_failed(e);
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
                continue;
            }
            for idx in evaluator.matching_rules(&event) {
                stats.matches += 1;
                let finding = detection_finding(&evaluator.rules()[idx], &event, &name, stats.matches);
                if let Err(e) = sink.write(finding) {
                    return write_failed(e);
                }
            }
        }
    }
    if let Err(e) = sink.finish() {
        return write_failed(e);
    }
    eprintln!(
        "{} events, {} malformed records, {rule_count} rules, {} matches",
        stats.events, stats.input_errors, stats.matches
    );
    if args.strict && stats.input_errors > 0 {
        return exit::INPUT_ERRORS;
    }
    if args.fail_on_match && stats.matches > 0 { exit::MATCHES } else { exit::OK }
}
```

Replace `crates/zaaf-cli/src/main.rs`:
```rust
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
#[command(name = "zaaf", version, about = "ZAAFElegia: Sigma-native detection engine")]
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
    let code = catch_unwind(AssertUnwindSafe(|| match cli.command {
        Command::Check(args) => check::run(args),
        Command::Hunt(args) => hunt::run(args),
    }))
    .unwrap_or(exit::INTERNAL);
    ExitCode::from(code)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p zaaf-cli`
Expected: 3 output unit tests, 5 check tests and 4 hunt tests pass. Also try it by hand: `printf '{"CommandLine":"whoami"}\n' | cargo run -q -p zaaf-cli -- hunt -r <dir-with-WHOAMI-rule> -o table` renders a one-row table.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(cli): zaaf hunt with OCSF Detection Finding output, filters and exit codes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: zaaf-testkit and the single-event conformance suite

**Files:**
- Create: `crates/zaaf-testkit/Cargo.toml`, `crates/zaaf-testkit/src/lib.rs`, `crates/zaaf-testkit/tests/conformance.rs`, `crates/zaaf-testkit/tests/runner.rs`
- Create: `conformance/README.md` and the 25 case directories `conformance/cases/NNN-*/` listed in Step 4

**Interfaces:**
- Consumes:
  - `zaaf_sigma::parse_file`
  - `zaaf_ir::{compile, SourcedDocument}`
  - `PipelineSet::load`
  - `Evaluator`
  - `read_json_events`
- Produces:
  - `CaseSpec { spec_ref, description, pipelines: Vec<String>, compile_errors: usize, expected: Vec<Vec<String>> }`
  - `CaseResult { name, failures: Vec<String> }`, with `.passed()`
  - `run_case(&Path) -> CaseResult`
  - `run_suite(&Path) -> Result<Vec<CaseResult>, String>`
- Case format. Each case is a directory containing:
  - `case.yml`, holding `spec_ref`, `description`, optionally `pipelines` (files relative to the case), `compile_errors` (default 0), and `expected`: one list of matching rule ids per event, in event order.
  - `rules/*.yml`
  - `events.ndjson`

- [ ] **Step 1: Write the failing runner test**

`crates/zaaf-testkit/Cargo.toml`:
```toml
[package]
name = "zaaf-testkit"
description = "Conformance and detection-as-code test harness for ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
serde-saphyr.workspace = true
zaaf-eval.workspace = true
zaaf-input.workspace = true
zaaf-ir.workspace = true
zaaf-pipeline.workspace = true
zaaf-sigma.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/zaaf-testkit/tests/runner.rs`:
```rust
use std::fs;

fn write_case(expected: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(
        dir.path().join("rules/r.yml"),
        "title: r\nid: r\nlogsource: {product: t}\ndetection:\n    s:\n        A: x\n    condition: s\n",
    )
    .unwrap();
    fs::write(dir.path().join("events.ndjson"), "{\"A\": \"x\"}\n{\"A\": \"y\"}\n").unwrap();
    fs::write(
        dir.path().join("case.yml"),
        format!("spec_ref: test\ndescription: runner self-test\nexpected:\n{expected}"),
    )
    .unwrap();
    dir
}

#[test]
fn passing_case_passes() {
    let dir = write_case("  - [r]\n  - []\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert!(result.passed(), "{:?}", result.failures);
}

#[test]
fn wrong_expectation_is_reported() {
    let dir = write_case("  - []\n  - [r]\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert_eq!(result.failures.len(), 2, "{:?}", result.failures);
    assert!(result.failures[0].contains("event 0"));
}

#[test]
fn event_count_mismatch_is_reported() {
    let dir = write_case("  - [r]\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert!(result.failures[0].contains("2 events but 1 expected"), "{:?}", result.failures);
}
```

`crates/zaaf-testkit/tests/conformance.rs`:
```rust
use std::path::Path;

#[test]
fn conformance_suite_passes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases");
    let results = zaaf_testkit::run_suite(&root).expect("conformance/cases is readable");
    assert!(results.len() >= 25, "expected at least 25 cases, found {}", results.len());
    let failed: Vec<_> = results.iter().filter(|r| !r.passed()).collect();
    for f in &failed {
        eprintln!("FAIL {}:\n  {}", f.name, f.failures.join("\n  "));
    }
    assert!(failed.is_empty(), "{} of {} conformance cases failed", failed.len(), results.len());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p zaaf-testkit`
Expected: compile error for the missing `zaaf_testkit::run_case`.

- [ ] **Step 3: Implement** `crates/zaaf-testkit/src/lib.rs`:

```rust
//! Runs the language-neutral Sigma conformance suite against the native evaluator.

use serde::Deserialize;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use zaaf_eval::Evaluator;
use zaaf_input::read_json_events;
use zaaf_ir::{SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Specification section(s) this case pins down.
    pub spec_ref: String,
    /// What is tested, including any interpretation of an ambiguous spec point.
    pub description: String,
    /// Pipeline files relative to the case directory.
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Number of rule errors (parse + compile) the case expects.
    #[serde(default)]
    pub compile_errors: usize,
    /// For each event, the ids of the rules that must match it (order irrelevant).
    pub expected: Vec<Vec<String>>,
}

#[derive(Debug)]
pub struct CaseResult {
    pub name: String,
    pub failures: Vec<String>,
}

impl CaseResult {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Runs every sub-directory of `root` that contains a `case.yml`, sorted by name.
pub fn run_suite(root: &Path) -> Result<Vec<CaseResult>, String> {
    let entries = fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("case.yml").is_file())
        .collect();
    dirs.sort();
    Ok(dirs.iter().map(|d| run_case(d)).collect())
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

pub fn run_case(dir: &Path) -> CaseResult {
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let fail = |msg: String| CaseResult { name: name.clone(), failures: vec![msg] };

    let spec: CaseSpec = match fs::read_to_string(dir.join("case.yml"))
        .map_err(|e| e.to_string())
        .and_then(|s| serde_saphyr::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => return fail(format!("case.yml: {e}")),
    };
    let pipeline_paths: Vec<PathBuf> = spec.pipelines.iter().map(|p| dir.join(p)).collect();
    let pipelines = match PipelineSet::load(&pipeline_paths) {
        Ok(p) => p,
        Err(d) => return fail(d.to_string()),
    };

    let mut docs = Vec::new();
    let mut errors = Vec::new();
    for f in yaml_files(&dir.join("rules")) {
        let parsed = zaaf_sigma::parse_file(&f);
        errors.extend(parsed.diagnostics.into_iter().filter(|d| d.is_error()));
        docs.extend(parsed.documents.into_iter().map(|document| SourcedDocument { document, source: Some(f.clone()) }));
    }
    let out = compile(docs, &pipelines);
    errors.extend(out.diagnostics.into_iter().filter(|d| d.is_error()));

    let mut failures = Vec::new();
    if errors.len() != spec.compile_errors {
        let listed: Vec<String> = errors.iter().map(|d| d.to_string()).collect();
        failures.push(format!("expected {} rule errors, got {}: {listed:#?}", spec.compile_errors, errors.len()));
    }

    let file = match fs::File::open(dir.join("events.ndjson")) {
        Ok(f) => f,
        Err(e) => return fail(format!("events.ndjson: {e}")),
    };
    let mut events = Vec::new();
    for item in read_json_events(BufReader::new(file)) {
        match item {
            Ok(e) => events.push(e),
            Err(e) => return fail(format!("events.ndjson:{}: {}", e.line, e.message)),
        }
    }
    if events.len() != spec.expected.len() {
        failures.push(format!("{} events but {} expected entries", events.len(), spec.expected.len()));
        return CaseResult { name, failures };
    }

    let evaluator = Evaluator::new(out.rules);
    for (i, (event, want)) in events.iter().zip(&spec.expected).enumerate() {
        let mut got: Vec<String> =
            evaluator.matching_rules(event).into_iter().map(|r| evaluator.rules()[r].info.id.clone()).collect();
        got.sort();
        let mut want = want.clone();
        want.sort();
        if got != want {
            failures.push(format!("event {i}: expected {want:?}, got {got:?}"));
        }
    }
    CaseResult { name, failures }
}
```

- [ ] **Step 4: Create the conformance cases**

Create the files exactly as listed. In `events.ndjson` each line is one JSON object; JSON `\\` is one backslash.

`conformance/README.md`:
````markdown
# Sigma conformance suite

A language-neutral test suite for Sigma 2.1 rule semantics. Any engine can run it:
load `rules/*.yml` (plus `pipelines` from `case.yml`, if any), evaluate every line of
`events.ndjson`, and compare the matching rule ids with `expected` in `case.yml`.

| File | Content |
|---|---|
| `case.yml` | `spec_ref` (spec section), `description` (what is tested, including any interpretation of an ambiguous point), optional `pipelines` and `compile_errors`, and `expected`: one list of rule ids per event |
| `rules/*.yml` | Standard Sigma rules (no extensions) |
| `events.ndjson` | One JSON event per line |

Interpretations used where the specification is silent (each is pinned by a case):

1. Keyword values match as `contains` over every value of the event (case 008).
2. `field: null` matches an absent field or a JSON null; `exists` checks presence only (009, 010).
3. `neq` is a negation, so an absent field satisfies it (012).
4. Regular expressions are unanchored searches; `re` is case-sensitive unless `|i` is given (003, 013).
5. Encoded values (`base64`, `base64offset`, `wide`) are matched case-insensitively like every other string (016, 017).
6. Field paths resolve an exact dotted key first, then nested objects; arrays match if any element matches (023).

Other engines are welcome to run the suite and to propose new cases or challenge an interpretation by opening an issue.
````

`conformance/cases/001-map-and-list/case.yml`:
```yaml
spec_ref: 'sigma-rules-specification.md#maps, #lists'
description: Map entries are AND-ed, list values are OR-ed; integers match their text form; matching is case-insensitive.
expected:
  - [c001]
  - [c001]
  - []
  - []
```
`conformance/cases/001-map-and-list/rules/c001.yml`:
```yaml
title: map AND, list OR
id: c001
logsource: {product: test}
detection:
    selection:
        EventID:
            - 4688
            - 1
        Image: 'C:\Windows\System32\cmd.exe'
    condition: selection
```
`conformance/cases/001-map-and-list/events.ndjson`:
```
{"EventID": 4688, "Image": "C:\\Windows\\System32\\cmd.exe"}
{"EventID": "1", "Image": "c:\\windows\\system32\\CMD.EXE"}
{"EventID": 4689, "Image": "C:\\Windows\\System32\\cmd.exe"}
{"EventID": 4688}
```

`conformance/cases/002-list-of-maps/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#lists
description: A list of maps is an OR of the maps.
expected:
  - [c002]
  - [c002]
  - []
```
`rules/c002.yml`:
```yaml
title: list of maps
id: c002
logsource: {product: test}
detection:
    selection:
        - Image|endswith: '\example.exe'
        - Description|contains: 'Test executable'
    condition: selection
```
`events.ndjson`:
```
{"Image": "C:\\x\\example.exe"}
{"Description": "A test Executable here"}
{"Image": "example.exe"}
```

`conformance/cases/003-case-sensitivity/case.yml`:
```yaml
spec_ref: 'sigma-rules-specification.md#general; sigma-appendix-modifiers.md#generic-modifiers (cased), #regular-expression'
description: Strings are case-insensitive by default; `cased` makes them sensitive; `re` is case-sensitive unless `|i`.
expected:
  - [c003-default, c003-re-i]
  - [c003-cased, c003-default, c003-re, c003-re-i]
  - []
```
`rules/default.yml`:
```yaml
title: default
id: c003-default
logsource: {product: test}
detection:
    s:
        User: admin
    condition: s
```
`rules/cased.yml`:
```yaml
title: cased
id: c003-cased
logsource: {product: test}
detection:
    s:
        User|cased: Admin
    condition: s
```
`rules/re.yml`:
```yaml
title: re
id: c003-re
logsource: {product: test}
detection:
    s:
        User|re: '^Admin$'
    condition: s
```
`rules/re-i.yml`:
```yaml
title: re i
id: c003-re-i
logsource: {product: test}
detection:
    s:
        User|re|i: '^admin$'
    condition: s
```
`events.ndjson`:
```
{"User": "ADMIN"}
{"User": "Admin"}
{"User": "admin2"}
```

`conformance/cases/004-wildcards/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#string-wildcard
description: '`*` matches any run of characters (including path separators), `?` exactly one.'
expected:
  - [c004-q, c004-star]
  - [c004-star]
  - []
```
`rules/star.yml`:
```yaml
title: star
id: c004-star
logsource: {product: test}
detection:
    s:
        Image: 'C:\Tools\\*.exe'
    condition: s
```
`rules/q.yml`:
```yaml
title: question mark
id: c004-q
logsource: {product: test}
detection:
    s:
        Name: 'prog?.exe'
    condition: s
```
`events.ndjson`:
```
{"Image": "C:\\Tools\\a.exe", "Name": "progA.exe"}
{"Image": "C:\\Tools\\sub\\b.exe", "Name": "progAB.exe"}
{"Image": "D:\\Tools\\a.exe", "Name": "prog.exe"}
```

`conformance/cases/005-escaping/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#escape-character
description: '`\*` is a literal star; `\\*` is a backslash then a wildcard; `\\\*` is backslash + literal star; three or four backslashes are two; a backslash before other characters is literal.'
expected:
  - [c005-lit-star]
  - []
  - [c005-bs-star]
  - [c005-bs-star, c005-triple]
  - [c005-bs-star, c005-quad]
  - [c005-bs-star, c005-single]
```
`rules/lit-star.yml`:
```yaml
title: escaped star
id: c005-lit-star
logsource: {product: test}
detection:
    s:
        Value: 'a\*b'
    condition: s
```
`rules/bs-star.yml`:
```yaml
title: backslash then wildcard
id: c005-bs-star
logsource: {product: test}
detection:
    s:
        Value: 'a\\*'
    condition: s
```
`rules/triple.yml`:
```yaml
title: backslash and literal star
id: c005-triple
logsource: {product: test}
detection:
    s:
        Value: 'a\\\*'
    condition: s
```
`rules/quad.yml`:
```yaml
title: four backslashes
id: c005-quad
logsource: {product: test}
detection:
    s:
        Value: 'a\\\\b'
    condition: s
```
`rules/single.yml`:
```yaml
title: plain backslash
id: c005-single
logsource: {product: test}
detection:
    s:
        Value: 'a\b'
    condition: s
```
`events.ndjson`:
```
{"Value": "a*b"}
{"Value": "axb"}
{"Value": "a\\anything"}
{"Value": "a\\*"}
{"Value": "a\\\\b"}
{"Value": "a\\b"}
```

`conformance/cases/006-contains-startswith-endswith/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#generic-modifiers
description: contains / startswith / endswith, case-insensitive.
expected:
  - [c006-c, c006-e, c006-s]
  - []
  - []
```
`rules/c.yml`:
```yaml
title: contains
id: c006-c
logsource: {product: test}
detection:
    s:
        CommandLine|contains: whoami
    condition: s
```
`rules/s.yml`:
```yaml
title: startswith
id: c006-s
logsource: {product: test}
detection:
    s:
        CommandLine|startswith: powershell
    condition: s
```
`rules/e.yml`:
```yaml
title: endswith
id: c006-e
logsource: {product: test}
detection:
    s:
        CommandLine|endswith: '.ps1'
    condition: s
```
`events.ndjson`:
```
{"CommandLine": "PowerShell -c Whoami; run.PS1"}
{"CommandLine": "cmd /c echo"}
{"CommandLine": "x powershell"}
```

`conformance/cases/007-all-modifier/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#generic-modifiers (all)
description: '`all` turns the OR between values into AND.'
expected:
  - [c007]
  - []
```
`rules/c007.yml`:
```yaml
title: all
id: c007
logsource: {product: test}
detection:
    s:
        CommandLine|contains|all:
            - '-enc'
            - 'bypass'
    condition: s
```
`events.ndjson`:
```
{"CommandLine": "powershell -ep Bypass -enc AAA"}
{"CommandLine": "powershell -enc AAA"}
```

`conformance/cases/008-keywords/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#keywords-search
description: Keyword lists are OR-ed `contains` searches over every value of the event (interpretation 1); `'|all'` requires every keyword somewhere in the event, not necessarily in the same field.
expected:
  - [c008-kw]
  - [c008-all]
  - [c008-all]
  - []
```
`rules/kw.yml`:
```yaml
title: keywords
id: c008-kw
logsource: {product: test}
detection:
    keywords:
        - 'event::clear'
        - 'event::drop'
    condition: keywords
```
`rules/all.yml`:
```yaml
title: keywords all
id: c008-all
logsource: {product: test}
detection:
    keywords_cmdlet:
        '|all':
            - 'OabVirtualDirectory'
            - ' -ExternalUrl '
    condition: keywords_cmdlet
```
`events.ndjson`:
```
{"msg": "mimikatz event::clear done"}
{"a": {"b": ["x", "Set-OabVirtualDirectory -ExternalUrl http://x"]}}
{"a": "OabVirtualDirectory", "b": "x -ExternalUrl y"}
{"a": "nothing"}
```

`conformance/cases/009-null-and-empty/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#special-field-values
description: '`null` matches an absent field or a JSON null (interpretation 2); `''''` matches only the empty string.'
expected:
  - [c009-null]
  - []
  - []
  - [c009-empty, c009-null]
```
`rules/null.yml`:
```yaml
title: not null
id: c009-null
logsource: {product: test}
detection:
    selection:
        EventID: 4738
    filter:
        PasswordLastSet: null
    condition: selection and not filter
```
`rules/empty.yml`:
```yaml
title: empty
id: c009-empty
logsource: {product: test}
detection:
    s:
        Field: ''
    condition: s
```
`events.ndjson`:
```
{"EventID": 4738, "PasswordLastSet": "2024"}
{"EventID": 4738, "PasswordLastSet": null}
{"EventID": 4738}
{"EventID": 4738, "PasswordLastSet": "x", "Field": ""}
```

`conformance/cases/010-exists/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#field-existence
description: '`exists` checks presence only, whatever the value (null or empty included).'
expected:
  - [c010-yes]
  - [c010-no]
  - [c010-yes]
```
`rules/yes.yml`:
```yaml
title: exists
id: c010-yes
logsource: {product: test}
detection:
    s:
        PasswordLastSet|exists: true
    condition: s
```
`rules/no.yml`:
```yaml
title: not exists
id: c010-no
logsource: {product: test}
detection:
    s:
        PasswordLastSet|exists: false
    condition: s
```
`events.ndjson`:
```
{"PasswordLastSet": null}
{"Other": 1}
{"PasswordLastSet": ""}
```

`conformance/cases/011-numeric/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#numeric-modifiers
description: Numeric comparisons accept numbers and numeric strings; plain integers match their exact text.
expected:
  - [c011-eq, c011-gt]
  - [c011-eq, c011-lte]
  - []
```
`rules/gt.yml`:
```yaml
title: gt
id: c011-gt
logsource: {product: test}
detection:
    s:
        Size|gt: 100
    condition: s
```
`rules/lte.yml`:
```yaml
title: lte
id: c011-lte
logsource: {product: test}
detection:
    s:
        Size|lte: 10
    condition: s
```
`rules/eq.yml`:
```yaml
title: eq
id: c011-eq
logsource: {product: test}
detection:
    s:
        Port: 443
    condition: s
```
`events.ndjson`:
```
{"Size": 150, "Port": "443"}
{"Size": "10", "Port": 443}
{"Size": "big", "Port": 8443}
```

`conformance/cases/012-neq/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#generic-modifiers (neq)
description: '`neq` negates the match, so an absent field satisfies it (interpretation 3).'
expected:
  - [c012]
  - []
  - [c012]
```
`rules/c012.yml`:
```yaml
title: neq
id: c012
logsource: {product: test}
detection:
    s:
        EventID: 1
        User|neq: SYSTEM
    condition: s
```
`events.ndjson`:
```
{"EventID": 1, "User": "alice"}
{"EventID": 1, "User": "system"}
{"EventID": 1}
```

`conformance/cases/013-regex/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#regular-expression
description: Unanchored search (interpretation 4); `m` and `s` flags; lookahead is supported through the backtracking fallback.
expected:
  - [c013-a, c013-look, c013-m]
  - [c013-s]
```
`rules/a.yml`:
```yaml
title: re basic
id: c013-a
logsource: {product: test}
detection:
    s:
        Image|re: '\\(cmd|powershell)\.exe$'
    condition: s
```
`rules/m.yml`:
```yaml
title: re multiline
id: c013-m
logsource: {product: test}
detection:
    s:
        Text|re|m: '^evil$'
    condition: s
```
`rules/s.yml`:
```yaml
title: re dotall
id: c013-s
logsource: {product: test}
detection:
    s:
        Text|re|s: 'a.b'
    condition: s
```
`rules/look.yml`:
```yaml
title: re lookahead
id: c013-look
logsource: {product: test}
detection:
    s:
        Name|re: '^(?!svchost).*\.exe$'
    condition: s
```
`events.ndjson`:
```
{"Image": "C:\\Windows\\System32\\cmd.exe", "Text": "line1\nevil\nline3", "Name": "evil.exe"}
{"Image": "C:\\x\\CMD.EXE", "Text": "a\nb", "Name": "svchost.exe"}
```

`conformance/cases/014-cidr/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#ip-internet-protocol-modifiers
description: IPv4 and IPv6 CIDR ranges; non-IP values never match.
expected:
  - [c014-v4]
  - [c014-v6]
  - []
  - []
```
`rules/v4.yml`:
```yaml
title: cidr v4
id: c014-v4
logsource: {product: test}
detection:
    s:
        DestinationIp|cidr:
            - 10.0.0.0/8
            - 192.168.0.0/16
    condition: s
```
`rules/v6.yml`:
```yaml
title: cidr v6
id: c014-v6
logsource: {product: test}
detection:
    s:
        DestinationIp|cidr: 'fd00::/8'
    condition: s
```
`events.ndjson`:
```
{"DestinationIp": "10.1.2.3"}
{"DestinationIp": "fd12::1"}
{"DestinationIp": "8.8.8.8"}
{"DestinationIp": "not-an-ip"}
```

`conformance/cases/015-windash/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#string-modifiers (windash)
description: '`windash` expands flag dashes to `-`, `/`, en dash, em dash and horizontal bar.'
expected:
  - [c015]
  - [c015]
  - [c015]
  - []
```
`rules/c015.yml`:
```yaml
title: windash
id: c015
logsource: {product: test}
detection:
    s:
        CommandLine|contains|windash: ' -s '
    condition: s
```
`events.ndjson`:
```
{"CommandLine": "psexec.exe -s cmd"}
{"CommandLine": "psexec.exe /s cmd"}
{"CommandLine": "psexec.exe \u2013s cmd"}
{"CommandLine": "psexec.exe --s cmd"}
```

`conformance/cases/016-base64/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#encoding
description: '`base64` encodes the value; `base64offset` produces the three offset variants (pySigma algorithm). Encoded values match case-insensitively (interpretation 5).'
expected:
  - [c016-b64]
  - [c016-off]
  - []
```
`rules/b64.yml`:
```yaml
title: base64
id: c016-b64
logsource: {product: test}
detection:
    s:
        Payload|base64|contains: whoami
    condition: s
```
`rules/off.yml`:
```yaml
title: base64offset
id: c016-off
logsource: {product: test}
detection:
    s:
        Payload|base64offset|contains: ping
    condition: s
```
`events.ndjson`:
```
{"Payload": "xx d2hvYW1p yy"}
{"Payload": "IHBpbmcgMTI3LjAuMC4x"}
{"Payload": "plain ping"}
```

`conformance/cases/017-utf16/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#encoding (wide, utf16)
description: '`wide|base64offset` finds UTF-16LE text inside base64 (e.g. PowerShell -enc); `utf16` prepends a BOM.'
expected:
  - [c017]
  - []
  - [c017-bom]
```
`rules/wide.yml`:
```yaml
title: wide base64offset
id: c017
logsource: {product: test}
detection:
    s:
        CommandLine|wide|base64offset|contains: cmd
    condition: s
```
`rules/bom.yml`:
```yaml
title: utf16 with BOM
id: c017-bom
logsource: {product: test}
detection:
    s:
        Data|utf16|base64: ab
    condition: s
```
`events.ndjson`:
```
{"CommandLine": "powershell -enc cgB1AG4AIABjAG0AZAAgAC8AYwAgAGQAaQByAA=="}
{"CommandLine": "powershell -enc cnVuIGNtZCAvYyBkaXI="}
{"Data": "//5hAGIA"}
```

`conformance/cases/018-fieldref/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#specific-modifiers (fieldref)
description: '`fieldref` compares two fields of the same event; combined with `contains` it is a substring test. A missing field never matches.'
expected:
  - [c018-contains, c018-eq]
  - []
  - []
```
`rules/eq.yml`:
```yaml
title: fieldref equals
id: c018-eq
logsource: {product: test}
detection:
    s:
        TargetFilename|fieldref: Image
    condition: s
```
`rules/contains.yml`:
```yaml
title: fieldref contains
id: c018-contains
logsource: {product: test}
detection:
    s:
        CommandLine|fieldref|contains: User
    condition: s
```
`events.ndjson`:
```
{"TargetFilename": "C:\\a.exe", "Image": "c:\\A.exe", "CommandLine": "run as bob", "User": "BOB"}
{"TargetFilename": "x", "Image": "y", "CommandLine": "z", "User": "q"}
{"TargetFilename": "x"}
```

`conformance/cases/019-expand/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#placeholders
description: '`expand` replaces %name% with pipeline values (wildcards allowed); without `expand` the text is literal.'
pipelines: [pipeline.yml]
expected:
  - [c019]
  - [c019]
  - [c019-literal]
  - []
```
`pipeline.yml`:
```yaml
name: vars
vars:
  Admins: ['adm_*', root]
```
`rules/expand.yml`:
```yaml
title: expand
id: c019
logsource: {product: test}
detection:
    s:
        User|expand: '%Admins%'
    condition: s
```
`rules/literal.yml`:
```yaml
title: literal percent
id: c019-literal
logsource: {product: test}
detection:
    s:
        User: '%Admins%'
    condition: s
```
`events.ndjson`:
```
{"User": "adm_bob"}
{"User": "ROOT"}
{"User": "%Admins%"}
{"User": "bob"}
```

`conformance/cases/020-condition-grammar/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md#condition
description: Precedence or < and < not < x-of < parentheses; `1 of`/`all of` patterns; `them` excludes identifiers starting with `_`; a condition list is OR-ed.
expected:
  - [c020-list, c020-oneof, c020-prec]
  - [c020-list, c020-oneof]
  - [c020-allof, c020-list, c020-oneof, c020-parens, c020-prec]
  - [c020-allof, c020-list, c020-oneof, c020-prec, c020-them]
  - []
```
Six rules share this detection block and differ only in `id` and `condition`:
```yaml
title: grammar
id: <ID>
logsource: {product: test}
detection:
    sel_a:
        A: 1
    sel_b:
        B: 1
    filter_c:
        C: 1
    _hidden:
        H: 1
    condition: <CONDITION>
```
| File | `id` | `condition` |
|---|---|---|
| `rules/prec.yml` | `c020-prec` | `sel_a or sel_b and not filter_c` |
| `rules/parens.yml` | `c020-parens` | `(sel_a or sel_b) and not filter_c` |
| `rules/oneof.yml` | `c020-oneof` | `1 of sel_*` |
| `rules/allof.yml` | `c020-allof` | `all of sel_*` |
| `rules/them.yml` | `c020-them` | `all of them` |
| `rules/list.yml` | `c020-list` | a YAML list: `- sel_a and sel_b` and `- filter_c` |

`events.ndjson`:
```
{"A": 1, "C": 1}
{"B": 1, "C": 1}
{"A": 1, "B": 1}
{"A": 1, "B": 1, "C": 1}
{"H": 1}
```

`conformance/cases/021-meta-filter/case.yml`:
```yaml
spec_ref: sigma-filters-specification.md
description: A meta filter suppresses matches of the rules it lists (rule AND NOT filter).
expected:
  - [c021]
  - []
  - []
```
`rules/rule.yml`:
```yaml
title: rar
id: c021
logsource: {product: test}
detection:
    s:
        Image|endswith: '\rar.exe'
    condition: s
```
`rules/filter.yml`:
```yaml
title: Filter admin accounts
id: c021-filter
logsource: {product: test}
filter:
    rules:
        - c021
    selection:
        User|startswith: 'adm_'
    condition: selection
```
`events.ndjson`:
```
{"Image": "C:\\rar.exe", "User": "bob"}
{"Image": "C:\\rar.exe", "User": "adm_x"}
{"Image": "x"}
```

`conformance/cases/022-time-modifiers/case.yml`:
```yaml
spec_ref: sigma-appendix-modifiers.md#time-modifiers
description: Time modifiers extract a number (UTC) from a timestamp value; they combine with numeric comparisons. Unparseable values never match.
expected:
  - [c022-hour]
  - [c022-night]
  - []
```
`rules/hour.yml`:
```yaml
title: hour
id: c022-hour
logsource: {product: test}
detection:
    s:
        EventTime|hour: 3
    condition: s
```
`rules/night.yml`:
```yaml
title: night
id: c022-night
logsource: {product: test}
detection:
    s:
        EventTime|hour|gte: 22
    condition: s
```
`events.ndjson`:
```
{"EventTime": "2026-11-07T03:15:00Z"}
{"EventTime": "2026-11-07T23:00:00Z"}
{"EventTime": "not a date"}
```

`conformance/cases/023-nested-and-arrays/case.yml`:
```yaml
spec_ref: ZAAFElegia event model (interpretation 6)
description: Dotted paths resolve exact keys first, then nested objects; arrays match if any element matches.
expected:
  - [c023-arr, c023-dot]
  - [c023-dotkey]
  - [c023-dot]
  - [c023-dotkey]
```
`rules/dot.yml`:
```yaml
title: nested
id: c023-dot
logsource: {product: test}
detection:
    s:
        process.parent.name: explorer.exe
    condition: s
```
`rules/arr.yml`:
```yaml
title: array
id: c023-arr
logsource: {product: test}
detection:
    s:
        Tags: malware
    condition: s
```
`rules/dotkey.yml`:
```yaml
title: dotted key
id: c023-dotkey
logsource: {product: test}
detection:
    s:
        user.name: alice
    condition: s
```
`events.ndjson`:
```
{"process": {"parent": {"name": "EXPLORER.EXE"}}, "Tags": ["benign", "Malware"]}
{"user.name": "alice"}
{"process": [{"parent": {"name": "x"}}, {"parent": {"name": "explorer.exe"}}]}
{"user": {"name": "alice"}}
```

`conformance/cases/024-field-mapping/case.yml`:
```yaml
spec_ref: ZAAFElegia pipelines (field_name_mapping)
description: Mapped fields are looked up under their new names (one-to-many is OR); rule_conditions limit a mapping to matching logsources.
pipelines: [pipeline.yml]
expected:
  - [c024-win]
  - [c024-linux]
  - []
```
`pipeline.yml`:
```yaml
name: ecs-test
transformations:
  - type: field_name_mapping
    mapping:
      Image: process.executable
      CommandLine: [process.command_line, process.args]
    rule_conditions:
      - product: windows
```
`rules/win.yml`:
```yaml
title: windows mapped
id: c024-win
logsource: {product: windows}
detection:
    s:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: whoami
    condition: s
```
`rules/linux.yml`:
```yaml
title: linux unmapped
id: c024-linux
logsource: {product: linux}
detection:
    s:
        Image: /bin/sh
    condition: s
```
`events.ndjson`:
```
{"process": {"executable": "C:\\Windows\\cmd.exe", "args": ["cmd", "/c", "whoami"]}}
{"Image": "/bin/sh"}
{"Image": "C:\\Windows\\cmd.exe", "CommandLine": "whoami"}
```

`conformance/cases/025-invalid-rules/case.yml`:
```yaml
spec_ref: sigma-rules-specification.md; sigma-appendix-modifiers.md
description: Invalid rules are rejected one error each, and do not stop valid rules from running.
compile_errors: 7
expected:
  - [c025-good]
```
Seven invalid rules plus one valid rule. Each file is `title: <file>\nid: <id>\nlogsource: {product: test}\ndetection:\n    selection:\n        <ITEM>\n    condition: <COND>`:

| File | `id` | `<ITEM>` | `<COND>` |
|---|---|---|---|
| `rules/bad-all.yml` | `c025-all` | `X\|all: 'single'` | `selection` |
| `rules/bad-null-list.yml` | `c025-null` | `X: ['', null]` | `selection` |
| `rules/bad-modifier.yml` | `c025-mod` | `X\|nope: a` | `selection` |
| `rules/bad-reflag.yml` | `c025-flag` | `X\|i: a` | `selection` |
| `rules/bad-cond.yml` | `c025-cond` | `X: a` | `selection and missing` |
| `rules/bad-agg.yml` | `c025-agg` | `X: a` | `selection \| count() > 5` |
| `rules/bad-placeholder.yml` | `c025-ph` | `X\|expand: '%Undefined%'` | `selection` |
| `rules/good.yml` | `c025-good` | `X: a` | `selection` |

(The `\|` in the table is the Markdown escape of `|`. Write a plain `|` in the YAML files.)

`events.ndjson`:
```
{"X": "a"}
```

- [ ] **Step 5: Run the suite**

Run: `cargo test -p zaaf-testkit`
Expected: 3 runner tests and `conformance_suite_passes` pass.

A failing case means one of two things:
- **The engine is wrong:** fix the engine and add a unit test in the owning crate.
- **The case misreads the spec:** fix the case, and update `description` and the README interpretation list.

Never change an `expected` entry only to make the suite green.

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "test: zaaf-testkit runner and 25-case Sigma 2.1 conformance suite

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 14: SigmaHQ corpus parse/compile regression

**Files:**
- Create: `scripts/sigmahq-corpus.sh`, `scripts/compare_known_unsupported.py`, `conformance/known-unsupported.txt`, `tests/sigmahq/placeholders.yml`
- Modify: `.github/workflows/ci.yml` (add the `sigmahq-corpus` job)

**Interfaces:**
- Consumes: the `zaaf check --format json` report from Task 11.
- Produces: one command that prints `SigmaHQ corpus: <ok>/<files> files parse and compile (<pct>%)`. It exits 1 on any unexpected failure, and also when a file listed as known-unsupported now passes, so the list never goes stale.

- [ ] **Step 1: Write the scripts and data files**

`scripts/sigmahq-corpus.sh`:
```bash
#!/usr/bin/env bash
# Parses and compiles the whole SigmaHQ corpus with `zaaf check` and compares the
# failing files with conformance/known-unsupported.txt.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="${SIGMA_REF:-master}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --quiet --depth 1 --branch "$REF" https://github.com/SigmaHQ/sigma.git "$WORK/sigma"
cargo build --quiet --release -p zaaf-cli --manifest-path "$ROOT/Cargo.toml"

cd "$WORK/sigma"
set +e
"$ROOT/target/release/zaaf" check --format json --quiet \
    -p "$ROOT/tests/sigmahq/placeholders.yml" \
    rules rules-emerging-threats rules-threat-hunting rules-placeholder rules-compliance \
    > "$WORK/report.json"
set -e
python3 -I "$ROOT/scripts/compare_known_unsupported.py" "$WORK/report.json" "$ROOT/conformance/known-unsupported.txt"
```

`scripts/compare_known_unsupported.py`:
```python
#!/usr/bin/env python3
"""Compare `zaaf check --format json` output with the known-unsupported list."""
import json
import sys


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)
    known = {}
    with open(sys.argv[2], encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            path, _, reason = line.partition("#")
            known[path.strip()] = reason.strip()

    failing = {}
    for d in report["diagnostics"]:
        if d["severity"] == "error" and d["file"]:
            failing.setdefault(d["file"], []).append(d["message"])

    unexpected = sorted(set(failing) - set(known))
    now_passing = sorted(set(known) - set(failing))
    files = report["files"]
    ok = files - len(failing)
    print(f"SigmaHQ corpus: {ok}/{files} files parse and compile ({100.0 * ok / max(files, 1):.2f}%)")
    print(f"known unsupported: {len(known)}, unexpected failures: {len(unexpected)}, now passing: {len(now_passing)}")
    for f in unexpected:
        print(f"UNEXPECTED {f}: {failing[f][0]}")
    for f in now_passing:
        print(f"NOW PASSING (remove from known-unsupported.txt) {f}")
    return 1 if unexpected or now_passing else 0


if __name__ == "__main__":
    sys.exit(main())
```

`conformance/known-unsupported.txt`:
```
# SigmaHQ rule files ZAAFElegia knowingly rejects, one per line:
#   <path relative to the SigmaHQ repo>  # <reason, with a spec reference>
# A file is listed here only when rejecting it is correct per the Sigma 2.1
# specification. Engine gaps are bugs and must be fixed instead.
```

`tests/sigmahq/placeholders.yml`:
```yaml
name: sigmahq-placeholders
# Dummy values so SigmaHQ placeholder rules compile in CI.
# Real deployments must define their own values for these placeholders.
vars:
  Administrators: [zaaf-placeholder]
  Admins_Workstations: [zaaf-placeholder]
  ApprovedUserUpn: [zaaf-placeholder]
  Approved_Inviters: [zaaf-placeholder]
  DomainControllers: [zaaf-placeholder]
  Domain_Controller: [zaaf-placeholder]
  HomeTenantID: [zaaf-placeholder]
  Important_AppIds: [zaaf-placeholder]
  KNOWN_LOCATION: [zaaf-placeholder]
  Known_Location: [zaaf-placeholder]
  Legitimate_Countries: [zaaf-placeholder]
  Legitimate_IP_Ranges: ['192.0.2.0/24']
  ServerSystems: [zaaf-placeholder]
  UnApprovedDevice: [zaaf-placeholder]
  UnApprovedIp: ['192.0.2.1']
  UnLegitCountries: [zaaf-placeholder]
  Workstations: [zaaf-placeholder]
  dc_ip_addresses: ['192.0.2.2']
  dc_machine_accounts: [zaaf-placeholder]
  domain_controller_hostnames: [zaaf-placeholder]
  internal_domains: [zaaf-placeholder]
  known_cdcs: [zaaf-placeholder]
  legit_ips: ['192.0.2.3']
  legtimate_identifiers: [zaaf-placeholder]
  userdomain: [zaaf-placeholder]
```

Append to `.github/workflows/ci.yml` under `jobs:`:
```yaml
  sigmahq-corpus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: bash scripts/sigmahq-corpus.sh
```

- [ ] **Step 2: Run against the real corpus**

Run: `chmod +x scripts/sigmahq-corpus.sh && bash scripts/sigmahq-corpus.sh`
Expected on the first run: a pass-rate line, plus possibly some `UNEXPECTED` lines.

- [ ] **Step 3: Triage every unexpected failure**

Repeat until the script exits 0. For each `UNEXPECTED <file>: <message>`:
1. **`placeholder %X% has no value`:** add `X` to `tests/sigmahq/placeholders.yml`. Use an IP-shaped dummy value if the rule applies `cidr` to it.
2. **A construct that Sigma 2.1 permits but the engine rejects:** this is an engine bug.
   - Add a failing unit test in the owning crate and a conformance case that pins the behaviour.
   - Fix the engine and commit the fix separately (`fix(<crate>): …`).
3. **A construct that Sigma 2.1 forbids, such as `null` inside a value list:** add the file to `conformance/known-unsupported.txt` with the reason and the spec section.

- [ ] **Step 4: Record the result**

Put the final pass-rate line in the commit body. Task 16 copies it into the README and the release notes.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test: SigmaHQ corpus parse/compile regression in CI

<paste the 'SigmaHQ corpus: …' line here>

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 15: Fuzz targets (parser, NDJSON reader, evaluator)

**Files:**
- Create: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/parse_rule.rs`, `fuzz/fuzz_targets/read_ndjson.rs`, `fuzz/fuzz_targets/eval_event.rs`, `.github/workflows/fuzz.yml`

**Interfaces:**
- Consumes the public APIs of zaaf-sigma, zaaf-ir, zaaf-pipeline, zaaf-event, zaaf-eval and zaaf-input.
- Produces: three libFuzzer targets. Each runs 30 s on every PR and 10 min nightly.

- [ ] **Step 1: Install the tooling**

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

- [ ] **Step 2: Write the targets**

`fuzz/Cargo.toml`:
```toml
[package]
name = "zaaf-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
serde_json = "1.0"
zaaf-eval = { path = "../crates/zaaf-eval" }
zaaf-event = { path = "../crates/zaaf-event" }
zaaf-input = { path = "../crates/zaaf-input" }
zaaf-ir = { path = "../crates/zaaf-ir" }
zaaf-pipeline = { path = "../crates/zaaf-pipeline" }
zaaf-sigma = { path = "../crates/zaaf-sigma" }

[[bin]]
name = "parse_rule"
path = "fuzz_targets/parse_rule.rs"
test = false
doc = false
bench = false

[[bin]]
name = "read_ndjson"
path = "fuzz_targets/read_ndjson.rs"
test = false
doc = false
bench = false

[[bin]]
name = "eval_event"
path = "fuzz_targets/eval_event.rs"
test = false
doc = false
bench = false
```

`fuzz/fuzz_targets/parse_rule.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let parsed = zaaf_sigma::parse_str(src);
        let docs = parsed
            .documents
            .into_iter()
            .map(|document| zaaf_ir::SourcedDocument { document, source: None })
            .collect();
        let _ = zaaf_ir::compile(docs, &zaaf_pipeline::PipelineSet::default());
    }
});
```

`fuzz/fuzz_targets/read_ndjson.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for _ in zaaf_input::read_json_events(std::io::Cursor::new(data.to_vec())) {}
});
```

`fuzz/fuzz_targets/eval_event.rs`:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zaaf_eval::Evaluator;
use zaaf_event::JsonEvent;

const RULES: &str = r#"
title: fuzz
id: fuzz-1
logsource: {product: fuzz}
detection:
    a:
        A|contains|all: [x, 'y*z']
        B|re: '^(?!q).*\d+$'
    b:
        C|cidr: [10.0.0.0/8, 'fd00::/8']
        D|gte: 5
    c:
        E|hour: 3
        F|fieldref|contains: G
    k:
        - 'kw?rd'
    n:
        H: null
        I|exists: true
    condition: 1 of a or (b and not c) or k or all of n
"#;

fn evaluator() -> &'static Evaluator {
    static E: OnceLock<Evaluator> = OnceLock::new();
    E.get_or_init(|| {
        let parsed = zaaf_sigma::parse_str(RULES);
        let docs = parsed
            .documents
            .into_iter()
            .map(|document| zaaf_ir::SourcedDocument { document, source: None })
            .collect();
        let out = zaaf_ir::compile(docs, &zaaf_pipeline::PipelineSet::default());
        assert_eq!(out.rules.len(), 1, "fuzz rule must compile: {:?}", out.diagnostics);
        Evaluator::new(out.rules)
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = evaluator().matching_rules(&JsonEvent::new(value));
    }
});
```

`.github/workflows/fuzz.yml`:
```yaml
name: fuzz
on:
  pull_request:
  schedule:
    - cron: "17 2 * * *"
permissions:
  contents: read
jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        target: [parse_rule, read_ndjson, eval_event]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz --locked
      - name: Fuzz ${{ matrix.target }}
        run: |
          if [ "${{ github.event_name }}" = "schedule" ]; then SECS=600; else SECS=30; fi
          cd fuzz && cargo +nightly fuzz run ${{ matrix.target }} -- -max_total_time=$SECS
```

- [ ] **Step 3: Run each target locally for 60 seconds**

```bash
cd fuzz
cargo +nightly fuzz run parse_rule -- -max_total_time=60
cargo +nightly fuzz run read_ndjson -- -max_total_time=60
cargo +nightly fuzz run eval_event -- -max_total_time=60
```
Expected: each run ends with `Done N runs in 60 second(s)` and no crash.

If a target crashes:
- Copy the reproducer from `fuzz/artifacts/<target>/` into a unit test in the owning crate.
- Fix the panic and commit the fix separately.
- Rerun the target.

- [ ] **Step 4: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets .github/workflows/fuzz.yml
git commit -m "test: cargo-fuzz targets for parser, NDJSON reader and evaluator

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 16: Community files, README, pre-release 0.0.1 and going public

**Files:**
- Create:
  - `README.md` (replacing the GitHub stub)
  - `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md`, `.github/PULL_REQUEST_TEMPLATE.md`
  - `docs/releases/0.0.1.md`

**Interfaces:**
- Consumes: the SigmaHQ pass-rate line from Task 14.
- Produces: tag `v0.0.1`, a GitHub pre-release, and a public repository. The last of these needs Rifqi's explicit confirmation.

- [ ] **Step 1: Write the documents**

`README.md`:
````markdown
# ZAAFElegia

A Sigma-native detection engine written in Rust. ZAAFElegia runs
[Sigma](https://github.com/SigmaHQ/sigma) rules directly over your logs.
It does not convert them to another query language first.

> **Status: 0.0.1 pre-release (milestone M1).** Single-event rules over JSON/NDJSON.
> Correlation rules arrive in M2, EVTX and cloud logs in M3, Parquet in M4,
> and the AI-attack rule pack in M5.
> See the [design spec](docs/superpowers/specs/2026-11-07-zaafelegia-v0.1-design.md).

## Why ZAAFElegia

- **Conformance you can check.**
  - A public, language-neutral [conformance suite](conformance/) for Sigma 2.1.
  - A CI run that parses and compiles the whole SigmaHQ corpus: <PASS-RATE LINE FROM TASK 14>.
- **One rule, live and historical (M4).** The same rule gives identical results on a stream and on Parquet.
- **Detection for the AI era (M5).** Logsources and rules for LLM gateways and MCP tool calls.
- **Apache-2.0.** No copyleft dependencies, enforced by `cargo-deny`.

## Install from source

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
The rule's `author` and `references` are always included under `unmapped.sigma`,
as the Detection Rule License (DRL 1.1) requires for SigmaHQ rules.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Matches found (only with `--fail-on-match`) |
| 2 | Rule errors (or usage errors) |
| 3 | Input errors (with `--strict`, or above `--max-errors`) |
| 4 | Internal error |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). ZAAFElegia does not bundle
the SigmaHQ rules; they are licensed separately under DRL 1.1.
````

`CONTRIBUTING.md`:
````markdown
# Contributing to ZAAFElegia

## Setup

```bash
rustup toolchain install stable --component clippy,rustfmt
cargo test --workspace
```

## Before opening a pull request

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` all pass.
- **A change in rule semantics comes with a conformance case** in `conformance/cases/`. The case states the spec section in `spec_ref` and its interpretation in `description`.
- **`zaaf-eval` is the semantic reference.** Other evaluators are tested against it, never the other way round.
- **New dependencies must pass `cargo deny check`.** AGPL, GPL, SSPL and Elastic-licensed crates are rejected.
- **Do not copy code from copyleft or source-available projects** (for example Hayabusa, Chainsaw, Velociraptor or elastic/detection-rules). Studying their behaviour is fine.

## Commit messages

Use conventional prefixes (`feat(crate):`, `fix(crate):`, `test:`, `docs:`, `build:`).
````

`SECURITY.md`:
```markdown
# Security policy

Report vulnerabilities privately through GitHub's
**Security → Report a vulnerability** form on this repository. Do not open public issues.
We aim to acknowledge reports within 3 working days.

Supported versions: the latest pre-release on `main`.
```

`CODE_OF_CONDUCT.md`: download the Contributor Covenant 2.1 and set the contact to the GitHub private reporting form.
```bash
curl -sSfL https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md -o CODE_OF_CONDUCT.md
grep -n "\[INSERT CONTACT METHOD\]" CODE_OF_CONDUCT.md
```
Replace `[INSERT CONTACT METHOD]` with `the private reporting form under the repository's Security tab`.

`.github/ISSUE_TEMPLATE/bug_report.md`:
```markdown
---
name: Bug report
about: A rule matches when it should not, or does not match when it should
labels: bug
---

**zaaf version** (`zaaf --version`):

**Rule** (YAML):

**Event(s)** (NDJSON):

**Expected vs actual**:
```

`.github/ISSUE_TEMPLATE/feature_request.md`:
```markdown
---
name: Feature request
about: Suggest a capability or a new conformance case
labels: enhancement
---

**What problem does this solve?**

**Proposed behaviour** (with a spec reference if it concerns Sigma semantics):
```

`.github/PULL_REQUEST_TEMPLATE.md`:
```markdown
## What and why

## Checklist
- [ ] `cargo fmt`, `clippy -D warnings`, `cargo test --workspace` pass
- [ ] Semantic change → conformance case added
- [ ] No new copyleft dependency (`cargo deny check`)
```

`docs/releases/0.0.1.md`:
```markdown
# ZAAFElegia 0.0.1 (M1: engine core), pre-release

- `zaaf check`: parse, compile and lint Sigma 2.1 rules (text or JSON report).
- `zaaf hunt`: single-event rules over NDJSON / JSON arrays / stdin. Output is OCSF Detection Finding, NDJSON, JSON, CSV or a table.
- Every Sigma 2.1 modifier, meta filters, placeholders through pipelines, and field-name mapping pipelines.
- 25-case conformance suite; SigmaHQ corpus: <PASS-RATE LINE FROM TASK 14>.

Not yet: correlation rules (M2), EVTX and cloud logs (M3), Parquet (M4), the AI rule pack and `zaaf test` (M5).
```

Replace both `<PASS-RATE LINE FROM TASK 14>` placeholders with the real line.

- [ ] **Step 2: Verify and commit**

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo deny check
grep -rn "PASS-RATE LINE" README.md docs/releases/ && echo "placeholder left!" || echo "ok"
git add -A
git commit -m "docs: README, contributing guide, security policy, templates, 0.0.1 notes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: all checks pass, and the output ends with `ok`.

- [ ] **Step 3: Tag, push and publish (STOP: ask Rifqi for explicit confirmation first)**

Pushing, creating a release and making the repository public are outward-facing.

```bash
git tag -a v0.0.1 -m "ZAAFElegia 0.0.1 (M1: engine core)"
git push origin main --tags
gh release create v0.0.1 --prerelease --title "0.0.1: M1 engine core" --notes-file docs/releases/0.0.1.md
gh repo edit rifqifitriady/ZAAFElegia --visibility public --accept-visibility-change-consequences
gh api -X PUT repos/rifqifitriady/ZAAFElegia/private-vulnerability-reporting
```
Expected:
- `gh release view v0.0.1` shows a pre-release.
- `gh repo view rifqifitriady/ZAAFElegia --json visibility` prints `PUBLIC`.
- The CI and fuzz workflows run green on GitHub.

---

## Self-review against the spec (M1 scope)

| Spec item | Task |
|---|---|
| §3.2 `zaaf-sigma` (rules, filters, correlation stub, diagnostics) | 1–4 |
| §3.2 Diagnostics as `file:line:col` with the YAML path (parse, pipeline, compile, `check` text and JSON) | 1, 4, 5, 7, 11 |
| §3.2 `zaaf-pipeline` (core: field mapping, conditions, vars) | 5 |
| §3.2 `zaaf-ir` (all modifiers resolved at compile time, meta filters folded) | 6–7 |
| §3.2 `zaaf-event` (JSON), `zaaf-eval` (reference) | 8–9 |
| §3.2 `zaaf-input` (NDJSON) | 10 |
| §4 `check` (lints except ATT&CK tags → M5 and correlation refs → M2), `hunt`, output formats, exit codes | 11–12 |
| §3.4 OCSF Detection Finding with DRL attribution | 12 |
| §5.3 Conformance suite (single-event parts) | 13 |
| §5.4 SigmaHQ regression, part 1: parse/compile of all rules (the `regression_data` match run is M3, after EVTX) | 14 |
| §6 Error handling (skip and report, `--strict`, `--max-errors`, ReDoS-safe regex, no panics) | 7, 12, 15 |
| §7 Testing (unit, conformance, fuzz, CI, cargo-deny) | 0, 13, 15 |
| §9 Licensing and community, repo public at M1 | 0, 16 |

Deferred by design (see "Scope notes for M1"): correlation (M2), EVTX, cloud presets and the full set of pipeline presets (M3), DataFusion, Parquet and `explain` (M4), `test`, `coverage`, the AI pack and the ATT&CK tag lint (M5).
