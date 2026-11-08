# Contributing to ZAAFElegia

## Setup

The minimum supported Rust version is 1.89. Install Rust with [rustup](https://rustup.rs/):

```bash
rustup toolchain install stable --component clippy,rustfmt
cargo test --workspace
```

## Before opening a pull request

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` all pass.
- **A change in rule semantics comes with a conformance case** in `conformance/cases/`. The case states the spec section in `spec_ref` and its interpretation in `description`. See [conformance/README.md](conformance/README.md).
- **`zaaf-eval` is the semantic reference.** Other evaluators are tested against it, never the other way round.
- **New dependencies must pass `cargo deny check`.** AGPL, GPL, SSPL and Elastic-licensed crates are rejected. YAML is parsed with saphyr / serde-saphyr (pure Rust); keep the dependency tree free of C libraries where possible.
- **Do not copy code from copyleft or source-available projects** (for example Hayabusa, Chainsaw, Velociraptor or elastic/detection-rules). Studying their behaviour is fine.
- To re-run the SigmaHQ corpus check locally: `scripts/sigmahq-corpus.sh`.

## Commit messages

Use conventional prefixes (`feat(crate):`, `fix(crate):`, `test:`, `docs:`, `build:`).
