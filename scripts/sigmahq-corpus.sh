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
