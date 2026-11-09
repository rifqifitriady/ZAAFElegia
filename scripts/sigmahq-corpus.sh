#!/usr/bin/env bash
# Parses and compiles the whole SigmaHQ corpus with `zaaf check` and compares the
# failing files with conformance/known-unsupported.txt.
#
# SigmaHQ is pinned to a fixed commit so CI is reproducible. Override with
# SIGMA_REF=<sha|branch|tag> (e.g. SIGMA_REF=master for a manual run on the latest).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="${SIGMA_REF:-53b90df66c5b6d1b9be6ba9289c56fe49dd74a73}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git init -q "$WORK/sigma"
git -C "$WORK/sigma" fetch -q --depth 1 https://github.com/SigmaHQ/sigma.git "$REF"
git -C "$WORK/sigma" checkout -q FETCH_HEAD
cargo build --locked --quiet --release -p zaaf-cli --manifest-path "$ROOT/Cargo.toml"

cd "$WORK/sigma"
set +e
"$ROOT/target/release/zaaf" check --format json --quiet \
    -p "$ROOT/tests/sigmahq/placeholders.yml" \
    rules rules-emerging-threats rules-threat-hunting rules-placeholder rules-compliance \
    > "$WORK/report.json"
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    echo "zaaf check exited with unexpected status $rc" >&2
    exit 1
fi
python3 -I "$ROOT/scripts/compare_known_unsupported.py" "$WORK/report.json" "$ROOT/conformance/known-unsupported.txt" --zaaf-exit "$rc"
