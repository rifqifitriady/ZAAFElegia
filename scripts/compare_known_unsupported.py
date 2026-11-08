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
