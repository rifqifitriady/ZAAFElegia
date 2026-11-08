#!/usr/bin/env python3
"""Compare `zaaf check --format json` output with the known-unsupported list.

usage: compare_known_unsupported.py REPORT.json KNOWN.txt [--zaaf-exit RC]
"""
import json
import posixpath
import sys

USAGE = "usage: compare_known_unsupported.py REPORT.json KNOWN.txt [--zaaf-exit RC]"


def norm(path: str) -> str:
    return posixpath.normpath(path.replace("\\", "/"))


def parse_known(lines):
    known = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path, _, reason = line.partition("#")
        known[norm(path.strip())] = reason.strip()
    return known


def check(report, known, zaaf_exit=None):
    """Return (exit_code, output_lines)."""
    out = []
    problems = []
    failing = {}
    error_count = 0
    for d in report["diagnostics"]:
        if d["severity"] != "error":
            continue
        error_count += 1
        if d["file"]:
            failing.setdefault(norm(d["file"]), []).append(d["message"])
        else:
            problems.append(f"UNEXPECTED (no file): {d['message']}")

    files = report["files"]
    docs = report["rules"] + report["filters"] + report["correlations_skipped"]
    ok = files - len(failing)

    if files == 0 or report["rules"] == 0:
        problems.append(f"degenerate report: files={files}, rules={report['rules']}")
    # Every file that did not fail must have produced at least one document
    # (rule, filter or skipped correlation). Multi-document files only raise the
    # document count, so this lower bound cannot be gamed by them; it catches a
    # run that silently scanned nothing for most files.
    if ok > docs:
        problems.append(f"{ok} passing files but only {docs} documents produced")
    if report["errors"] != error_count:
        problems.append(f"report says {report['errors']} errors but {error_count} error diagnostics seen")
    if zaaf_exit is not None and (zaaf_exit == 0) != (report["errors"] == 0):
        problems.append(f"zaaf exit code {zaaf_exit} inconsistent with {report['errors']} errors")

    unexpected = sorted(set(failing) - set(known))
    now_passing = sorted(set(known) - set(failing))
    out.append(f"SigmaHQ corpus: {ok}/{files} files parse and compile ({100.0 * ok / max(files, 1):.2f}%)")
    out.append(f"known unsupported: {len(known)}, unexpected failures: {len(unexpected)}, now passing: {len(now_passing)}")
    for f in unexpected:
        out.append(f"UNEXPECTED {f}: {failing[f][0]}")
    for f in now_passing:
        out.append(f"NOW PASSING (remove from known-unsupported.txt) {f}")
    for p in problems:
        out.append(f"FAIL: {p}")
    return (1 if unexpected or now_passing or problems else 0), out


def main(argv) -> int:
    args = argv[1:]
    rc = None
    if len(args) == 4 and args[2] == "--zaaf-exit":
        try:
            rc = int(args[3])
        except ValueError:
            print(USAGE, file=sys.stderr)
            return 2
        args = args[:2]
    if len(args) != 2:
        print(USAGE, file=sys.stderr)
        return 2
    with open(args[0], encoding="utf-8") as fh:
        report = json.load(fh)
    with open(args[1], encoding="utf-8") as fh:
        known = parse_known(fh)
    code, lines = check(report, known, rc)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
