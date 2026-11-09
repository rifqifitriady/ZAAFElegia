#!/usr/bin/env python3
"""Compare `zaaf check --format json` output with the known-unsupported list.

usage: compare_known_unsupported.py REPORT.json KNOWN.txt [--zaaf-exit RC] [--expect-counts FILES,RULES]

Exit status: 0 ok, 1 comparison failed, 2 usage error or malformed report.
"""
import json
import posixpath
import sys

USAGE = "usage: compare_known_unsupported.py REPORT.json KNOWN.txt [--zaaf-exit RC] [--expect-counts FILES,RULES]"

REPORT_KEYS = ("files", "rules", "filters", "correlations_skipped", "errors", "diagnostics")
DIAGNOSTIC_KEYS = ("severity", "file", "message")


class SchemaError(Exception):
    pass


def validate_report(report):
    """Raise SchemaError if the report lacks a key `check` relies on."""
    if not isinstance(report, dict):
        raise SchemaError("report is not a JSON object")
    missing = [k for k in REPORT_KEYS if k not in report]
    if missing:
        raise SchemaError("report is missing keys: " + ", ".join(missing))
    if not isinstance(report["diagnostics"], list):
        raise SchemaError("report.diagnostics is not a list")
    for i, d in enumerate(report["diagnostics"]):
        if not isinstance(d, dict):
            raise SchemaError(f"diagnostics[{i}] is not an object")
        bad = [k for k in DIAGNOSTIC_KEYS if k not in d]
        if bad:
            raise SchemaError(f"diagnostics[{i}] is missing keys: " + ", ".join(bad))


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


def check(report, known, zaaf_exit=None, expect=None):
    """Return (exit_code, output_lines).

    `expect` is an optional (files, rules) pair that must match the report exactly.
    """
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
    # For a pinned corpus the sizes are known exactly, which closes the gap the
    # lower bound above leaves.
    if expect is not None and (files, report["rules"]) != tuple(expect):
        problems.append(
            f"expected exactly {expect[0]} files and {expect[1]} rules, "
            f"got {files} files and {report['rules']} rules"
        )
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
    expect = None
    while len(args) > 2:
        if len(args) < 4 or args[2] not in ("--zaaf-exit", "--expect-counts"):
            print(USAGE, file=sys.stderr)
            return 2
        flag, value = args[2], args[3]
        try:
            if flag == "--zaaf-exit":
                rc = int(value)
            else:
                n_files, n_rules = value.split(",")
                expect = (int(n_files), int(n_rules))
        except ValueError:
            print(USAGE, file=sys.stderr)
            return 2
        args = args[:2] + args[4:]
    if len(args) != 2:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        with open(args[0], encoding="utf-8") as fh:
            report = json.load(fh)
        validate_report(report)
    except (OSError, ValueError, SchemaError) as e:
        print(f"error: invalid report {args[0]}: {e}", file=sys.stderr)
        return 2
    with open(args[1], encoding="utf-8") as fh:
        known = parse_known(fh)
    code, lines = check(report, known, rc, expect)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
