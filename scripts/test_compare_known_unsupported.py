"""Run with: python3 -I scripts/test_compare_known_unsupported.py"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_known_unsupported as c  # noqa: E402


def report(files=3, rules=3, filters=0, corr=0, diags=()):
    errs = sum(1 for d in diags if d["severity"] == "error")
    return {"files": files, "rules": rules, "filters": filters, "correlations_skipped": corr,
            "errors": errs, "warnings": 0, "diagnostics": list(diags)}


def err(file, msg="boom"):
    return {"severity": "error", "file": file, "line": 1, "col": 1, "path": None, "message": msg}


class Tests(unittest.TestCase):
    def test_normal_pass(self):
        self.assertEqual(c.check(report(), {}, 0)[0], 0)

    def test_known_failure_passes(self):
        r = report(rules=2, diags=[err("rules/a.yml")])
        self.assertEqual(c.check(r, {"rules/a.yml": "why"}, 2)[0], 0)

    def test_zero_files(self):
        self.assertEqual(c.check(report(files=0, rules=0), {}, 0)[0], 1)

    def test_zero_rules(self):
        self.assertEqual(c.check(report(rules=0), {}, 0)[0], 1)

    def test_files_without_documents(self):
        self.assertEqual(c.check(report(files=10, rules=2), {}, 0)[0], 1)

    def test_null_file_error(self):
        r = report(diags=[err(None)])
        self.assertEqual(c.check(r, {}, 2)[0], 1)

    def test_errors_count_mismatch(self):
        r = report()
        r["errors"] = 1
        self.assertEqual(c.check(r, {}, 2)[0], 1)

    def test_bad_rc(self):
        self.assertEqual(c.check(report(), {}, 2)[0], 1)
        r = report(diags=[err("rules/a.yml")])
        self.assertEqual(c.check(r, {"rules/a.yml": ""}, 0)[0], 1)

    def test_stale_known_entry(self):
        self.assertEqual(c.check(report(), {"rules/gone.yml": "x"}, 0)[0], 1)

    def test_path_normalisation(self):
        r = report(rules=2, diags=[err("rules\\a.yml")])
        self.assertEqual(c.check(r, c.parse_known(["./rules/a.yml # why"]), 2)[0], 0)

    def test_exact_counts(self):
        self.assertEqual(c.check(report(), {}, 0, (3, 3))[0], 0)
        self.assertEqual(c.check(report(), {}, 0, (4, 3))[0], 1)
        self.assertEqual(c.check(report(), {}, 0, (3, 4))[0], 1)

    def test_validate_report(self):
        c.validate_report(report())
        r = report()
        del r["filters"]
        with self.assertRaises(c.SchemaError):
            c.validate_report(r)
        with self.assertRaises(c.SchemaError):
            c.validate_report(report(diags=[{"severity": "error"}]))
        with self.assertRaises(c.SchemaError):
            c.validate_report([])

    def test_main_schema_error_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            rp, kp = os.path.join(d, "r.json"), os.path.join(d, "k.txt")
            with open(rp, "w") as fh:
                json.dump({"files": 1}, fh)
            open(kp, "w").close()
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(c.main(["x", rp, kp]), 2)
            self.assertIn("missing keys", err.getvalue())
            with open(rp, "w") as fh:
                fh.write("not json")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(c.main(["x", rp, kp]), 2)

    def test_main_expect_counts(self):
        with tempfile.TemporaryDirectory() as d:
            rp, kp = os.path.join(d, "r.json"), os.path.join(d, "k.txt")
            with open(rp, "w") as fh:
                json.dump(report(), fh)
            open(kp, "w").close()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(c.main(["x", rp, kp, "--expect-counts", "3,3"]), 0)
                self.assertEqual(c.main(["x", rp, kp, "--expect-counts", "9,9"]), 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(c.main(["x", rp, kp, "--expect-counts", "bad"]), 2)

    def test_usage(self):
        self.assertEqual(c.main(["x"]), 2)


if __name__ == "__main__":
    unittest.main()
