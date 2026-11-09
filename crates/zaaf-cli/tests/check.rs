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
    zaaf().arg("check").arg(dir.path()).assert().code(2).stdout(
        predicate::str::contains("bad.yml:7:9: detection.sel.CommandLine|nope")
            .and(predicate::str::contains("unknown modifier")),
    );
}

#[test]
fn json_report_and_correlation_warning() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("r.yml"),
        format!("{GOOD}---\ntitle: corr\ncorrelation:\n    type: event_count\n"),
    )
    .unwrap();
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
    let out = zaaf()
        .args(["check", "--format", "json"])
        .arg(dir.path())
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
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
        .stdout(
            predicate::str::contains("path does not exist")
                .and(predicate::str::contains("no rule files found").not()),
        );
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

#[cfg(debug_assertions)]
#[test]
fn internal_panic_exits_four() {
    zaaf()
        .env("ZAAF_INTERNAL_PANIC_TEST", "1")
        .args(["check", "."])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("zaaf internal panic test"));
}

#[cfg(unix)]
#[test]
fn symlinked_rule_file_is_followed() {
    let dir = tempfile::tempdir().unwrap();
    let real = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("good.yml"), GOOD).unwrap();
    fs::write(
        real.path().join("other.yml"),
        GOOD.replace("r-whoami", "r-other"),
    )
    .unwrap();
    std::os::unix::fs::symlink(real.path().join("other.yml"), dir.path().join("link.yml")).unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("checked 2 files: 2 rules"));
}

#[cfg(unix)]
#[test]
fn symlink_loop_is_an_error_not_a_hang() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("good.yml"), GOOD).unwrap();
    std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("cannot read directory"));
    let out = zaaf()
        .args(["check", "--format", "json"])
        .arg(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let file = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| {
            d["message"]
                .as_str()
                .unwrap()
                .contains("cannot read directory")
        })
        .unwrap()["file"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        file.ends_with("loop"),
        "diagnostic should name the failing entry: {file}"
    );
}

#[test]
fn uppercase_and_mixed_case_yaml_extensions_are_loaded() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.YML"), GOOD).unwrap();
    fs::write(dir.path().join("b.Yaml"), GOOD.replace("r-whoami", "r-b")).unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("checked 2 files: 2 rules"));
}

#[test]
fn yaml_extension_loaded() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.yaml"), GOOD).unwrap();
    zaaf()
        .arg("check")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("checked 1 files: 1 rules"));
}

#[test]
fn duplicate_inputs_are_deduped() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("good.yml");
    fs::write(&f, GOOD).unwrap();
    zaaf()
        .arg("check")
        .arg(&f)
        .arg(&f)
        .arg(dir.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("checked 1 files: 1 rules")
                .and(predicate::str::contains("0 errors")),
        );
}

#[test]
fn no_rule_files_is_an_error_even_when_quiet() {
    let dir = tempfile::tempdir().unwrap();
    for extra in [None, Some("-q")] {
        let mut cmd = zaaf();
        cmd.arg("check");
        cmd.args(extra);
        cmd.arg(dir.path())
            .assert()
            .code(2)
            .stdout(predicate::str::contains("no rule files found"));
    }
}

#[test]
fn no_rule_files_among_several_paths_is_fine_when_one_has_rules() {
    let empty = tempfile::tempdir().unwrap();
    let good = tempfile::tempdir().unwrap();
    fs::write(good.path().join("good.yml"), GOOD).unwrap();
    zaaf()
        .arg("check")
        .arg(empty.path())
        .arg(good.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no rule files found").not());
}

#[test]
fn quiet_keeps_errors() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bad.yml"), BAD).unwrap();
    zaaf()
        .args(["check", "-q"])
        .arg(dir.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("unknown modifier"));
}

#[test]
fn check_with_closed_stdout_exits_zero() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("good.yml"), GOOD).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zaaf"))
        .arg("check")
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close the read end at once, so the process's first write hits a broken pipe.
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn check_output_escapes_control_characters_in_titles() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("w.yml"),
        "title: \"T \\e]0;pwned\\a\"\nid: r-w\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|nope: x\n    condition: sel\n",
    )
    .unwrap();
    let out = zaaf().arg("check").arg(dir.path()).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}'),
        "{text:?}"
    );
}

#[test]
fn check_with_closed_stdout_still_exits_two_on_rule_errors() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bad.yml"), BAD).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zaaf"))
        .arg("check")
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
