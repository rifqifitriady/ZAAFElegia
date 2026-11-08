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
