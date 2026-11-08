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
    c.arg("hunt")
        .arg("-r")
        .arg(dir.join("rules"))
        .arg(dir.join("events.ndjson"));
    c
}

#[test]
fn ndjson_findings_with_attribution() {
    let dir = setup();
    let out = hunt(dir.path())
        .args(["-o", "ndjson"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let findings: Vec<serde_json::Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(findings.len(), 2);
    let whoami = findings
        .iter()
        .find(|f| f["finding_info"]["analytic"]["uid"] == "r-whoami")
        .unwrap();
    assert_eq!(whoami["class_uid"], 2004);
    assert_eq!(whoami["unmapped"]["sigma"]["author"], "Tester");
    assert_eq!(
        whoami["unmapped"]["sigma"]["references"][0],
        "https://example.com/ref"
    );
    assert_eq!(
        whoami["evidences"][0]["data"]["CommandLine"],
        "cmd /c whoami"
    );
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
    fs::write(
        dir.path().join("events.ndjson"),
        "{\"CommandLine\": \"whoami\"}\nnot json\n",
    )
    .unwrap();
    hunt(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains(":2: invalid JSON"));
    hunt(dir.path()).arg("--strict").assert().code(3);
    hunt(dir.path())
        .args(["--max-errors", "0"])
        .assert()
        .code(3);
    fs::write(
        dir.path().join("rules/bad.yml"),
        "title: bad\nlogsource:\n    product: x\ndetection:\n    s:\n        A|nope: 1\n    condition: s\n",
    )
    .unwrap();
    hunt(dir.path()).arg("--strict").assert().code(2);
}

#[test]
fn regex_limit_hits_are_reported_without_changing_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(
        dir.path().join("rules/re.yml"),
        "title: Backtrack\nid: r-backtrack\nstatus: test\nlevel: high\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|re: '^(a|a)*\\1$'\n    condition: sel\n",
    )
    .unwrap();
    let ev = format!("{{\"CommandLine\": \"{}b\"}}\n", "a".repeat(40));
    fs::write(dir.path().join("events.ndjson"), ev).unwrap();
    hunt(dir.path())
        .args(["-o", "ndjson"])
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("hit the backtracking limit")
                .and(predicate::str::contains("r-backtrack")),
        );
}

fn backtrack_rule(dir: &Path) {
    fs::write(
        dir.join("rules/re.yml"),
        "title: Backtrack\nid: r-backtrack\nstatus: test\nlevel: high\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|re: '^(a|a)*\\1$'\n    condition: sel\n",
    )
    .unwrap();
}

fn only_rule(rules: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(dir.path().join("rules/r.yml"), rules).unwrap();
    dir
}

#[test]
fn unreadable_input_exits_three_after_processing_others() {
    let dir = setup();
    hunt(dir.path())
        .arg(dir.path().join("missing.ndjson"))
        .args(["-o", "ndjson"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("r-whoami"))
        .stderr(predicate::str::contains("1 unreadable inputs"));
}

#[test]
fn table_output_escapes_control_characters() {
    let dir = only_rule(
        "title: \"T\\rX \\e[31mred\"\nid: r-esc\nstatus: test\nlevel: low\nlogsource:\n    product: test\ndetection:\n    sel:\n        CommandLine|contains: whoami\n    condition: sel\n",
    );
    fs::write(
        dir.path().join("e.ndjson"),
        "{\"CommandLine\": \"whoami\"}\n",
    )
    .unwrap();
    let out = zaaf()
        .arg("hunt")
        .arg("-r")
        .arg(dir.path().join("rules"))
        .args(["-o", "table"])
        .arg(dir.path().join("e.ndjson"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains('\u{1b}') && !text.contains('\r'), "{text:?}");
    assert!(text.contains("\\x1b"), "{text:?}");
}

#[test]
fn regex_warning_on_max_errors_abort() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    backtrack_rule(dir.path());
    let ev = format!(
        "{{\"CommandLine\": \"{}b\"}}\nbad\nbad\nbad\n",
        "a".repeat(40)
    );
    fs::write(dir.path().join("events.ndjson"), ev).unwrap();
    hunt(dir.path())
        .args(["--max-errors", "1"])
        .assert()
        .code(3)
        .stderr(
            predicate::str::contains("hit the backtracking limit")
                .and(predicate::str::contains("r-backtrack")),
        );
}

#[test]
fn filters_removing_all_rules_say_so() {
    let dir = setup();
    hunt(dir.path())
        .args(["--min-level", "critical", "--status", "test"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "no rules left after --min-level/--status filters",
        ));
}

#[test]
fn to_bound_and_missing_timestamp_and_bad_from() {
    let dir = setup();
    hunt(dir.path())
        .args(["--to", "2026-11-07T01:30:00Z", "-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("r-whoami").and(predicate::str::contains("r-mimi").not()))
        .stderr(predicate::str::contains("outside time range"));
    zaaf()
        .arg("hunt")
        .arg("-r")
        .arg(dir.path().join("rules"))
        .args(["--from", "2030-01-01T00:00:00Z", "-o", "csv", "-"])
        .write_stdin("{\"CommandLine\": \"whoami\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("r-whoami"));
    hunt(dir.path())
        .args(["--from", "garbage"])
        .assert()
        .code(2);
}

#[test]
fn max_errors_boundary() {
    let dir = setup();
    fs::write(dir.path().join("events.ndjson"), "bad\nbad\n").unwrap();
    hunt(dir.path())
        .args(["--max-errors", "2"])
        .assert()
        .code(0);
    hunt(dir.path())
        .args(["--max-errors", "1"])
        .assert()
        .code(3);
}

#[test]
fn mixed_stdin_and_file_inputs() {
    let dir = setup();
    zaaf()
        .arg("hunt")
        .arg("-r")
        .arg(dir.path().join("rules"))
        .args(["-o", "ndjson", "-"])
        .arg(dir.path().join("events.ndjson"))
        .write_stdin("{\"CommandLine\": \"whoami\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("<stdin>").and(predicate::str::contains("events.ndjson")))
        .stderr(predicate::str::contains("4 events"));
}

#[test]
fn strict_malformed_beats_fail_on_match() {
    let dir = setup();
    fs::write(
        dir.path().join("events.ndjson"),
        "{\"CommandLine\": \"whoami\"}\nnot json\n",
    )
    .unwrap();
    hunt(dir.path())
        .args(["--strict", "--fail-on-match"])
        .assert()
        .code(3);
}
