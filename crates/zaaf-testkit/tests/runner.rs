use std::fs;

fn write_case(expected: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(
        dir.path().join("rules/r.yml"),
        "title: r\nid: r\nlogsource: {product: t}\ndetection:\n    s:\n        A: x\n    condition: s\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("events.ndjson"),
        "{\"A\": \"x\"}\n{\"A\": \"y\"}\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("case.yml"),
        format!("spec_ref: test\ndescription: runner self-test\nexpected:\n{expected}"),
    )
    .unwrap();
    dir
}

#[test]
fn passing_case_passes() {
    let dir = write_case("  - [r]\n  - []\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert!(result.passed(), "{:?}", result.failures);
}

#[test]
fn wrong_expectation_is_reported() {
    let dir = write_case("  - []\n  - [r]\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert_eq!(result.failures.len(), 2, "{:?}", result.failures);
    assert!(result.failures[0].contains("event 0"));
}

#[test]
fn event_count_mismatch_is_reported() {
    let dir = write_case("  - [r]\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert!(
        result.failures[0].contains("2 events but 1 expected"),
        "{:?}",
        result.failures
    );
}

#[test]
fn missing_events_file_is_reported() {
    let dir = write_case("  - [r]\n  - []\n");
    fs::remove_file(dir.path().join("events.ndjson")).unwrap();
    let result = zaaf_testkit::run_case(dir.path());
    assert!(!result.passed());
    assert!(
        result.failures[0].contains("events.ndjson"),
        "{:?}",
        result.failures
    );
}

#[test]
fn missing_rules_directory_is_reported() {
    let dir = write_case("  - [r]\n  - []\n");
    fs::remove_dir_all(dir.path().join("rules")).unwrap();
    let result = zaaf_testkit::run_case(dir.path());
    assert!(!result.passed());
    assert!(
        result.failures.iter().any(|f| f.contains("rules")),
        "{:?}",
        result.failures
    );
}

#[test]
fn empty_rules_directory_is_reported() {
    let dir = write_case("  - []\n  - []\n");
    fs::remove_file(dir.path().join("rules/r.yml")).unwrap();
    let result = zaaf_testkit::run_case(dir.path());
    assert!(
        !result.passed(),
        "a case with no rules must not pass vacuously"
    );
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.contains("rules/ contains no rule documents")),
        "{:?}",
        result.failures
    );
}

#[test]
fn empty_expected_is_reported() {
    let dir = write_case("  - [r]\n  - []\n");
    fs::write(
        dir.path().join("case.yml"),
        "spec_ref: t\ndescription: d\nexpected: []\n",
    )
    .unwrap();
    fs::write(dir.path().join("events.ndjson"), "").unwrap();
    let result = zaaf_testkit::run_case(dir.path());
    assert!(
        !result.passed(),
        "an empty expected list must not pass vacuously"
    );
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.contains("`expected` must list at least one event")),
        "{:?}",
        result.failures
    );
}

#[test]
fn error_count_mismatch_is_reported() {
    let dir = write_case("  - [r]\n  - []\n");
    fs::write(dir.path().join("rules/bad.yml"), "title: bad\nid: bad\nlogsource: {product: t}\ndetection:\n    s:\n        A|nope: x\n    condition: s\n").unwrap();
    let result = zaaf_testkit::run_case(dir.path());
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.contains("expected 0 rule errors, got 1")),
        "{:?}",
        result.failures
    );
}

#[test]
fn unknown_case_key_is_reported() {
    let dir = write_case("  - [r]\n  - []\n");
    fs::write(
        dir.path().join("case.yml"),
        "spec_ref: t\ndescription: d\nexpeced_typo: 1\nexpected:\n  - [r]\n  - []\n",
    )
    .unwrap();
    let result = zaaf_testkit::run_case(dir.path());
    assert!(
        result.failures[0].contains("case.yml"),
        "{:?}",
        result.failures
    );
}

#[test]
fn directory_without_case_yml_is_reported_by_the_suite() {
    let root = tempfile::tempdir().unwrap();
    let case = write_case("  - [r]\n  - []\n");
    fs::remove_file(case.path().join("case.yml")).unwrap();
    let target = root.path().join("typo-case");
    fs::create_dir(&target).unwrap();
    fs::rename(case.path().join("rules"), target.join("rules")).unwrap();
    let results = zaaf_testkit::run_suite(root.path()).unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed(), "{:?}", results[0].failures);
}
