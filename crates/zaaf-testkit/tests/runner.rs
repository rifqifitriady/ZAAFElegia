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
