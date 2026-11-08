use std::path::Path;

#[test]
fn conformance_suite_passes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases");
    let results = zaaf_testkit::run_suite(&root).expect("conformance/cases is readable");
    assert!(
        results.len() >= 29,
        "expected at least 29 cases, found {}",
        results.len()
    );
    let failed: Vec<_> = results.iter().filter(|r| !r.passed()).collect();
    for f in &failed {
        eprintln!("FAIL {}:\n  {}", f.name, f.failures.join("\n  "));
    }
    assert!(
        failed.is_empty(),
        "{} of {} conformance cases failed",
        failed.len(),
        results.len()
    );
}
