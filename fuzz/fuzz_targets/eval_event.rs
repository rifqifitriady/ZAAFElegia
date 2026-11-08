#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zaaf_eval::Evaluator;
use zaaf_event::JsonEvent;

const RULES: &str = r#"
title: fuzz
id: fuzz-1
logsource: {product: fuzz}
detection:
    a:
        A|contains|all: [x, 'y*z']
        B|re: '^(?!q).*\d+$'
    b:
        C|cidr: [10.0.0.0/8, 'fd00::/8']
        D|gte: 5
    c:
        E|hour: 3
        F|fieldref|contains: G
    k:
        - 'kw?rd'
    n:
        H: null
        I|exists: true
    condition: 1 of a or (b and not c) or k or all of n
"#;

fn evaluator() -> &'static Evaluator {
    static E: OnceLock<Evaluator> = OnceLock::new();
    E.get_or_init(|| {
        let parsed = zaaf_sigma::parse_str(RULES);
        let docs = parsed
            .documents
            .into_iter()
            .map(|document| zaaf_ir::SourcedDocument {
                document,
                source: None,
            })
            .collect();
        let out = zaaf_ir::compile(docs, &zaaf_pipeline::PipelineSet::default());
        assert_eq!(
            out.rules.len(),
            1,
            "fuzz rule must compile: {:?}",
            out.diagnostics
        );
        Evaluator::new(out.rules)
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = evaluator().matching_rules(&JsonEvent::new(value));
    }
});
