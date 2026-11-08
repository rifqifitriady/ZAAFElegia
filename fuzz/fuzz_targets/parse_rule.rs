#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let parsed = zaaf_sigma::parse_str(src);
        let docs = parsed
            .documents
            .into_iter()
            .map(|document| zaaf_ir::SourcedDocument { document, source: None })
            .collect();
        let _ = zaaf_ir::compile(docs, &zaaf_pipeline::PipelineSet::default());
    }
});
