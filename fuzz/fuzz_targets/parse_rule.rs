#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zaaf_pipeline::PipelineSet;

const PIPELINE: &str = "name: fuzz\npriority: 1\nvars:\n  Admins: [root, 'adm_*']\n  Paths: ['C:\\\\Temp\\\\*', x]\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: process.executable\n      User: user.name\n      CommandLine: [process.command_line, process.args]\n";

fn pipelines() -> &'static PipelineSet {
    static P: OnceLock<PipelineSet> = OnceLock::new();
    P.get_or_init(|| {
        PipelineSet::new(vec![
            zaaf_pipeline::parse_pipeline(PIPELINE).expect("fuzz pipeline parses"),
        ])
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let parsed = zaaf_sigma::parse_str(src);
        let docs = parsed
            .documents
            .into_iter()
            .map(|document| zaaf_ir::SourcedDocument {
                document,
                source: None,
            })
            .collect();
        let _ = zaaf_ir::compile(docs, pipelines());
    }
});
