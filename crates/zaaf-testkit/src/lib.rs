//! Runs the language-neutral Sigma conformance suite against the native evaluator.

use serde::Deserialize;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use zaaf_eval::Evaluator;
use zaaf_input::read_json_events;
use zaaf_ir::{SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Specification section(s) this case pins down.
    pub spec_ref: String,
    /// What is tested, including any interpretation of an ambiguous spec point.
    pub description: String,
    /// Pipeline files relative to the case directory.
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Number of rule errors (parse + compile) the case expects.
    #[serde(default)]
    pub compile_errors: usize,
    /// For each event, the ids of the rules that must match it (order irrelevant).
    pub expected: Vec<Vec<String>>,
}

#[derive(Debug)]
pub struct CaseResult {
    pub name: String,
    pub failures: Vec<String>,
}

impl CaseResult {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Runs every sub-directory of `root` that contains a `case.yml`, sorted by name.
pub fn run_suite(root: &Path) -> Result<Vec<CaseResult>, String> {
    let entries = fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    Ok(dirs
        .iter()
        .filter_map(|d| {
            if d.join("case.yml").is_file() {
                Some(run_case(d))
            } else if d.join("rules").exists() || d.join("events.ndjson").exists() {
                // Looks like a case but has no case.yml: most likely a typo, never skip silently.
                let name = d
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Some(CaseResult {
                    name,
                    failures: vec!["directory has rules/ or events.ndjson but no case.yml".into()],
                })
            } else {
                None
            }
        })
        .collect())
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

pub fn run_case(dir: &Path) -> CaseResult {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fail = |msg: String| CaseResult {
        name: name.clone(),
        failures: vec![msg],
    };

    let spec: CaseSpec = match fs::read_to_string(dir.join("case.yml"))
        .map_err(|e| e.to_string())
        .and_then(|s| serde_saphyr::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => return fail(format!("case.yml: {e}")),
    };
    if spec.expected.is_empty() {
        return fail("case.yml: `expected` must list at least one event".into());
    }
    let pipeline_paths: Vec<PathBuf> = spec.pipelines.iter().map(|p| dir.join(p)).collect();
    let pipelines = match PipelineSet::load(&pipeline_paths) {
        Ok(p) => p,
        Err(d) => return fail(d.to_string()),
    };

    if !dir.join("rules").is_dir() {
        return fail("rules/ directory is missing".into());
    }
    let mut docs = Vec::new();
    let mut errors = Vec::new();
    for f in yaml_files(&dir.join("rules")) {
        let parsed = zaaf_sigma::parse_file(&f);
        errors.extend(parsed.diagnostics.into_iter().filter(|d| d.is_error()));
        docs.extend(
            parsed
                .documents
                .into_iter()
                .map(|document| SourcedDocument {
                    document,
                    source: Some(f.clone()),
                }),
        );
    }
    if docs.is_empty() && errors.is_empty() {
        return fail("rules/ contains no rule documents".into());
    }
    let out = compile(docs, &pipelines);
    errors.extend(out.diagnostics.into_iter().filter(|d| d.is_error()));

    let mut failures = Vec::new();
    if errors.len() != spec.compile_errors {
        let listed: Vec<String> = errors.iter().map(|d| d.to_string()).collect();
        failures.push(format!(
            "expected {} rule errors, got {}: {listed:#?}",
            spec.compile_errors,
            errors.len()
        ));
    }

    let file = match fs::File::open(dir.join("events.ndjson")) {
        Ok(f) => f,
        Err(e) => return fail(format!("events.ndjson: {e}")),
    };
    let mut events = Vec::new();
    for item in read_json_events(BufReader::new(file)) {
        match item {
            Ok(e) => events.push(e),
            Err(e) => return fail(format!("events.ndjson:{}: {}", e.line, e.message)),
        }
    }
    if events.len() != spec.expected.len() {
        failures.push(format!(
            "{} events but {} expected entries",
            events.len(),
            spec.expected.len()
        ));
        return CaseResult { name, failures };
    }

    let evaluator = Evaluator::new(out.rules);
    for (i, (event, want)) in events.iter().zip(&spec.expected).enumerate() {
        let mut got: Vec<String> = evaluator
            .matching_rules(event)
            .into_iter()
            .map(|r| evaluator.rules()[r].info.id.clone())
            .collect();
        got.sort();
        let mut want = want.clone();
        want.sort();
        if got != want {
            failures.push(format!("event {i}: expected {want:?}, got {got:?}"));
        }
    }
    CaseResult { name, failures }
}
