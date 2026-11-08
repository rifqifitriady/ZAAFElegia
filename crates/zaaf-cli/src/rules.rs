//! Locating, parsing and compiling rule files.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zaaf_ir::{CompileOutput, SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{Diagnostic, Location};

pub struct LoadedRules {
    pub output: CompileOutput,
    pub files: usize,
    pub diagnostics: Vec<Diagnostic>,
}

fn is_yaml(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
}

pub fn collect_rule_files(paths: &[PathBuf]) -> (Vec<PathBuf>, Vec<Diagnostic>) {
    let mut files = Vec::new();
    let mut diags = Vec::new();
    for p in paths {
        if p.is_file() {
            files.push(p.clone());
        } else if p.is_dir() {
            for entry in WalkDir::new(p).follow_links(true).sort_by_file_name() {
                match entry {
                    Ok(e) if e.file_type().is_file() && is_yaml(e.path()) => {
                        files.push(e.into_path())
                    }
                    Ok(_) => {}
                    Err(e) => diags.push(
                        Diagnostic::error(Location::Unknown, format!("cannot read directory: {e}"))
                            .with_file(p.clone()),
                    ),
                }
            }
        } else {
            diags.push(
                Diagnostic::error(Location::Unknown, "path does not exist").with_file(p.clone()),
            );
        }
    }
    // De-duplicate (first seen wins); canonicalize for comparison only.
    let mut seen = HashSet::new();
    files.retain(|f| seen.insert(std::fs::canonicalize(f).unwrap_or_else(|_| f.clone())));
    if files.is_empty() {
        diags.push(Diagnostic::warning(
            Location::Unknown,
            "no rule files found",
        ));
    }
    (files, diags)
}

pub fn load_rules(paths: &[PathBuf], pipelines: &PipelineSet) -> LoadedRules {
    let (files, mut diagnostics) = collect_rule_files(paths);
    let mut docs = Vec::new();
    for f in &files {
        let parsed = zaaf_sigma::parse_file(f);
        diagnostics.extend(parsed.diagnostics);
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
    let mut output = compile(docs, pipelines);
    diagnostics.append(&mut output.diagnostics);
    LoadedRules {
        output,
        files: files.len(),
        diagnostics,
    }
}
