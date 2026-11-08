//! Processing pipelines: field-name mapping and placeholder variables.
//!
//! A pipeline is a YAML file with a `name`, a `priority` (lower runs first,
//! default 0), placeholder `vars` for `|expand` values, and `transformations`:
//!
//! ```yaml
//! name: ecs-windows
//! priority: 10
//! vars:
//!   Admins: ['adm_*', root]
//! transformations:
//!   - type: field_name_mapping
//!     mapping:
//!       Image: process.executable
//!       CommandLine: [process.command_line, process.args]
//!     rule_conditions:
//!       - product: windows
//! ```

use indexmap::IndexMap;
use serde::Deserialize;
use std::path::PathBuf;
use zaaf_sigma::{Diagnostic, Location, LogSource};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pipeline {
    pub name: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub vars: IndexMap<String, Vec<String>>,
    #[serde(default)]
    pub transformations: Vec<Transformation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transformation {
    FieldNameMapping {
        #[serde(deserialize_with = "non_empty_mapping")]
        mapping: IndexMap<String, OneOrMany>,
        #[serde(default)]
        rule_conditions: Vec<LogSourceCondition>,
    },
}

/// Deserializes a field mapping, rejecting a field with an empty target list (it would
/// otherwise map to no field at all). The error carries the YAML position.
fn non_empty_mapping<'de, D>(d: D) -> Result<IndexMap<String, OneOrMany>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mapping = IndexMap::<String, OneOrMany>::deserialize(d)?;
    for (field, targets) in &mapping {
        if targets.targets().is_empty() {
            return Err(serde::de::Error::custom(format!(
                "mapping for `{field}` has an empty target list"
            )));
        }
    }
    Ok(mapping)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn targets(&self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSourceCondition {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

impl LogSourceCondition {
    pub fn matches(&self, ls: &LogSource) -> bool {
        fn eq(want: &Option<String>, have: &Option<String>) -> bool {
            match want {
                None => true,
                Some(w) => have.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(w)),
            }
        }
        eq(&self.category, &ls.category)
            && eq(&self.product, &ls.product)
            && eq(&self.service, &ls.service)
    }
}

/// Field names a rule field maps to, and whether any pipeline mapped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedField {
    pub names: Vec<String>,
    pub mapped: bool,
}

pub fn parse_pipeline(src: &str) -> Result<Pipeline, String> {
    parse_located(src).map_err(|(_, msg)| msg)
}

/// Parses a pipeline; an error carries its 1-based position when the YAML library knows it.
fn parse_located(src: &str) -> Result<Pipeline, (Location, String)> {
    serde_saphyr::from_str(src).map_err(|e| {
        let location = e.location().map_or(Location::Unknown, |l| {
            Location::at(l.line() as usize, l.column() as usize, "")
        });
        (location, e.without_snippet().to_string())
    })
}

/// Pipelines applied in ascending priority order.
#[derive(Debug, Clone, Default)]
pub struct PipelineSet {
    pipelines: Vec<Pipeline>,
}

impl PipelineSet {
    pub fn new(mut pipelines: Vec<Pipeline>) -> Self {
        pipelines.sort_by_key(|p| p.priority);
        Self { pipelines }
    }

    pub fn load(paths: &[PathBuf]) -> Result<Self, Diagnostic> {
        let mut pipelines = Vec::new();
        for p in paths {
            let src = std::fs::read_to_string(p).map_err(|e| {
                Diagnostic::error(Location::Unknown, format!("cannot read pipeline: {e}"))
                    .with_file(p)
            })?;
            let pipeline = parse_located(&src).map_err(|(location, e)| {
                Diagnostic::error(location, format!("invalid pipeline: {e}")).with_file(p)
            })?;
            pipelines.push(pipeline);
        }
        Ok(Self::new(pipelines))
    }

    pub fn is_empty(&self) -> bool {
        self.pipelines.is_empty()
    }

    /// True when any loaded pipeline has a `field_name_mapping` transformation.
    pub fn has_field_mappings(&self) -> bool {
        self.pipelines.iter().any(|p| {
            p.transformations
                .iter()
                .any(|t| matches!(t, Transformation::FieldNameMapping { .. }))
        })
    }

    pub fn map_field(&self, ls: &LogSource, field: &str) -> MappedField {
        let mut names = vec![field.to_string()];
        let mut mapped = false;
        for p in &self.pipelines {
            for t in &p.transformations {
                let Transformation::FieldNameMapping {
                    mapping,
                    rule_conditions,
                } = t;
                if !rule_conditions.is_empty() && !rule_conditions.iter().any(|c| c.matches(ls)) {
                    continue;
                }
                let mut next: Vec<String> = Vec::new();
                for n in &names {
                    match mapping.get(n) {
                        Some(targets) => {
                            mapped = true;
                            for t in targets.targets() {
                                if !next.contains(&t) {
                                    next.push(t);
                                }
                            }
                        }
                        None => {
                            if !next.contains(n) {
                                next.push(n.clone());
                            }
                        }
                    }
                }
                names = next;
            }
        }
        MappedField { names, mapped }
    }

    pub fn placeholder(&self, name: &str) -> Option<&[String]> {
        self.pipelines
            .iter()
            .rev()
            .find_map(|p| p.vars.get(name).map(Vec::as_slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(product: &str) -> LogSource {
        LogSource {
            product: Some(product.into()),
            ..Default::default()
        }
    }

    const ECS: &str = "name: ecs\npriority: 10\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: process.executable\n      CommandLine: [process.command_line, process.args]\n    rule_conditions:\n      - product: windows\n";

    #[test]
    fn maps_one_to_one_and_one_to_many() {
        let set = PipelineSet::new(vec![parse_pipeline(ECS).unwrap()]);
        assert_eq!(
            set.map_field(&ls("windows"), "Image"),
            MappedField {
                names: vec!["process.executable".into()],
                mapped: true
            }
        );
        assert_eq!(
            set.map_field(&ls("Windows"), "CommandLine").names,
            vec!["process.command_line", "process.args"]
        );
    }

    #[test]
    fn unmatched_condition_or_field_passes_through() {
        let set = PipelineSet::new(vec![parse_pipeline(ECS).unwrap()]);
        assert_eq!(
            set.map_field(&ls("linux"), "Image"),
            MappedField {
                names: vec!["Image".into()],
                mapped: false
            }
        );
        assert!(!set.map_field(&ls("windows"), "User").mapped);
    }

    #[test]
    fn pipelines_chain_in_priority_order() {
        let late = parse_pipeline(
            "name: late\npriority: 20\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      process.executable: proc.exe\n",
        )
        .unwrap();
        let set = PipelineSet::new(vec![late, parse_pipeline(ECS).unwrap()]);
        assert_eq!(
            set.map_field(&ls("windows"), "Image").names,
            vec!["proc.exe"]
        );
    }

    #[test]
    fn later_pipeline_vars_override_earlier() {
        let a = parse_pipeline("name: a\npriority: 1\nvars:\n  Admins: [root]\n").unwrap();
        let b = parse_pipeline("name: b\npriority: 2\nvars:\n  Admins: ['adm_*']\n").unwrap();
        let set = PipelineSet::new(vec![b, a]);
        assert_eq!(set.placeholder("Admins"), Some(&["adm_*".to_string()][..]));
        assert_eq!(set.placeholder("Missing"), None);
    }

    #[test]
    fn rejects_unknown_transformation_and_fields() {
        let err =
            parse_pipeline("name: x\ntransformations:\n  - type: drop_everything\n").unwrap_err();
        assert!(err.contains("drop_everything"), "{err}");
        assert!(parse_pipeline("name: x\nbogus: 1\n").is_err());
    }

    #[test]
    fn load_reports_missing_file_with_path() {
        let err = PipelineSet::load(&[PathBuf::from("/nonexistent/p.yml")]).unwrap_err();
        assert!(err.is_error());
        assert_eq!(
            err.file.as_deref(),
            Some(std::path::Path::new("/nonexistent/p.yml"))
        );
    }

    #[test]
    fn load_reports_the_position_of_an_invalid_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.yml");
        std::fs::write(&p, "name: x\ntransformations:\n  - type: drop_everything\n").unwrap();
        let err = PipelineSet::load(&[p]).unwrap_err();
        assert!(
            matches!(err.location, Location::At { line: 3, .. }),
            "{err:?}"
        );
        assert!(err.message.contains("drop_everything"), "{err}");
    }

    #[test]
    fn empty_target_lists_are_rejected_with_a_position() {
        let err = parse_pipeline(
            "name: x\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      F: []\n",
        )
        .unwrap_err();
        assert!(err.contains("`F`") && err.contains("empty"), "{err}");
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.yml");
        std::fs::write(
            &p,
            "name: x\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      F: []\n",
        )
        .unwrap();
        let err = PipelineSet::load(&[p]).unwrap_err();
        assert!(
            matches!(err.location, Location::At { line, .. } if line >= 3),
            "{err:?}"
        );
    }

    #[test]
    fn has_field_mappings_ignores_vars_only_pipelines() {
        let vars = parse_pipeline("name: v\nvars:\n  A: [x]\n").unwrap();
        assert!(!PipelineSet::new(vec![vars.clone()]).has_field_mappings());
        assert!(!PipelineSet::default().has_field_mappings());
        let set = PipelineSet::new(vec![vars, parse_pipeline(ECS).unwrap()]);
        assert!(set.has_field_mappings());
    }

    #[test]
    fn empty_set_maps_nothing() {
        let set = PipelineSet::default();
        assert!(set.is_empty());
        assert_eq!(set.map_field(&ls("windows"), "Image").names, vec!["Image"]);
    }
}
