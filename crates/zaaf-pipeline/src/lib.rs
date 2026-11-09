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

/// One pipeline file: a named, prioritised set of transformations and placeholder values.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pipeline {
    /// Human-readable pipeline name.
    pub name: String,
    /// Lower priorities are applied first; defaults to 0.
    #[serde(default)]
    pub priority: i32,
    /// Placeholder values referenced by `|expand` modifiers, keyed by placeholder name.
    #[serde(default)]
    pub vars: IndexMap<String, Vec<String>>,
    /// Transformations applied, in order, when the pipeline runs.
    #[serde(default)]
    pub transformations: Vec<Transformation>,
}

/// A pipeline transformation, selected by its `type` key.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transformation {
    /// Renames rule fields to event field names.
    FieldNameMapping {
        /// Rule field name to one or more event field names (never an empty list).
        #[serde(deserialize_with = "non_empty_mapping")]
        mapping: IndexMap<String, OneOrMany>,
        /// The mapping applies when any condition matches the rule's logsource
        /// (conditions are OR'd; the fields inside one condition are AND'd).
        /// Empty means it always applies.
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

/// A single target or a list of targets in a mapping.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    /// One target field name.
    One(String),
    /// Several target field names; a rule field maps to all of them (OR'd).
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

/// A logsource condition. Every field that is set must match (AND); fields that are
/// unset match anything. Comparison is Unicode case-insensitive.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSourceCondition {
    /// Required logsource category, if any.
    pub category: Option<String>,
    /// Required logsource product, if any.
    pub product: Option<String>,
    /// Required logsource service, if any.
    pub service: Option<String>,
}

impl LogSourceCondition {
    /// True when every set field equals the logsource's field (Unicode case-insensitive).
    pub fn matches(&self, ls: &LogSource) -> bool {
        fn eq(want: &Option<String>, have: &Option<String>) -> bool {
            match want {
                None => true,
                Some(w) => have
                    .as_deref()
                    .is_some_and(|h| h.to_lowercase() == w.to_lowercase()),
            }
        }
        eq(&self.category, &ls.category)
            && eq(&self.product, &ls.product)
            && eq(&self.service, &ls.service)
    }
}

/// Field names a rule field maps to, and whether any pipeline mapped it.
///
/// A mapping that maps a field to itself (an identity mapping) still counts as mapped:
/// `mapped` records that a pipeline mentioned the field, not that the name changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedField {
    /// The event field names to look at, deduplicated, in mapping order.
    pub names: Vec<String>,
    /// Whether any applicable pipeline mapping covered the field.
    pub mapped: bool,
}

/// Parses one pipeline from YAML text.
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
    /// Builds a set from already-parsed pipelines, ordering them by ascending priority
    /// (stable for equal priorities).
    pub fn new(mut pipelines: Vec<Pipeline>) -> Self {
        pipelines.sort_by_key(|p| p.priority);
        Self { pipelines }
    }

    /// Reads and parses pipeline files.
    ///
    /// Fails fast: the first unreadable or invalid file aborts the load and is the only
    /// diagnostic returned; later files are not examined.
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

    /// True when no pipeline is loaded.
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

    /// Maps a rule field through every applicable pipeline in priority order.
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

    /// Values of the placeholder `name`; a pipeline applied later overrides an earlier one.
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

    fn mapping_with_conditions(conds: &str) -> PipelineSet {
        let y = format!(
            "name: c\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: exe\n    rule_conditions:\n{conds}"
        );
        PipelineSet::new(vec![parse_pipeline(&y).unwrap()])
    }

    fn full_ls(category: &str, product: &str) -> LogSource {
        LogSource {
            category: Some(category.into()),
            product: Some(product.into()),
            service: None,
        }
    }

    #[test]
    fn any_of_the_rule_conditions_may_match() {
        let set = mapping_with_conditions("      - product: windows\n      - product: linux\n");
        assert!(set.map_field(&ls("linux"), "Image").mapped);
        assert!(set.map_field(&ls("windows"), "Image").mapped);
        assert!(!set.map_field(&ls("macos"), "Image").mapped);
    }

    #[test]
    fn fields_within_one_condition_are_anded() {
        let set =
            mapping_with_conditions("      - product: windows\n        category: process_creation\n");
        assert!(
            set.map_field(&full_ls("process_creation", "windows"), "Image")
                .mapped
        );
        assert!(
            !set.map_field(&full_ls("network_connection", "windows"), "Image")
                .mapped
        );
        assert!(!set.map_field(&ls("windows"), "Image").mapped);
    }

    #[test]
    fn rule_conditions_match_unicode_case_insensitively() {
        let set = mapping_with_conditions("      - product: ÄÖÜ\n");
        assert!(set.map_field(&ls("äöü"), "Image").mapped);
        assert!(set.map_field(&ls("ÄÖÜ"), "Image").mapped);
    }

    #[test]
    fn identity_mapping_counts_as_mapped() {
        let set = PipelineSet::new(vec![
            parse_pipeline(
                "name: i\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: Image\n",
            )
            .unwrap(),
        ]);
        let m = set.map_field(&ls("windows"), "Image");
        assert!(m.mapped);
        assert_eq!(m.names, vec!["Image"]);
    }

    #[test]
    fn load_reads_several_files_and_orders_by_priority() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.yml");
        let b = dir.path().join("b.yml");
        std::fs::write(
            &a,
            "name: a\npriority: 20\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      process.executable: proc.exe\n",
        )
        .unwrap();
        std::fs::write(&b, ECS).unwrap();
        let set = PipelineSet::load(&[a, b]).unwrap();
        assert_eq!(
            set.map_field(&ls("windows"), "Image").names,
            vec!["proc.exe"]
        );
    }

    #[test]
    fn load_stops_at_the_first_bad_file() {
        let dir = tempfile::tempdir().unwrap();
        let bad1 = dir.path().join("bad1.yml");
        let bad2 = dir.path().join("bad2.yml");
        std::fs::write(&bad1, "name: x\nbogus: 1\n").unwrap();
        std::fs::write(&bad2, "name: [unclosed\n").unwrap();
        let err = PipelineSet::load(&[bad1.clone(), bad2]).unwrap_err();
        assert_eq!(err.file.as_deref(), Some(bad1.as_path()));
    }

    #[test]
    fn load_reports_the_position_of_a_yaml_syntax_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("syntax.yml");
        std::fs::write(&p, "name: x\nvars: [unclosed\n").unwrap();
        let err = PipelineSet::load(&[p]).unwrap_err();
        assert!(
            matches!(err.location, Location::At { line, .. } if line >= 2),
            "{err:?}"
        );
        assert!(err.message.contains("invalid pipeline"), "{err}");
    }

    #[test]
    fn empty_set_maps_nothing() {
        let set = PipelineSet::default();
        assert!(set.is_empty());
        assert_eq!(set.map_field(&ls("windows"), "Image").names, vec!["Image"]);
    }
}
