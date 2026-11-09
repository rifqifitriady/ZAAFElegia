//! Sigma YAML documents: rules, meta filters and (stubbed) correlation rules.

use crate::condition::{CondExpr, parse_condition};
use crate::diagnostic::{Diagnostic, Location};
use crate::modifier::{Modifier, parse_field_key};
use crate::value::RuleValue;
use saphyr::{AnnotatedMapping, LoadableYamlNode, MarkedYaml, Scalar, YamlData};
use std::path::Path;

type Node<'a> = MarkedYaml<'a>;
type Map<'a> = AnnotatedMapping<'a, MarkedYaml<'a>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// One `field|modifiers: values` entry. `field` is `None` for keyword search.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldItem {
    pub field: Option<String>,
    pub modifiers: Vec<Modifier>,
    pub values: Vec<RuleValue>,
    /// YAML path used in diagnostics, e.g. `detection.selection.Image|endswith`.
    pub path: String,
    /// 1-based position of the item's key (of the search identifier for keyword lists).
    pub line: usize,
    pub col: usize,
}

/// A named search identifier. Alternatives are OR'd; items in one alternative are AND'd.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchIdentifier {
    pub name: String,
    pub alternatives: Vec<Vec<FieldItem>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub search_ids: Vec<SearchIdentifier>,
    /// Several conditions are OR'd.
    pub conditions: Vec<CondExpr>,
    /// 1-based position of the `condition` value (of its first entry for a list).
    pub condition_line: usize,
    pub condition_col: usize,
    /// 1-based `(line, col)` of each entry of `conditions`, in the same order. The first
    /// equals `(condition_line, condition_col)` unless `condition` is a list.
    pub condition_positions: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleMeta {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub meta: RuleMeta,
    pub logsource: LogSource,
    pub detection: Detection,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub logsource: LogSource,
    /// Ids or names of the rules the filter applies to.
    pub rules: Vec<String>,
    pub detection: Detection,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

/// Placeholder until correlation rules are implemented (milestone M2).
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationStub {
    pub title: String,
    pub id: Option<String>,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    Rule(Rule),
    Filter(Filter),
    Correlation(CorrelationStub),
}

#[derive(Debug, Default)]
pub struct ParsedFile {
    pub documents: Vec<Document>,
    pub diagnostics: Vec<Diagnostic>,
}

type Diags = Vec<Diagnostic>;

/// 1-based line and column where `node` starts.
fn line_col(node: &Node) -> (usize, usize) {
    (node.span.start.line(), node.span.start.col() + 1)
}

fn err(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::error(Location::at(line, col, path), msg)
}

/// The key and value nodes of `key` in a mapping.
fn entry<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<(&'n Node<'a>, &'n Node<'a>)> {
    map.iter().find(|(k, _)| k.data.as_str() == Some(key))
}

fn get<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<&'n Node<'a>> {
    entry(map, key).map(|(_, v)| v)
}

/// Parses a (possibly multi-document) Sigma YAML string.
pub fn parse_str(src: &str) -> ParsedFile {
    let mut out = ParsedFile::default();
    let docs = match MarkedYaml::load_from_str(src) {
        Ok(docs) => docs,
        Err(e) => {
            let m = e.marker();
            out.diagnostics.push(Diagnostic::error(
                Location::at(m.line(), m.col() + 1, ""),
                format!("invalid YAML: {}", e.info()),
            ));
            return out;
        }
    };
    for doc in &docs {
        if doc.data.is_null() {
            continue;
        }
        match parse_document(doc, &mut out.diagnostics) {
            Ok(d) => out.documents.push(d),
            Err(mut d) => out.diagnostics.append(&mut d),
        }
    }
    out
}

/// Reads and parses a rule file; every diagnostic carries `path`.
pub fn parse_file(path: &Path) -> ParsedFile {
    let mut parsed = match std::fs::read_to_string(path) {
        Ok(src) => parse_str(&src),
        Err(e) => ParsedFile {
            documents: Vec::new(),
            diagnostics: vec![Diagnostic::error(
                Location::Unknown,
                format!("cannot read file: {e}"),
            )],
        },
    };
    for d in &mut parsed.diagnostics {
        d.file = Some(path.to_path_buf());
    }
    parsed
}

/// `warns` collects non-fatal findings (they are kept even when the document is rejected).
fn parse_document(doc: &Node, warns: &mut Diags) -> Result<Document, Diags> {
    let YamlData::Mapping(map) = &doc.data else {
        return Err(vec![err(doc, "", "document is not a YAML mapping")]);
    };
    if let Some(d) = merge_key_error(map, "") {
        return Err(vec![d]);
    }
    if let Some((key, _)) = entry(map, "action") {
        return Err(vec![err(
            key,
            "action",
            "Sigma 1.x collection actions (`action: global|reset|repeat`) are not supported; \
             split the collection into standalone rules",
        )]);
    }
    let (line, col) = line_col(doc);
    let has = |key: &str| entry(map, key).is_some();
    if has("correlation") {
        return Ok(Document::Correlation(CorrelationStub {
            title: get_str(map, "title").unwrap_or_default(),
            id: get_str(map, "id"),
            line,
            col,
        }));
    }
    if has("filter") && !has("detection") {
        return parse_filter(doc, map, warns).map(Document::Filter);
    }
    if has("detection") {
        return parse_rule(doc, map, warns).map(Document::Rule);
    }
    Err(vec![err(
        doc,
        "",
        "document is not a Sigma rule, filter or correlation (no `detection`, `filter` or `correlation` key)",
    )])
}

/// A scalar mapping value as text. `Ok(None)` when the key is absent or null, `Err` with
/// the value node when it has the wrong type (booleans, lists, mappings).
fn str_of<'n, 'a>(map: &'n Map<'a>, key: &str) -> Result<Option<String>, &'n Node<'a>> {
    let Some(node) = get(map, key) else {
        return Ok(None);
    };
    match &node.data {
        YamlData::Value(Scalar::String(s)) => Ok(Some(s.to_string())),
        YamlData::Value(Scalar::Integer(i)) => Ok(Some(i.to_string())),
        YamlData::Value(Scalar::FloatingPoint(f)) => Ok(Some(f.into_inner().to_string())),
        YamlData::Value(Scalar::Null) => Ok(None),
        _ => Err(node),
    }
}

/// Lenient text lookup: a missing or wrongly typed value is `None`.
fn get_str(map: &Map, key: &str) -> Option<String> {
    str_of(map, key).ok().flatten()
}

fn warn(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::warning(Location::at(line, col, path), msg)
}

/// Optional text metadata; a wrongly typed value is ignored with a warning.
fn meta_str(map: &Map, key: &str, warns: &mut Diags) -> Option<String> {
    match str_of(map, key) {
        Ok(v) => v,
        Err(node) => {
            warns.push(warn(
                node,
                key,
                format!("`{key}` must be a string; the value is ignored"),
            ));
            None
        }
    }
}

/// A list of strings (or one string). Entries of another type are dropped with a warning
/// naming the field.
fn get_str_list(map: &Map, key: &str, warns: &mut Diags) -> Vec<String> {
    let Some(node) = get(map, key) else {
        return Vec::new();
    };
    match &node.data {
        YamlData::Sequence(seq) => {
            let mut out = Vec::new();
            for (i, v) in seq.iter().enumerate() {
                match v.data.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => warns.push(warn(
                        v,
                        &format!("{key}[{i}]"),
                        format!("`{key}` entries must be strings; this entry is ignored"),
                    )),
                }
            }
            out
        }
        YamlData::Value(Scalar::String(s)) => vec![s.to_string()],
        YamlData::Value(Scalar::Null) => Vec::new(),
        _ => {
            warns.push(warn(
                node,
                key,
                format!("`{key}` must be a string or a list of strings; the value is ignored"),
            ));
            Vec::new()
        }
    }
}

/// An error when `map` uses a YAML merge key (`<<`), which Sigma documents may not use.
fn merge_key_error(map: &Map, path: &str) -> Option<Diagnostic> {
    map.iter()
        .find(|(k, _)| k.data.as_str() == Some("<<"))
        .map(|(k, _)| err(k, path, "YAML merge keys (`<<`) are not supported"))
}

/// The mandatory `title` (a missing or non-string one is an error in `diags`).
fn parse_title(doc: &Node, map: &Map, diags: &mut Diags) -> Option<String> {
    match str_of(map, "title") {
        Ok(Some(t)) => Some(t),
        Ok(None) => {
            diags.push(err(doc, "title", "missing mandatory `title`"));
            None
        }
        Err(node) => {
            diags.push(err(node, "title", "`title` must be a string"));
            None
        }
    }
}

/// Shared skeleton of rules and filters: the common title and logsource, then the
/// detection parsed by `detection`. Builds the document with `build` when everything is
/// valid, otherwise returns all collected errors.
fn assemble<T>(
    doc: &Node,
    map: &Map,
    mut diags: Diags,
    detection: Option<Detection>,
    build: impl FnOnce(String, LogSource, Detection) -> T,
) -> Result<T, Diags> {
    let title = parse_title(doc, map, &mut diags);
    let logsource = parse_logsource(doc, map)
        .map_err(|mut d| diags.append(&mut d))
        .ok();
    match (title, logsource, detection) {
        (Some(title), Some(logsource), Some(detection)) if diags.is_empty() => {
            Ok(build(title, logsource, detection))
        }
        _ => Err(diags),
    }
}

fn parse_logsource(doc: &Node, map: &Map) -> Result<LogSource, Diags> {
    match entry(map, "logsource") {
        Some((
            _,
            Node {
                data: YamlData::Mapping(ls),
                ..
            },
        )) => Ok(LogSource {
            category: get_str(ls, "category"),
            product: get_str(ls, "product"),
            service: get_str(ls, "service"),
        }),
        other => Err(vec![err(
            other.map_or(doc, |(_, v)| v),
            "logsource",
            "missing mandatory `logsource` mapping",
        )]),
    }
}

fn parse_rule(doc: &Node, map: &Map, warns: &mut Diags) -> Result<Rule, Diags> {
    let mut diags = Vec::new();
    let detection = match entry(map, "detection") {
        Some((
            key,
            Node {
                data: YamlData::Mapping(dm),
                ..
            },
        )) => parse_detection("detection", key, dm, &[])
            .map_err(|mut d| diags.append(&mut d))
            .ok(),
        other => {
            diags.push(err(
                other.map_or(doc, |(_, v)| v),
                "detection",
                "`detection` must be a mapping",
            ));
            None
        }
    };
    let (line, col) = line_col(doc);
    let meta = RuleMeta {
        title: String::new(),
        id: meta_str(map, "id", warns),
        name: meta_str(map, "name", warns),
        status: meta_str(map, "status", warns),
        level: meta_str(map, "level", warns),
        description: meta_str(map, "description", warns),
        author: meta_str(map, "author", warns),
        references: get_str_list(map, "references", warns),
        tags: get_str_list(map, "tags", warns),
        falsepositives: get_str_list(map, "falsepositives", warns),
        date: meta_str(map, "date", warns),
        modified: meta_str(map, "modified", warns),
    };
    assemble(doc, map, diags, detection, |title, logsource, detection| {
        Rule {
            meta: RuleMeta { title, ..meta },
            logsource,
            detection,
            line,
            col,
        }
    })
}

fn parse_filter(doc: &Node, map: &Map, warns: &mut Diags) -> Result<Filter, Diags> {
    let mut diags = Vec::new();
    let mut rules = Vec::new();
    let detection = match entry(map, "filter") {
        Some((
            key,
            Node {
                data: YamlData::Mapping(fm),
                ..
            },
        )) => {
            rules = get_str_list(fm, "rules", warns);
            if rules.is_empty() {
                let at = entry(fm, "rules").map_or(key, |(k, _)| k);
                diags.push(err(
                    at,
                    "filter.rules",
                    "`filter.rules` must list at least one rule id or name",
                ));
            }
            parse_detection("filter", key, fm, &["rules"])
                .map_err(|mut d| diags.append(&mut d))
                .ok()
        }
        other => {
            diags.push(err(
                other.map_or(doc, |(_, v)| v),
                "filter",
                "`filter` must be a mapping",
            ));
            None
        }
    };
    let (line, col) = line_col(doc);
    let (id, name) = (meta_str(map, "id", warns), meta_str(map, "name", warns));
    assemble(doc, map, diags, detection, |title, logsource, detection| {
        Filter {
            title,
            id,
            name,
            logsource,
            rules,
            detection,
            line,
            col,
        }
    })
}

/// `key` is the `detection:` / `filter:` key node, `dm` its mapping.
fn parse_detection(
    base: &str,
    key: &Node,
    dm: &Map,
    reserved: &[&str],
) -> Result<Detection, Diags> {
    let mut diags = Vec::new();
    if let Some(d) = merge_key_error(dm, base) {
        return Err(vec![d]);
    }
    let mut search_ids = Vec::new();
    let mut conditions = Vec::new();
    let mut condition_positions = Vec::new();
    let mut condition_at = None;
    for (k, v) in dm {
        let Some(name) = k.data.as_str() else {
            diags.push(err(k, base, "search identifier names must be strings"));
            continue;
        };
        let path = format!("{base}.{name}");
        match name {
            "condition" => {
                condition_at = Some(line_col(v));
                let sources: Vec<(&str, &Node)> = match &v.data {
                    YamlData::Value(Scalar::String(s)) => vec![(s.as_ref(), v)],
                    YamlData::Sequence(seq) => {
                        let mut items = Vec::new();
                        for (i, x) in seq.iter().enumerate() {
                            match x.data.as_str() {
                                Some(s) => items.push((s, x)),
                                None => diags.push(err(
                                    x,
                                    &format!("{path}[{i}]"),
                                    "`condition` list entries must be strings",
                                )),
                            }
                        }
                        items
                    }
                    _ => {
                        diags.push(err(
                            v,
                            &path,
                            "`condition` must be a string or a list of strings",
                        ));
                        continue;
                    }
                };
                for (s, node) in sources {
                    match parse_condition(s) {
                        Ok(c) => {
                            conditions.push(c);
                            condition_positions.push(line_col(node));
                        }
                        Err(e) => diags.push(err(node, &path, format!("invalid condition: {e}"))),
                    }
                }
            }
            "timeframe" => diags.push(err(
                k,
                &path,
                "`timeframe` inside `detection` was removed in Sigma 2.0; use a correlation rule",
            )),
            n if reserved.contains(&n) => {}
            _ => match parse_search_id(&path, name, k, v) {
                Ok(s) => search_ids.push(s),
                Err(mut d) => diags.append(&mut d),
            },
        }
    }
    if conditions.is_empty() && diags.is_empty() {
        diags.push(err(key, base, "missing `condition`"));
    }
    if !diags.is_empty() {
        return Err(diags);
    }
    let (condition_line, condition_col) = condition_positions
        .first()
        .copied()
        .or(condition_at)
        .unwrap_or_else(|| line_col(key));
    Ok(Detection {
        search_ids,
        conditions,
        condition_line,
        condition_col,
        condition_positions,
    })
}

fn parse_search_id(
    path: &str,
    name: &str,
    key: &Node,
    v: &Node,
) -> Result<SearchIdentifier, Diags> {
    let (line, col) = line_col(key);
    let keyword_item = |values| FieldItem {
        field: None,
        modifiers: Vec::new(),
        values,
        path: path.to_string(),
        line,
        col,
    };
    let alternatives = match &v.data {
        YamlData::Mapping(m) => vec![parse_map(path, v, m)?],
        YamlData::Sequence(seq) if !seq.is_empty() && seq.iter().all(|x| x.data.is_mapping()) => {
            let mut alts = Vec::new();
            for (i, item) in seq.iter().enumerate() {
                if let YamlData::Mapping(m) = &item.data {
                    alts.push(parse_map(&format!("{path}[{i}]"), item, m)?);
                }
            }
            alts
        }
        YamlData::Sequence(seq) if !seq.is_empty() => {
            vec![vec![keyword_item(parse_values(path, v)?)]]
        }
        YamlData::Value(Scalar::String(_) | Scalar::Integer(_) | Scalar::FloatingPoint(_)) => {
            vec![vec![keyword_item(parse_values(path, v)?)]]
        }
        _ => {
            return Err(vec![err(
                v,
                path,
                "a search identifier must be a mapping, a list of mappings or a list of keywords",
            )]);
        }
    };
    Ok(SearchIdentifier {
        name: name.to_string(),
        alternatives,
    })
}

/// `node` is the mapping node itself, `m` its entries.
fn parse_map(path: &str, node: &Node, m: &Map) -> Result<Vec<FieldItem>, Diags> {
    let mut items = Vec::new();
    let mut diags = Vec::new();
    if let Some(d) = merge_key_error(m, path) {
        return Err(vec![d]);
    }
    if m.is_empty() {
        diags.push(err(node, path, "empty selection"));
    }
    for (k, v) in m {
        let Some(key) = k.data.as_str() else {
            diags.push(err(k, path, "field names must be strings"));
            continue;
        };
        let item_path = format!("{path}.{key}");
        let fk = match parse_field_key(key) {
            Ok(fk) => fk,
            Err(msg) => {
                diags.push(err(k, &item_path, msg));
                continue;
            }
        };
        let (line, col) = line_col(k);
        match parse_values(&item_path, v) {
            Ok(values) => items.push(FieldItem {
                field: fk.field,
                modifiers: fk.modifiers,
                values,
                path: item_path,
                line,
                col,
            }),
            Err(mut d) => diags.append(&mut d),
        }
    }
    if diags.is_empty() {
        Ok(items)
    } else {
        Err(diags)
    }
}

fn parse_values(path: &str, v: &Node) -> Result<Vec<RuleValue>, Diags> {
    let scalars: Vec<&Node> = match &v.data {
        YamlData::Sequence(seq) => seq.iter().collect(),
        _ => vec![v],
    };
    if scalars.is_empty() {
        return Err(vec![err(v, path, "empty value list")]);
    }
    let mut out = Vec::new();
    for s in &scalars {
        match RuleValue::from_yaml(s) {
            Some(rv) => out.push(rv),
            None => {
                return Err(vec![err(
                    s,
                    path,
                    "values must be scalars (string, number, boolean or null)",
                )]);
            }
        }
    }
    if out.len() > 1
        && let Some(null) = scalars.iter().find(|s| s.data.is_null())
    {
        return Err(vec![err(
            null,
            path,
            "`null` cannot be part of a list of values; use a separate selection",
        )]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modifier::Modifier;

    const QUICKASSIST: &str = r#"
title: QuickAssist Execution
id: e20b5b14-ce93-4230-88af-981983ef6e74
status: experimental
description: Detects QuickAssist.exe
references:
    - https://example.com/a
author: Muhammad Faisal (@faisalusuf)
date: 2024-12-19
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\QuickAssist.exe'
    condition: selection
falsepositives:
    - Legitimate use of Quick Assist in the environment.
level: low
"#;

    fn rule_with(detection: &str) -> String {
        format!("title: t\nid: r1\nlogsource:\n    product: test\ndetection:\n{detection}")
    }

    fn only_rule(src: &str) -> Rule {
        let parsed = parse_str(src);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        match parsed.documents.into_iter().next() {
            Some(Document::Rule(r)) => r,
            other => panic!("expected a rule, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_sigmahq_rule() {
        let r = only_rule(QUICKASSIST);
        assert_eq!(r.meta.title, "QuickAssist Execution");
        assert_eq!(
            r.meta.id.as_deref(),
            Some("e20b5b14-ce93-4230-88af-981983ef6e74")
        );
        assert_eq!(r.meta.level.as_deref(), Some("low"));
        assert_eq!(r.meta.date.as_deref(), Some("2024-12-19"));
        assert_eq!(
            r.meta.tags,
            vec!["attack.command-and-control", "attack.t1219.002"]
        );
        assert_eq!(r.meta.references, vec!["https://example.com/a"]);
        assert_eq!(
            r.meta.author.as_deref(),
            Some("Muhammad Faisal (@faisalusuf)")
        );
        assert_eq!(r.logsource.product.as_deref(), Some("windows"));
        assert_eq!(r.logsource.category.as_deref(), Some("process_creation"));
        assert_eq!(
            r.detection.conditions,
            vec![CondExpr::Ident("selection".into())]
        );
        let item = &r.detection.search_ids[0].alternatives[0][0];
        assert_eq!(item.field.as_deref(), Some("Image"));
        assert_eq!(item.modifiers, vec![Modifier::EndsWith]);
        assert_eq!(
            item.values,
            vec![RuleValue::Str(r"\QuickAssist.exe".into())]
        );
        assert_eq!(item.path, "detection.selection.Image|endswith");
        assert_eq!((item.line, item.col), (18, 9));
        assert_eq!(
            (r.detection.condition_line, r.detection.condition_col),
            (19, 16)
        );
        assert_eq!((r.line, r.col), (2, 1));
    }

    #[test]
    fn quoted_numbers_stay_strings() {
        let r = only_rule(&rule_with(
            "    s:\n        EventID: '4688'\n        Other: 4688\n    condition: s\n",
        ));
        let items = &r.detection.search_ids[0].alternatives[0];
        assert_eq!(items[0].values, vec![RuleValue::Str("4688".into())]);
        assert_eq!(items[1].values, vec![RuleValue::Int(4688)]);
    }

    #[test]
    fn list_of_maps_becomes_alternatives() {
        let r = only_rule(&rule_with(
            "    selection:\n        - A: 1\n        - B: 2\n          C: 3\n    condition: selection\n",
        ));
        let alts = &r.detection.search_ids[0].alternatives;
        assert_eq!(alts.len(), 2);
        assert_eq!(alts[1].len(), 2);
        assert_eq!(alts[1][0].path, "detection.selection[1].B");
        assert_eq!((alts[1][0].line, alts[1][0].col), (8, 11));
    }

    #[test]
    fn keyword_lists_have_no_field() {
        let r = only_rule(&rule_with(
            "    keywords:\n        - 'event::clear'\n        - 'event::drop'\n    kw_all:\n        '|all':\n            - a\n            - b\n    condition: keywords or kw_all\n",
        ));
        let kw = &r.detection.search_ids[0].alternatives[0][0];
        assert_eq!(kw.field, None);
        assert_eq!(kw.values.len(), 2);
        assert_eq!((kw.line, kw.col), (6, 5));
        let all = &r.detection.search_ids[1].alternatives[0][0];
        assert_eq!(all.field, None);
        assert_eq!(all.modifiers, vec![Modifier::All]);
    }

    #[test]
    fn block_scalar_condition() {
        let r = only_rule(&rule_with(
            "    a:\n        X: 1\n    b:\n        Y: 1\n    condition: |\n        a\n        or b\n",
        ));
        assert_eq!(r.detection.conditions.len(), 1);
    }

    #[test]
    fn condition_list_is_kept() {
        let r = only_rule(&rule_with(
            "    a:\n        X: 1\n    condition:\n        - a\n        - not a\n",
        ));
        assert_eq!(r.detection.conditions.len(), 2);
    }

    #[test]
    fn parses_filter_document() {
        let src = "title: Filter admins\nlogsource:\n    product: windows\nfilter:\n    rules:\n        - 6f3e2987-db24-4c78-a860-b4f4095a7095\n    selection:\n        User|startswith: 'adm_'\n    condition: selection\n";
        let parsed = parse_str(src);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let Some(Document::Filter(f)) = parsed.documents.first() else {
            panic!("expected a filter")
        };
        assert_eq!(f.rules, vec!["6f3e2987-db24-4c78-a860-b4f4095a7095"]);
        assert_eq!(f.detection.search_ids.len(), 1);
        assert_eq!(f.detection.search_ids[0].name, "selection");
        assert_eq!((f.line, f.col), (1, 1));
    }

    #[test]
    fn multi_document_with_correlation_stub() {
        let src = format!(
            "{}---\ntitle: many\nid: c1\ncorrelation:\n    type: event_count\n    rules: [r1]\n    timespan: 1h\n",
            rule_with("    sel:\n        A: 1\n    condition: sel\n")
        );
        let parsed = parse_str(&src);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        assert_eq!(parsed.documents.len(), 2);
        let Document::Correlation(c) = &parsed.documents[1] else {
            panic!("{:?}", parsed.documents[1])
        };
        assert_eq!((c.line, c.col), (10, 1));
    }

    #[test]
    fn reports_errors_with_positions_and_yaml_paths() {
        let parsed = parse_str(&rule_with(
            "    sel:\n        A|bogus: 1\n        B:\n            - ''\n            - null\n    condition: sel\n",
        ));
        let msgs: Vec<String> = parsed.diagnostics.iter().map(|d| d.to_string()).collect();
        assert!(
            msgs.iter()
                .any(|m| m.contains("<input>:7:9: detection.sel.A|bogus: unknown modifier")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("<input>:10:15: detection.sel.B: `null`")),
            "{msgs:?}"
        );
        assert!(parsed.documents.is_empty());
    }

    #[test]
    fn semantic_error_reports_the_right_line() {
        let parsed = parse_str(&rule_with(
            "    sel:\n        A: 1\n    condition: sel and\n",
        ));
        assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
        assert_eq!(
            parsed.diagnostics[0].location,
            Location::at(8, 16, "detection.condition")
        );
        assert!(parsed.diagnostics[0].message.contains("invalid condition"));
    }

    #[test]
    fn rejects_missing_title_aggregations_and_actions() {
        let p = parse_str(
            "logsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s | count() > 5\n",
        );
        let all = p
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("title"), "{all}");
        assert!(all.contains("correlation rule"), "{all}");
        let p = parse_str("title: x\naction: global\n");
        assert!(p.diagnostics[0].message.contains("action"));
        assert_eq!(p.diagnostics[0].location, Location::at(2, 1, "action"));
    }

    #[test]
    fn yaml_syntax_error_has_line_and_column() {
        let p = parse_str("title: x\ndetection: [unclosed\n");
        assert_eq!(
            p.diagnostics[0].location,
            Location::at(3, 1, ""),
            "{:?}",
            p.diagnostics
        );
        assert!(
            p.diagnostics[0].message.starts_with("invalid YAML"),
            "{:?}",
            p.diagnostics
        );
    }

    #[test]
    fn duplicate_key_is_an_error() {
        let p = parse_str(
            "title: a\ntitle: b\nlogsource: {product: x}\ndetection: {s: {A: 1}, condition: s}\n",
        );
        assert!(p.documents.is_empty());
        assert_eq!(
            p.diagnostics[0].location,
            Location::at(2, 1, ""),
            "{:?}",
            p.diagnostics
        );
        assert!(
            p.diagnostics[0].message.contains("duplicated key"),
            "{:?}",
            p.diagnostics
        );
    }

    #[test]
    fn parse_file_attaches_the_path() {
        let p = parse_file(std::path::Path::new("/nonexistent/rule.yml"));
        assert_eq!(
            p.diagnostics[0].file.as_deref(),
            Some(std::path::Path::new("/nonexistent/rule.yml"))
        );
    }

    fn diag_msgs(p: &ParsedFile) -> Vec<String> {
        p.diagnostics.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn non_string_condition_items_are_errors_at_their_position() {
        let p = parse_str(&rule_with(
            "    s:\n        A: 1\n    condition:\n        - s\n        - 5\n        - true\n",
        ));
        assert!(p.documents.is_empty());
        assert_eq!(p.diagnostics.len(), 2, "{:?}", p.diagnostics);
        assert_eq!(
            p.diagnostics[0].location,
            Location::at(10, 11, "detection.condition[1]")
        );
        assert_eq!(
            p.diagnostics[1].location,
            Location::at(11, 11, "detection.condition[2]")
        );
        assert!(p.diagnostics[0].message.contains("must be strings"));
    }

    #[test]
    fn condition_positions_track_each_list_entry() {
        let r = only_rule(&rule_with(
            "    s:\n        A: 1\n    condition:\n        - s\n        - not s\n",
        ));
        assert_eq!(r.detection.condition_positions, vec![(9, 11), (10, 11)]);
        assert_eq!(
            (r.detection.condition_line, r.detection.condition_col),
            r.detection.condition_positions[0]
        );
        let r = only_rule(&rule_with("    s:\n        A: 1\n    condition: s\n"));
        assert_eq!(r.detection.condition_positions, vec![(8, 16)]);
    }

    #[test]
    fn non_string_title_is_a_type_error_not_missing() {
        let p = parse_str(
            "title: true\nlogsource: {product: x}\ndetection: {s: {A: 1}, condition: s}\n",
        );
        assert!(p.documents.is_empty());
        assert_eq!(p.diagnostics.len(), 1, "{:?}", p.diagnostics);
        assert_eq!(p.diagnostics[0].message, "`title` must be a string");
        assert_eq!(p.diagnostics[0].location, Location::at(1, 8, "title"));
        let p = parse_str("logsource: {product: x}\ndetection: {s: {A: 1}, condition: s}\n");
        assert_eq!(p.diagnostics[0].message, "missing mandatory `title`");
    }

    #[test]
    fn wrongly_typed_metadata_warns_naming_the_field() {
        let src = "title: t\nid: r1\nlogsource: {product: x}\ntags:\n    - ok\n    - 5\nreferences: [a, [b]]\nfalsepositives:\n    - {x: 1}\nlevel: [high]\ndetection: {s: {A: 1}, condition: s}\n";
        let p = parse_str(src);
        assert_eq!(p.documents.len(), 1, "{:?}", p.diagnostics);
        let Document::Rule(r) = &p.documents[0] else {
            panic!("rule expected")
        };
        assert_eq!(r.meta.tags, vec!["ok"]);
        assert_eq!(r.meta.references, vec!["a"]);
        assert!(r.meta.falsepositives.is_empty());
        assert_eq!(r.meta.level, None);
        assert!(p.diagnostics.iter().all(|d| !d.is_error()));
        let msgs = diag_msgs(&p);
        for field in ["tags", "references", "falsepositives", "level"] {
            assert!(
                msgs.iter()
                    .any(|m| m.contains("warning") && m.contains(&format!("`{field}`"))),
                "{field}: {msgs:?}"
            );
        }
    }

    #[test]
    fn yaml_merge_keys_are_rejected_clearly() {
        let anchored = "defaults: &d\n    A: 1\n";
        // inside a selection
        let p = parse_str(&format!(
            "{anchored}title: t\nlogsource: {{product: x}}\ndetection:\n    s:\n        <<: *d\n    condition: s\n"
        ));
        let msgs = diag_msgs(&p);
        assert!(
            msgs.iter()
                .any(|m| m.contains("YAML merge keys (`<<`) are not supported")),
            "{msgs:?}"
        );
        // at document level
        let p = parse_str(&format!("{anchored}<<: *d\ntitle: t\n"));
        let msgs = diag_msgs(&p);
        assert!(msgs.iter().any(|m| m.contains("merge keys")), "{msgs:?}");
        // directly in `detection`
        let p = parse_str(&format!(
            "{anchored}title: t\nlogsource: {{product: x}}\ndetection:\n    <<: *d\n    condition: s\n"
        ));
        let msgs = diag_msgs(&p);
        assert!(msgs.iter().any(|m| m.contains("merge keys")), "{msgs:?}");
    }

    #[test]
    fn hostile_deep_nesting_reports_the_recursion_limit() {
        let src = format!("a: {}1{}\n", "[".repeat(5_000), "]".repeat(5_000));
        let p = parse_str(&src);
        assert!(p.documents.is_empty());
        assert_eq!(p.diagnostics.len(), 1, "{:?}", p.diagnostics);
        let m = &p.diagnostics[0].message;
        assert!(m.starts_with("invalid YAML"), "{m}");
        assert!(m.contains("recursion limit"), "{m}");
    }

    #[test]
    fn hostile_alias_bomb_reports_the_node_budget() {
        let mut src = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let prev = format!("*a{}", i - 1);
            let items = vec![prev; 10].join(", ");
            src.push_str(&format!("a{i}: &a{i} [{items}]\n"));
        }
        let p = parse_str(&src);
        assert!(p.documents.is_empty());
        assert_eq!(p.diagnostics.len(), 1, "{:?}", p.diagnostics);
        let m = &p.diagnostics[0].message;
        assert!(m.starts_with("invalid YAML"), "{m}");
        assert!(m.contains("node budget"), "{m}");
    }
}
