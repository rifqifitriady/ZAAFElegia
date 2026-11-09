//! Value transformation modifiers (Sigma modifiers appendix).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use regex::Regex;
use std::sync::OnceLock;
use zaaf_sigma::{Modifier, SigmaString, Tok};

/// Upper bound on variants produced by any value expansion.
pub(crate) const MAX_EXPANSION: usize = 4096;

fn expansion_error() -> String {
    format!("value expansion exceeds {MAX_EXPANSION} variants")
}

/// A value during transformation: a Sigma string, or raw bytes after `utf16*`.
#[derive(Debug, Clone)]
pub(crate) enum Val {
    S(SigmaString),
    B(Vec<u8>),
}

impl Val {
    /// Bytes are mapped one-to-one to chars (latin-1), so `wide` without
    /// `base64` yields `c\0m\0d\0` like pySigma.
    pub(crate) fn into_sigma(self) -> SigmaString {
        match self {
            Val::S(s) => s,
            Val::B(b) => SigmaString::literal(&b.iter().map(|&c| c as char).collect::<String>()),
        }
    }

    fn bytes(&self, m: Modifier) -> Result<Vec<u8>, String> {
        match self {
            Val::B(b) => Ok(b.clone()),
            Val::S(s) => s.as_plain().map(String::into_bytes).ok_or_else(|| {
                format!("`{}` cannot be applied to a value with wildcards", m.name())
            }),
        }
    }

    fn text(&self, m: Modifier) -> Result<String, String> {
        match self {
            Val::S(s) => s.as_plain().ok_or_else(|| {
                format!("`{}` cannot be applied to a value with wildcards", m.name())
            }),
            Val::B(_) => Err(format!("`{}` needs a text value", m.name())),
        }
    }
}

/// Applies one string transformation modifier to every value.
pub(crate) fn apply(m: Modifier, vals: Vec<Val>) -> Result<Vec<Val>, String> {
    let mut out = Vec::new();
    for v in vals {
        match m {
            Modifier::Contains => {
                let mut s = v.into_sigma();
                s.prepend_any_many();
                s.append_any_many();
                out.push(Val::S(s));
            }
            Modifier::StartsWith => {
                let mut s = v.into_sigma();
                s.append_any_many();
                out.push(Val::S(s));
            }
            Modifier::EndsWith => {
                let mut s = v.into_sigma();
                s.prepend_any_many();
                out.push(Val::S(s));
            }
            Modifier::Base64 => {
                out.push(Val::S(SigmaString::literal(&STANDARD.encode(v.bytes(m)?))))
            }
            Modifier::Base64Offset => {
                for s in base64_offsets(&v.bytes(m)?) {
                    out.push(Val::S(SigmaString::literal(&s)));
                }
            }
            Modifier::Utf16Le | Modifier::Wide => {
                out.push(Val::B(utf16(&v.text(m)?, false, false)))
            }
            Modifier::Utf16Be => out.push(Val::B(utf16(&v.text(m)?, true, false))),
            Modifier::Utf16 => out.push(Val::B(utf16(&v.text(m)?, false, true))),
            Modifier::Windash => {
                let variants = windash(&v.into_sigma())?;
                // Check before extending so the peak stays near MAX_EXPANSION.
                if out.len() + variants.len() > MAX_EXPANSION {
                    return Err(expansion_error());
                }
                out.extend(variants.into_iter().map(Val::S));
            }
            other => return Err(format!("`{}` is not a string transformation", other.name())),
        }
        // Checked after every value, so the output never grows far past the cap.
        if out.len() > MAX_EXPANSION {
            return Err(expansion_error());
        }
    }
    Ok(out)
}

/// The three base64 representations of `value` at byte offsets 0, 1 and 2,
/// trimmed to the characters that do not depend on surrounding bytes.
pub(crate) fn base64_offsets(value: &[u8]) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END_STRIP: [usize; 3] = [0, 3, 2];
    (0..3)
        .filter_map(|i| {
            let mut input = vec![b' '; i];
            input.extend_from_slice(value);
            let enc = STANDARD.encode(&input);
            let end = enc.len().saturating_sub(END_STRIP[(value.len() + i) % 3]);
            (START[i] < end).then(|| enc[START[i]..end].to_string())
        })
        .collect()
}

pub(crate) fn utf16(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if bom {
        out.extend_from_slice(if big_endian {
            &[0xFE, 0xFF]
        } else {
            &[0xFF, 0xFE]
        });
    }
    for unit in text.encode_utf16() {
        let b = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        out.extend_from_slice(&b);
    }
    out
}

const DASHES: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

fn windash_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\B[-/]\b").expect("static regex"))
}

/// All permutations of command-line flag dashes (`-x`, `/x`, `–x`, `—x`, `―x`).
pub(crate) fn windash(s: &SigmaString) -> Result<Vec<SigmaString>, String> {
    let mut results = vec![SigmaString::default()];
    for tok in s.toks() {
        match tok {
            Tok::Lit(text) => {
                let mut variants = vec![String::new()];
                let mut last = 0;
                for m in windash_regex().find_iter(text) {
                    let seg = &text[last..m.start()];
                    if variants.len() * DASHES.len() > MAX_EXPANSION {
                        return Err(expansion_error());
                    }
                    variants = variants
                        .into_iter()
                        .flat_map(|v| DASHES.iter().map(move |d| format!("{v}{seg}{d}")))
                        .collect();
                    last = m.end();
                }
                let tail = &text[last..];
                for v in &mut variants {
                    v.push_str(tail);
                }
                if results.len() * variants.len() > MAX_EXPANSION {
                    return Err(expansion_error());
                }
                results = results
                    .into_iter()
                    .flat_map(|r| {
                        variants.iter().map(move |v| {
                            let mut r2 = r.clone();
                            r2.push_lit(v);
                            r2
                        })
                    })
                    .collect();
            }
            other => {
                for r in &mut results {
                    r.push(other.clone());
                }
            }
        }
    }
    Ok(results)
}

enum Piece {
    Text(String),
    Var(String),
}

/// `%name%` is a placeholder, `\%` a literal percent; a lone `%` stays literal.
fn split_placeholders(text: &str) -> Vec<Piece> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && chars.get(i + 1) == Some(&'%') {
            buf.push('%');
            i += 2;
            continue;
        }
        if chars[i] == '%'
            && let Some(rel) = chars[i + 1..].iter().position(|&c| c == '%')
        {
            let name: String = chars[i + 1..i + 1 + rel].iter().collect();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                if !buf.is_empty() {
                    out.push(Piece::Text(std::mem::take(&mut buf)));
                }
                out.push(Piece::Var(name));
                i += rel + 2;
                continue;
            }
        }
        buf.push(chars[i]);
        i += 1;
    }
    if !buf.is_empty() {
        out.push(Piece::Text(buf));
    }
    out
}

/// Expands placeholders in a raw rule value into every combination of values.
pub(crate) fn expand_raw(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<Vec<String>>,
) -> Result<Vec<String>, String> {
    let mut results = vec![String::new()];
    for piece in split_placeholders(text) {
        match piece {
            Piece::Text(t) => {
                for r in &mut results {
                    r.push_str(&t);
                }
            }
            Piece::Var(name) => {
                let vals = lookup(&name).filter(|v| !v.is_empty()).ok_or_else(|| {
                    format!(
                        "placeholder `%{name}%` has no value; define it under `vars:` in a pipeline"
                    )
                })?;
                if results.len() * vals.len() > MAX_EXPANSION {
                    return Err(expansion_error());
                }
                results = results
                    .into_iter()
                    .flat_map(|r| vals.iter().map(move |v| format!("{r}{v}")))
                    .collect();
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64offset_matches_pysigma_vectors() {
        assert_eq!(base64_offsets(b"ping"), vec!["cGluZ", "Bpbm", "waW5n"]);
        assert_eq!(
            base64_offsets(&utf16("cmd", false, false)),
            vec!["YwBtAGQA", "MAbQBkA", "jAG0AZA"]
        );
    }

    #[test]
    fn base64offset_drops_empty_variants() {
        assert!(base64_offsets(b"a").iter().all(|s| !s.is_empty()));
    }

    #[test]
    fn utf16_variants() {
        assert_eq!(utf16("ab", false, false), vec![0x61, 0, 0x62, 0]);
        assert_eq!(utf16("ab", true, false), vec![0, 0x61, 0, 0x62]);
        assert_eq!(utf16("ab", false, true), vec![0xFF, 0xFE, 0x61, 0, 0x62, 0]);
    }

    #[test]
    fn windash_permutes_flag_dashes_only() {
        let v = windash(&SigmaString::parse(" -s ")).unwrap();
        assert_eq!(v.len(), 5);
        assert!(v.contains(&SigmaString::literal(" /s ")));
        assert!(v.contains(&SigmaString::literal(" \u{2015}s ")));
        assert_eq!(
            windash(&SigmaString::parse("foo-bar")).unwrap(),
            vec![SigmaString::literal("foo-bar")]
        );
    }

    #[test]
    fn windash_keeps_wildcards() {
        let v = windash(&SigmaString::parse("* -a -b*")).unwrap();
        assert_eq!(v.len(), 25);
        assert!(v.iter().all(|s| s.has_wildcards()));
    }

    #[test]
    fn expand_raw_placeholders() {
        let lookup =
            |n: &str| (n == "Admins").then(|| vec!["adm_*".to_string(), "root".to_string()]);
        assert_eq!(
            expand_raw("%Admins%", &lookup).unwrap(),
            vec!["adm_*", "root"]
        );
        assert_eq!(
            expand_raw("x-%Admins%-y", &lookup).unwrap(),
            vec!["x-adm_*-y", "x-root-y"]
        );
        assert_eq!(expand_raw(r"\%Admins%", &lookup).unwrap(), vec!["%Admins%"]);
        assert_eq!(expand_raw("100%", &lookup).unwrap(), vec!["100%"]);
        let err = expand_raw("%Nope%", &lookup).unwrap_err();
        assert!(err.contains("Nope"), "{err}");
    }

    #[test]
    fn apply_contains_then_base64_errors_on_wildcards() {
        let vals = apply(Modifier::Contains, vec![Val::S(SigmaString::literal("x"))]).unwrap();
        let err = apply(Modifier::Base64, vals).unwrap_err();
        assert!(err.contains("base64"), "{err}");
    }

    #[test]
    fn apply_wide_then_base64() {
        let vals = apply(Modifier::Wide, vec![Val::S(SigmaString::literal("ab"))]).unwrap();
        let vals = apply(Modifier::Base64, vals).unwrap();
        assert_eq!(
            vals.into_iter().next().unwrap().into_sigma(),
            SigmaString::literal("YQBiAA==")
        );
    }

    #[test]
    fn windash_expansion_is_capped() {
        let err = windash(&SigmaString::parse(&" -a".repeat(20))).unwrap_err();
        assert!(err.contains("value expansion exceeds"), "{err}");
    }

    #[test]
    fn windash_boundaries_compile() {
        let four = windash(&SigmaString::parse(&" -a".repeat(4))).unwrap();
        assert_eq!(four.len(), 625);
        let five = windash(&SigmaString::parse(&" -a".repeat(5))).unwrap();
        assert_eq!(five.len(), 3125);
        let six = windash(&SigmaString::parse(&" -a".repeat(6)));
        assert!(six.is_err());
        let vals = apply(
            Modifier::Windash,
            vec![Val::S(SigmaString::parse(&" -a".repeat(5)))],
        )
        .unwrap();
        assert_eq!(vals.len(), 3125);
    }

    #[test]
    fn apply_rejects_a_second_value_that_would_cross_the_cap() {
        // 3125 + 3125 > 4096: rejected without ever holding both in `out`.
        let vals = vec![
            Val::S(SigmaString::parse(&" -a".repeat(5))),
            Val::S(SigmaString::parse(&" -a".repeat(5))),
        ];
        let err = apply(Modifier::Windash, vals).unwrap_err();
        assert!(err.contains("value expansion exceeds"), "{err}");
    }

    #[test]
    fn expand_raw_expansion_is_capped() {
        let lookup = |_: &str| Some((0..20).map(|i| i.to_string()).collect::<Vec<_>>());
        let err = expand_raw("%a%%b%%c%", &lookup).unwrap_err();
        assert!(err.contains("value expansion exceeds"), "{err}");
    }

    #[test]
    fn apply_total_output_is_capped() {
        let vals: Vec<Val> = (0..MAX_EXPANSION)
            .map(|_| Val::S(SigmaString::literal("a -b")))
            .collect();
        let err = apply(Modifier::Windash, vals).unwrap_err();
        assert!(err.contains("value expansion exceeds"), "{err}");
    }

    #[test]
    fn base64_offsets_of_empty_input_is_empty() {
        assert!(base64_offsets(b"").is_empty());
    }
}
