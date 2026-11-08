//! Regular expressions: linear-time `regex` first, `fancy-regex` with a
//! backtracking limit only for patterns that need lookaround or backreferences.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum backtracking steps for patterns that need the backtracking engine.
pub const BACKTRACK_LIMIT: usize = 1_000_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegexFlags {
    pub insensitive: bool,
    pub multiline: bool,
    pub dot_all: bool,
}

#[derive(Clone)]
enum Engine {
    Linear(regex::Regex),
    Backtracking(fancy_regex::Regex),
}

#[derive(Clone)]
pub struct CompiledRegex {
    source: String,
    flags: RegexFlags,
    engine: Engine,
    /// Backtrack-limit hits; clones share the counter.
    limit_hits: Arc<AtomicU64>,
}

impl CompiledRegex {
    pub fn new(source: &str, flags: RegexFlags) -> Result<Self, String> {
        Self::with_backtrack_limit(source, flags, BACKTRACK_LIMIT)
    }

    pub fn with_backtrack_limit(
        source: &str,
        flags: RegexFlags,
        limit: usize,
    ) -> Result<Self, String> {
        let linear = regex::RegexBuilder::new(source)
            .case_insensitive(flags.insensitive)
            .multi_line(flags.multiline)
            .dot_matches_new_line(flags.dot_all)
            .build();
        match linear {
            Ok(re) => Ok(Self {
                source: source.to_string(),
                flags,
                engine: Engine::Linear(re),
                limit_hits: Arc::default(),
            }),
            Err(linear_err) => {
                let mut inline = String::new();
                if flags.insensitive {
                    inline.push('i');
                }
                if flags.multiline {
                    inline.push('m');
                }
                if flags.dot_all {
                    inline.push('s');
                }
                let pattern = if inline.is_empty() {
                    source.to_string()
                } else {
                    format!("(?{inline}){source}")
                };
                fancy_regex::RegexBuilder::new(&pattern)
                    .backtrack_limit(limit)
                    .build()
                    .map(|re| Self {
                        source: source.to_string(),
                        flags,
                        engine: Engine::Backtracking(re),
                        limit_hits: Arc::default(),
                    })
                    .map_err(|fancy_err| {
                        format!(
                            "invalid regular expression `{source}`: {linear_err}; backtracking engine: {fancy_err}"
                        )
                    })
            }
        }
    }

    /// Unanchored search. A pattern that exceeds the backtracking limit does not
    /// match, but the hit is counted (see `limit_hits`).
    pub fn is_match(&self, text: &str) -> bool {
        match &self.engine {
            Engine::Linear(re) => re.is_match(text),
            Engine::Backtracking(re) => re.is_match(text).unwrap_or_else(|_| {
                self.limit_hits.fetch_add(1, Ordering::Relaxed);
                false
            }),
        }
    }

    /// How many times the backtracking engine gave up (shared across clones).
    pub fn limit_hits(&self) -> u64 {
        self.limit_hits.load(Ordering::Relaxed)
    }

    /// The same compiled engine with a new, zeroed hit counter not shared with `self`.
    pub fn with_fresh_counter(&self) -> CompiledRegex {
        CompiledRegex {
            limit_hits: Arc::default(),
            ..self.clone()
        }
    }

    /// Identity of the shared hit counter: clones report the same id.
    pub fn counter_id(&self) -> usize {
        Arc::as_ptr(&self.limit_hits) as usize
    }

    pub fn needs_backtracking(&self) -> bool {
        matches!(self.engine, Engine::Backtracking(_))
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn flags(&self) -> RegexFlags {
        self.flags
    }
}

impl fmt::Debug for CompiledRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}/{:?}", self.source, self.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_engine_with_case_flag() {
        let re = CompiledRegex::new(
            "^admin$",
            RegexFlags {
                insensitive: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(re.is_match("ADMIN"));
        assert!(!re.needs_backtracking());
    }

    #[test]
    fn lookaround_falls_back_to_backtracking() {
        let re = CompiledRegex::new(r"^(?!svchost).*\.exe$", RegexFlags::default()).unwrap();
        assert!(re.needs_backtracking());
        assert!(re.is_match("evil.exe"));
        assert!(!re.is_match("svchost.exe"));
    }

    #[test]
    fn multiline_and_dot_all() {
        let m = CompiledRegex::new(
            "^evil$",
            RegexFlags {
                multiline: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(m.is_match("a\nevil\nb"));
        let plain = CompiledRegex::new("^evil$", RegexFlags::default()).unwrap();
        assert!(!plain.is_match("a\nevil\nb"));
        let s = CompiledRegex::new(
            "a.b",
            RegexFlags {
                dot_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(s.is_match("a\nb"));
        assert!(
            !CompiledRegex::new("a.b", RegexFlags::default())
                .unwrap()
                .is_match("a\nb")
        );
    }

    #[test]
    fn invalid_regex_is_an_error() {
        let err = CompiledRegex::new("(unclosed", RegexFlags::default()).unwrap_err();
        assert!(err.contains("(unclosed"), "{err}");
    }

    #[test]
    fn backtrack_limit_hit_is_counted_and_not_a_match() {
        let re =
            CompiledRegex::with_backtrack_limit(r"^(a|a)*\1$", RegexFlags::default(), 10).unwrap();
        assert!(re.needs_backtracking());
        assert!(!re.is_match(&format!("{}b", "a".repeat(200))));
        assert!(re.limit_hits() >= 1);
        let clone = re.clone();
        assert_eq!(clone.limit_hits(), re.limit_hits());
    }

    #[test]
    fn normal_match_leaves_limit_hits_at_zero() {
        let re = CompiledRegex::new(r"^(?!svchost).*\.exe$", RegexFlags::default()).unwrap();
        assert!(re.is_match("evil.exe"));
        assert_eq!(re.limit_hits(), 0);
    }

    #[test]
    fn double_failure_reports_both_errors() {
        let err = CompiledRegex::new("(unclosed", RegexFlags::default()).unwrap_err();
        assert!(err.contains("backtracking engine"), "{err}");
    }
}
