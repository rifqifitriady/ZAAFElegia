//! Regular expressions: linear-time `regex` first, `fancy-regex` with a
//! backtracking limit only for patterns that need lookaround or backreferences.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum compiled size of one regular expression (program and lazy-DFA cache), in bytes.
pub const REGEX_SIZE_LIMIT: usize = 4 << 20;

/// Size tiers tried in order, with the budget weight of the first one that compiles
/// (about 1 KiB of compiled size per unit in every tier).
const SIZE_TIERS: &[(usize, u32)] = &[
    (16 << 10, 16),
    (256 << 10, 256),
    (1 << 20, 1024),
    (REGEX_SIZE_LIMIT, 4096),
];

enum BuildError {
    TooBig,
    Invalid(String),
}

/// Maximum backtracking steps for patterns that need the backtracking engine.
pub const BACKTRACK_LIMIT: usize = 1_000_000;

fn too_big(source: &str) -> String {
    format!(
        "regular expression `{source}` exceeds the compiled size limit of {REGEX_SIZE_LIMIT} bytes"
    )
}

fn is_too_big(e: &fancy_regex::Error) -> bool {
    // The size-limit failure is only visible in the error's Debug form.
    format!("{e:?}").contains("ExceededSizeLimit")
}

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
    weight: u32,
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
        for &(size, weight) in SIZE_TIERS {
            match Self::build(source, flags, limit, size, weight) {
                Err(BuildError::TooBig) => continue,
                Err(BuildError::Invalid(msg)) => return Err(msg),
                Ok(re) => return Ok(re),
            }
        }
        Err(too_big(source))
    }

    fn build(
        source: &str,
        flags: RegexFlags,
        limit: usize,
        size: usize,
        weight: u32,
    ) -> Result<Self, BuildError> {
        let linear = regex::RegexBuilder::new(source)
            .case_insensitive(flags.insensitive)
            .multi_line(flags.multiline)
            .dot_matches_new_line(flags.dot_all)
            .size_limit(size)
            .dfa_size_limit(size)
            .build();
        let linear_err = match linear {
            Ok(re) => {
                return Ok(Self {
                    source: source.to_string(),
                    flags,
                    engine: Engine::Linear(re),
                    weight,
                    limit_hits: Arc::default(),
                });
            }
            Err(regex::Error::CompiledTooBig(_)) => return Err(BuildError::TooBig),
            Err(e) => e,
        };
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
            .delegate_size_limit(size)
            .delegate_dfa_size_limit(size)
            .build()
            .map(|re| Self {
                source: source.to_string(),
                flags,
                engine: Engine::Backtracking(re),
                weight,
                limit_hits: Arc::default(),
            })
            .map_err(|fancy_err| {
                if is_too_big(&fancy_err) {
                    return BuildError::TooBig;
                }
                BuildError::Invalid(format!(
                    "invalid regular expression `{source}`: {linear_err}; backtracking engine: {fancy_err}"
                ))
            })
    }

    /// Budget weight in units of about 1 KiB of compiled size: 16, 256, 1024 or 4096,
    /// by the smallest size tier the pattern compiled under.
    pub fn weight(&self) -> u32 {
        self.weight
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
    fn oversized_pattern_is_a_compile_error_naming_the_limit() {
        let big = r"\w{200}".repeat(50);
        let err = CompiledRegex::new(&big, RegexFlags::default()).unwrap_err();
        assert!(err.contains("size limit"), "{err}");
        assert!(err.contains(&REGEX_SIZE_LIMIT.to_string()), "{err}");
        // A backtracking-only pattern is bounded too.
        let big_fancy = format!(r"(?=a){}", r"\w{200}".repeat(50));
        let err = CompiledRegex::new(&big_fancy, RegexFlags::default()).unwrap_err();
        assert!(err.contains("size limit"), "{err}");
    }

    #[test]
    fn weights_follow_the_size_tier() {
        let w = |p: &str| {
            CompiledRegex::new(p, RegexFlags::default())
                .unwrap()
                .weight()
        };
        assert_eq!(w("^admin$"), 16);
        assert_eq!(w(r"\w{1,64}"), 4096);
        assert_eq!(w(r"(?=a)\w{1,64}"), 4096);
        assert!(CompiledRegex::new(r"\w{200}", RegexFlags::default()).is_err());
    }

    #[test]
    fn normal_patterns_compile_under_the_size_limit() {
        CompiledRegex::new(r"\w{20}", RegexFlags::default()).unwrap();
        CompiledRegex::new(r"(?i)^[a-z0-9_\-\.]{1,64}\.exe$", RegexFlags::default()).unwrap();
    }

    #[test]
    fn double_failure_reports_both_errors() {
        let err = CompiledRegex::new("(unclosed", RegexFlags::default()).unwrap_err();
        assert!(err.contains("backtracking engine"), "{err}");
    }
}
