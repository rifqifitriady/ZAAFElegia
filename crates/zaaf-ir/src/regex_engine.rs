//! Regular expressions: linear-time `regex` first, `fancy-regex` with a
//! backtracking limit only for patterns that need lookaround or backreferences.

use std::fmt;

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
}

impl CompiledRegex {
    pub fn new(source: &str, flags: RegexFlags) -> Result<Self, String> {
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
                    .backtrack_limit(BACKTRACK_LIMIT)
                    .build()
                    .map(|re| Self {
                        source: source.to_string(),
                        flags,
                        engine: Engine::Backtracking(re),
                    })
                    .map_err(|_| format!("invalid regular expression `{source}`: {linear_err}"))
            }
        }
    }

    /// Unanchored search. A pattern that exceeds the backtracking limit does not match.
    pub fn is_match(&self, text: &str) -> bool {
        match &self.engine {
            Engine::Linear(re) => re.is_match(text),
            Engine::Backtracking(re) => re.is_match(text).unwrap_or(false),
        }
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
}
