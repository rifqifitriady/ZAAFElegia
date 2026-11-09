//! Sigma string values with `*` / `?` wildcards and backslash escaping
//! (Sigma rules specification, "String Wildcard" and "Escape Character").

/// One token of a Sigma string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tok {
    Lit(String),
    /// `?`: exactly one character.
    AnyOne,
    /// `*`: any number of characters.
    AnyMany,
}

/// A Sigma string value: literal text interleaved with wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SigmaString {
    toks: Vec<Tok>,
}

impl SigmaString {
    /// Parses a rule value. `\` escapes `*`, `?` and `\`; before any other
    /// character it is a plain backslash.
    pub fn parse(s: &str) -> Self {
        let mut out = Self::default();
        let mut lit = String::new();
        let mut escaped = false;
        for c in s.chars() {
            if escaped {
                if c != '*' && c != '?' && c != '\\' {
                    lit.push('\\');
                }
                lit.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '*' || c == '?' {
                out.push_lit(&lit);
                lit.clear();
                out.push(if c == '*' { Tok::AnyMany } else { Tok::AnyOne });
            } else {
                lit.push(c);
            }
        }
        if escaped {
            lit.push('\\');
        }
        out.push_lit(&lit);
        out
    }

    /// A string whose characters are all literal.
    pub fn literal(s: &str) -> Self {
        let mut out = Self::default();
        out.push_lit(s);
        out
    }

    pub fn from_toks(toks: Vec<Tok>) -> Self {
        let mut out = Self::default();
        for t in toks {
            out.push(t);
        }
        out
    }

    pub fn toks(&self) -> &[Tok] {
        &self.toks
    }

    pub fn push_lit(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        if let Some(Tok::Lit(prev)) = self.toks.last_mut() {
            prev.push_str(s);
        } else {
            self.toks.push(Tok::Lit(s.to_string()));
        }
    }

    pub fn push(&mut self, t: Tok) {
        match t {
            Tok::Lit(s) => self.push_lit(&s),
            Tok::AnyMany if matches!(self.toks.last(), Some(Tok::AnyMany)) => {}
            other => self.toks.push(other),
        }
    }

    pub fn prepend_any_many(&mut self) {
        if !matches!(self.toks.first(), Some(Tok::AnyMany)) {
            self.toks.insert(0, Tok::AnyMany);
        }
    }

    pub fn append_any_many(&mut self) {
        self.push(Tok::AnyMany);
    }

    pub fn has_wildcards(&self) -> bool {
        self.toks.iter().any(|t| !matches!(t, Tok::Lit(_)))
    }

    /// The text if the string has no wildcards.
    pub fn as_plain(&self) -> Option<String> {
        let mut out = String::new();
        for t in &self.toks {
            match t {
                Tok::Lit(s) => out.push_str(s),
                _ => return None,
            }
        }
        Some(out)
    }

    pub fn to_lowercase(&self) -> Self {
        Self {
            toks: self
                .toks
                .iter()
                .map(|t| match t {
                    Tok::Lit(s) => Tok::Lit(s.to_lowercase()),
                    other => other.clone(),
                })
                .collect(),
        }
    }

    pub fn concat(&self, other: &SigmaString) -> SigmaString {
        let mut out = self.clone();
        for t in &other.toks {
            out.push(t.clone());
        }
        out
    }

    /// Exact-case glob match of the whole `text`.
    pub fn matches(&self, text: &str) -> bool {
        match self.toks.as_slice() {
            [] => text.is_empty(),
            [Tok::Lit(l)] => text == l,
            [Tok::AnyMany] => true,
            [Tok::AnyMany, Tok::Lit(l)] => text.ends_with(l.as_str()),
            [Tok::Lit(l), Tok::AnyMany] => text.starts_with(l.as_str()),
            [Tok::AnyMany, Tok::Lit(l), Tok::AnyMany] => text.contains(l.as_str()),
            toks => glob(toks, text),
        }
    }
}

/// A cursor into a token list: token index and byte offset inside a `Lit`.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Cur {
    tok: usize,
    off: usize,
}

/// One pattern element at a cursor.
#[derive(Clone, Copy, PartialEq, Eq)]
enum P {
    C(char),
    One,
    Many,
}

/// The pattern element at `cur` and the cursor after it; `None` at the end.
fn peek(toks: &[Tok], cur: Cur) -> Option<(P, Cur)> {
    match toks.get(cur.tok)? {
        Tok::AnyOne => Some((
            P::One,
            Cur {
                tok: cur.tok + 1,
                off: 0,
            },
        )),
        Tok::AnyMany => Some((
            P::Many,
            Cur {
                tok: cur.tok + 1,
                off: 0,
            },
        )),
        Tok::Lit(s) => {
            // Invariant: `push_lit` never stores an empty literal, so a `Lit` always
            // has a character at offset 0 and `None` below only means "end of pattern".
            debug_assert!(!s.is_empty(), "empty Tok::Lit");
            let c = s[cur.off..].chars().next()?;
            let off = cur.off + c.len_utf8();
            let next = if off >= s.len() {
                Cur {
                    tok: cur.tok + 1,
                    off: 0,
                }
            } else {
                Cur { tok: cur.tok, off }
            };
            Some((P::C(c), next))
        }
    }
}

/// Iterative wildcard matching with single-star backtracking. Walks the tokens and the
/// text in place (byte cursors), so it never allocates.
fn glob(toks: &[Tok], text: &str) -> bool {
    let mut p = Cur { tok: 0, off: 0 };
    let mut t = 0usize;
    let mut star: Option<Cur> = None;
    let mut mark = 0usize;
    while let Some(tc) = text[t..].chars().next() {
        let cur = peek(toks, p);
        let step = match cur {
            Some((P::C(c), next)) if c == tc => Some(next),
            Some((P::One, next)) => Some(next),
            _ => None,
        };
        if let Some(next) = step {
            p = next;
            t += tc.len_utf8();
        } else if let Some((P::Many, next)) = cur {
            star = Some(next);
            mark = t;
            p = next;
        } else if let Some(s) = star {
            p = s;
            mark += text[mark..].chars().next().map_or(1, char::len_utf8);
            t = mark;
        } else {
            return false;
        }
    }
    while let Some((P::Many, next)) = peek(toks, p) {
        p = next;
    }
    peek(toks, p).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> Tok {
        Tok::Lit(s.to_string())
    }

    #[test]
    fn parses_wildcards() {
        assert_eq!(
            SigmaString::parse("prog?.exe").toks(),
            &[lit("prog"), Tok::AnyOne, lit(".exe")]
        );
        assert_eq!(
            SigmaString::parse(r"*\cmd.exe").toks(),
            &[Tok::AnyMany, lit(r"\cmd.exe")]
        );
    }

    #[test]
    fn escaping_follows_the_spec_table() {
        let plain = |s: &str| SigmaString::parse(s).as_plain();
        assert_eq!(plain(r"C:\Windows").as_deref(), Some(r"C:\Windows"));
        assert_eq!(plain(r"C:\\Windows").as_deref(), Some(r"C:\Windows"));
        assert_eq!(plain(r"a\*b").as_deref(), Some("a*b"));
        assert_eq!(
            SigmaString::parse(r"a\\*").toks(),
            &[lit(r"a\"), Tok::AnyMany]
        );
        assert_eq!(plain(r"a\\\*").as_deref(), Some(r"a\*"));
        assert_eq!(plain(r"a\\\b").as_deref(), Some(r"a\\b"));
        assert_eq!(plain(r"a\\\\b").as_deref(), Some(r"a\\b"));
        assert_eq!(plain(r"dir\").as_deref(), Some(r"dir\"));
        assert_eq!(plain("").as_deref(), Some(""));
    }

    #[test]
    fn matches_fast_paths_and_general_globs() {
        let m = |p: &str, t: &str| SigmaString::parse(p).matches(t);
        assert!(m("abc", "abc"));
        assert!(!m("abc", "abcd"));
        assert!(m("*bc", "abc"));
        assert!(m("ab*", "abc"));
        assert!(m("*b*", "abc"));
        assert!(m("*", ""));
        assert!(m("", ""));
        assert!(!m("", "x"));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(m("a*c*e", "abcde"));
        assert!(!m("a*c*e", "abcdef"));
        assert!(m("*a*a*a*", "xaxaxax"));
        assert!(m("?", "é"));
    }

    /// The previous allocating implementation, kept as the behavioural reference.
    fn glob_reference(toks: &[Tok], text: &str) -> bool {
        let pat: Vec<P> = toks
            .iter()
            .flat_map(|t| match t {
                Tok::Lit(s) => s.chars().map(P::C).collect::<Vec<_>>(),
                Tok::AnyOne => vec![P::One],
                Tok::AnyMany => vec![P::Many],
            })
            .collect();
        let txt: Vec<char> = text.chars().collect();
        let (mut p, mut t) = (0usize, 0usize);
        let mut star: Option<usize> = None;
        let mut mark = 0usize;
        while t < txt.len() {
            let step = p < pat.len()
                && match pat[p] {
                    P::C(c) => c == txt[t],
                    P::One => true,
                    P::Many => false,
                };
            if step {
                p += 1;
                t += 1;
            } else if p < pat.len() && pat[p] == P::Many {
                star = Some(p);
                mark = t;
                p += 1;
            } else if let Some(s) = star {
                p = s + 1;
                mark += 1;
                t = mark;
            } else {
                return false;
            }
        }
        while p < pat.len() && pat[p] == P::Many {
            p += 1;
        }
        p == pat.len()
    }

    #[test]
    fn glob_agrees_with_the_reference_on_all_small_inputs() {
        // Every pattern of up to 4 elements and every text of up to 5 characters over a
        // small alphabet that includes multibyte characters.
        let pat_alphabet = ["a", "é", "日", "?", "*"];
        let txt_alphabet = ['a', 'b', 'é', '日'];
        let mut patterns = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for f in &frontier {
                for a in pat_alphabet {
                    next.push(format!("{f}{a}"));
                }
            }
            patterns.extend(next.iter().cloned());
            frontier = next;
        }
        let mut texts = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..5 {
            let mut next = Vec::new();
            for f in &frontier {
                for a in txt_alphabet {
                    next.push(format!("{f}{a}"));
                }
            }
            texts.extend(next.iter().cloned());
            frontier = next;
        }
        for pat in &patterns {
            let s = SigmaString::parse(pat);
            for text in &texts {
                assert_eq!(
                    glob(s.toks(), text),
                    glob_reference(s.toks(), text),
                    "pattern {pat:?} text {text:?}"
                );
            }
        }
    }

    #[test]
    fn escaped_question_mark_is_literal() {
        let s = SigmaString::parse(r"a\?b");
        assert_eq!(s.as_plain().as_deref(), Some("a?b"));
        assert!(s.matches("a?b"));
        assert!(!s.matches("axb"));
        // an escaped backslash followed by a real wildcard
        let s = SigmaString::parse(r"a\\?b");
        assert!(s.matches(r"a\xb"));
        assert!(!s.matches("a?b"));
    }

    #[test]
    fn general_glob_with_single_char_wildcard_inside_stars() {
        let m = |p: &str, t: &str| SigmaString::parse(p).matches(t);
        assert!(m("*a?b*", "xxaZbyy"));
        assert!(m("*a?b*", "a b"));
        assert!(!m("*a?b*", "ab"));
        assert!(!m("*a?b*", "xxaZZbyy"));
        assert!(m("*a?b*", "aab"));
    }

    #[test]
    fn multibyte_text_with_wildcards() {
        let m = |p: &str, t: &str| SigmaString::parse(p).matches(t);
        assert!(m("*é*", "caféteria"));
        assert!(m("日*本", "日本語本"));
        assert!(!m("日*本", "日本語"));
        assert!(m("?é*", "aéz"));
        assert!(m("*日?", "x日本"));
        assert!(!m("*日?", "x日"));
        assert!(m("*本*語*", "日本語"));
    }

    #[test]
    fn helpers() {
        let mut s = SigmaString::literal("x");
        s.prepend_any_many();
        s.prepend_any_many();
        s.append_any_many();
        s.append_any_many();
        assert_eq!(s.toks(), &[Tok::AnyMany, lit("x"), Tok::AnyMany]);
        assert!(s.has_wildcards());
        assert_eq!(s.as_plain(), None);
        assert_eq!(
            SigmaString::literal("A*")
                .to_lowercase()
                .as_plain()
                .as_deref(),
            Some("a*")
        );
        assert_eq!(
            SigmaString::literal("ab")
                .concat(&SigmaString::parse("c*"))
                .toks(),
            &[lit("abc"), Tok::AnyMany]
        );
        assert_eq!(
            SigmaString::from_toks(vec![lit("a"), lit("b"), Tok::AnyMany, Tok::AnyMany]).toks(),
            &[lit("ab"), Tok::AnyMany]
        );
    }
}
