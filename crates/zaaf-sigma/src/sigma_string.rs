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

/// Iterative wildcard matching with single-star backtracking (linear memory).
fn glob(toks: &[Tok], text: &str) -> bool {
    #[derive(Clone, Copy)]
    enum P {
        C(char),
        One,
        Many,
    }
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
        } else if p < pat.len() && matches!(pat[p], P::Many) {
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
    while p < pat.len() && matches!(pat[p], P::Many) {
        p += 1;
    }
    p == pat.len()
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
