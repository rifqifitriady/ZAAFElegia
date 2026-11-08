//! Sigma condition grammar.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quantifier {
    One,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelTarget {
    /// All search identifiers not starting with `_`.
    Them,
    /// A pattern with `*` wildcards, e.g. `selection_*`.
    Pattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondExpr {
    Ident(String),
    Not(Box<CondExpr>),
    And(Vec<CondExpr>),
    Or(Vec<CondExpr>),
    Of(Quantifier, SelTarget),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum T {
    LParen,
    RParen,
    Word(String),
}

fn tokenize(s: &str) -> Result<Vec<T>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    fn flush(cur: &mut String, out: &mut Vec<T>) {
        if !cur.is_empty() {
            out.push(T::Word(std::mem::take(cur)));
        }
    }
    for c in s.chars() {
        match c {
            '(' => {
                flush(&mut cur, &mut out);
                out.push(T::LParen);
            }
            ')' => {
                flush(&mut cur, &mut out);
                out.push(T::RParen);
            }
            '|' => {
                return Err(
                    "aggregation expressions (`| count() ...`) were removed in Sigma 2.0; \
                            use a correlation rule instead"
                        .into(),
                );
            }
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            c => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    Ok(out)
}

struct Parser {
    toks: Vec<T>,
    pos: usize,
}

impl Parser {
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.toks.get(self.pos), Some(T::Word(w)) if w.eq_ignore_ascii_case(kw))
    }

    fn expr(&mut self) -> Result<CondExpr, String> {
        let mut items = vec![self.and_expr()?];
        while self.is_kw("or") {
            self.pos += 1;
            items.push(self.and_expr()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            CondExpr::Or(items)
        })
    }

    fn and_expr(&mut self) -> Result<CondExpr, String> {
        let mut items = vec![self.not_expr()?];
        while self.is_kw("and") {
            self.pos += 1;
            items.push(self.not_expr()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            CondExpr::And(items)
        })
    }

    fn not_expr(&mut self) -> Result<CondExpr, String> {
        if self.is_kw("not") {
            self.pos += 1;
            return Ok(CondExpr::Not(Box::new(self.not_expr()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<CondExpr, String> {
        match self.toks.get(self.pos).cloned() {
            Some(T::LParen) => {
                self.pos += 1;
                let e = self.expr()?;
                if self.toks.get(self.pos) == Some(&T::RParen) {
                    self.pos += 1;
                    Ok(e)
                } else {
                    Err("missing closing parenthesis".into())
                }
            }
            Some(T::RParen) => Err("unexpected `)`".into()),
            Some(T::Word(w)) => {
                let lower = w.to_ascii_lowercase();
                let next_is_of = matches!(self.toks.get(self.pos + 1), Some(T::Word(o)) if o.eq_ignore_ascii_case("of"));
                if (lower == "1" || lower == "all") && next_is_of {
                    self.pos += 2;
                    let q = if lower == "all" {
                        Quantifier::All
                    } else {
                        Quantifier::One
                    };
                    let target = match self.toks.get(self.pos).cloned() {
                        Some(T::Word(t)) => {
                            self.pos += 1;
                            if t.eq_ignore_ascii_case("them") {
                                SelTarget::Them
                            } else {
                                SelTarget::Pattern(t)
                            }
                        }
                        _ => {
                            return Err(format!("`{w} of` must be followed by `them` or a pattern"));
                        }
                    };
                    return Ok(CondExpr::Of(q, target));
                }
                if ["and", "or", "not", "of", "them"].contains(&lower.as_str()) {
                    return Err(format!("unexpected keyword `{w}`"));
                }
                self.pos += 1;
                Ok(CondExpr::Ident(w))
            }
            None => Err("unexpected end of condition".into()),
        }
    }
}

/// Parses one condition string.
pub fn parse_condition(s: &str) -> Result<CondExpr, String> {
    let toks = tokenize(s)?;
    if toks.is_empty() {
        return Err("empty condition".into());
    }
    let mut p = Parser { toks, pos: 0 };
    let e = p.expr()?;
    if p.pos != p.toks.len() {
        return Err(format!("unexpected token after position {}", p.pos));
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> CondExpr {
        CondExpr::Ident(s.into())
    }

    #[test]
    fn precedence_or_and_not() {
        assert_eq!(
            parse_condition("a or b and not c").unwrap(),
            CondExpr::Or(vec![
                id("a"),
                CondExpr::And(vec![id("b"), CondExpr::Not(Box::new(id("c")))])
            ])
        );
    }

    #[test]
    fn parentheses_and_newlines() {
        assert_eq!(
            parse_condition("(a or b)\n  and c").unwrap(),
            CondExpr::And(vec![CondExpr::Or(vec![id("a"), id("b")]), id("c")])
        );
    }

    #[test]
    fn quantifiers() {
        assert_eq!(
            parse_condition("1 of selection_*").unwrap(),
            CondExpr::Of(Quantifier::One, SelTarget::Pattern("selection_*".into()))
        );
        assert_eq!(
            parse_condition("all of them").unwrap(),
            CondExpr::Of(Quantifier::All, SelTarget::Them)
        );
        assert_eq!(
            parse_condition("sel and not 1 of filter_*").unwrap(),
            CondExpr::And(vec![
                id("sel"),
                CondExpr::Not(Box::new(CondExpr::Of(
                    Quantifier::One,
                    SelTarget::Pattern("filter_*".into())
                )))
            ])
        );
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(
            parse_condition("a AND NOT b").unwrap(),
            parse_condition("a and not b").unwrap()
        );
    }

    #[test]
    fn errors() {
        for bad in ["", "a and", "(a", "a b", "and a", "1 of", "a)"] {
            assert!(parse_condition(bad).is_err(), "should reject {bad:?}");
        }
        let agg = parse_condition("sel | count() > 5").unwrap_err();
        assert!(agg.contains("correlation rule"), "{agg}");
    }
}
