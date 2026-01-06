use crate::lexer::{Token, TokenType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Parser<'a> {
    tokens: &'a [Token<'a>],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn peek(&self) -> Option<&'a Token<'a>> {
        self.tokens.get(self.pos)
    }

    pub fn next(&mut self) -> Option<&'a Token<'a>> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    pub fn expect(&mut self, kind: TokenType) -> Result<&'a Token, ParseError> {
        match self.next() {
            Some(t) if t.kind == kind => Ok(t),
            Some(t) => Err(ParseError {
                message: format!(
                    "expected {:?}, got {:?} at line {}",
                    kind, t.kind, t.number_line
                ),
            }),
            None => Err(ParseError {
                message: format!("expected {:?}, got EOF", kind),
            }),
        }
    }
}
