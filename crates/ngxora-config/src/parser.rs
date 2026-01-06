use crate::{
    Node,
    lexer::{Token, TokenType},
};

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

    fn peek(&self) -> Option<&'a Token<'a>> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&'a Token<'a>> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, kind: TokenType) -> Result<(), ParseError> {
        let tok = self.next().ok_or(ParseError {
            message: "unexpected EOF".into(),
        })?;
        if tok.kind == kind {
            Ok(())
        } else {
            Err(ParseError {
                message: format!("expected {:?}, got {:?}", kind, tok.kind),
            })
        }
    }

    fn parse_items(&mut self, until_rbrace: bool) -> Result<Vec<Node>, ParseError> {
        let mut items: Vec<Node> = Vec::new();

        while let Some(token) = self.peek() {
            if token.kind == TokenType::RBrace {
                if until_rbrace {
                    break;
                }

                return Err(ParseError {
                    message: "unexpected '}'".into(),
                });
            }

            items.push(self.parse_stmt()?);
        }

        if until_rbrace {
            // TODO
        }

        Ok(items)
    }

    fn parse_stmt(&mut self) -> Result<Node, ParseError> {
        let name_tok = self.next().ok_or(ParseError {
            message: "unexpected EOF".into(),
        })?;

        if name_tok.kind != TokenType::Ident {
            return Err(ParseError {
                message: format!("expected Ident, got {:?}", name_tok.kind),
            });
        };

        let name = name_tok.lexeme.to_string();
        let mut args = Vec::new();
    }
}
