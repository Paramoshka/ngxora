use crate::{
    Node,
    ast::Ast,
    lexer::{Token, TokenType},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl Ast {
    pub fn parse_config(input: &str) -> Result<Self, ParseError> {
        let tokens = Token::tokenize(input);
        Self::parse_tokens(&tokens)
    }

    fn parse_tokens(tokens: &Vec<Token>) -> Result<Self, ParseError> {
        let ast = Ast { items: Vec::new() };
        let mut iterable_token = tokens.iter().peekable();
        if let Some(token) = iterable_token.next() {
            match token.kind {
                TokenType::Ident => todo!(),
                TokenType::LBrace => todo!(),
                TokenType::RBrace => todo!(),
                TokenType::Semicolon => todo!(),
            }
        }

        Ok(ast)
    }
}
