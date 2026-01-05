use crate::{ast::Ast, lexer::Token};

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
        // TODO
        Ok(ast)
    }
}
