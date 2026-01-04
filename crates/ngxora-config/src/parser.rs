use crate::ast::Ast;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl Ast {
    pub fn parse_config(input: &str) -> Result<Self, ParseError> {
        let _ = input;
        Ok(Self { items: Vec::new() })
    }
}
