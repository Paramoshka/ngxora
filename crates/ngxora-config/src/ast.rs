use crate::{ParseError, lexer::Token, parser::Parser};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ast {
    pub items: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Directive(Directive),
    Block(Block),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Block {
    pub name: String,
    pub args: Vec<String>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn directive(name: String, args: Vec<String>) -> Self {
        Self::Directive(Directive { name, args })
    }

    pub fn block(name: String, args: Vec<String>, children: Vec<Node>) -> Self {
        Self::Block(Block {
            name,
            args,
            children,
        })
    }
}

impl Ast {
    pub fn parse_config(input: &str) -> Result<Self, ParseError> {
        let tokens = Token::tokenize(input);
        Self::parse_tokens(&tokens)
    }

    fn parse_tokens<'a>(tokens: &[Token<'a>]) -> Result<Self, ParseError> {
        let mut parser = Parser::new(tokens);
        let items = parser.parse_items(false)?;
        Ok(Ast { items })
    }
}
