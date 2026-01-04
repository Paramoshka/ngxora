use std::error::Error;

#[derive(Debug, PartialEq, Clone)]
pub struct Token {
    pub kind: TokenType,
    pub len: u8,
    pub lexeme: String,
    pub number_line: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum TokenType {
    LBrace,
    RBrace,
    Semicolone,
    Ident,
}

impl Token {
    pub fn tokenize(input: &str) -> Option<Vec<Token>> {
        let len_input = input.len();
        if len_input == 0 {
            return None;
        }

        let mut tokens: Vec<Token> = Vec::with_capacity(len_input);
        let mut peekable_iterator = input.chars().peekable();
        while let Some(current_character) = peekable_iterator.next() {}

        Some(tokens)
    }
}
