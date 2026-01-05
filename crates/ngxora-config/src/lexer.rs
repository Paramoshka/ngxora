use crate::Node;

#[derive(Debug, PartialEq, Clone)]
pub struct Token<'a> {
    pub kind: TokenType,
    pub len: usize,
    pub lexeme: &'a str,
    pub number_line: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum TokenType {
    LBrace,
    RBrace,
    Semicolon,
    Ident,
}

impl<'a> Token<'a> {
    pub fn tokenize(input: &str) -> Vec<Token> {
        let len_input = input.len();

        let mut tokens: Vec<Token> = Vec::with_capacity(len_input);
        let mut lines = input.lines();
        let mut count_lines = 0;

        while let Some(line) = lines.next() {
            count_lines += 1;
            let end_line = line.len() - 1; // index last symbol in line
            let mut end_lexeme = 1;

            for (i, current_char) in line.char_indices() {
                if let lexeme = build_lexeme(input, i, end_lexeme, end_line) {
                    if let Some(kind) = punct_token_type(current_char) {
                        continue;
                    }

                    if current_char.is_whitespace() {
                        end_lexeme = i + 1;
                        continue;
                    }

                    if current_char == '#' {
                        end_lexeme = i + 1;
                        break;
                    }

                    end_lexeme += 1;

                    tokens.push(Token {
                        kind,
                        len: 1,
                        lexeme: lexeme,
                        number_line: count_lines,
                    });
                }
            }
        }

        tokens
    }
}

fn build_lexeme(input: &str, start: usize, end: usize, end_line: usize) -> Option<&str> {
    if end < end_line {
        return Some(&input[start..end]);
    } else {
        return None;
    }
}

fn flush<'a>(
    tokens: &mut Vec<Token<'a>>,
    input: &'a str,
    start: Option<usize>,
    end: usize,
    line: usize,
) {
    if let Some(s) = start {
        if s < end {
            tokens.push(Token {
                kind: TokenType::Ident,
                lexeme: &input[s..end],
                len: end - s,
                number_line: line,
            });
        }
    }
}

fn punct_token_type(c: char) -> Option<TokenType> {
    match c {
        '{' => Some(TokenType::LBrace),
        '}' => Some(TokenType::RBrace),
        ';' => Some(TokenType::Semicolon),
        _ => None,
    }
}
