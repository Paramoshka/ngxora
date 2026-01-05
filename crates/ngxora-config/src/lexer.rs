
#[derive(Debug, PartialEq, Clone)]
pub struct Token {
    pub kind: TokenType,
    pub len: usize,
    pub lexeme: String,
    pub number_line: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum TokenType {
    LBrace,
    RBrace,
    Semicolon,
    Ident,
}

impl Token {
    pub fn tokenize(input: &str) -> Vec<Token> {
        let len_input = input.len();

        let mut tokens: Vec<Token> = Vec::with_capacity(len_input);
        let mut lines = input.lines();
        let mut count_lines = 0;
        let mut ident_word = String::new();

        while let Some(line) = lines.next() {
            count_lines += 1;
            let mut chars = line.chars().peekable();
            while let Some(current_char) = chars.next() {
                if let Some(kind) = punct_token_type(current_char) {
                    flush(&mut tokens, TokenType::Ident, &mut ident_word, count_lines);
                    tokens.push(Token {
                        kind,
                        len: 1,
                        lexeme: current_char.to_string(),
                        number_line: count_lines,
                    });
                    continue;
                }

                if current_char.is_whitespace() {
                    flush(&mut tokens, TokenType::Ident, &mut ident_word, count_lines);
                    continue;
                }

                if current_char == '#' {
                    flush(&mut tokens, TokenType::Ident, &mut ident_word, count_lines);
                    break;
                }

                ident_word.push(current_char);
            }

            flush(&mut tokens, TokenType::Ident, &mut ident_word, count_lines);
        }

        tokens
    }
}

fn flush(tokens: &mut Vec<Token>, kind_token: TokenType, ident: &mut String, number_line: usize) {
    if !ident.is_empty() {
        tokens.push(Token {
            kind: kind_token,
            lexeme: ident.clone(),
            number_line: number_line,
            len: ident.len(),
        });

        ident.clear();
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
