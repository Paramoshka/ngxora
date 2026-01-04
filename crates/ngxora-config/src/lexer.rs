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
    pub fn tokenize(input: &'a str) -> Vec<Token<'a>> {
        let mut tokens: Vec<Token<'a>> = Vec::new();
        let mut line: usize = 1;

        let mut word_start: Option<usize> = None;
        let mut chars = input.char_indices().peekable();

        while let Some((i, c)) = chars.next() {
            if c == '\n' {
                flush(&mut tokens, input, &mut word_start, i, line);
                line += 1;
                continue;
            }

            if c.is_whitespace() {
                flush(&mut tokens, input, &mut word_start, i, line);
                continue;
            }

            if c == '#' {
                flush(&mut tokens, input, &mut word_start, i, line);
                while let Some((_, cc)) = chars.next() {
                    if cc == '\n' {
                        line += 1;
                        break;
                    }
                }
                continue;
            }

            if let Some(kind) = punct_token_type(c) {
                flush(&mut tokens, input, &mut word_start, i, line);

                let end = i + c.len_utf8();
                tokens.push(Token {
                    kind,
                    len: end - i,
                    lexeme: &input[i..end],
                    number_line: line,
                });
                continue;
            }

            if word_start.is_none() {
                word_start = Some(i);
            }
        }

        flush(&mut tokens, input, &mut word_start, input.len(), line);
        tokens
    }
}

fn flush<'a>(
    tokens: &mut Vec<Token<'a>>,
    input: &'a str,
    start: &mut Option<usize>,
    end: usize,
    line: usize,
) {
    let Some(s) = start.take() else {
        return;
    };
    if s < end {
        tokens.push(Token {
            kind: TokenType::Ident,
            lexeme: &input[s..end],
            len: end - s,
            number_line: line,
        });
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
