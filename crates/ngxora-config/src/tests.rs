#[cfg(test)]
mod tests {
    use crate::lexer::{Token, TokenType};

    #[test]
    fn tokenizes_simple_block_and_comment() {
        let input = "server { listen 80; # comment\n}";
        let tokens = Token::tokenize(input);
        let kinds: Vec<_> = tokens.into_iter().map(|t| t.kind).collect();

        assert_eq!(
            kinds,
            vec![
                TokenType::Ident,
                TokenType::LBrace,
                TokenType::Ident,
                TokenType::Ident,
                TokenType::Semicolon,
                TokenType::RBrace,
            ]
        );
    }
}
