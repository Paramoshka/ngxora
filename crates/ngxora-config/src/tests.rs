#[cfg(test)]
mod tests {
    use crate::{
        Ast, Node,
        lexer::{Token, TokenType},
    };

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

    #[test]
    fn parses_golden_conf() {
        let input = include_str!("fixtures/golden.conf");
        let ast = Ast::parse_config(input).unwrap();

        let expected = Ast {
            items: vec![Node::block(
                "http".to_string(),
                vec![],
                vec![Node::block(
                    "server".to_string(),
                    vec![],
                    vec![
                        Node::directive("listen".to_string(), vec!["80".to_string()]),
                        Node::directive(
                            "server_name".to_string(),
                            vec!["example.com".to_string()],
                        ),
                    ],
                )],
            )],
        };

        assert_eq!(ast, expected);
    }

    #[test]
    fn errors_on_unexpected_rbrace_top_level() {
        let err = Ast::parse_config("}").unwrap_err();
        assert!(err.message.contains("unexpected"));
    }
}
