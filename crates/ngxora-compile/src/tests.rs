#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ngxora_config::Ast;
    use url::Url;

    use crate::ir::{Ir, LocationDirective, LocationMatcher, Switch};

    #[test]
    fn from_ast_parses_basic_http() {
        let input = r#"
http {
  keepalive_timeout 30s;
  tcp_nodelay off;
  server {
    listen 443 ssl default_server;
    server_name example.com www.example.com;
    location / {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        assert_eq!(http.keepalive_timeout, "30s");
        assert_eq!(http.tcp_nodelay, Switch::Off);
        assert_eq!(http.servers.len(), 1);

        let server = &http.servers[0];
        assert_eq!(
            server.server_names,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
        assert_eq!(server.listens.len(), 1);
        assert_eq!(server.listens[0].port, 443);
        assert_eq!(server.listens[0].addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(server.listens[0].ssl);
        assert!(server.listens[0].default_server);

        assert_eq!(server.locations.len(), 1);
        let location = &server.locations[0];
        assert_eq!(location.matcher, LocationMatcher::Prefix("/".to_string()));
        assert_eq!(
            location.directives,
            vec![LocationDirective::ProxyPass(
                Url::parse("http://127.0.0.1:8080").unwrap()
            )]
        );
    }
}
