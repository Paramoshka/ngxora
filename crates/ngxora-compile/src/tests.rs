#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    use ngxora_plugin_api::PluginSpec;
    use ngxora_config::Ast;
    use serde_json::json;
    use url::Url;

    use crate::ir::{
        Ir, KeepaliveTimeout, LocationDirective, LocationMatcher, PemSource, Switch,
        TlsProtocolBounds, TlsProtocolVersion, TlsVerifyClient,
    };

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
        assert_eq!(
            http.keepalive_timeout,
            KeepaliveTimeout::Timeout {
                idle: Duration::from_secs(30),
                header: None,
            }
        );
        assert_eq!(http.keepalive_requests, None);
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
        assert!(!server.listens[0].http2);
        assert!(!server.listens[0].http2_only);

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

    #[test]
    fn from_ast_parses_keepalive_timeout_variants() {
        let input = r#"
http {
  keepalive_timeout 1m30s 10s;
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        assert_eq!(
            http.keepalive_timeout,
            KeepaliveTimeout::Timeout {
                idle: Duration::from_secs(90),
                header: Some(Duration::from_secs(10)),
            }
        );
    }

    #[test]
    fn from_ast_parses_keepalive_timeout_off() {
        let input = r#"
http {
  keepalive_timeout 0;
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        assert_eq!(http.keepalive_timeout, KeepaliveTimeout::Off);
    }

    #[test]
    fn from_ast_rejects_invalid_keepalive_timeout_unit() {
        let input = r#"
http {
  keepalive_timeout 10q;
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let err = Ir::from_ast(&ast).expect_err("expected keepalive_timeout to fail");

        assert!(
            err.message
                .contains("keepalive_timeout: unsupported time unit `q` in `10q`")
        );
    }

    #[test]
    fn from_ast_parses_downstream_protocol_and_tls_options() {
        let input = r#"
http {
  h2c on;
  keepalive_requests 1000;
  allow_connect_method_proxying on;

  server {
    listen 443 ssl http2;
    server_name example.com;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_verify_client optional;
    ssl_client_certificate /etc/ssl/clients/ca.pem;
    location / {
      proxy_pass https://127.0.0.1:8443;
    }
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        assert_eq!(http.h2c, Switch::On);
        assert_eq!(http.keepalive_requests, Some(1000));
        assert_eq!(http.allow_connect_method_proxying, Switch::On);

        let server = &http.servers[0];
        assert!(server.listens[0].http2);
        assert!(!server.listens[0].http2_only);
        assert_eq!(
            server.tls_options.protocols,
            Some(TlsProtocolBounds {
                min: TlsProtocolVersion::Tls1_2,
                max: TlsProtocolVersion::Tls1_3,
            })
        );
        assert_eq!(server.tls_options.verify_client, TlsVerifyClient::Optional);
        assert_eq!(
            server.tls_options.client_certificate,
            Some(PemSource::Path(PathBuf::from("/etc/ssl/clients/ca.pem")))
        );
    }

    #[test]
    fn from_ast_rejects_listen_http2_without_ssl() {
        let input = r#"
http {
  server {
    listen 80 http2;
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let err = Ir::from_ast(&ast).expect_err("expected listen http2 to fail");

        assert!(err.message.contains("http2/http2_only requires ssl"));
    }

    #[test]
    fn from_ast_rejects_verify_client_without_ca() {
        let input = r#"
http {
  server {
    listen 443 ssl;
    ssl_verify_client required;
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let err = Ir::from_ast(&ast).expect_err("expected verify_client to fail");

        assert!(err.message.contains("requires ssl_client_certificate"));
    }

    #[test]
    fn from_ast_parses_proxy_timeouts() {
        let input = r#"
http {
  server {
    listen 8080;
    location /api/ {
      proxy_connect_timeout 3s;
      proxy_read_timeout 15s;
      proxy_write_timeout 20s;
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        let location = &http.servers[0].locations[0];
        assert_eq!(
            location.directives,
            vec![
                LocationDirective::ProxyConnectTimeout(Duration::from_secs(3)),
                LocationDirective::ProxyReadTimeout(Duration::from_secs(15)),
                LocationDirective::ProxyWriteTimeout(Duration::from_secs(20)),
                LocationDirective::ProxyPass(Url::parse("http://127.0.0.1:8080").unwrap()),
            ]
        );
    }

    #[test]
    fn from_ast_parses_headers_plugin_block() {
        let input = r#"
http {
  server {
    listen 8080;
    location / {
      headers {
        request_set X-Request-Id abc;
        request_remove X-Debug;
        upstream_request_add X-Upstream edge;
        response_add X-Proxy ngxora edge;
      }
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        let location = &http.servers[0].locations[0];
        assert_eq!(
            location.plugins,
            vec![PluginSpec {
                name: "headers".into(),
                config: json!({
                    "request": {
                        "add": [],
                        "set": [
                            { "name": "X-Request-Id", "value": "abc" }
                        ],
                        "remove": ["X-Debug"]
                    },
                    "upstream_request": {
                        "add": [
                            { "name": "X-Upstream", "value": "edge" }
                        ],
                        "set": [],
                        "remove": []
                    },
                    "response": {
                        "add": [
                            { "name": "X-Proxy", "value": "ngxora edge" }
                        ],
                        "set": [],
                        "remove": []
                    }
                }),
            }]
        );
    }
}
