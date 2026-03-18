#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    use ngxora_config::Ast;
    use ngxora_plugin_api::PluginSpec;
    use serde_json::json;
    use url::Url;

    use crate::ir::{
        Ir, KeepaliveTimeout, LocationDirective, LocationMatcher, PemSource, ProxyPassTarget,
        Switch, TlsProtocolBounds, TlsProtocolVersion, TlsVerifyClient, UpstreamHealthCheckType,
        UpstreamHttpProtocol, UpstreamSelectionPolicy,
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
        assert_eq!(http.client_max_body_size, None);
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
            vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                Url::parse("http://127.0.0.1:8080").unwrap()
            ))]
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
  client_max_body_size 10m;
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
        assert_eq!(http.client_max_body_size, Some(10 * 1024 * 1024));
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
                LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    Url::parse("http://127.0.0.1:8080").unwrap(),
                )),
            ]
        );
    }

    #[test]
    fn from_ast_parses_proxy_upstream_protocol() {
        let input = r#"
http {
  server {
    listen 8080;
    location /grpc/ {
      proxy_upstream_protocol h2c;
      proxy_pass http://127.0.0.1:50051;
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
                LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2c),
                LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    Url::parse("http://127.0.0.1:50051").unwrap(),
                )),
            ]
        );
    }

    #[test]
    fn from_ast_parses_proxy_ssl_options() {
        let input = r#"
http {
  server {
    listen 8080;
    location /api/ {
      proxy_ssl_verify off;
      proxy_ssl_trusted_certificate /etc/ssl/upstreams/ca.pem;
      proxy_pass https://127.0.0.1:8443;
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
                LocationDirective::ProxySslVerify(Switch::Off),
                LocationDirective::ProxySslTrustedCertificate(PemSource::Path(PathBuf::from(
                    "/etc/ssl/upstreams/ca.pem",
                ))),
                LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    Url::parse("https://127.0.0.1:8443").unwrap(),
                )),
            ]
        );
    }

    #[test]
    fn from_ast_parses_client_max_body_size_off() {
        let input = r#"
http {
  client_max_body_size 0;
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        assert_eq!(http.client_max_body_size, None);
    }

    #[test]
    fn from_ast_rejects_invalid_client_max_body_size_unit() {
        let input = r#"
http {
  client_max_body_size 10q;
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let err = Ir::from_ast(&ast).expect_err("expected client_max_body_size to fail");

        assert!(
            err.message
                .contains("client_max_body_size: unsupported size unit `q` in `10q`")
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

    #[test]
    fn from_ast_parses_upstream_blocks() {
        let input = r#"
http {
  upstream backend {
    policy random;
    server 127.0.0.1:8080;
    server demo-gui:80;
  }

  server {
    listen 8080;
    location / {
      proxy_pass http://backend;
    }
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        assert_eq!(http.upstreams.len(), 1);
        assert_eq!(http.upstreams[0].name, "backend");
        assert_eq!(http.upstreams[0].policy, UpstreamSelectionPolicy::Random);
        assert_eq!(http.upstreams[0].servers[0].host, "127.0.0.1");
        assert_eq!(http.upstreams[0].servers[0].port, 8080);
        assert_eq!(http.upstreams[0].servers[1].host, "demo-gui");
        assert_eq!(http.upstreams[0].servers[1].port, 80);
        assert!(http.upstreams[0].health_check.is_none());
        assert_eq!(
            http.servers[0].locations[0].directives,
            vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                Url::parse("http://backend").unwrap(),
            ))]
        );
    }

    #[test]
    fn from_ast_parses_upstream_http_health_check_block() {
        let input = r#"
http {
  upstream backend {
    server 127.0.0.1:8080;

    health_check {
      type http;
      host backend.internal;
      path /readyz;
      use_tls on;
      timeout 2s;
      interval 10s;
      consecutive_success 2;
      consecutive_failure 3;
    }
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let ir = Ir::from_ast(&ast).expect("from_ast failed");

        let http = ir.http.expect("http missing");
        let health_check = http.upstreams[0]
            .health_check
            .as_ref()
            .expect("health check present");
        assert_eq!(
            health_check.check_type,
            UpstreamHealthCheckType::Http {
                host: "backend.internal".into(),
                path: "/readyz".into(),
                use_tls: true,
            }
        );
        assert_eq!(health_check.timeout, Duration::from_secs(2));
        assert_eq!(health_check.interval, Duration::from_secs(10));
        assert_eq!(health_check.consecutive_success, 2);
        assert_eq!(health_check.consecutive_failure, 3);
    }

    #[test]
    fn from_ast_rejects_invalid_upstream_server() {
        let input = r#"
http {
  upstream backend {
    server demo-gui;
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let err = Ir::from_ast(&ast).expect_err("expected upstream server to fail");

        assert!(err.message.contains("upstream server: expected host:port"));
    }

    #[test]
    fn from_ast_rejects_invalid_upstream_policy() {
        let input = r#"
http {
  upstream backend {
    policy least_conn;
    server 127.0.0.1:8080;
  }
}
"#;
        let ast = Ast::parse_config(input).unwrap();
        let err = Ir::from_ast(&ast).expect_err("expected upstream policy to fail");

        assert!(
            err.message
                .contains("unsupported upstream selection policy")
        );
    }

    #[test]
    fn from_ast_parses_basic_auth_plugin_block() {
        let input = r#"
http {
  server {
    listen 8080;
    location /admin {
      basic_auth {
        username demo;
        password s3cret phrase;
        realm Admin Area;
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
                name: "basic-auth".into(),
                config: json!({
                    "username": "demo",
                    "password": "s3cret phrase",
                    "realm": "Admin Area"
                }),
            }]
        );
    }
}
