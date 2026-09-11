//! HTTP, listener, TLS and location directive parsing.

use crate::ir::{
    Ir, KeepaliveTimeout, LocationDirective, LocationIpRule, LocationMatcher, PemSource,
    ProxyPassTarget, SslProvider, Switch, TlsProtocolBounds, TlsProtocolVersion, TlsVerifyClient,
    UpstreamHttpProtocol,
};
use ipnet::IpNet;
use ngxora_config::Ast;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

#[test]
fn from_ast_parses_basic_http() {
    let input = r#"
http {
  keepalive_timeout 30s;
  tcp_nodelay off;
  server {
    listen 443 ssl default_server;
    server_name example.com www.example.com;
    ssl_certificate /tmp/cert.pem;
    ssl_certificate_key /tmp/key.pem;
    location / {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    assert_eq!(http.ssl_provider, None);
    assert_eq!(
        http.keepalive_timeout,
        KeepaliveTimeout::Timeout {
            idle: Duration::from_secs(30),
            header: None,
        }
    );
    assert_eq!(http.keepalive_requests, None);
    assert_eq!(http.client_max_body_size, None);
    assert_eq!(http.proxy_cache_max_size, None);
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

    assert!(matches!(server.tls, Some(SslProvider::Custom(_))));

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
    ssl_certificate /tmp/cert.pem;
    ssl_certificate_key /tmp/key.pem;
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
fn from_ast_parses_proxy_ssl_client_certificate() {
    let input = r#"
http {
  server {
    listen 8080;
    location /api/ {
      proxy_ssl_certificate /etc/ssl/upstreams/client.crt;
      proxy_ssl_certificate_key /etc/ssl/upstreams/client.key;
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
            LocationDirective::ProxySslCertificate(PemSource::Path(PathBuf::from(
                "/etc/ssl/upstreams/client.crt",
            ))),
            LocationDirective::ProxySslCertificateKey(PemSource::Path(PathBuf::from(
                "/etc/ssl/upstreams/client.key",
            ))),
            LocationDirective::ProxyPass(ProxyPassTarget::Url(
                Url::parse("https://127.0.0.1:8443").unwrap(),
            )),
        ]
    );
}

#[test]
fn from_ast_parses_location_access_rules() {
    let input = r#"
http {
  server {
    listen 8080;
    location /api/ {
      allow 10.0.0.0/8;
      deny 192.0.2.10;
      allow all;
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let location = &ir.http.expect("http missing").servers[0].locations[0];
    assert_eq!(
        location.access_rules,
        vec![
            LocationIpRule::Allow(IpNet::from_str("10.0.0.0/8").expect("10.0.0.0/8 is valid")),
            LocationIpRule::Deny(IpNet::from_str("192.0.2.10/32").expect("192.0.2.10/32 is valid"),),
            LocationIpRule::AllowAll,
        ]
    );
}

#[test]
fn from_ast_rejects_invalid_location_access_rule() {
    let input = r#"
http {
  server {
    listen 8080;
    location / {
      allow not-an-ip;
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected invalid allow value");

    assert!(
        err.message
            .contains("allow: expected an IP address or CIDR")
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

    assert!(err.message.contains("unsupported size unit"));
}

#[test]
fn from_ast_parses_return_redirect() {
    let input = r#"
http {
  server {
    listen 8080;
    location /old {
      return 301 https://example.com/new;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");
    let location = &ir.http.unwrap().servers[0].locations[0];
    assert_eq!(
        location.directives,
        vec![LocationDirective::Return {
            status: 301,
            location: "https://example.com/new".into()
        }]
    );
}

#[test]
fn from_ast_rejects_return_without_args() {
    let input = r#"
http {
  server {
    listen 8080;
    location /old {
      return;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected return to fail");
    assert!(err.message.contains("return: expected 2 arguments"));
}

#[test]
fn from_ast_rejects_return_non_redirect_status() {
    let input = r#"
http {
  server {
    listen 8080;
    location /old {
      return 200 https://example.com/new;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected return to fail");
    assert!(err.message.contains("not a redirect"));
}

// --- ssl_provider letsencrypt tests ---

#[test]
fn http2_settings_parse_sizes_and_reject_invalid_values() {
    let ast = Ast::parse_config("http { http2_max_concurrent_streams 32; http2_max_header_list_size 64k; http2_stream_window_size 1m; http2_connection_window_size 4m; }").unwrap();
    let http = Ir::from_ast(&ast).unwrap().http.unwrap();
    assert_eq!(
        http.http2,
        crate::ir::Http2Options {
            max_concurrent_streams: Some(32),
            max_header_list_size: Some(65536),
            stream_window_size: Some(1048576),
            connection_window_size: Some(4194304),
        }
    );
    for directive in [
        "http2_max_concurrent_streams",
        "http2_max_header_list_size",
        "http2_stream_window_size",
        "http2_connection_window_size",
    ] {
        for value in ["0", "-1", "4294967296", "bad", "1 2", ""] {
            let ast = Ast::parse_config(&format!("http {{ {directive} {value}; }}")).unwrap();
            assert!(Ir::from_ast(&ast).is_err(), "{directive} {value}");
        }
        let ast = Ast::parse_config(&format!("http {{ {directive} 1; {directive} 2; }}")).unwrap();
        assert!(Ir::from_ast(&ast).is_err(), "duplicate {directive}");
    }
    for directive in ["http2_stream_window_size", "http2_connection_window_size"] {
        for (value, valid) in [("2147483647", true), ("2147483648", false)] {
            let ast = Ast::parse_config(&format!("http {{ {directive} {value}; }}")).unwrap();
            assert_eq!(Ir::from_ast(&ast).is_ok(), valid);
        }
    }
}

#[test]
fn upstream_http2_directives_parse_and_validate_sizes() {
    for directive in [
        "proxy_http2_max_concurrent_streams",
        "proxy_http2_stream_window_size",
        "proxy_http2_connection_window_size",
    ] {
        for (value, valid) in [
            ("1", true),
            ("0", false),
            ("4294967296", false),
            ("1 2", false),
            ("", false),
        ] {
            let ast = Ast::parse_config(&format!("http {{ server {{ listen 8080; location / {{ proxy_pass http://localhost; {directive} {value}; }} }} }}")).unwrap();
            assert_eq!(Ir::from_ast(&ast).is_ok(), valid, "{directive} {value}");
        }
    }
}
