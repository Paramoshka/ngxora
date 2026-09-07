//! Automatic TLS configuration and rejection cases.

use crate::ir::{Ir, SslProvider};
use ngxora_config::Ast;
use std::path::PathBuf;

#[test]
fn from_ast_parses_ssl_provider_letsencrypt() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    acme_directory https://acme-staging-v02.api.letsencrypt.org/directory;
    email admin@example.com;
    cache_dir /var/lib/ngxora/certs;
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    let le = http.ssl_provider.expect("ssl_provider missing");
    assert_eq!(
        le.acme_directory,
        Some("https://acme-staging-v02.api.letsencrypt.org/directory".into())
    );
    assert_eq!(le.email, Some("admin@example.com".into()));
    assert_eq!(le.cache_dir, Some(PathBuf::from("/var/lib/ngxora/certs")));
}

#[test]
fn from_ast_ssl_provider_defaults_to_production() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email admin@example.com;
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    let le = http.ssl_provider.expect("ssl_provider missing");
    assert_eq!(le.acme_directory, None);
    assert_eq!(le.cache_dir, None);
}

#[test]
fn from_ast_server_uses_letsencrypt_without_ssl_certificate() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email admin@example.com;
  }
  server {
    listen 443 ssl;
    server_name example.com;
    location / {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    let server = &http.servers[0];
    assert!(matches!(server.tls, Some(SslProvider::LetsEncrypt)));
}

#[test]
fn from_ast_custom_certificate_wins_over_letsencrypt() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email admin@example.com;
  }
  server {
    listen 443 ssl;
    server_name example.com;
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
    let server = &http.servers[0];
    // Explicit ssl_certificate takes priority over LE.
    assert!(matches!(server.tls, Some(SslProvider::Custom(_))));
}

#[test]
fn from_ast_rejects_ssl_listener_without_certificate_or_le() {
    let input = r#"
http {
  server {
    listen 443 ssl;
    server_name example.com;
    location / {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected ssl without cert to fail");
    assert!(err.message.contains("ssl listener requires a certificate"));
}

#[test]
fn from_ast_rejects_letsencrypt_without_server_name() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email admin@example.com;
  }
  server {
    listen 443 ssl;
    location / {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected LE without server_name to fail");
    assert!(err.message.contains("requires at least one server_name"));
}

#[test]
fn from_ast_rejects_letsencrypt_with_multiple_server_names() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email admin@example.com;
  }
  server {
    listen 443 ssl;
    server_name example.com www.example.com;
    location / {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected multi-name LE server to fail");
    assert!(err.message.contains("supports exactly one server_name"));
}

#[test]
fn from_ast_rejects_duplicate_ssl_provider() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email a@example.com;
  }
  ssl_provider letsencrypt {
    email b@example.com;
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected duplicate ssl_provider to fail");
    assert!(err.message.contains("duplicate ssl_provider"));
}

#[test]
fn from_ast_rejects_ssl_provider_unknown_name() {
    let input = r#"
http {
  ssl_provider zerossl {
    email admin@example.com;
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected unknown provider to fail");
    assert!(err.message.contains("only 'letsencrypt' is supported"));
}

#[test]
fn from_ast_rejects_ssl_provider_unexpected_block() {
    let input = r#"
http {
  ssl_provider letsencrypt {
    email admin@example.com;
    nested {
      value on;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("expected nested block to fail");
    assert!(err.message.contains("unexpected block"));
}
