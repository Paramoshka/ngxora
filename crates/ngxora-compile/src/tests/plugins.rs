//! Authentication, headers, CORS and rate-limit plugin configuration.

use crate::ir::Ir;
use ngxora_config::Ast;
use ngxora_plugin_api::PluginSpec;
use serde_json::json;

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
fn from_ast_parses_client_ip_forwarding_for_headers_plugin() {
    let input = r#"
http {
  server {
    listen 8080;
    location / {
      headers {
        forward_client_ip on;
        trusted_proxy 10.0.0.0/8;
        trusted_proxy 2001:db8::2;
      }
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let location = &ir.http.expect("http missing").servers[0].locations[0];
    assert_eq!(
        location.plugins,
        vec![PluginSpec {
            name: "headers".into(),
            config: json!({
                "forward_client_ip": true,
                "trusted_proxies": ["10.0.0.0/8", "2001:db8::2"],
                "request": { "add": [], "set": [], "remove": [] },
                "upstream_request": { "add": [], "set": [], "remove": [] },
                "response": { "add": [], "set": [], "remove": [] }
            }),
        }]
    );
}

#[test]
fn headers_plugin_rejects_duplicate_forward_client_ip() {
    let input = r#"
http {
  server {
    listen 8080;
    location / {
      headers {
        forward_client_ip on;
        forward_client_ip off;
      }
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let error = Ir::from_ast(&ast).expect_err("duplicate directive should fail");

    assert_eq!(
        error.message,
        "headers block: duplicate forward_client_ip directive"
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

#[test]
fn from_ast_parses_rate_limit_plugin_block() {
    let input = r#"
http {
  server {
    listen 8080;
    location /api {
      rate-limit {
        rate 50;
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
            name: "rate-limit".into(),
            config: json!({
                "max_requests_per_second": 50
            }),
        }]
    );
}

#[test]
fn from_ast_parses_cors_plugin_block() {
    let input = r#"
http {
  server {
    listen 8080;
    location /api {
      cors {
        allow_origin "*";
        allow_methods "GET, POST, OPTIONS";
        allow_credentials on;
        max_age 86400;
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
            name: "cors".into(),
            config: json!({
                "allow_origin": "*",
                "allow_methods": "GET, POST, OPTIONS",
                "allow_credentials": true,
                "max_age": 86400
            }),
        }]
    );
}

#[test]
fn from_ast_parses_ext_authz_plugin_block() {
    let input = r#"
http {
  server {
    listen 8080;
    location /api {
      ext_authz {
        uri http://127.0.0.1:9091/auth;
        allowed_host 127.0.0.1;
        timeout 2000;
        pass_request_header Authorization;
        pass_request_header Cookie;
        pass_response_header X-Remote-User;
        pass_response_header X-Role;
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
            name: "ext_authz".into(),
            config: json!({
                "uri": "http://127.0.0.1:9091/auth",
                "allowed_hosts": ["127.0.0.1"],
                "timeout_ms": 2000,
                "pass_request_headers": ["Authorization", "Cookie"],
                "pass_response_headers": ["X-Remote-User", "X-Role"]
            }),
        }]
    );
}

#[test]
fn from_ast_parses_jwt_auth_plugin_block() {
    let input = r#"
http {
  server {
    listen 80;
    location /secure {
      jwt_auth {
        algorithm RS256;
        secret_file /path/to/public.pem;
      }
      proxy_pass http://api;
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
            name: "jwt_auth".into(),
            config: json!({
                "algorithm": "RS256",
                "secret_file": "/path/to/public.pem",
            }),
        }]
    );
}

#[test]
fn from_ast_parses_jwt_auth_claim_policy() {
    let input = r#"
http {
  server {
    listen 80;
    location /secure {
      jwt_auth {
        algorithm HS256;
        secret secret;
        iss https://issuer.example;
        aud orders-api;
        aud reporting-api;
        sub service-account;
        required_scope orders:read;
        required_scope profile;
      }
      proxy_pass http://api;
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
            name: "jwt_auth".into(),
            config: json!({
                "algorithm": "HS256",
                "secret": "secret",
                "iss": "https://issuer.example",
                "aud": ["orders-api", "reporting-api"],
                "sub": "service-account",
                "required_scopes": ["orders:read", "profile"],
            }),
        }]
    );
}

// ── Cache config tests ──
