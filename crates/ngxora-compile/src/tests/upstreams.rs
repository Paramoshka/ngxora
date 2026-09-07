//! Upstream policies, health checks and NRF discovery configuration.

use crate::ir::{
    Ir, LocationDirective, NrfEndpointScheme, PemSource, ProxyPassTarget, UpstreamHashKey,
    UpstreamHealthCheckType, UpstreamSelectionPolicy,
};
use ngxora_config::Ast;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

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
    assert_eq!(http.upstreams[0].servers[0].weight, 1);
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
fn from_ast_parses_weighted_consistent_hash_upstream() {
    let input = r#"
http {
  upstream backend {
    policy consistent_hash;
    hash_key header X-Tenant-ID;
    server 127.0.0.1:8080 weight=3;
    server 127.0.0.1:8081 weight=1;
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");
    let upstream = &ir.http.expect("http missing").upstreams[0];

    assert_eq!(upstream.policy, UpstreamSelectionPolicy::ConsistentHash);
    assert_eq!(
        upstream.hash_key,
        Some(UpstreamHashKey::Header("X-Tenant-ID".into()))
    );
    assert_eq!(upstream.servers[0].weight, 3);
    assert_eq!(upstream.servers[1].weight, 1);
}

#[test]
fn from_ast_rejects_hash_key_without_consistent_hash_policy() {
    let input = r#"
http {
  upstream backend {
    hash_key client_ip;
    server 127.0.0.1:8080;
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
    let err = ir
        .validate()
        .expect_err("hash_key must require consistent_hash");

    assert!(
        err.message
            .contains("hash_key requires policy consistent_hash")
    );
}

#[test]
fn from_ast_rejects_invalid_upstream_weight() {
    let input = r#"
http {
  upstream backend {
    server 127.0.0.1:8080 weight=0;
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("zero weight must fail");

    assert!(err.message.contains("weight must be greater than zero"));
}

#[test]
fn validation_rejects_excessive_total_upstream_weight() {
    let input = r#"
http {
  upstream backend {
    server 127.0.0.1:8080 weight=65535;
    server 127.0.0.1:8081 weight=1;
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
    let err = ir.validate().expect_err("excessive total weight must fail");

    assert!(
        err.message
            .contains("total backend weight must not exceed 65535")
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
fn from_ast_parses_nrf_discovery_upstream() {
    let input = r#"
http {
  upstream smf_pool {
    nrf_discovery {
      api_root https://nrf.internal/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme https;
      timeout 2s;
      stale_if_error 45s;
      ssl_verify on;
      ssl_trusted_certificate /etc/ngxora/nrf/ca.pem;
      ssl_certificate /etc/ngxora/nrf/client.crt;
      ssl_certificate_key /etc/ngxora/nrf/client.key;
    }
    health_check {
      type tcp;
    }
  }
  server {
    listen 8080;
    location / {
      proxy_pass https://smf_pool;
      proxy_upstream_protocol h2;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");
    ir.validate().expect("NRF config should validate");
    let discovery = ir.http.unwrap().upstreams[0]
        .nrf_discovery
        .clone()
        .expect("NRF discovery present");

    assert_eq!(discovery.api_root, "https://nrf.internal/nnrf-disc/v1");
    assert_eq!(discovery.target_nf_type, "SMF");
    assert_eq!(discovery.requester_nf_type, "SCP");
    assert_eq!(discovery.service_name, "nsmf-pdusession");
    assert_eq!(discovery.endpoint_scheme, NrfEndpointScheme::Https);
    assert_eq!(discovery.timeout, Duration::from_secs(2));
    assert_eq!(discovery.stale_if_error, Duration::from_secs(45));
    assert_eq!(
        discovery.tls_options.client_certificate,
        Some(PemSource::Path(PathBuf::from("/etc/ngxora/nrf/client.crt")))
    );
}

#[test]
fn validation_rejects_static_and_nrf_discovery_together() {
    let input = r#"
http {
  upstream smf_pool {
    server 127.0.0.1:8443;
    nrf_discovery {
      api_root https://nrf.internal/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme https;
    }
    health_check { type tcp; }
  }
  server {
    listen 8080;
    location / { proxy_pass https://smf_pool; }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");
    let err = ir.validate().expect_err("mixed discovery must fail");
    assert!(err.message.contains("cannot combine server directives"));
}

#[test]
fn validation_rejects_nrf_discovery_without_health_check() {
    let input = r#"
http {
  upstream smf_pool {
    nrf_discovery {
      api_root https://nrf.internal/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme https;
    }
  }
  server {
    listen 8080;
    location / { proxy_pass https://smf_pool; }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");
    let err = ir.validate().expect_err("health check must be required");
    assert!(err.message.contains("must define health_check"));
}

#[test]
fn from_ast_rejects_missing_nrf_discovery_selector() {
    let input = r#"
http {
  upstream smf_pool {
    nrf_discovery {
      api_root https://nrf.internal/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      endpoint_scheme https;
    }
    health_check { type tcp; }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let err = Ir::from_ast(&ast).expect_err("service_name must be required");
    assert!(err.message.contains("service_name is required"));
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
