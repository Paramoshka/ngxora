//! Global and per-location cache configuration.

use crate::ir::{CacheKeyMode, Ir};
use ngxora_config::Ast;
use std::time::Duration;

#[test]
fn from_ast_parses_global_proxy_cache_max_size() {
    let input = r#"
http {
  proxy_cache_max_size 256m;
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    assert_eq!(http.proxy_cache_max_size, Some(256 * 1024 * 1024));
}

#[test]
fn from_ast_parses_global_proxy_cache_max_size_zero() {
    let input = r#"
http {
  proxy_cache_max_size 0;
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    assert_eq!(http.proxy_cache_max_size, Some(0));
}

#[test]
fn from_ast_parses_proxy_cache_on_inline() {
    let input = r#"
http {
  server {
    listen 80;
    location /api/ {
      proxy_cache on;
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    let cache = http.servers[0].locations[0]
        .cache
        .as_ref()
        .expect("cache configured");

    assert!(cache.enabled);
    assert_eq!(cache.ttl, Some(Duration::from_secs(60))); // default
    assert_eq!(cache.cache_key, CacheKeyMode::Uri); // default
    assert!(cache.valid_statuses.contains(&200));
}

#[test]
fn from_ast_parses_proxy_cache_off() {
    let input = r#"
http {
  server {
    listen 80;
    location /realtime/ {
      proxy_cache off;
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    let cache = http.servers[0].locations[0]
        .cache
        .as_ref()
        .expect("cache configured");
    assert!(!cache.enabled);
}

#[test]
fn from_ast_parses_proxy_cache_block_with_all_options() {
    let input = r#"
http {
  server {
    listen 80;
    location /blog/ {
      proxy_cache {
        proxy_cache_ttl 5m;
        proxy_cache_stale_if_error 30s;
        proxy_cache_key normalized_uri;
        proxy_cache_min_uses 3;
        proxy_cache_valid 200 301 302;
        proxy_cache_max_size 256m;
      }
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    let cache = http.servers[0].locations[0]
        .cache
        .as_ref()
        .expect("cache configured");

    assert!(cache.enabled);
    assert_eq!(cache.ttl, Some(Duration::from_secs(300)));
    assert_eq!(cache.stale_if_error, Some(Duration::from_secs(30)));
    assert_eq!(cache.cache_key, CacheKeyMode::NormalizedUri);
    assert_eq!(cache.min_uses, Some(3));
    assert_eq!(cache.valid_statuses, vec![200, 301, 302]);
    assert_eq!(cache.max_size, Some(256 * 1024 * 1024));
}

#[test]
fn from_ast_location_without_cache_is_none() {
    let input = r#"
http {
  server {
    listen 80;
    location /plain/ {
      proxy_pass http://127.0.0.1:8080;
    }
  }
}
"#;
    let ast = Ast::parse_config(input).unwrap();
    let ir = Ir::from_ast(&ast).expect("from_ast failed");

    let http = ir.http.expect("http missing");
    assert!(http.servers[0].locations[0].cache.is_none());
}
