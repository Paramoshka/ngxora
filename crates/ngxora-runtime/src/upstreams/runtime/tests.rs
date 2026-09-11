use super::response::write_route_response;
use super::*;
use http::StatusCode;
use ipnet::IpNet;
use ngxora_compile::ir::LocationIpRule;
use ngxora_plugin_api::{HttpPlugin, PluginFlow, async_trait, empty_plugin_chain};
use tokio::io::{AsyncWriteExt, duplex};

use super::completion::should_mark_span_as_error;
use super::selection::{location_allows_client, prefixed_upstream_uri};
use crate::cache::{CacheBackend, CacheKey};
use crate::control::RuntimeState;
use crate::upstreams::types::CompiledRouter;
use bytes::{Bytes, BytesMut};
use ngxora_compile::ir::{CacheConfig, UpstreamSslOptions, UpstreamTimeouts};
use ngxora_plugin_api::{LocalResponse, PluginError, ResponseCtx};
use pingora::http::ResponseHeader;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn test_session() -> Session {
    let (mut client, server) = duplex(1024);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");

    let mut session = Session::new_h1(Box::new(server));
    session.read_request().await.expect("read request");
    session
}

#[test]
fn nrf_api_prefix_rewrites_path_and_preserves_query() {
    let uri: http::Uri = "/nsmf-pdusession/v1/sm-contexts?trace=1".parse().unwrap();

    assert_eq!(
        prefixed_upstream_uri(&uri, "/operator/edge")
            .unwrap()
            .to_string(),
        "/operator/edge/nsmf-pdusession/v1/sm-contexts?trace=1"
    );
}

#[test]
fn nrf_api_prefix_preserves_root_path_separator() {
    let uri: http::Uri = "/".parse().unwrap();

    assert_eq!(
        prefixed_upstream_uri(&uri, "/operator/edge")
            .unwrap()
            .to_string(),
        "/operator/edge/"
    );
}

fn cached_route(cache: CacheConfig, plugins: ngxora_plugin_api::PluginChain) -> SelectedRoute {
    SelectedRoute {
        url_rewrite: None,
        matched_prefix: None,
        route_id: 1,
        access_rules: Vec::new(),
        target: SelectedTarget::Upstream(SelectedPeer {
            host: "127.0.0.1".into(),
            port: 8080,
            tls: false,
            sni: String::new(),
            upstream_group: Some("backend".into()),
            api_prefix: None,
        }),
        upstream_timeouts: UpstreamTimeouts::default(),
        upstream_protocol: None,
        upstream_http2: Default::default(),
        upstream_ssl_options: UpstreamSslOptions::default(),
        upstream_trusted_ca: None,
        upstream_client_identity: None,
        plugins,
        cache: Some(cache),
    }
}

struct StatusRewritePlugin {
    status: StatusCode,
}

struct FailingResponsePlugin(Arc<AtomicUsize>);

#[async_trait]
impl HttpPlugin for FailingResponsePlugin {
    fn name(&self) -> &'static str {
        "failing-response"
    }
    async fn on_response(&self, _: &mut ResponseCtx<'_>) -> Result<PluginFlow, PluginError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(PluginError::new(self.name(), "test failure"))
    }
}

#[tokio::test]
async fn local_response_plugin_failure_sends_500_without_recursing() {
    use tokio::io::AsyncReadExt;
    let calls = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn HttpPlugin>> = vec![Arc::new(FailingResponsePlugin(calls.clone()))];
    let mut ctx = ProxyContext {
        selected: Some(cached_route(CacheConfig::default(), plugins.into())),
        ..Default::default()
    };
    let (mut client, server) = duplex(4096);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut session = Session::new_h1(Box::new(server));
    session.read_request().await.unwrap();
    let error = write_route_response(
        &mut session,
        &mut ctx,
        LocalResponse::new(StatusCode::OK, "body"),
    )
    .await
    .expect_err("response plugin fails");
    assert!(session.response_written().is_none());
    let proxy = DynamicProxy::from_router(CompiledRouter::default());
    let result = ProxyHttp::fail_to_proxy(&proxy, &mut session, &error, &mut ctx).await;
    assert_eq!(result.error_code, 500);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let mut response = [0; 4096];
    let len = client.read(&mut response).await.unwrap();
    assert!(response[..len].starts_with(b"HTTP/1.1 500"));
}

#[async_trait]
impl HttpPlugin for StatusRewritePlugin {
    fn name(&self) -> &'static str {
        "status-rewrite"
    }

    async fn on_response(&self, ctx: &mut ResponseCtx<'_>) -> Result<PluginFlow, PluginError> {
        *ctx.status = self.status;
        Ok(PluginFlow::Continue)
    }
}

#[tokio::test]
async fn response_body_filter_preserves_downstream_body() {
    let proxy = DynamicProxy::from_router(CompiledRouter::default());
    let mut session = test_session().await;
    let mut ctx = ProxyContext {
        cache_headers: Some(http::HeaderMap::new()),
        cache_body_limit: Some(1024),
        ..Default::default()
    };
    let original = Bytes::from_static(b"hello");
    let mut body = Some(original.clone());

    ProxyHttp::response_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
        .expect("body filter succeeds");

    assert_eq!(body, Some(original.clone()));
    assert_eq!(ctx.response_body_buf, original);
}

#[tokio::test]
async fn response_body_filter_stops_buffering_at_cache_limit() {
    let proxy = DynamicProxy::from_router(CompiledRouter::default());
    let mut session = test_session().await;
    let mut ctx = ProxyContext {
        cache_status: Some(StatusCode::OK),
        cache_headers: Some(http::HeaderMap::new()),
        cache_body_limit: Some(4),
        response_body_buf: BytesMut::from(&b"abc"[..]),
        ..Default::default()
    };
    let original = Bytes::from_static(b"de");
    let mut body = Some(original.clone());

    ProxyHttp::response_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
        .expect("body filter succeeds");

    assert_eq!(body, Some(original));
    assert!(ctx.response_body_buf.is_empty());
    assert!(ctx.cache_headers.is_none());
    assert!(ctx.cache_body_limit.is_none());
}

#[test]
fn location_access_rules_defaults_to_allow() {
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    assert!(location_allows_client(&[], Some(ip)));
}

#[test]
fn location_access_rules_first_match_wins() {
    let rules = vec![
        LocationIpRule::Deny("10.0.0.0/8".parse::<IpNet>().expect("allowlist parse")),
        LocationIpRule::Allow(
            "10.0.0.1/32"
                .parse::<IpNet>()
                .expect("10.0.0.1/32 is valid"),
        ),
    ];
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    assert!(!location_allows_client(&rules, Some(ip)));
}

#[test]
fn location_access_rules_without_client_ip_is_denied_if_restricted() {
    let rules = vec![LocationIpRule::AllowAll];
    assert!(!location_allows_client(&rules, None));
}

#[tokio::test]
async fn response_filter_uses_final_plugin_status_for_cacheability() {
    let proxy = DynamicProxy::from_router(CompiledRouter::default());
    let mut session = test_session().await;
    let cache_cfg = CacheConfig {
        valid_statuses: vec![302],
        ..CacheConfig::default()
    };
    let plugins: ngxora_plugin_api::PluginChain = vec![Arc::new(StatusRewritePlugin {
        status: StatusCode::FOUND,
    }) as Arc<dyn HttpPlugin>]
    .into();
    let mut ctx = ProxyContext {
        selected: Some(cached_route(cache_cfg.clone(), plugins)),
        cache_key: Some(CacheKey {
            generation: 1,
            route_id: 1,
            host: "localhost".into(),
            method: "GET".into(),
            uri: "/".into(),
        }),
        ..Default::default()
    };
    let mut upstream_response =
        ResponseHeader::build(StatusCode::OK, None).expect("build response");

    ProxyHttp::response_filter(&proxy, &mut session, &mut upstream_response, &mut ctx)
        .await
        .expect("response filter succeeds");

    assert_eq!(upstream_response.status, StatusCode::FOUND);
    assert_eq!(ctx.cache_status, Some(StatusCode::FOUND));
    assert!(ctx.cache_headers.is_some());
}

#[tokio::test]
async fn logging_skips_cache_write_after_error() {
    let cache_backend = CacheBackend::new(10 * 1024 * 1024);
    let proxy = DynamicProxy::new_with_cache(
        Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
        cache_backend,
    );
    let mut session = test_session().await;
    let cache_cfg = CacheConfig::default();
    let key = CacheKey {
        generation: 1,
        route_id: 1,
        host: "localhost".into(),
        method: "GET".into(),
        uri: "/partial".into(),
    };
    let mut ctx = ProxyContext {
        selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
        cache_key: Some(key.clone()),
        cache_status: Some(StatusCode::OK),
        cache_headers: Some(http::HeaderMap::new()),
        response_body_buf: BytesMut::from(&b"partial"[..]),
        ..Default::default()
    };
    let err = pingora::Error::explain(pingora::ErrorType::InternalError, "boom");

    ProxyHttp::logging(&proxy, &mut session, Some(err.as_ref()), &mut ctx).await;

    assert!(proxy.cache_backend.get(&key, &cache_cfg).await.is_none());
    assert_eq!(proxy.cache_backend.total_entries(), 0);
    assert!(ctx.response_body_buf.is_empty());
}

#[tokio::test]
async fn logging_caches_empty_cacheable_response() {
    let cache_backend = CacheBackend::new(10 * 1024 * 1024);
    let proxy = DynamicProxy::new_with_cache(
        Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
        cache_backend,
    );
    let mut session = test_session().await;
    let cache_cfg = CacheConfig {
        valid_statuses: vec![301],
        ..CacheConfig::default()
    };
    let key = CacheKey {
        generation: 1,
        route_id: 1,
        host: "localhost".into(),
        method: "GET".into(),
        uri: "/redirect".into(),
    };
    let mut ctx = ProxyContext {
        selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
        cache_key: Some(key.clone()),
        ..Default::default()
    };
    let mut upstream_response =
        ResponseHeader::build(StatusCode::MOVED_PERMANENTLY, None).expect("build response");

    ProxyHttp::response_filter(&proxy, &mut session, &mut upstream_response, &mut ctx)
        .await
        .expect("response filter succeeds");
    ProxyHttp::logging(&proxy, &mut session, None, &mut ctx).await;

    let cached = proxy
        .cache_backend
        .get(&key, &cache_cfg)
        .await
        .expect("empty redirect should be cached");
    assert_eq!(cached.status, StatusCode::MOVED_PERMANENTLY);
    assert!(cached.body.is_empty());
}

#[tokio::test]
async fn logging_skips_cache_write_until_min_uses_is_reached() {
    let cache_backend = CacheBackend::new(10 * 1024 * 1024);
    let proxy = DynamicProxy::new_with_cache(
        Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
        cache_backend,
    );
    let mut session = test_session().await;
    let cache_cfg = CacheConfig {
        min_uses: Some(2),
        ..CacheConfig::default()
    };
    let key = CacheKey {
        generation: 1,
        route_id: 1,
        host: "localhost".into(),
        method: "GET".into(),
        uri: "/warming".into(),
    };

    let mut first_ctx = ProxyContext {
        selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
        cache_key: Some(key.clone()),
        cache_store_allowed: false,
        cache_status: Some(StatusCode::OK),
        cache_headers: Some(http::HeaderMap::new()),
        response_body_buf: BytesMut::from(&b"first"[..]),
        ..Default::default()
    };

    ProxyHttp::logging(&proxy, &mut session, None, &mut first_ctx).await;
    assert!(proxy.cache_backend.get(&key, &cache_cfg).await.is_none());

    let mut second_ctx = ProxyContext {
        selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
        cache_key: Some(key.clone()),
        cache_store_allowed: true,
        cache_status: Some(StatusCode::OK),
        cache_headers: Some(http::HeaderMap::new()),
        response_body_buf: BytesMut::from(&b"second"[..]),
        ..Default::default()
    };

    ProxyHttp::logging(&proxy, &mut session, None, &mut second_ctx).await;

    let cached = proxy
        .cache_backend
        .get(&key, &cache_cfg)
        .await
        .expect("response should be cached after min_uses is reached");
    assert_eq!(cached.body, Bytes::from_static(b"second"));
}

#[test]
fn span_status_ignores_http_4xx_error_responses() {
    let err = pingora::Error::explain(pingora::ErrorType::HTTPStatus(404), "not found");
    assert!(!should_mark_span_as_error(Some(err.as_ref()), 404));
}

#[test]
fn span_status_marks_http_5xx_responses_as_errors() {
    let err = pingora::Error::explain(pingora::ErrorType::HTTPStatus(503), "unavailable");
    assert!(should_mark_span_as_error(Some(err.as_ref()), 503));
    assert!(should_mark_span_as_error(None, 502));
}

#[test]
fn span_status_marks_non_http_errors_as_failures() {
    let err = pingora::Error::explain(pingora::ErrorType::InternalError, "boom");
    assert!(should_mark_span_as_error(Some(err.as_ref()), 0));
}

#[test]
fn peer_preparation_isolates_pools_and_rejects_unsupported_ip_verification() {
    use pingora::upstreams::peer::Peer;
    let mut route = cached_route(
        CacheConfig::default(),
        ngxora_plugin_api::empty_plugin_chain(),
    );
    let mut a = HttpPeer::new(("127.0.0.1", 443), true, "backend.example".into());
    route.configure_peer(&mut a, 1, None).unwrap();
    let mut b = a.clone();
    route.configure_peer(&mut b, 2, None).unwrap();
    assert_ne!(a.reuse_hash(), b.reuse_hash());
    route.route_id += 1;
    route.configure_peer(&mut b, 1, None).unwrap();
    assert_ne!(a.reuse_hash(), b.reuse_hash());
    for name in ["", "127.0.0.1", "::1"] {
        let mut peer = HttpPeer::new(("127.0.0.1", 443), true, name.into());
        assert!(route.configure_peer(&mut peer, 1, None).is_err());
        route.upstream_ssl_options.verify_cert = ngxora_compile::ir::Switch::Off;
        assert!(route.configure_peer(&mut peer, 1, None).is_ok());
        route.upstream_ssl_options.verify_cert = ngxora_compile::ir::Switch::On;
    }
}

#[tokio::test]
async fn proxy_retry_policy_preserves_idempotency() {
    let proxy = DynamicProxy::from_router(CompiledRouter::default());
    let peer = HttpPeer::new(("127.0.0.1", 8080), false, String::new());
    for (method, reused, expected) in [
        (http::Method::GET, true, true),
        (http::Method::GET, false, false),
        (http::Method::POST, true, false),
        (http::Method::PATCH, true, false),
    ] {
        let mut session = test_session().await;
        session.req_header_mut().set_method(method);
        let mut ctx = ProxyContext::default();
        let mut error = pingora::Error::new(pingora::ErrorType::ConnectionClosed);
        error.retry = pingora::RetryType::ReusedOnly;
        let error = proxy.error_while_proxy(&peer, &mut session, error, &mut ctx, reused);
        assert_eq!(error.retry.retry(), expected);
    }
}

#[tokio::test]
async fn upstream_filter_injects_trace_context_through_pingora_header_api() {
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };
    crate::tracing::configure("http://127.0.0.1:4317", "ngxora-test");
    let span = SpanContext::new(
        TraceId::from_hex("1234567890abcdef1234567890abcdef").unwrap(),
        SpanId::from_hex("1234567890abcdef").unwrap(),
        TraceFlags::SAMPLED,
        false,
        TraceState::default(),
    );
    let proxy = DynamicProxy::from_router(CompiledRouter::default());
    let mut session = test_session().await;
    let mut ctx = ProxyContext {
        selected: Some(cached_route(CacheConfig::default(), empty_plugin_chain())),
        upstream_trace_ctx: opentelemetry::Context::new().with_remote_span_context(span),
        ..Default::default()
    };
    let mut request = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
    request.insert_header("X-Custom", "preserved").unwrap();
    request.insert_header("traceparent", "old").unwrap();
    proxy
        .upstream_request_filter(&mut session, &mut request, &mut ctx)
        .await
        .unwrap();
    assert_eq!(
        request.headers["traceparent"],
        "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
    );
    assert_eq!(request.headers["x-custom"], "preserved");
}
