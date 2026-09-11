use super::*;
use http::HeaderValue;

#[test]
fn build_cache_key_uri_mode() {
    let cfg = CacheConfig::default();
    let key = build_cache_key(
        &http::Method::GET,
        "/api/users?page=1",
        7,
        42,
        "Example.COM",
        &cfg,
    );
    assert_eq!(key.generation, 7);
    assert_eq!(key.route_id, 42);
    assert_eq!(key.host, "example.com");
    assert_eq!(key.uri, "/api/users?page=1");
}

#[test]
fn build_cache_key_uri_and_method_mode() {
    let cfg = CacheConfig {
        cache_key: ngxora_compile::ir::CacheKeyMode::UriAndMethod,
        ..CacheConfig::default()
    };
    let key = build_cache_key(&http::Method::GET, "/api/users", 1, 99, "example.com", &cfg);
    assert_eq!(key.uri, "GET /api/users");
}

#[test]
fn normalized_uri_uses_exact_uri_to_avoid_collisions() {
    let cfg = CacheConfig {
        cache_key: ngxora_compile::ir::CacheKeyMode::NormalizedUri,
        ..CacheConfig::default()
    };
    let key = build_cache_key(
        &http::Method::GET,
        "/search?role=user&role=admin&debug",
        1,
        1,
        "example.com",
        &cfg,
    );
    assert_eq!(key.uri, "/search?role=user&role=admin&debug");
}

#[test]
fn is_cacheable_rejects_no_store() {
    let cfg = CacheConfig::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    assert!(!is_cacheable(StatusCode::OK, &headers, &cfg));
}

#[test]
fn is_cacheable_rejects_set_cookie() {
    let cfg = CacheConfig::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::SET_COOKIE,
        HeaderValue::from_static("session=abc"),
    );
    assert!(!is_cacheable(StatusCode::OK, &headers, &cfg));
}

#[test]
fn is_cacheable_rejects_vary_and_no_cache() {
    let cfg = CacheConfig::default();
    let mut headers = HeaderMap::new();
    headers.insert(http::header::VARY, HeaderValue::from_static("Origin"));
    assert!(!is_cacheable(StatusCode::OK, &headers, &cfg));

    headers.remove(http::header::VARY);
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    assert!(!is_cacheable(StatusCode::OK, &headers, &cfg));
}

#[test]
fn cacheable_request_is_get_without_private_or_revalidation_headers() {
    let mut headers = HeaderMap::new();
    assert!(is_cacheable_request(&http::Method::GET, &headers));
    assert!(!is_cacheable_request(&http::Method::POST, &headers));

    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer token"),
    );
    assert!(!is_cacheable_request(&http::Method::GET, &headers));

    headers.remove(http::header::AUTHORIZATION);
    headers.insert(
        http::header::COOKIE,
        HeaderValue::from_static("session=abc"),
    );
    assert!(!is_cacheable_request(&http::Method::GET, &headers));

    headers.remove(http::header::COOKIE);
    headers.insert(http::header::RANGE, HeaderValue::from_static("bytes=0-9"));
    assert!(!is_cacheable_request(&http::Method::GET, &headers));

    headers.remove(http::header::RANGE);
    headers.insert(
        http::header::IF_NONE_MATCH,
        HeaderValue::from_static("\"etag\""),
    );
    assert!(!is_cacheable_request(&http::Method::GET, &headers));
}

#[test]
fn cacheable_request_honors_client_bypass_directives() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=0"),
    );
    assert!(!is_cacheable_request(&http::Method::GET, &headers));

    headers.remove(http::header::CACHE_CONTROL);
    headers.insert(http::header::PRAGMA, HeaderValue::from_static("no-cache"));
    assert!(!is_cacheable_request(&http::Method::GET, &headers));
}

#[test]
fn is_cacheable_allows_cache_control_public() {
    let cfg = CacheConfig::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    assert!(is_cacheable(StatusCode::OK, &headers, &cfg));
}

#[tokio::test]
async fn cache_backend_put_and_get() {
    let backend = CacheBackend::new(10 * 1024 * 1024);
    let cfg = CacheConfig::default();
    let key = CacheKey {
        generation: 1,
        route_id: 1,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/test".into(),
    };

    let cached = CachedResponse {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"hello"),
        created_at: Instant::now(),
    };

    backend.put(key.clone(), cached.clone(), &cfg).await;

    let found = backend.get(&key, &cfg).await.expect("entry should exist");
    assert_eq!(found.body, Bytes::from_static(b"hello"));
}

#[test]
fn cache_backend_min_uses_requires_repeated_misses() {
    let backend = CacheBackend::new(10 * 1024 * 1024);
    let cfg = CacheConfig {
        min_uses: Some(2),
        ..CacheConfig::default()
    };
    let key = CacheKey {
        generation: 1,
        route_id: 3,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/gated".into(),
    };

    assert!(!backend.record_miss(&key, &cfg));
    assert!(backend.record_miss(&key, &cfg));
}

#[tokio::test]
async fn cache_backend_disabled_config_skips() {
    let backend = CacheBackend::new(10 * 1024 * 1024);
    let cfg = CacheConfig {
        enabled: false,
        ..CacheConfig::default()
    };
    let key = CacheKey {
        generation: 1,
        route_id: 2,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/nope".into(),
    };

    backend
        .put(
            key.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"nope"),
                created_at: Instant::now(),
            },
            &cfg,
        )
        .await;

    assert!(backend.get(&key, &cfg).await.is_none());
}

#[tokio::test]
async fn different_locations_are_isolated() {
    let backend = CacheBackend::new(10 * 1024 * 1024);
    let cfg = CacheConfig::default();

    let key_a = CacheKey {
        generation: 1,
        route_id: 1,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/a".into(),
    };
    let key_b = CacheKey {
        generation: 1,
        route_id: 2,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/b".into(),
    };

    backend
        .put(
            key_a.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"a"),
                created_at: Instant::now(),
            },
            &cfg,
        )
        .await;

    backend
        .put(
            key_b.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"b"),
                created_at: Instant::now(),
            },
            &cfg,
        )
        .await;

    assert_eq!(
        backend.get(&key_a, &cfg).await.unwrap().body,
        Bytes::from_static(b"a")
    );
    assert_eq!(
        backend.get(&key_b, &cfg).await.unwrap().body,
        Bytes::from_static(b"b")
    );
    assert_eq!(backend.total_entries(), 2);

    backend.invalidate_route(1);
    assert!(backend.get(&key_a, &cfg).await.is_none());
    assert!(backend.get(&key_b, &cfg).await.is_some());
    assert_eq!(backend.total_entries(), 1);
}

#[tokio::test]
async fn cache_entries_are_isolated_by_generation_and_host() {
    let backend = CacheBackend::new(10 * 1024 * 1024);
    let cfg = CacheConfig::default();
    let key = CacheKey {
        generation: 1,
        route_id: 1,
        host: "a.example".into(),
        method: "GET".into(),
        uri: "/account".into(),
    };
    backend
        .put(
            key.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"a"),
                created_at: Instant::now(),
            },
            &cfg,
        )
        .await;

    let mut other_generation = key.clone();
    other_generation.generation = 2;
    assert!(backend.get(&other_generation, &cfg).await.is_none());

    let mut other_host = key;
    other_host.host = "b.example".into();
    assert!(backend.get(&other_host, &cfg).await.is_none());
}

#[tokio::test]
async fn cache_backend_stale_if_error_respects_window() {
    let backend = CacheBackend::new(10 * 1024 * 1024);
    let cfg = CacheConfig {
        ttl: Some(Duration::from_secs(60)),
        stale_if_error: Some(Duration::from_secs(30)),
        ..CacheConfig::default()
    };
    let key = CacheKey {
        generation: 1,
        route_id: 3,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/stale".into(),
    };

    backend
        .put(
            key.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"stale"),
                created_at: Instant::now() - Duration::from_secs(70),
            },
            &cfg,
        )
        .await;

    assert!(backend.get(&key, &cfg).await.is_none());
    assert!(backend.get_stale(&key, &cfg).await.is_some());

    backend
        .put(
            key.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"expired"),
                created_at: Instant::now() - Duration::from_secs(91),
            },
            &cfg,
        )
        .await;

    assert!(backend.get_stale(&key, &cfg).await.is_none());
}

#[tokio::test]
async fn cache_backend_rejects_entries_larger_than_max_size() {
    let backend = CacheBackend::new(1024);
    let cfg = CacheConfig {
        max_size: Some(128),
        ..CacheConfig::default()
    };
    let key = CacheKey {
        generation: 1,
        route_id: 4,
        host: "example.com".into(),
        method: "GET".into(),
        uri: "/oversized".into(),
    };

    backend
        .put(
            key.clone(),
            CachedResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from(vec![b'x'; 1024]),
                created_at: Instant::now(),
            },
            &cfg,
        )
        .await;

    assert!(backend.get(&key, &cfg).await.is_none());
    assert_eq!(backend.total_entries(), 0);
}
#[test]
fn unique_misses_and_long_keys_share_the_location_budget() {
    let cfg = CacheConfig {
        min_uses: Some(2),
        ..CacheConfig::default()
    };
    let mut store = LocationCache::new(&cfg, 1024);
    for i in 0..10_000 {
        let key = build_cache_key(
            &http::Method::GET,
            &format!("/?id={i}"),
            1,
            1,
            "example.com",
            &cfg,
        );
        assert!(!store.record_miss(&key, 2));
        assert!(store.current_size <= 1024);
    }
    assert!(store.request_counts.len() < 10);
    let key = build_cache_key(
        &http::Method::GET,
        &"x".repeat(8000),
        1,
        1,
        "example.com",
        &cfg,
    );
    store.put(
        key,
        CachedResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            created_at: Instant::now(),
        },
    );
    assert!(store.entries.is_empty());
    let accounted: u64 = store
        .request_counts
        .keys()
        .map(|k| k.estimated_size() + 64)
        .sum();
    assert_eq!(accounted, store.current_size);
}

#[test]
fn cleanup_expires_counts_but_preserves_stale_responses() {
    let cfg = CacheConfig {
        ttl: Some(Duration::from_secs(60)),
        stale_if_error: Some(Duration::from_secs(30)),
        min_uses: Some(2),
        ..CacheConfig::default()
    };
    let mut store = LocationCache::new(&cfg, 4096);
    let key = build_cache_key(&http::Method::GET, "/", 1, 1, "example.com", &cfg);
    store.put(
        key.clone(),
        CachedResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            created_at: Instant::now() - Duration::from_secs(70),
        },
    );
    assert!(!store.record_miss(&key, 2));
    store.request_counts.get_mut(&key).unwrap().last_seen =
        Instant::now() - Duration::from_secs(61);
    store.evict_stale();
    assert!(store.request_counts.is_empty());
    assert!(store.entries.contains_key(&key));
    assert!(!store.record_miss(&key, 2));
    assert!(store.record_miss(&key, 2));
    store.entries.get_mut(&key).unwrap().created_at = Instant::now() - Duration::from_secs(91);
    store.evict_stale();
    assert!(store.entries.is_empty());
    store.sync_limits(&cfg, 1);
    assert_eq!(store.current_size, 0);
}

#[tokio::test]
async fn retired_generation_cannot_repopulate_deleted_routes() {
    let backend = CacheBackend::new(4096);
    let cfg = CacheConfig::default();
    let old = build_cache_key(&http::Method::GET, "/", 1, 1, "example.com", &cfg);
    let response = CachedResponse {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: Bytes::new(),
        created_at: Instant::now(),
    };
    backend.advance_generation(1);
    backend.put(old.clone(), response.clone(), &cfg).await;
    backend.advance_generation(2);
    backend.advance_generation(1);
    backend.put(old.clone(), response, &cfg).await;
    assert!(!backend.record_miss(&old, &cfg));
    assert!(backend.get(&old, &cfg).await.is_none());
    assert!(backend.stores.read().unwrap().locations.is_empty());
}
