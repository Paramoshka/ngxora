use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, StatusCode};
use ngxora_compile::ir::CacheConfig;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cache key derived from request properties, governed by `CacheKeyMode`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub route_id: u64,
    pub method: String,
    pub uri: String,
}

/// A stored response ready to be served from cache.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub created_at: Instant,
}

impl CachedResponse {
    fn estimated_size(&self) -> u64 {
        // Body length + ~512 bytes for headers overhead
        self.body.len() as u64 + 512
    }
}

/// Per-location cache store, protected by an `RwLock`.
///
/// Contention is minimal because each location has its own lock, and
/// `CacheBackend` uses `DashMap` to shard access across locations.
struct LocationCache {
    ttl: Duration,
    max_size: u64,
    current_size: u64,
    entries: HashMap<CacheKey, CachedResponse>,
}

impl LocationCache {
    fn new(ttl: Duration, max_size: u64) -> Self {
        Self {
            ttl,
            max_size,
            current_size: 0,
            entries: HashMap::new(),
        }
    }

    fn is_fresh(entry: &CachedResponse, ttl: Duration) -> bool {
        entry.created_at.elapsed() < ttl
    }

    fn get(&self, key: &CacheKey, ttl: Duration) -> Option<&CachedResponse> {
        let entry = self.entries.get(key)?;
        if !Self::is_fresh(entry, ttl) {
            return None;
        }
        Some(entry)
    }

    fn get_stale(
        &self,
        key: &CacheKey,
        ttl: Duration,
        stale_if_error: Duration,
    ) -> Option<&CachedResponse> {
        let entry = self.entries.get(key)?;
        let max_stale_age = ttl.saturating_add(stale_if_error);
        if entry.created_at.elapsed() >= max_stale_age {
            return None;
        }
        Some(entry)
    }

    fn sync_limits(&mut self, ttl: Duration, max_size: u64) {
        self.ttl = ttl;
        self.max_size = max_size;
        self.evict_until_within_limit();
    }

    fn evict_until_within_limit(&mut self) {
        while self.current_size > self.max_size && !self.entries.is_empty() {
            let Some(key) = self.entries.keys().next().cloned() else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&key) {
                self.current_size = self.current_size.saturating_sub(evicted.estimated_size());
            }
        }
    }

    fn put(&mut self, key: CacheKey, response: CachedResponse) {
        let entry_size = response.estimated_size();

        // Remove old entry for the same key first
        if let Some(old) = self.entries.remove(&key) {
            self.current_size = self.current_size.saturating_sub(old.estimated_size());
        }

        if entry_size > self.max_size {
            return;
        }

        // Evict oldest entries while over capacity (simple FIFO-like eviction)
        while self.current_size + entry_size > self.max_size && !self.entries.is_empty() {
            // Take an arbitrary key (HashMap iteration order is not guaranteed
            // FIFO, but it is deterministic and cheap)
            if let Some(stale_key) = self.entries.keys().next().cloned() {
                if let Some(evicted) = self.entries.remove(&stale_key) {
                    self.current_size = self.current_size.saturating_sub(evicted.estimated_size());
                }
            }
        }

        self.current_size += entry_size;
        self.entries.insert(key, response);
    }

    fn evict_stale(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_key, entry| {
            if !Self::is_fresh(entry, ttl) {
                self.current_size = self.current_size.saturating_sub(entry.estimated_size());
                false
            } else {
                true
            }
        });
    }
}

/// Global cache backend with sharded per-location stores.
///
/// `DashMap` provides concurrent access across locations without a global lock.
/// Each location's `LocationCache` is behind its own `RwLock`, so writes to
/// one location never block reads from another.
pub struct CacheBackend {
    stores: DashMap<u64, RwLock<LocationCache>>,
    request_counts: DashMap<CacheKey, u64>,
    default_max_size: AtomicU64,
}

impl CacheBackend {
    /// Create a new cache backend with a default per-location max size.
    pub fn new(default_max_size: u64) -> Self {
        Self {
            stores: DashMap::new(),
            request_counts: DashMap::new(),
            default_max_size: AtomicU64::new(default_max_size),
        }
    }

    /// Update the fallback max size used when a location doesn't specify its
    /// own `proxy_cache_max_size`. Safe to call at any time.
    pub fn set_default_max_size(&self, size: u64) {
        self.default_max_size.store(size, Ordering::Relaxed);
    }

    /// Look up a cached response for the given key and config.
    ///
    /// Returns `None` if the cache is disabled, the entry is missing, or the
    /// entry has expired.
    pub async fn get(&self, key: &CacheKey, cfg: &CacheConfig) -> Option<CachedResponse> {
        if !cfg.enabled {
            return None;
        }

        let ttl = cfg.ttl.unwrap_or(Duration::from_secs(60));
        let store = self.stores.get(&key.route_id)?;
        let guard = store.read().await;
        guard.get(key, ttl).cloned()
    }

    /// Record a cache miss and decide whether the next cacheable upstream
    /// response is allowed to be stored for this key.
    pub fn record_miss(&self, key: &CacheKey, cfg: &CacheConfig) -> bool {
        if !cfg.enabled {
            return false;
        }

        let Some(min_uses) = cfg.min_uses else {
            return true;
        };
        if min_uses <= 1 {
            return true;
        }

        let mut count = self.request_counts.entry(key.clone()).or_insert(0);
        *count = count.saturating_add(1);
        usize::try_from(*count).unwrap_or(usize::MAX) >= min_uses
    }

    /// Look up a cached response **ignoring TTL** — used for stale-if-error.
    ///
    /// Returns any entry regardless of age, as long as the cache is enabled.
    pub async fn get_stale(&self, key: &CacheKey, cfg: &CacheConfig) -> Option<CachedResponse> {
        if !cfg.enabled {
            return None;
        }

        let ttl = cfg.ttl.unwrap_or(Duration::from_secs(60));
        let stale_if_error = cfg.stale_if_error?;
        let store = self.stores.get(&key.route_id)?;
        let guard = store.read().await;
        guard.get_stale(key, ttl, stale_if_error).cloned()
    }

    /// Store a response in the cache for the given key and config.
    ///
    /// If the location doesn't have a cache yet, one is created with the
    /// configured TTL and max size.
    pub async fn put(&self, key: CacheKey, response: CachedResponse, cfg: &CacheConfig) {
        if !cfg.enabled {
            return;
        }

        let ttl = cfg.ttl.unwrap_or(Duration::from_secs(60));
        let max_size = cfg
            .max_size
            .unwrap_or(self.default_max_size.load(Ordering::Relaxed));

        // Get or create the per-location store. `DashMap::entry` locks only
        // the shard containing this route_id.
        let store = self
            .stores
            .entry(key.route_id)
            .or_insert_with(|| RwLock::new(LocationCache::new(ttl, max_size)));

        let mut guard = store.write().await;
        guard.sync_limits(ttl, max_size);
        self.request_counts.remove(&key);
        guard.put(key, response);
    }

    /// Evict stale entries across all locations without blocking reads for
    /// longer than a single location lock.
    pub async fn evict_stale(&self) {
        for entry in self.stores.iter() {
            entry.value().write().await.evict_stale();
        }
    }

    /// Invalidate all cache entries for a specific route.
    pub fn invalidate_route(&self, route_id: u64) {
        self.stores.remove(&route_id);

        let keys: Vec<CacheKey> = self
            .request_counts
            .iter()
            .filter(|entry| entry.key().route_id == route_id)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            self.request_counts.remove(&key);
        }
    }

    /// Return the total number of cached entries across all locations.
    pub fn total_entries(&self) -> usize {
        let mut total = 0;
        for entry in self.stores.iter() {
            // We use try_read to avoid blocking. During a write of a tiny
            // location this will succeed near-instantly.
            if let Ok(guard) = entry.value().try_read() {
                total += guard.entries.len();
            }
        }
        total
    }
}

/// Build a cache key from request properties according to the configured mode.
pub fn build_cache_key(
    method: &http::Method,
    uri: &str,
    route_id: u64,
    cfg: &CacheConfig,
) -> CacheKey {
    let uri_key = match cfg.cache_key {
        ngxora_compile::ir::CacheKeyMode::Uri => uri.to_string(),
        ngxora_compile::ir::CacheKeyMode::UriAndMethod => {
            format!("{} {}", method.as_str(), uri)
        }
        ngxora_compile::ir::CacheKeyMode::NormalizedUri => normalize_uri(uri),
    };

    CacheKey {
        route_id,
        method: method.as_str().to_string(),
        uri: uri_key,
    }
}

/// Normalize a URI by sorting query parameters for stable cache keys.
fn normalize_uri(uri: &str) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };

    let mut params: Vec<(&str, &str)> = query
        .split('&')
        .filter_map(|param| param.split_once('='))
        .collect();
    params.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    let sorted: String = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    format!("{path}?{sorted}")
}

/// Check if a response should be cached based on its status and headers.
pub fn is_cacheable(status: StatusCode, headers: &HeaderMap, cfg: &CacheConfig) -> bool {
    if !cfg.valid_statuses.contains(&status.as_u16()) {
        return false;
    }

    if let Some(cache_control) = headers.get(http::header::CACHE_CONTROL) {
        if let Ok(value) = cache_control.to_str() {
            let lower = value.to_lowercase();
            if lower.contains("no-store") || lower.contains("private") {
                return false;
            }
        }
    }

    if headers.contains_key(http::header::SET_COOKIE) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn normalize_uri_sorts_query_params() {
        let result = normalize_uri("/search?b=2&a=1&c=3");
        assert_eq!(result, "/search?a=1&b=2&c=3");
    }

    #[test]
    fn normalize_uri_handles_no_query() {
        let result = normalize_uri("/plain/path");
        assert_eq!(result, "/plain/path");
    }

    #[test]
    fn build_cache_key_uri_mode() {
        let cfg = CacheConfig::default();
        let key = build_cache_key(&http::Method::GET, "/api/users?page=1", 42, &cfg);
        assert_eq!(key.route_id, 42);
        assert_eq!(key.uri, "/api/users?page=1");
    }

    #[test]
    fn build_cache_key_uri_and_method_mode() {
        let mut cfg = CacheConfig::default();
        cfg.cache_key = ngxora_compile::ir::CacheKeyMode::UriAndMethod;
        let key = build_cache_key(&http::Method::POST, "/api/users", 99, &cfg);
        assert_eq!(key.uri, "POST /api/users");
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
            route_id: 1,
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
            route_id: 3,
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
            route_id: 2,
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
            route_id: 1,
            method: "GET".into(),
            uri: "/a".into(),
        };
        let key_b = CacheKey {
            route_id: 2,
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
    async fn cache_backend_stale_if_error_respects_window() {
        let backend = CacheBackend::new(10 * 1024 * 1024);
        let cfg = CacheConfig {
            ttl: Some(Duration::from_secs(60)),
            stale_if_error: Some(Duration::from_secs(30)),
            ..CacheConfig::default()
        };
        let key = CacheKey {
            route_id: 3,
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
            route_id: 4,
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
}
