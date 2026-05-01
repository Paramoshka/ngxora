use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use ngxora_compile::ir::CacheConfig;
use std::collections::HashMap;
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

/// Per-location cache store.
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

    fn get(&self, key: &CacheKey) -> Option<&CachedResponse> {
        let entry = self.entries.get(key)?;
        if entry.created_at.elapsed() >= self.ttl {
            return None;
        }
        Some(entry)
    }

    fn put(&mut self, key: CacheKey, response: CachedResponse) {
        let entry_size = response.body.len() as u64 + 512;

        if let Some(old) = self.entries.remove(&key) {
            self.current_size = self
                .current_size
                .saturating_sub(old.body.len() as u64 + 512);
        }

        while self.current_size + entry_size > self.max_size && !self.entries.is_empty() {
            if let Some(stale_key) = self.entries.keys().next().cloned() {
                if let Some(evicted) = self.entries.remove(&stale_key) {
                    self.current_size = self
                        .current_size
                        .saturating_sub(evicted.body.len() as u64 + 512);
                }
            }
        }

        self.current_size += entry_size;
        self.entries.insert(key, response);
    }

    fn evict_stale(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_key, entry| {
            if entry.created_at.elapsed() >= ttl {
                self.current_size = self
                    .current_size
                    .saturating_sub(entry.body.len() as u64 + 512);
                false
            } else {
                true
            }
        });
    }
}

/// Global cache backend shared across all locations.
/// Each location gets its own isolated `LocationCache` based on `route_id`.
pub struct CacheBackend {
    stores: RwLock<HashMap<u64, LocationCache>>,
    default_max_size: u64,
}

impl CacheBackend {
    /// Create a new cache backend with a default per-location max size.
    pub fn new(default_max_size: u64) -> Self {
        Self {
            stores: RwLock::new(HashMap::new()),
            default_max_size,
        }
    }

    /// Look up a cached response for the given key and config.
    pub async fn get(&self, key: &CacheKey, cfg: &CacheConfig) -> Option<CachedResponse> {
        if !cfg.enabled {
            return None;
        }
        let stores = self.stores.read().await;
        let store = stores.get(&key.route_id)?;
        store.get(key).cloned()
    }

    /// Store a response in the cache for the given key and config.
    pub async fn put(&self, key: CacheKey, response: CachedResponse, cfg: &CacheConfig) {
        if !cfg.enabled {
            return;
        }
        let ttl = cfg.ttl.unwrap_or(Duration::from_secs(60));
        let max_size = cfg.max_size.unwrap_or(self.default_max_size);
        let route_id = key.route_id;

        let mut stores = self.stores.write().await;
        let store = stores
            .entry(route_id)
            .or_insert_with(|| LocationCache::new(ttl, max_size));
        store.put(key, response);
    }

    /// Evict stale entries across all locations.
    pub async fn evict_stale(&self) {
        let mut stores = self.stores.write().await;
        for store in stores.values_mut() {
            store.evict_stale();
        }
    }

    /// Invalidate all cache entries for a specific route.
    pub async fn invalidate_route(&self, route_id: u64) {
        self.stores.write().await.remove(&route_id);
    }

    /// Return the total number of cached entries across all locations.
    pub async fn total_entries(&self) -> usize {
        self.stores
            .read()
            .await
            .values()
            .map(|s| s.entries.len())
            .sum()
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
}
