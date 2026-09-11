use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use ngxora_compile::ir::CacheConfig;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Cache key derived from request properties, governed by `CacheKeyMode`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub generation: u64,
    pub route_id: u64,
    pub host: String,
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
    pub(crate) fn estimated_size(&self) -> u64 {
        (self.body.len() as u64)
            .saturating_add(estimated_headers_size(&self.headers))
            .saturating_add(128)
    }
}

pub(crate) fn estimated_headers_size(headers: &HeaderMap) -> u64 {
    headers.iter().fold(0_u64, |size, (name, value)| {
        size.saturating_add(name.as_str().len() as u64)
            .saturating_add(value.as_bytes().len() as u64)
    })
}

struct MissCount {
    count: usize,
    last_seen: Instant,
}

struct LocationCache {
    ttl: Duration,
    retention: Duration,
    max_size: u64,
    current_size: u64,
    entries: HashMap<CacheKey, CachedResponse>,
    request_counts: HashMap<CacheKey, MissCount>,
    last_sweep: Instant,
}

impl CacheKey {
    pub(crate) fn estimated_size(&self) -> u64 {
        (self.host.len() as u64)
            .saturating_add(self.method.len() as u64)
            .saturating_add(self.uri.len() as u64)
            .saturating_add(128)
    }
}

impl LocationCache {
    fn new(cfg: &CacheConfig, max_size: u64) -> Self {
        let ttl = cfg.ttl.unwrap_or(Duration::from_secs(60));
        Self {
            ttl,
            retention: ttl.saturating_add(cfg.stale_if_error.unwrap_or_default()),
            max_size,
            current_size: 0,
            entries: HashMap::new(),
            request_counts: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    fn sync_limits(&mut self, cfg: &CacheConfig, max_size: u64) {
        self.ttl = cfg.ttl.unwrap_or(Duration::from_secs(60));
        self.retention = self
            .ttl
            .saturating_add(cfg.stale_if_error.unwrap_or_default());
        self.max_size = max_size;
        if self.last_sweep.elapsed() >= Duration::from_secs(1) {
            self.evict_stale();
        }
        self.make_room(0);
    }

    fn remove_response(&mut self, key: &CacheKey) {
        if let Some(value) = self.entries.remove(key) {
            self.current_size -= key.estimated_size().saturating_add(value.estimated_size());
        }
    }

    fn remove_count(&mut self, key: &CacheKey) {
        if self.request_counts.remove(key).is_some() {
            self.current_size -= key.estimated_size().saturating_add(64);
        }
    }

    fn make_room(&mut self, size: u64) -> bool {
        if size > self.max_size {
            return false;
        }
        while self.current_size > self.max_size - size {
            // Counts are expendable: dropping one only delays cache admission.
            if let Some(key) = self.request_counts.keys().next().cloned() {
                self.remove_count(&key);
            } else if let Some(key) = self.entries.keys().next().cloned() {
                self.remove_response(&key);
            } else {
                break;
            }
        }
        true
    }

    fn record_miss(&mut self, key: &CacheKey, min_uses: usize) -> bool {
        if min_uses <= 1 {
            return true;
        }
        if let Some(value) = self.request_counts.get_mut(key) {
            if value.last_seen.elapsed() >= self.ttl {
                value.count = 0;
            }
            value.count = value.count.saturating_add(1);
            value.last_seen = Instant::now();
            return value.count >= min_uses;
        }
        let size = key.estimated_size().saturating_add(64);
        if !self.make_room(size) {
            return false;
        }
        self.request_counts.insert(
            key.clone(),
            MissCount {
                count: 1,
                last_seen: Instant::now(),
            },
        );
        self.current_size += size;
        false
    }

    fn put(&mut self, key: CacheKey, response: CachedResponse) {
        self.remove_count(&key);
        self.remove_response(&key);
        let size = key
            .estimated_size()
            .saturating_add(response.estimated_size());
        if self.make_room(size) {
            self.current_size += size;
            self.entries.insert(key, response);
        }
    }

    fn evict_stale(&mut self) {
        self.entries.retain(|key, entry| {
            if entry.created_at.elapsed() >= self.retention {
                self.current_size -= key.estimated_size().saturating_add(entry.estimated_size());
                false
            } else {
                true
            }
        });
        self.request_counts.retain(|key, entry| {
            if entry.last_seen.elapsed() >= self.ttl {
                self.current_size -= key.estimated_size().saturating_add(64);
                false
            } else {
                true
            }
        });
        self.entries.shrink_to_fit();
        self.request_counts.shrink_to_fit();
        self.last_sweep = Instant::now();
    }
}

#[derive(Default)]
struct CacheStores {
    generation: u64,
    locations: HashMap<u64, Arc<Mutex<LocationCache>>>,
}

/// Each location accounts for response data, keys, and admission counters.
/// Async public methods retain their API; no lock is held across an await.
pub struct CacheBackend {
    stores: RwLock<CacheStores>,
    default_max_size: AtomicU64,
}

impl CacheBackend {
    pub fn new(default_max_size: u64) -> Self {
        Self {
            stores: RwLock::new(CacheStores::default()),
            default_max_size: AtomicU64::new(default_max_size),
        }
    }

    pub fn set_default_max_size(&self, size: u64) {
        self.default_max_size.store(size, Ordering::Relaxed);
    }

    pub fn max_size(&self, cfg: &CacheConfig) -> u64 {
        cfg.max_size
            .unwrap_or(self.default_max_size.load(Ordering::Relaxed))
    }

    /// Retire all previous routes together. Old in-flight writes cannot recreate them.
    pub(crate) fn advance_generation(&self, generation: u64) {
        let stores = self.stores.read().expect("cache stores lock poisoned");
        if generation <= stores.generation {
            return;
        }
        drop(stores);
        let mut stores = self.stores.write().expect("cache stores lock poisoned");
        if generation > stores.generation {
            stores.locations.clear();
            stores.locations.shrink_to_fit();
            stores.generation = generation;
        }
    }

    fn store(
        &self,
        key: &CacheKey,
        cfg: &CacheConfig,
        create: bool,
    ) -> Option<Arc<Mutex<LocationCache>>> {
        if !cfg.enabled {
            return None;
        }
        let stores = self.stores.read().expect("cache stores lock poisoned");
        if key.generation < stores.generation {
            return None;
        }
        if let Some(store) = stores.locations.get(&key.route_id) {
            return Some(store.clone());
        }
        if !create {
            return None;
        }
        drop(stores);
        let mut stores = self.stores.write().expect("cache stores lock poisoned");
        if key.generation < stores.generation {
            return None;
        }
        Some(
            stores
                .locations
                .entry(key.route_id)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(LocationCache::new(cfg, self.max_size(cfg))))
                })
                .clone(),
        )
    }

    pub async fn get(&self, key: &CacheKey, cfg: &CacheConfig) -> Option<CachedResponse> {
        let store = self.store(key, cfg, false)?;
        let guard = store.lock().expect("location cache lock poisoned");
        let response = guard.entries.get(key)?;
        (response.created_at.elapsed() < cfg.ttl.unwrap_or(Duration::from_secs(60)))
            .then(|| response.clone())
    }

    pub fn record_miss(&self, key: &CacheKey, cfg: &CacheConfig) -> bool {
        let Some(store) = self.store(key, cfg, true) else {
            return false;
        };
        let mut guard = store.lock().expect("location cache lock poisoned");
        guard.sync_limits(cfg, self.max_size(cfg));
        guard.record_miss(key, cfg.min_uses.unwrap_or(1))
    }

    pub async fn get_stale(&self, key: &CacheKey, cfg: &CacheConfig) -> Option<CachedResponse> {
        let retention = cfg
            .ttl
            .unwrap_or(Duration::from_secs(60))
            .saturating_add(cfg.stale_if_error?);
        let store = self.store(key, cfg, false)?;
        let guard = store.lock().expect("location cache lock poisoned");
        let response = guard.entries.get(key)?;
        (response.created_at.elapsed() < retention).then(|| response.clone())
    }

    pub async fn put(&self, key: CacheKey, response: CachedResponse, cfg: &CacheConfig) {
        let Some(store) = self.store(&key, cfg, true) else {
            return;
        };
        let mut guard = store.lock().expect("location cache lock poisoned");
        guard.sync_limits(cfg, self.max_size(cfg));
        guard.put(key, response);
    }

    pub async fn evict_stale(&self) {
        let stores = self.stores.read().expect("cache stores lock poisoned");
        for store in stores.locations.values() {
            store
                .lock()
                .expect("location cache lock poisoned")
                .evict_stale();
        }
    }

    pub fn invalidate_route(&self, route_id: u64) {
        self.stores
            .write()
            .expect("cache stores lock poisoned")
            .locations
            .remove(&route_id);
    }

    pub fn total_entries(&self) -> usize {
        self.stores
            .read()
            .expect("cache stores lock poisoned")
            .locations
            .values()
            .map(|store| {
                store
                    .lock()
                    .expect("location cache lock poisoned")
                    .entries
                    .len()
            })
            .sum()
    }
}

/// Build a cache key from request properties according to the configured mode.
pub fn build_cache_key(
    method: &http::Method,
    uri: &str,
    generation: u64,
    route_id: u64,
    host: &str,
    cfg: &CacheConfig,
) -> CacheKey {
    let uri_key = match cfg.cache_key {
        ngxora_compile::ir::CacheKeyMode::Uri | ngxora_compile::ir::CacheKeyMode::NormalizedUri => {
            uri.to_string()
        }
        ngxora_compile::ir::CacheKeyMode::UriAndMethod => {
            format!("{} {}", method.as_str(), uri)
        }
    };

    CacheKey {
        generation,
        route_id,
        host: host.to_ascii_lowercase(),
        method: method.as_str().to_string(),
        uri: uri_key,
    }
}

fn has_cache_control_directive(headers: &HeaderMap, directives: &[&str]) -> Result<bool, ()> {
    for value in headers.get_all(http::header::CACHE_CONTROL) {
        let value = value.to_str().map_err(|_| ())?;
        for directive in value.split(',') {
            let directive = directive.trim().to_ascii_lowercase();
            let (name, value) = directive
                .split_once('=')
                .map_or((directive.as_str(), None), |(name, value)| {
                    (name.trim(), Some(value.trim().trim_matches('"')))
                });
            if directives.contains(&name) || (name == "max-age" && value == Some("0")) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Check whether a request may use or populate the shared response cache.
pub fn is_cacheable_request(method: &http::Method, headers: &HeaderMap) -> bool {
    if method != http::Method::GET {
        return false;
    }

    const PRIVATE_REQUEST_HEADERS: [http::HeaderName; 9] = [
        http::header::AUTHORIZATION,
        http::header::COOKIE,
        http::header::RANGE,
        http::header::IF_MATCH,
        http::header::IF_NONE_MATCH,
        http::header::IF_MODIFIED_SINCE,
        http::header::IF_UNMODIFIED_SINCE,
        http::header::IF_RANGE,
        http::header::PROXY_AUTHORIZATION,
    ];
    if PRIVATE_REQUEST_HEADERS
        .iter()
        .any(|header| headers.contains_key(header))
    {
        return false;
    }

    match has_cache_control_directive(headers, &["no-cache", "no-store"]) {
        Ok(true) | Err(()) => return false,
        Ok(false) => {}
    }

    for value in headers.get_all(http::header::PRAGMA) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        if value
            .split(',')
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-cache"))
        {
            return false;
        }
    }

    true
}

/// Check if a response should be cached based on its status and headers.
pub fn is_cacheable(status: StatusCode, headers: &HeaderMap, cfg: &CacheConfig) -> bool {
    if !cfg.valid_statuses.contains(&status.as_u16()) {
        return false;
    }

    match has_cache_control_directive(headers, &["no-store", "private", "no-cache"]) {
        Ok(true) | Err(()) => return false,
        Ok(false) => {}
    }

    if headers.contains_key(http::header::SET_COOKIE) || headers.contains_key(http::header::VARY) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests;
