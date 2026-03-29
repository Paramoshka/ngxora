use http::{HeaderValue, StatusCode, header};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec, RequestCtx,
    async_trait,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

const PLUGIN_NAME: &str = "rate-limit";
const BUCKET_TTL_SECS: u64 = 120;
const SWEEP_INTERVAL_REQUESTS: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPluginConfig {
    pub max_requests_per_second: isize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    window: u64,
    count: u32,
    last_seen: u64,
}

impl Bucket {
    fn new(window: u64) -> Self {
        Self {
            window,
            count: 0,
            last_seen: window,
        }
    }
}

pub struct RateLimitPlugin {
    max_requests_per_second: u32,
    started_at: Instant,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    requests_since_sweep: AtomicU64,
}

impl std::fmt::Debug for RateLimitPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPlugin")
            .field("max_requests_per_second", &self.max_requests_per_second)
            .finish()
    }
}

impl RateLimitPlugin {
    fn current_window(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    fn lock_buckets(&self) -> MutexGuard<'_, HashMap<IpAddr, Bucket>> {
        match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn maybe_sweep(&self, current_window: u64) {
        let requests = self.requests_since_sweep.fetch_add(1, Ordering::Relaxed) + 1;
        if requests % SWEEP_INTERVAL_REQUESTS != 0 {
            return;
        }

        let oldest_allowed_window = current_window.saturating_sub(BUCKET_TTL_SECS);
        let mut buckets = self.lock_buckets();
        buckets.retain(|_, bucket| bucket.last_seen >= oldest_allowed_window);
    }

    fn allow_request(&self, client_ip: IpAddr) -> bool {
        let current_window = self.current_window();
        let allowed = {
            let mut buckets = self.lock_buckets();
            let bucket = buckets
                .entry(client_ip)
                .or_insert_with(|| Bucket::new(current_window));
            if bucket.window != current_window {
                *bucket = Bucket::new(current_window);
            }
            bucket.last_seen = current_window;
            bucket.count = bucket.count.saturating_add(1);
            bucket.count <= self.max_requests_per_second
        };
        self.maybe_sweep(current_window);
        allowed
    }

    fn rate_limited_response(&self) -> PluginFlow {
        let mut response = LocalResponse::new(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests");
        response.headers.push((
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ));
        response
            .headers
            .push((header::RETRY_AFTER, HeaderValue::from_static("1")));
        response.headers.push((
            header::HeaderName::from_static("x-ratelimit-limit"),
            HeaderValue::from_str(&self.max_requests_per_second.to_string())
                .expect("numeric rate limit header value should be valid"),
        ));
        response.headers.push((
            header::HeaderName::from_static("x-ratelimit-remaining"),
            HeaderValue::from_static("0"),
        ));
        PluginFlow::Respond(response)
    }
}

#[async_trait]
impl HttpPlugin for RateLimitPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    async fn on_request(
        &self,
        ctx: &mut RequestCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        let Some(client_ip) = ctx.client_ip else {
            return Ok(PluginFlow::Continue);
        };

        if self.allow_request(client_ip) {
            Ok(PluginFlow::Continue)
        } else {
            Ok(self.rate_limited_response())
        }
    }
}

#[derive(Debug, Default)]
pub struct RateLimitPluginFactory;

impl PluginFactory for RateLimitPluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let config = serde_json::from_value::<RateLimitPluginConfig>(spec.config.clone()).map_err(
            |err| PluginBuildError::new(self.name(), format!("invalid plugin config: {err}")),
        )?;

        if config.max_requests_per_second <= 0 {
            return Err(PluginBuildError::new(
                self.name(),
                "max_requests_per_second must be positive",
            ));
        }

        let max_requests_per_second =
            u32::try_from(config.max_requests_per_second).map_err(|_| {
                PluginBuildError::new(
                    self.name(),
                    "max_requests_per_second exceeds supported range",
                )
            })?;

        Ok(Arc::new(RateLimitPlugin {
            max_requests_per_second,
            started_at: Instant::now(),
            buckets: Mutex::new(HashMap::new()),
            requests_since_sweep: AtomicU64::new(0),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitPlugin, RateLimitPluginFactory};
    use futures::executor::block_on;
    use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
    use ngxora_plugin_api::{
        HeaderMapMut, HttpPlugin, PluginFactory, PluginFlow, PluginSpec, PluginState, RequestCtx,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, Instant};

    struct FakeHeaders {
        inner: HeaderMap,
    }

    impl Default for FakeHeaders {
        fn default() -> Self {
            Self {
                inner: HeaderMap::new(),
            }
        }
    }

    impl HeaderMapMut for FakeHeaders {
        fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
            self.inner.get(name)
        }

        fn add(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.inner.append(name, value);
            Ok(())
        }

        fn set(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.inner.insert(name, value);
            Ok(())
        }

        fn remove(&mut self, name: &HeaderName) {
            self.inner.remove(name);
        }
    }

    fn test_plugin(limit: u32) -> RateLimitPlugin {
        RateLimitPlugin {
            max_requests_per_second: limit,
            started_at: Instant::now(),
            buckets: Mutex::new(HashMap::new()),
            requests_since_sweep: AtomicU64::new(0),
        }
    }

    fn run_request(plugin: &RateLimitPlugin, client_ip: Option<IpAddr>) -> PluginFlow {
        let method = Method::GET;
        let mut state = PluginState {
            extensions: Extensions::new(),
        };
        let mut headers = FakeHeaders::default();

        block_on(plugin.on_request(&mut RequestCtx {
            state: &mut state,
            path: "/",
            host: Some("example.com"),
            method: &method,
            client_ip,
            headers: &mut headers,
        }))
        .expect("request hook should succeed")
    }

    #[test]
    fn factory_builds_valid_config() {
        let spec = PluginSpec {
            name: "rate-limit".into(),
            config: json!({ "max_requests_per_second": 10 }),
        };
        let plugin = RateLimitPluginFactory
            .build(&spec)
            .expect("build should succeed");
        assert_eq!(plugin.name(), "rate-limit");
    }

    #[test]
    fn factory_rejects_invalid_config_negative_rate() {
        let spec = PluginSpec {
            name: "rate-limit".into(),
            config: json!({ "max_requests_per_second": -5 }),
        };
        let result = RateLimitPluginFactory.build(&spec);
        match result {
            Ok(_) => panic!("expected build to fail"),
            Err(e) => assert!(e.message.contains("must be positive")),
        }
    }

    #[test]
    fn factory_rejects_invalid_config_zero_rate() {
        let spec = PluginSpec {
            name: "rate-limit".into(),
            config: json!({ "max_requests_per_second": 0 }),
        };
        let result = RateLimitPluginFactory.build(&spec);
        assert!(result.is_err());
    }

    #[test]
    fn request_without_client_ip_fails_open() {
        let plugin = test_plugin(1);

        assert!(matches!(run_request(&plugin, None), PluginFlow::Continue));
        assert!(matches!(run_request(&plugin, None), PluginFlow::Continue));
        assert!(matches!(run_request(&plugin, None), PluginFlow::Continue));
    }

    #[test]
    fn rate_limit_rejects_requests_beyond_current_window_budget() {
        let plugin = test_plugin(2);
        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        assert!(matches!(
            run_request(&plugin, Some(client_ip)),
            PluginFlow::Continue
        ));
        assert!(matches!(
            run_request(&plugin, Some(client_ip)),
            PluginFlow::Continue
        ));

        let flow = run_request(&plugin, Some(client_ip));
        match flow {
            PluginFlow::Respond(response) => {
                assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(response.body.as_ref(), b"Too Many Requests");
                assert_eq!(
                    response
                        .headers
                        .iter()
                        .find(|(name, _)| name == &header::RETRY_AFTER)
                        .map(|(_, value)| value),
                    Some(&HeaderValue::from_static("1"))
                );
                assert_eq!(
                    response
                        .headers
                        .iter()
                        .find(|(name, _)| name
                            == &header::HeaderName::from_static("x-ratelimit-limit"))
                        .map(|(_, value)| value),
                    Some(&HeaderValue::from_static("2"))
                );
            }
            PluginFlow::Continue => panic!("third request in the same window should be rejected"),
        }
    }

    #[test]
    fn rate_limit_resets_after_window_rollover() {
        let plugin = test_plugin(1);
        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));

        assert!(matches!(
            run_request(&plugin, Some(client_ip)),
            PluginFlow::Continue
        ));
        assert!(matches!(
            run_request(&plugin, Some(client_ip)),
            PluginFlow::Respond(_)
        ));

        std::thread::sleep(Duration::from_millis(1100));

        assert!(matches!(
            run_request(&plugin, Some(client_ip)),
            PluginFlow::Continue
        ));
    }

    #[test]
    fn different_client_ips_have_independent_buckets() {
        let plugin = test_plugin(1);
        let client_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));
        let client_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));

        assert!(matches!(
            run_request(&plugin, Some(client_a)),
            PluginFlow::Continue
        ));
        assert!(matches!(
            run_request(&plugin, Some(client_a)),
            PluginFlow::Respond(_)
        ));
        assert!(matches!(
            run_request(&plugin, Some(client_b)),
            PluginFlow::Continue
        ));
    }
}
