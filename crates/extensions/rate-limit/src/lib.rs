use http::{HeaderValue, StatusCode, header};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec, RequestCtx,
};
use pingora_limits::rate::Rate;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

const PLUGIN_NAME: &str = "rate-limit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPluginConfig {
    pub max_requests_per_second: isize,
}

pub struct RateLimitPlugin {
    pub max_requests_per_second: isize,
    pub rate_estimator: Rate,
}

impl std::fmt::Debug for RateLimitPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPlugin")
            .field("max_requests_per_second", &self.max_requests_per_second)
            .finish()
    }
}

impl RateLimitPlugin {
    fn rate_limited_response(&self) -> PluginFlow {
        let mut response = LocalResponse::new(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests");
        response.headers.push((
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ));
        PluginFlow::Respond(response)
    }
}

impl HttpPlugin for RateLimitPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn on_request(
        &self,
        ctx: &mut RequestCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        let client_ip = ctx
            .headers
            .get(&http::header::HeaderName::from_static("x-forwarded-for"))
            .and_then(|val| val.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim())
            .unwrap_or(ctx.host.unwrap_or("global"));

        let key = client_ip.to_string();

        let current_rate = self.rate_estimator.rate(&key);
        if current_rate > self.max_requests_per_second as f64 {
            return Ok(self.rate_limited_response());
        }

        self.rate_estimator.observe(&key, 1);

        Ok(PluginFlow::Continue)
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

        Ok(Arc::new(RateLimitPlugin {
            max_requests_per_second: config.max_requests_per_second,
            rate_estimator: Rate::new(Duration::from_secs(1)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitPluginConfig, RateLimitPluginFactory};
    use ngxora_plugin_api::{PluginFactory, PluginSpec};
    use serde_json::json;

    #[test]
    fn factory_builds_valid_config() {
        let spec = PluginSpec {
            name: "rate-limit".into(),
            config: json!({ "max_requests_per_second": 10 }),
        };
        let plugin = RateLimitPluginFactory.build(&spec).expect("build should succeed");
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
}
