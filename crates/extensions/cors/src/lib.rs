use http::{HeaderValue, Method, StatusCode, header};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec, RequestCtx,
    ResponseCtx,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const PLUGIN_NAME: &str = "cors";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsPluginConfig {
    #[serde(default)]
    pub allow_origin: Option<String>,
    #[serde(default)]
    pub allow_methods: Option<String>,
    #[serde(default)]
    pub allow_headers: Option<String>,
    #[serde(default)]
    pub expose_headers: Option<String>,
    #[serde(default)]
    pub allow_credentials: Option<bool>,
    #[serde(default)]
    pub max_age: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CorsPlugin {
    allow_origin: Option<HeaderValue>,
    allow_methods: Option<HeaderValue>,
    allow_headers: Option<HeaderValue>,
    expose_headers: Option<HeaderValue>,
    allow_credentials: Option<HeaderValue>,
    max_age: Option<HeaderValue>,
}

impl CorsPlugin {
    fn apply_headers(&self, headers: &mut dyn ngxora_plugin_api::HeaderMapMut) {
        if let Some(val) = &self.allow_origin {
            let _ = headers.set(&header::ACCESS_CONTROL_ALLOW_ORIGIN, val.clone());
        }
        if let Some(val) = &self.allow_credentials {
            let _ = headers.set(&header::ACCESS_CONTROL_ALLOW_CREDENTIALS, val.clone());
        }
    }
}

impl HttpPlugin for CorsPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn on_request(
        &self,
        ctx: &mut RequestCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        if ctx.method == &Method::OPTIONS
            && ctx.headers.get(&header::ORIGIN).is_some()
            && ctx
                .headers
                .get(&header::ACCESS_CONTROL_REQUEST_METHOD)
                .is_some()
        {
            let mut response = LocalResponse::new(StatusCode::NO_CONTENT, "");

            if let Some(val) = &self.allow_origin {
                response
                    .headers
                    .push((header::ACCESS_CONTROL_ALLOW_ORIGIN, val.clone()));
            }
            if let Some(val) = &self.allow_methods {
                response
                    .headers
                    .push((header::ACCESS_CONTROL_ALLOW_METHODS, val.clone()));
            }
            if let Some(val) = &self.allow_headers {
                response
                    .headers
                    .push((header::ACCESS_CONTROL_ALLOW_HEADERS, val.clone()));
            }
            if let Some(val) = &self.allow_credentials {
                response
                    .headers
                    .push((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, val.clone()));
            }
            if let Some(val) = &self.max_age {
                response
                    .headers
                    .push((header::ACCESS_CONTROL_MAX_AGE, val.clone()));
            }

            return Ok(PluginFlow::Respond(response));
        }

        Ok(PluginFlow::Continue)
    }

    fn on_response(
        &self,
        ctx: &mut ResponseCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        self.apply_headers(ctx.headers);
        if let Some(val) = &self.expose_headers {
            let _ = ctx
                .headers
                .set(&header::ACCESS_CONTROL_EXPOSE_HEADERS, val.clone());
        }
        Ok(PluginFlow::Continue)
    }
}

#[derive(Debug, Default)]
pub struct CorsPluginFactory;

impl PluginFactory for CorsPluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let config = serde_json::from_value::<CorsPluginConfig>(spec.config.clone()).map_err(
            |err| PluginBuildError::new(self.name(), format!("invalid plugin config: {err}")),
        )?;

        let parse_hdr =
            |opt: &Option<String>, name: &str| -> Result<Option<HeaderValue>, PluginBuildError> {
                match opt {
                    Some(s) => {
                        let val = HeaderValue::from_str(s).map_err(|e| {
                            PluginBuildError::new(PLUGIN_NAME, format!("invalid {name}: {e}"))
                        })?;
                        Ok(Some(val))
                    }
                    None => Ok(None),
                }
            };

        let allow_origin = parse_hdr(&config.allow_origin, "allow_origin")?;
        let allow_methods = parse_hdr(&config.allow_methods, "allow_methods")?;
        let allow_headers = parse_hdr(&config.allow_headers, "allow_headers")?;
        let expose_headers = parse_hdr(&config.expose_headers, "expose_headers")?;

        let allow_credentials = if let Some(b) = config.allow_credentials {
            let s = if b { "true" } else { "false" };
            Some(HeaderValue::from_static(s))
        } else {
            None
        };

        let max_age = config
            .max_age
            .map(|v| HeaderValue::from_str(&v.to_string()).unwrap());

        Ok(Arc::new(CorsPlugin {
            allow_origin,
            allow_methods,
            allow_headers,
            expose_headers,
            allow_credentials,
            max_age,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Extensions, HeaderMap, HeaderName};
    use ngxora_plugin_api::{HeaderMapMut, PluginState};
    use serde_json::json;

    struct FakeHeaders {
        inner: HeaderMap,
    }
    impl Default for FakeHeaders {
        fn default() -> Self {
            Self { inner: HeaderMap::new() }
        }
    }
    impl HeaderMapMut for FakeHeaders {
        fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
            self.inner.get(name)
        }
        fn add(&mut self, name: &HeaderName, value: HeaderValue) -> Result<(), ngxora_plugin_api::PluginError> {
            self.inner.append(name, value); Ok(())
        }
        fn set(&mut self, name: &HeaderName, value: HeaderValue) -> Result<(), ngxora_plugin_api::PluginError> {
            self.inner.insert(name, value); Ok(())
        }
        fn remove(&mut self, name: &HeaderName) {
            self.inner.remove(name);
        }
    }

    #[test]
    fn factory_builds_valid_config() {
        let spec = PluginSpec {
            name: "cors".into(),
            config: json!({
                "allow_origin": "*",
                "allow_methods": "GET, POST, OPTIONS",
                "allow_credentials": true,
                "max_age": 86400
            }),
        };
        let plugin = CorsPluginFactory.build(&spec).expect("build should succeed");
        assert_eq!(plugin.name(), "cors");
    }

    #[test]
    fn cors_plugin_handles_preflight() {
        let spec = PluginSpec {
            name: "cors".into(),
            config: json!({
                "allow_origin": "*",
                "max_age": 3600
            }),
        };
        let plugin = CorsPluginFactory.build(&spec).unwrap();
        let method = Method::OPTIONS;
        let mut state = PluginState { extensions: Extensions::new() };
        let mut headers = FakeHeaders::default();
        headers.set(&header::ORIGIN, HeaderValue::from_static("https://example.com")).unwrap();
        headers.set(&header::ACCESS_CONTROL_REQUEST_METHOD, HeaderValue::from_static("GET")).unwrap();

        let flow = plugin.on_request(&mut RequestCtx {
            state: &mut state,
            path: "/",
            host: Some("api.com"),
            method: &method,
            headers: &mut headers,
        }).unwrap();

        if let PluginFlow::Respond(res) = flow {
            assert_eq!(res.status, StatusCode::NO_CONTENT);
            
            let origin = res.headers.iter().find(|(k, _)| k == &header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap();
            assert_eq!(origin.1.to_str().unwrap(), "*");
            
            let max_age = res.headers.iter().find(|(k, _)| k == &header::ACCESS_CONTROL_MAX_AGE).unwrap();
            assert_eq!(max_age.1.to_str().unwrap(), "3600");
        } else {
            panic!("Expected preflight interception");
        }
    }
}
