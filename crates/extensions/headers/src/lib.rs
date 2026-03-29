use http::{HeaderName, HeaderValue};
use ngxora_plugin_api::{
    HeaderMapMut, HttpPlugin, PluginBuildError, PluginError, PluginFactory, PluginFlow,
    PluginSpec, RequestCtx, ResponseCtx, UpstreamRequestCtx, async_trait,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersPluginConfig {
    #[serde(default)]
    pub request: HeaderPatchConfig,
    #[serde(default)]
    pub upstream_request: HeaderPatchConfig,
    #[serde(default)]
    pub response: HeaderPatchConfig,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderPatchConfig {
    #[serde(default)]
    pub add: Vec<HeaderEntry>,
    #[serde(default)]
    pub set: Vec<HeaderEntry>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
struct HeaderValueOp {
    name: HeaderName,
    value: HeaderValue,
}

#[derive(Debug, Clone, Default)]
struct HeaderPatch {
    add: Vec<HeaderValueOp>,
    set: Vec<HeaderValueOp>,
    remove: Vec<HeaderName>,
}

impl HeaderPatch {
    fn compile(plugin: &str, raw: HeaderPatchConfig) -> Result<Self, PluginBuildError> {
        let add = raw
            .add
            .into_iter()
            .map(|entry| compile_entry(plugin, entry))
            .collect::<Result<Vec<_>, _>>()?;
        let set = raw
            .set
            .into_iter()
            .map(|entry| compile_entry(plugin, entry))
            .collect::<Result<Vec<_>, _>>()?;
        let remove = raw
            .remove
            .into_iter()
            .map(|name| {
                name.parse::<HeaderName>().map_err(|err| {
                    PluginBuildError::new(plugin, format!("invalid header name `{name}`: {err}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { add, set, remove })
    }

    fn apply(
        &self,
        _plugin: &'static str,
        headers: &mut dyn HeaderMapMut,
    ) -> Result<(), PluginError> {
        for op in &self.remove {
            headers.remove(op);
        }

        for op in &self.set {
            headers.set(&op.name, op.value.clone())?;
        }

        for op in &self.add {
            headers.add(&op.name, op.value.clone())?;
        }

        Ok(())
    }
}

fn compile_entry(plugin: &str, entry: HeaderEntry) -> Result<HeaderValueOp, PluginBuildError> {
    let name = entry.name.parse::<HeaderName>().map_err(|err| {
        PluginBuildError::new(
            plugin,
            format!("invalid header name `{}`: {err}", entry.name),
        )
    })?;
    let value = entry.value.parse::<HeaderValue>().map_err(|err| {
        PluginBuildError::new(
            plugin,
            format!("invalid header value for `{}`: {err}", entry.name),
        )
    })?;

    Ok(HeaderValueOp { name, value })
}

#[derive(Debug, Clone)]
pub struct HeadersPlugin {
    request: HeaderPatch,
    upstream_request: HeaderPatch,
    response: HeaderPatch,
}

#[async_trait]
impl HttpPlugin for HeadersPlugin {
    fn name(&self) -> &'static str {
        "headers"
    }

    async fn on_request(&self, ctx: &mut RequestCtx<'_>) -> Result<PluginFlow, PluginError> {
        self.request.apply(self.name(), ctx.headers)?;
        Ok(PluginFlow::Continue)
    }

    async fn on_upstream_request(
        &self,
        ctx: &mut UpstreamRequestCtx<'_>,
    ) -> Result<PluginFlow, PluginError> {
        self.upstream_request.apply(self.name(), ctx.headers)?;
        Ok(PluginFlow::Continue)
    }

    async fn on_response(&self, ctx: &mut ResponseCtx<'_>) -> Result<PluginFlow, PluginError> {
        self.response.apply(self.name(), ctx.headers)?;
        Ok(PluginFlow::Continue)
    }
}

#[derive(Debug, Default)]
pub struct HeadersPluginFactory;

impl PluginFactory for HeadersPluginFactory {
    fn name(&self) -> &'static str {
        "headers"
    }

    fn build(
        &self,
        spec: &PluginSpec,
    ) -> Result<Arc<dyn ngxora_plugin_api::HttpPlugin>, PluginBuildError> {
        let config =
            serde_json::from_value::<HeadersPluginConfig>(spec.config.clone()).map_err(|err| {
                PluginBuildError::new(self.name(), format!("invalid plugin config: {err}"))
            })?;

        Ok(Arc::new(HeadersPlugin {
            request: HeaderPatch::compile(self.name(), config.request)?,
            upstream_request: HeaderPatch::compile(self.name(), config.upstream_request)?,
            response: HeaderPatch::compile(self.name(), config.response)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderEntry, HeaderPatchConfig, HeadersPluginConfig, HeadersPluginFactory};
    use futures::executor::block_on;
    use http::{Extensions, HeaderName, HeaderValue, Method, StatusCode};
    use ngxora_plugin_api::{
        HeaderMapMut, PluginFactory, PluginSpec, PluginState, RequestCtx, ResponseCtx,
        UpstreamRequestCtx,
    };
    use serde_json::json;

    #[derive(Default)]
    struct FakeHeaders {
        added: Vec<(HeaderName, HeaderValue)>,
        set: Vec<(HeaderName, HeaderValue)>,
        removed: Vec<HeaderName>,
    }

    impl HeaderMapMut for FakeHeaders {
        fn add(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.added.push((name.clone(), value));
            Ok(())
        }

        fn set(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.set.push((name.clone(), value));
            Ok(())
        }

        fn remove(&mut self, name: &HeaderName) {
            self.removed.push(name.clone());
        }
    }

    fn plugin_spec() -> PluginSpec {
        PluginSpec {
            name: "headers".into(),
            config: json!(HeadersPluginConfig {
                request: HeaderPatchConfig {
                    set: vec![HeaderEntry {
                        name: "x-request-id".into(),
                        value: "abc".into(),
                    }],
                    ..HeaderPatchConfig::default()
                },
                upstream_request: HeaderPatchConfig {
                    add: vec![HeaderEntry {
                        name: "x-upstream".into(),
                        value: "yes".into(),
                    }],
                    ..HeaderPatchConfig::default()
                },
                response: HeaderPatchConfig {
                    remove: vec!["x-remove-me".into()],
                    ..HeaderPatchConfig::default()
                },
            }),
        }
    }

    #[test]
    fn headers_plugin_applies_all_hook_patches() {
        let plugin = HeadersPluginFactory
            .build(&plugin_spec())
            .expect("headers plugin build should succeed");
        let method = Method::GET;
        let mut state = PluginState {
            extensions: Extensions::new(),
        };

        let mut request_headers = FakeHeaders::default();
        let mut request_ctx = RequestCtx {
            state: &mut state,
            path: "/",
            host: Some("example.com"),
            method: &method,
            headers: &mut request_headers,
        };
        block_on(plugin.on_request(&mut request_ctx)).expect("request patch should succeed");
        assert_eq!(request_headers.set.len(), 1);

        let mut upstream_headers = FakeHeaders::default();
        let mut upstream_ctx = UpstreamRequestCtx {
            state: &mut state,
            headers: &mut upstream_headers,
        };
        block_on(plugin.on_upstream_request(&mut upstream_ctx))
            .expect("upstream patch should succeed");
        assert_eq!(upstream_headers.added.len(), 1);

        let mut response_headers = FakeHeaders::default();
        let mut status = StatusCode::OK;
        let mut response_ctx = ResponseCtx {
            state: &mut state,
            status: &mut status,
            headers: &mut response_headers,
        };
        block_on(plugin.on_response(&mut response_ctx)).expect("response patch should succeed");
        assert_eq!(response_headers.removed.len(), 1);
    }
}
