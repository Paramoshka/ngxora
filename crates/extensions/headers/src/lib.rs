use http::{HeaderName, HeaderValue};
use ipnet::IpNet;
use ngxora_plugin_api::{
    HeaderMapMut, HttpPlugin, PluginBuildError, PluginError, PluginFactory, PluginFlow, PluginSpec,
    RequestCtx, ResponseCtx, UpstreamRequestCtx, async_trait,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersPluginConfig {
    #[serde(default)]
    pub forward_client_ip: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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
struct ClientIpForwarding {
    trusted_proxies: Vec<IpNet>,
}

impl ClientIpForwarding {
    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|network| network.contains(ip))
    }

    fn resolve_chain(
        &self,
        client_ip: Option<IpAddr>,
        headers: &dyn HeaderMapMut,
    ) -> Option<Vec<IpAddr>> {
        let peer_ip = client_ip?;
        if !self.is_trusted(&peer_ip) {
            return Some(vec![peer_ip]);
        }

        let Some(raw_forwarded_for) = headers.get(&X_FORWARDED_FOR) else {
            return Some(vec![peer_ip]);
        };
        let Ok(raw_forwarded_for) = raw_forwarded_for.to_str() else {
            return Some(vec![peer_ip]);
        };
        let Ok(mut forwarded_for) = raw_forwarded_for
            .split(',')
            .map(|value| value.trim().parse::<IpAddr>())
            .collect::<Result<Vec<_>, _>>()
        else {
            return Some(vec![peer_ip]);
        };
        if forwarded_for.is_empty() {
            return Some(vec![peer_ip]);
        }

        let mut current_ip = peer_ip;
        let mut trusted_chain = vec![peer_ip];
        while self.is_trusted(&current_ip) {
            let Some(next_ip) = forwarded_for.pop() else {
                break;
            };
            current_ip = next_ip;
            trusted_chain.push(current_ip);
        }
        trusted_chain.reverse();
        Some(trusted_chain)
    }

    fn apply(
        &self,
        plugin: &'static str,
        chain: Option<Vec<IpAddr>>,
        headers: &mut dyn HeaderMapMut,
    ) -> Result<(), PluginError> {
        let Some(chain) = chain else {
            headers.remove(&X_REAL_IP);
            headers.remove(&X_FORWARDED_FOR);
            return Ok(());
        };

        let client_ip = chain
            .first()
            .expect("resolved client IP chain is never empty")
            .to_string();
        let forwarded_for = chain
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let client_ip = HeaderValue::from_str(&client_ip).map_err(|err| {
            PluginError::new(plugin, format!("failed to encode X-Real-IP: {err}"))
        })?;
        let forwarded_for = HeaderValue::from_str(&forwarded_for).map_err(|err| {
            PluginError::new(plugin, format!("failed to encode X-Forwarded-For: {err}"))
        })?;

        headers.set(&X_REAL_IP, client_ip)?;
        headers.set(&X_FORWARDED_FOR, forwarded_for)?;
        Ok(())
    }
}

fn compile_trusted_proxy(plugin: &str, raw: String) -> Result<IpNet, PluginBuildError> {
    if let Ok(network) = raw.parse::<IpNet>() {
        return Ok(network);
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }

    Err(PluginBuildError::new(
        plugin,
        format!("invalid trusted_proxy `{raw}`: expected an IP address or CIDR"),
    ))
}

#[derive(Debug, Clone)]
pub struct HeadersPlugin {
    client_ip_forwarding: Option<ClientIpForwarding>,
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
        let client_ip_chain = self
            .client_ip_forwarding
            .as_ref()
            .and_then(|forwarding| forwarding.resolve_chain(ctx.client_ip, ctx.headers));
        self.request.apply(self.name(), ctx.headers)?;
        if let Some(forwarding) = &self.client_ip_forwarding {
            forwarding.apply(self.name(), client_ip_chain, ctx.headers)?;
        }
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

        let trusted_proxies = config
            .trusted_proxies
            .into_iter()
            .map(|raw| compile_trusted_proxy(self.name(), raw))
            .collect::<Result<Vec<_>, _>>()?;
        let client_ip_forwarding = config
            .forward_client_ip
            .then_some(ClientIpForwarding { trusted_proxies });

        Ok(Arc::new(HeadersPlugin {
            client_ip_forwarding,
            request: HeaderPatch::compile(self.name(), config.request)?,
            upstream_request: HeaderPatch::compile(self.name(), config.upstream_request)?,
            response: HeaderPatch::compile(self.name(), config.response)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HeaderEntry, HeaderPatchConfig, HeadersPluginConfig, HeadersPluginFactory, X_FORWARDED_FOR,
        X_REAL_IP,
    };
    use futures::executor::block_on;
    use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
    use ngxora_plugin_api::{
        HeaderMapMut, HttpPlugin, PluginFactory, PluginSpec, PluginState, RequestCtx, ResponseCtx,
        UpstreamRequestCtx,
    };
    use serde_json::json;
    use std::net::IpAddr;
    use std::sync::Arc;

    #[derive(Default)]
    struct FakeHeaders {
        inner: HeaderMap,
        added: Vec<(HeaderName, HeaderValue)>,
        set: Vec<(HeaderName, HeaderValue)>,
        removed: Vec<HeaderName>,
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
            self.inner.append(name.clone(), value.clone());
            self.added.push((name.clone(), value));
            Ok(())
        }

        fn set(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.inner.insert(name.clone(), value.clone());
            self.set.push((name.clone(), value));
            Ok(())
        }

        fn remove(&mut self, name: &HeaderName) {
            self.inner.remove(name);
            self.removed.push(name.clone());
        }
    }

    fn plugin_spec() -> PluginSpec {
        PluginSpec {
            name: "headers".into(),
            config: json!(HeadersPluginConfig {
                forward_client_ip: false,
                trusted_proxies: Vec::new(),
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

    fn forwarding_plugin(
        trusted_proxies: &[&str],
        request: HeaderPatchConfig,
    ) -> Arc<dyn HttpPlugin> {
        HeadersPluginFactory
            .build(&PluginSpec {
                name: "headers".into(),
                config: json!(HeadersPluginConfig {
                    forward_client_ip: true,
                    trusted_proxies: trusted_proxies
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect(),
                    request,
                    ..HeadersPluginConfig::default()
                }),
            })
            .expect("headers plugin build should succeed")
    }

    fn run_request(plugin: &dyn HttpPlugin, client_ip: Option<IpAddr>, headers: &mut FakeHeaders) {
        let method = Method::GET;
        let mut state = PluginState {
            extensions: Extensions::new(),
        };
        let mut ctx = RequestCtx {
            state: &mut state,
            path: "/",
            host: Some("example.com"),
            method: &method,
            client_ip,
            headers,
        };

        block_on(plugin.on_request(&mut ctx)).expect("request hook should succeed");
    }

    fn header_value<'a>(headers: &'a FakeHeaders, name: &HeaderName) -> &'a str {
        headers
            .inner
            .get(name)
            .expect("header should be present")
            .to_str()
            .expect("header should contain text")
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
            client_ip: None,
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

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_for() {
        let plugin = forwarding_plugin(&["10.0.0.0/8"], HeaderPatchConfig::default());
        let mut headers = FakeHeaders::default();
        headers
            .inner
            .insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.40"));

        run_request(
            plugin.as_ref(),
            Some("203.0.113.7".parse().unwrap()),
            &mut headers,
        );

        assert_eq!(header_value(&headers, &X_REAL_IP), "203.0.113.7");
        assert_eq!(header_value(&headers, &X_FORWARDED_FOR), "203.0.113.7");
    }

    #[test]
    fn disabled_forwarding_leaves_client_headers_unchanged() {
        let plugin = HeadersPluginFactory
            .build(&PluginSpec {
                name: "headers".into(),
                config: json!({ "forward_client_ip": false }),
            })
            .expect("headers plugin build should succeed");
        let mut headers = FakeHeaders::default();
        headers
            .inner
            .insert(X_REAL_IP, HeaderValue::from_static("198.51.100.40"));
        headers
            .inner
            .insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.40"));

        run_request(
            plugin.as_ref(),
            Some("203.0.113.7".parse().unwrap()),
            &mut headers,
        );

        assert_eq!(header_value(&headers, &X_REAL_IP), "198.51.100.40");
        assert_eq!(header_value(&headers, &X_FORWARDED_FOR), "198.51.100.40");
    }

    #[test]
    fn trusted_proxy_chain_discards_untrusted_prefix() {
        let plugin = forwarding_plugin(&["10.0.0.0/8"], HeaderPatchConfig::default());
        let mut headers = FakeHeaders::default();
        headers.inner.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("198.51.100.40, 203.0.113.7, 10.0.0.2"),
        );

        run_request(
            plugin.as_ref(),
            Some("10.0.0.3".parse().unwrap()),
            &mut headers,
        );

        assert_eq!(header_value(&headers, &X_REAL_IP), "203.0.113.7");
        assert_eq!(
            header_value(&headers, &X_FORWARDED_FOR),
            "203.0.113.7, 10.0.0.2, 10.0.0.3"
        );
    }

    #[test]
    fn exact_ipv6_trusted_proxy_is_supported() {
        let plugin = forwarding_plugin(&["2001:db8::2"], HeaderPatchConfig::default());
        let mut headers = FakeHeaders::default();
        headers
            .inner
            .insert(X_FORWARDED_FOR, HeaderValue::from_static("2001:db8:1::10"));

        run_request(
            plugin.as_ref(),
            Some("2001:db8::2".parse().unwrap()),
            &mut headers,
        );

        assert_eq!(header_value(&headers, &X_REAL_IP), "2001:db8:1::10");
        assert_eq!(
            header_value(&headers, &X_FORWARDED_FOR),
            "2001:db8:1::10, 2001:db8::2"
        );
    }

    #[test]
    fn malformed_forwarded_for_falls_back_to_peer() {
        let plugin = forwarding_plugin(&["10.0.0.0/8"], HeaderPatchConfig::default());
        let mut headers = FakeHeaders::default();
        headers.inner.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("not-an-ip, 10.0.0.2"),
        );

        run_request(
            plugin.as_ref(),
            Some("10.0.0.3".parse().unwrap()),
            &mut headers,
        );

        assert_eq!(header_value(&headers, &X_REAL_IP), "10.0.0.3");
        assert_eq!(header_value(&headers, &X_FORWARDED_FOR), "10.0.0.3");
    }

    #[test]
    fn automatic_headers_override_request_patch() {
        let plugin = forwarding_plugin(
            &[],
            HeaderPatchConfig {
                set: vec![HeaderEntry {
                    name: "X-Real-IP".into(),
                    value: "198.51.100.40".into(),
                }],
                ..HeaderPatchConfig::default()
            },
        );
        let mut headers = FakeHeaders::default();

        run_request(
            plugin.as_ref(),
            Some("203.0.113.7".parse().unwrap()),
            &mut headers,
        );

        assert_eq!(header_value(&headers, &X_REAL_IP), "203.0.113.7");
    }

    #[test]
    fn missing_peer_removes_forwarded_headers() {
        let plugin = forwarding_plugin(&[], HeaderPatchConfig::default());
        let mut headers = FakeHeaders::default();
        headers
            .inner
            .insert(X_REAL_IP, HeaderValue::from_static("198.51.100.40"));
        headers
            .inner
            .insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.40"));

        run_request(plugin.as_ref(), None, &mut headers);

        assert!(!headers.inner.contains_key(&X_REAL_IP));
        assert!(!headers.inner.contains_key(&X_FORWARDED_FOR));
    }

    #[test]
    fn invalid_trusted_proxy_is_rejected() {
        let error = match HeadersPluginFactory.build(&PluginSpec {
            name: "headers".into(),
            config: json!({
                "forward_client_ip": true,
                "trusted_proxies": ["10.0.0.0/99"]
            }),
        }) {
            Ok(_) => panic!("invalid trusted proxy should fail plugin build"),
            Err(error) => error,
        };

        assert!(error.message.contains("invalid trusted_proxy"));
    }
}
