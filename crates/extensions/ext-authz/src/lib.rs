use http::{HeaderName, StatusCode};
use log::{debug, error};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec, RequestCtx,
};
use reqwest::{Client, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use url::Host;

const PLUGIN_NAME: &str = "ext_authz";
const DEFAULT_TIMEOUT_MS: u64 = 3_000;
const MAX_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtAuthzPluginConfig {
    pub uri: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub pass_request_headers: Vec<String>,
    #[serde(default)]
    pub pass_response_headers: Vec<String>,
}

#[derive(Debug)]
pub struct ExtAuthzPlugin {
    client: Client,
    uri: Url,
    pass_request_headers: Vec<HeaderName>,
    pass_response_headers: Vec<HeaderName>,
}

#[ngxora_plugin_api::async_trait]
impl HttpPlugin for ExtAuthzPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    async fn on_request(
        &self,
        ctx: &mut RequestCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        let mut req_builder = self.client.get(self.uri.clone());

        // Pass explicit headers from incoming request to the auth service
        for header_name in &self.pass_request_headers {
            if let Some(val) = ctx.headers.get(header_name) {
                req_builder = req_builder.header(header_name.clone(), val.clone());
            }
        }

        // These headers belong to the auth service, even when it omits them.
        // Build the sub-request first because the two allowlists may overlap.
        for header_name in &self.pass_response_headers {
            ctx.headers.remove(header_name);
        }

        let auth_resp = match req_builder.send().await {
            Ok(resp) => resp,
            Err(err) => {
                if err.is_timeout() {
                    error!("ext_authz plugin sub-request timed out");
                } else if err.is_connect() {
                    error!("ext_authz plugin could not connect to auth service");
                } else {
                    error!("ext_authz plugin sub-request failed");
                }
                return Ok(PluginFlow::Respond(LocalResponse::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Auth Service Error",
                )));
            }
        };

        if auth_resp.status().is_success() {
            // Extract explicitly defined response headers and append to the upstream request
            for header_name in &self.pass_response_headers {
                if let Some(val) = auth_resp.headers().get(header_name) {
                    ctx.headers.set(header_name, val.clone()).inspect_err(|_| {
                        error!("ext_authz plugin could not apply auth response header");
                    })?;
                }
            }
            debug!("ext_authz checks passed. Continuing flow.");
            Ok(PluginFlow::Continue)
        } else {
            debug!(
                "ext_authz rejected request with status: {}",
                auth_resp.status()
            );
            Ok(PluginFlow::Respond(LocalResponse::new(
                auth_resp.status(),
                "Unauthorized",
            )))
        }
    }
}

#[derive(Debug, Default)]
pub struct ExtAuthzPluginFactory;

impl PluginFactory for ExtAuthzPluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let config =
            serde_json::from_value::<ExtAuthzPluginConfig>(spec.config.clone()).map_err(|err| {
                PluginBuildError::new(self.name(), format!("invalid plugin config: {err}"))
            })?;

        let allowed_hosts = parse_allowed_hosts(&config.allowed_hosts)?;
        let uri = parse_uri(&config.uri, &allowed_hosts)?;
        let timeout = normalize_timeout(config.timeout_ms)?;

        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|e| {
                PluginBuildError::new(
                    self.name(),
                    format!("failed to initialize HTTP client: {}", e),
                )
            })?;

        let parse_headers =
            |list: &[String], field: &str| -> Result<Vec<HeaderName>, PluginBuildError> {
                list.iter()
                    .map(|s| {
                        HeaderName::from_bytes(s.as_bytes()).map_err(|e| {
                            PluginBuildError::new(
                                PLUGIN_NAME,
                                format!("invalid {field} header '{s}': {e}"),
                            )
                        })
                    })
                    .collect()
            };

        let pass_request_headers =
            parse_headers(&config.pass_request_headers, "pass_request_header")?;
        let pass_response_headers =
            parse_headers(&config.pass_response_headers, "pass_response_header")?;

        Ok(Arc::new(ExtAuthzPlugin {
            client,
            uri,
            pass_request_headers,
            pass_response_headers,
        }))
    }
}

fn normalize_timeout(timeout_ms: Option<u64>) -> Result<Duration, PluginBuildError> {
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(PluginBuildError::new(
            PLUGIN_NAME,
            format!("timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"),
        ));
    }

    Ok(Duration::from_millis(timeout_ms))
}

fn parse_allowed_hosts(values: &[String]) -> Result<Vec<Host>, PluginBuildError> {
    if values.is_empty() {
        return Err(PluginBuildError::new(
            PLUGIN_NAME,
            "at least one allowed_host must be configured",
        ));
    }

    values
        .iter()
        .map(|value| {
            Host::parse(value).map_err(|_| {
                PluginBuildError::new(PLUGIN_NAME, "allowed_host must be a valid host or IP")
            })
        })
        .collect()
}

fn parse_uri(uri: &str, allowed_hosts: &[Host]) -> Result<Url, PluginBuildError> {
    let uri = Url::parse(uri)
        .map_err(|_| PluginBuildError::new(PLUGIN_NAME, "uri must be an absolute URL"))?;

    if !matches!(uri.scheme(), "http" | "https") {
        return Err(PluginBuildError::new(
            PLUGIN_NAME,
            "uri scheme must be http or https",
        ));
    }
    if !uri.username().is_empty() || uri.password().is_some() {
        return Err(PluginBuildError::new(
            PLUGIN_NAME,
            "uri must not contain userinfo",
        ));
    }
    if uri.fragment().is_some() {
        return Err(PluginBuildError::new(
            PLUGIN_NAME,
            "uri must not contain a fragment",
        ));
    }

    let host = uri
        .host()
        .map(|host| host.to_owned())
        .ok_or_else(|| PluginBuildError::new(PLUGIN_NAME, "uri must contain a host"))?;
    if !allowed_hosts.contains(&host) {
        return Err(PluginBuildError::new(
            PLUGIN_NAME,
            "uri host is not in allowed_hosts",
        ));
    }

    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_TIMEOUT_MS, ExtAuthzPluginFactory, normalize_timeout};
    use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
    use ngxora_plugin_api::{
        HeaderMapMut, HttpPlugin, PluginFactory, PluginFlow, PluginSpec, PluginState, RequestCtx,
    };
    use serde_json::json;
    use std::time::Duration;
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
        time::sleep,
    };

    struct TestHeaders(HeaderMap);

    impl HeaderMapMut for TestHeaders {
        fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
            self.0.get(name)
        }

        fn add(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.0.append(name, value);
            Ok(())
        }

        fn set(
            &mut self,
            name: &HeaderName,
            value: HeaderValue,
        ) -> Result<(), ngxora_plugin_api::PluginError> {
            self.0.insert(name, value);
            Ok(())
        }

        fn remove(&mut self, name: &HeaderName) {
            self.0.remove(name);
        }
    }

    fn spec(uri: String, timeout_ms: Option<u64>) -> PluginSpec {
        PluginSpec {
            name: "ext_authz".into(),
            config: json!({
                "uri": uri,
                "allowed_hosts": ["127.0.0.1"],
                "timeout_ms": timeout_ms,
            }),
        }
    }

    async fn run_request(plugin: Arc<dyn HttpPlugin>) -> PluginFlow {
        let mut headers = TestHeaders(HeaderMap::new());
        let mut state = PluginState {
            extensions: Extensions::new(),
        };
        let method = Method::GET;

        plugin
            .on_request(&mut RequestCtx {
                state: &mut state,
                path: "/",
                host: Some("example.com"),
                method: &method,
                client_ip: None,
                headers: &mut headers,
            })
            .await
            .expect("ext_authz request should not return a plugin error")
    }

    async fn spawn_server(
        response: String,
        delay: Duration,
        hits: Arc<AtomicUsize>,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test server should bind");
        let addr = listener
            .local_addr()
            .expect("test server should have an address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test server should accept");
            hits.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await;
            sleep(delay).await;
            stream
                .write_all(response.as_bytes())
                .await
                .expect("test server should write response");
        });
        (addr, task)
    }

    #[test]
    fn default_timeout_is_bounded() {
        assert_eq!(
            normalize_timeout(None).expect("default timeout should be valid"),
            Duration::from_millis(DEFAULT_TIMEOUT_MS)
        );
        assert!(normalize_timeout(Some(0)).is_err());
        assert!(normalize_timeout(Some(30_001)).is_err());
    }

    #[test]
    fn factory_rejects_disallowed_and_crafted_uris() {
        let factory = ExtAuthzPluginFactory;
        for uri in [
            "http://127.0.0.1/auth",
            "http://localhost/auth",
            "http://10.0.0.1/auth",
            "http://[::1]/auth",
            "http://2130706433/auth",
            "ftp://auth.example/auth",
            "http://user:password@auth.example/auth",
            "http://auth.example/auth#fragment",
        ] {
            let result = factory.build(&PluginSpec {
                name: "ext_authz".into(),
                config: json!({
                    "uri": uri,
                    "allowed_hosts": ["auth.example"],
                }),
            });
            assert!(result.is_err(), "uri should be rejected: {uri}");
        }
    }

    #[test]
    fn factory_requires_explicit_allowed_host() {
        let result = ExtAuthzPluginFactory.build(&PluginSpec {
            name: "ext_authz".into(),
            config: json!({"uri": "http://127.0.0.1/auth"}),
        });
        assert!(result.is_err());

        let result = ExtAuthzPluginFactory.build(&PluginSpec {
            name: "ext_authz".into(),
            config: json!({
                "uri": "http://127.0.0.1/auth",
                "allowed_hosts": ["127.0.0.1"],
            }),
        });
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn request_times_out() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (addr, task) = spawn_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            Duration::from_millis(100),
            hits.clone(),
        )
        .await;
        let plugin = ExtAuthzPluginFactory
            .build(&spec(format!("http://{addr}/auth"), Some(20)))
            .expect("ext_authz plugin should build");

        let flow = run_request(plugin).await;
        assert!(
            matches!(flow, PluginFlow::Respond(response) if response.status == StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        task.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn request_does_not_follow_redirects() {
        let target_hits = Arc::new(AtomicUsize::new(0));
        let (target_addr, target_task) = spawn_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            Duration::ZERO,
            target_hits.clone(),
        )
        .await;
        let source_hits = Arc::new(AtomicUsize::new(0));
        let (source_addr, source_task) = spawn_server(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            Duration::ZERO,
            source_hits.clone(),
        )
        .await;
        let plugin = ExtAuthzPluginFactory
            .build(&spec(format!("http://{source_addr}/auth"), Some(500)))
            .expect("ext_authz plugin should build");

        let flow = run_request(plugin).await;
        assert!(
            matches!(flow, PluginFlow::Respond(response) if response.status == StatusCode::FOUND)
        );
        assert_eq!(source_hits.load(Ordering::SeqCst), 1);
        assert_eq!(target_hits.load(Ordering::SeqCst), 0);

        source_task.await.expect("source server task should finish");
        target_task.abort();
    }
    #[tokio::test]
    async fn auth_response_headers_replace_client_identity_and_preserve_subrequest_inputs() {
        for trusted in [None, Some("trusted-user")] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let header = trusted
                    .map(|v| format!("X-User: {v}\r\n"))
                    .unwrap_or_default();
                stream.write_all(format!("HTTP/1.1 200 OK\r\n{header}Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                String::from_utf8(request).unwrap()
            });
            let plugin = ExtAuthzPluginFactory.build(&PluginSpec {
                name: "ext_authz".into(),
                config: json!({ "uri": format!("http://{addr}/auth"), "allowed_hosts": ["127.0.0.1"], "pass_request_headers": ["X-User"], "pass_response_headers": ["X-User"] }),
            }).unwrap();
            let mut headers = TestHeaders(HeaderMap::new());
            headers
                .0
                .append("x-user", HeaderValue::from_static("forged-admin"));
            headers
                .0
                .append("x-user", HeaderValue::from_static("also-forged"));
            let flow = plugin
                .on_request(&mut RequestCtx {
                    state: &mut PluginState::default(),
                    path: "/",
                    host: None,
                    method: &Method::GET,
                    client_ip: None,
                    headers: &mut headers,
                })
                .await
                .unwrap();
            assert!(matches!(flow, PluginFlow::Continue));
            assert_eq!(
                headers.0.get("x-user").map(|v| v.to_str().unwrap()),
                trusted
            );
            assert_eq!(
                headers.0.get_all("x-user").iter().count(),
                usize::from(trusted.is_some())
            );
            assert!(
                server
                    .await
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("x-user: forged-admin")
            );
        }
    }
}
