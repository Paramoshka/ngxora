use http::{HeaderName, HeaderValue, StatusCode};
use log::{debug, error};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec, RequestCtx,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

const PLUGIN_NAME: &str = "ext_authz";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtAuthzPluginConfig {
    pub uri: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub pass_request_headers: Vec<String>,
    #[serde(default)]
    pub pass_response_headers: Vec<String>,
}

#[derive(Debug)]
pub struct ExtAuthzPlugin {
    client: Client,
    uri: String,
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
        let mut req_builder = self.client.get(&self.uri);

        // Pass explicit headers from incoming request to the auth service
        for header_name in &self.pass_request_headers {
            if let Some(val) = ctx.headers.get(header_name) {
                req_builder = req_builder.header(header_name.clone(), val.clone());
            }
        }

        let auth_resp = match req_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                error!("ext_authz plugin sub-request failed: {}", e);
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
                    let _ = ctx.headers.set(header_name, val.clone());
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
        let config = serde_json::from_value::<ExtAuthzPluginConfig>(spec.config.clone()).map_err(
            |err| PluginBuildError::new(self.name(), format!("invalid plugin config: {err}")),
        )?;

        if config.uri.is_empty() {
            return Err(PluginBuildError::new(self.name(), "uri cannot be empty"));
        }

        let mut client_builder = Client::builder();
        if let Some(timeout) = config.timeout_ms {
            client_builder = client_builder.timeout(Duration::from_millis(timeout));
        }

        let client = client_builder.build().map_err(|e| {
            PluginBuildError::new(
                self.name(),
                format!("failed to initialize HTTP client: {}", e),
            )
        })?;

        let parse_headers = |list: &[String], field: &str| -> Result<Vec<HeaderName>, PluginBuildError> {
            list.iter()
                .map(|s| {
                    HeaderName::from_bytes(s.as_bytes()).map_err(|e| {
                        PluginBuildError::new(PLUGIN_NAME, format!("invalid {field} header '{s}': {e}"))
                    })
                })
                .collect()
        };

        let pass_request_headers = parse_headers(&config.pass_request_headers, "pass_request_header")?;
        let pass_response_headers = parse_headers(&config.pass_response_headers, "pass_response_header")?;

        Ok(Arc::new(ExtAuthzPlugin {
            client,
            uri: config.uri,
            pass_request_headers,
            pass_response_headers,
        }))
    }
}
