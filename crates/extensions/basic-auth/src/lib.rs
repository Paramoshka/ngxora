use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderValue, StatusCode, header};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec,
    RequestCtx, async_trait,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const PLUGIN_NAME: &str = "basic-auth";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicAuthPluginConfig {
    pub username: String,
    pub password: String,
    #[serde(default = "default_realm")]
    pub realm: String,
}

fn default_realm() -> String {
    "Restricted".into()
}

#[derive(Debug, Clone)]
pub struct BasicAuthPlugin {
    expected_credentials: String,
    challenge_header: HeaderValue,
}

impl BasicAuthPlugin {
    fn unauthorized_response(&self) -> PluginFlow {
        let mut response = LocalResponse::new(StatusCode::UNAUTHORIZED, "Unauthorized");
        response.headers.push((
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ));
        response
            .headers
            .push((header::WWW_AUTHENTICATE, self.challenge_header.clone()));
        PluginFlow::Respond(response)
    }
}

#[async_trait]
impl HttpPlugin for BasicAuthPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    async fn on_request(
        &self,
        ctx: &mut RequestCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        let Some(value) = ctx.headers.get(&header::AUTHORIZATION) else {
            return Ok(self.unauthorized_response());
        };
        let Ok(value) = value.to_str() else {
            return Ok(self.unauthorized_response());
        };

        let mut parts = value.split_ascii_whitespace();
        let Some(scheme) = parts.next() else {
            return Ok(self.unauthorized_response());
        };
        let Some(credentials) = parts.next() else {
            return Ok(self.unauthorized_response());
        };
        if parts.next().is_some() {
            return Ok(self.unauthorized_response());
        }
        if !scheme.eq_ignore_ascii_case("Basic") {
            return Ok(self.unauthorized_response());
        }
        if credentials != self.expected_credentials {
            return Ok(self.unauthorized_response());
        }

        Ok(PluginFlow::Continue)
    }
}

#[derive(Debug, Default)]
pub struct BasicAuthPluginFactory;

impl PluginFactory for BasicAuthPluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let config = serde_json::from_value::<BasicAuthPluginConfig>(spec.config.clone()).map_err(
            |err| PluginBuildError::new(self.name(), format!("invalid plugin config: {err}")),
        )?;

        if config.username.is_empty() {
            return Err(PluginBuildError::new(
                self.name(),
                "username cannot be empty",
            ));
        }
        if config.username.contains(':') {
            return Err(PluginBuildError::new(
                self.name(),
                "username cannot contain `:`",
            ));
        }
        if config.password.is_empty() {
            return Err(PluginBuildError::new(
                self.name(),
                "password cannot be empty",
            ));
        }

        let challenge = format!(
            "Basic realm=\"{}\"",
            config.realm.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let challenge_header = HeaderValue::from_str(&challenge).map_err(|err| {
            PluginBuildError::new(
                self.name(),
                format!("invalid WWW-Authenticate challenge header: {err}"),
            )
        })?;

        Ok(Arc::new(BasicAuthPlugin {
            expected_credentials: STANDARD
                .encode(format!("{}:{}", config.username, config.password)),
            challenge_header,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{BasicAuthPluginConfig, BasicAuthPluginFactory};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use futures::executor::block_on;
    use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method};
    use ngxora_plugin_api::{
        HeaderMapMut, PluginFactory, PluginFlow, PluginSpec, PluginState, RequestCtx,
    };
    use serde_json::json;

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

    fn plugin_spec() -> PluginSpec {
        PluginSpec {
            name: "basic-auth".into(),
            config: json!(BasicAuthPluginConfig {
                username: "demo".into(),
                password: "s3cret".into(),
                realm: "Admin".into(),
            }),
        }
    }

    #[test]
    fn basic_auth_plugin_allows_matching_credentials() {
        let plugin = BasicAuthPluginFactory
            .build(&plugin_spec())
            .expect("basic-auth build should succeed");
        let method = Method::GET;
        let mut state = PluginState {
            extensions: Extensions::new(),
        };
        let mut headers = FakeHeaders::default();
        headers
            .set(
                &http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("demo:s3cret")))
                    .unwrap(),
            )
            .unwrap();

        let flow = block_on(plugin.on_request(&mut RequestCtx {
            state: &mut state,
            path: "/",
            host: Some("example.com"),
            method: &method,
            client_ip: None,
            headers: &mut headers,
        }))
        .expect("request hook should succeed");

        assert!(matches!(flow, PluginFlow::Continue));
    }

    #[test]
    fn basic_auth_plugin_rejects_missing_credentials() {
        let plugin = BasicAuthPluginFactory
            .build(&plugin_spec())
            .expect("basic-auth build should succeed");
        let method = Method::GET;
        let mut state = PluginState {
            extensions: Extensions::new(),
        };
        let mut headers = FakeHeaders::default();

        let flow = block_on(plugin.on_request(&mut RequestCtx {
            state: &mut state,
            path: "/",
            host: Some("example.com"),
            method: &method,
            client_ip: None,
            headers: &mut headers,
        }))
        .expect("request hook should succeed");

        match flow {
            PluginFlow::Respond(response) => {
                assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);
                assert_eq!(response.body.as_ref(), b"Unauthorized");
                assert_eq!(
                    response
                        .headers
                        .iter()
                        .find(|(name, _)| name == http::header::WWW_AUTHENTICATE)
                        .map(|(_, value)| value),
                    Some(&HeaderValue::from_static("Basic realm=\"Admin\""))
                );
            }
            PluginFlow::Continue => panic!("missing credentials should be rejected"),
        }
    }

    #[test]
    fn basic_auth_factory_rejects_invalid_username() {
        let result = BasicAuthPluginFactory.build(&PluginSpec {
            name: "basic-auth".into(),
            config: json!({
                "username": "bad:user",
                "password": "secret"
            }),
        });
        let err = match result {
            Ok(_) => panic!("invalid username should fail"),
            Err(err) => err,
        };

        assert!(err.message.contains("username cannot contain `:`"));
    }
}
