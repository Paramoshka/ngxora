use http::StatusCode;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use log::{debug, error};
use ngxora_plugin_api::{
    HttpPlugin, LocalResponse, PluginBuildError, PluginFactory, PluginFlow, PluginSpec, RequestCtx,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const PLUGIN_NAME: &str = "jwt_auth";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthPluginConfig {
    pub algorithm: String, // e.g. "HS256", "RS256"
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub secret_file: Option<String>,
}

pub struct JwtAuthPlugin {
    pub decoding_key: DecodingKey,
    pub validation: Validation,
}

impl std::fmt::Debug for JwtAuthPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuthPlugin")
            .field("validation", &self.validation)
            .finish()
    }
}

#[ngxora_plugin_api::async_trait]
impl HttpPlugin for JwtAuthPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    async fn on_request(
        &self,
        ctx: &mut RequestCtx<'_>,
    ) -> Result<PluginFlow, ngxora_plugin_api::PluginError> {
        let auth_header = match ctx.headers.get(&http::header::AUTHORIZATION) {
            Some(hdr) => hdr,
            None => {
                debug!("jwt_auth: Missing authorization header");
                return Ok(PluginFlow::Respond(LocalResponse::new(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized: Missing Token",
                )));
            }
        };

        let auth_str = match std::str::from_utf8(auth_header.as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                debug!("jwt_auth: Invalid authorization header format");
                return Ok(PluginFlow::Respond(LocalResponse::new(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized: Invalid Token Format",
                )));
            }
        };

        let token = if let Some(stripped) = auth_str.strip_prefix("Bearer ") {
            stripped
        } else {
            debug!("jwt_auth: Missing Bearer prefix");
            return Ok(PluginFlow::Respond(LocalResponse::new(
                StatusCode::UNAUTHORIZED,
                "Unauthorized: Invalid Token Format",
            )));
        };

        // Dummy payload to validate signature and expiry without parsing custom claims
        #[derive(Debug, Deserialize)]
        struct DummyClaims {}

        match decode::<DummyClaims>(token, &self.decoding_key, &self.validation) {
            Ok(_) => {
                debug!("jwt_auth: Token is valid");
                Ok(PluginFlow::Continue)
            }
            Err(e) => {
                error!("jwt_auth: Token validation failed: {}", e);
                Ok(PluginFlow::Respond(LocalResponse::new(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized: Invalid or Expired Token",
                )))
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct JwtAuthPluginFactory;

impl PluginFactory for JwtAuthPluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let config =
            serde_json::from_value::<JwtAuthPluginConfig>(spec.config.clone()).map_err(|err| {
                PluginBuildError::new(self.name(), format!("invalid plugin config: {err}"))
            })?;

        let algo: Algorithm = config.algorithm.parse().map_err(|e| {
            PluginBuildError::new(
                self.name(),
                format!("unsupported algorithm '{}': {}", config.algorithm, e),
            )
        })?;

        let validation = Validation::new(algo);

        let raw_secret = if let Some(path) = &config.secret_file {
            std::fs::read(path).map_err(|e| {
                PluginBuildError::new(
                    self.name(),
                    format!("could not read secret_file '{}': {}", path, e),
                )
            })?
        } else if let Some(secret) = &config.secret {
            secret.as_bytes().to_vec()
        } else {
            return Err(PluginBuildError::new(
                self.name(),
                "either `secret` or `secret_file` must be provided",
            ));
        };

        let decoding_key = match algo {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                DecodingKey::from_secret(&raw_secret)
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => DecodingKey::from_rsa_pem(&raw_secret).map_err(|e| {
                PluginBuildError::new(self.name(), format!("failed to parse RSA PEM: {}", e))
            })?,
            Algorithm::ES256 | Algorithm::ES384 => {
                DecodingKey::from_ec_pem(&raw_secret).map_err(|e| {
                    PluginBuildError::new(self.name(), format!("failed to parse EC PEM: {}", e))
                })?
            }
            Algorithm::EdDSA => DecodingKey::from_ed_pem(&raw_secret).map_err(|e| {
                PluginBuildError::new(self.name(), format!("failed to parse EdDSA PEM: {}", e))
            })?,
        };

        Ok(Arc::new(JwtAuthPlugin {
            decoding_key,
            validation,
        }) as Arc<dyn HttpPlugin>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use http::header::AUTHORIZATION;
    use jsonwebtoken::{Header, encode};
    use ngxora_plugin_api::{HeaderMapMut, PluginError, PluginSpec, PluginState, RequestCtx};
    use serde_json::json;

    struct MockHeaderMap(http::HeaderMap);

    impl HeaderMapMut for MockHeaderMap {
        fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
            self.0.get(name)
        }
        fn add(
            &mut self,
            name: &http::HeaderName,
            value: http::HeaderValue,
        ) -> Result<(), PluginError> {
            self.0.append(name, value);
            Ok(())
        }
        fn set(
            &mut self,
            name: &http::HeaderName,
            value: http::HeaderValue,
        ) -> Result<(), PluginError> {
            self.0.insert(name, value);
            Ok(())
        }
        fn remove(&mut self, name: &http::HeaderName) {
            self.0.remove(name);
        }
    }

    #[tokio::test]
    async fn test_jwt_auth_hs256_success() {
        let secret = "secret123";
        let factory = JwtAuthPluginFactory;
        let spec = PluginSpec {
            name: "jwt_auth".into(),
            config: json!({
                "algorithm": "HS256",
                "secret": secret,
            }),
        };
        let plugin = factory.build(&spec).unwrap();

        // Generate token
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            exp: usize,
        }
        let my_claims = Claims {
            exp: 2000000000, // Year 2033
        };
        let token = encode(
            &Header::default(),
            &my_claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let mut h = http::HeaderMap::new();
        h.insert(AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
        let mut mock_headers = MockHeaderMap(h);
        let mut state = PluginState::default();
        let method = Method::GET;

        let mut ctx = RequestCtx {
            state: &mut state,
            path: "/test",
            host: Some("localhost"),
            method: &method,
            client_ip: None,
            headers: &mut mock_headers,
        };

        let res = plugin.on_request(&mut ctx).await.unwrap();
        assert!(matches!(res, PluginFlow::Continue));
    }

    #[tokio::test]
    async fn test_jwt_auth_missing_header() {
        let factory = JwtAuthPluginFactory;
        let spec = PluginSpec {
            name: "jwt_auth".into(),
            config: json!({
                "algorithm": "HS256",
                "secret": "secret123",
            }),
        };
        let plugin = factory.build(&spec).unwrap();

        let mut mock_headers = MockHeaderMap(http::HeaderMap::new());
        let mut state = PluginState::default();
        let method = Method::GET;

        let mut ctx = RequestCtx {
            state: &mut state,
            path: "/test",
            host: Some("localhost"),
            method: &method,
            client_ip: None,
            headers: &mut mock_headers,
        };

        let res = plugin.on_request(&mut ctx).await.unwrap();
        if let PluginFlow::Respond(resp) = res {
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        } else {
            panic!("Expected Respond");
        }
    }

    #[tokio::test]
    async fn test_jwt_auth_invalid_token() {
        let factory = JwtAuthPluginFactory;
        let spec = PluginSpec {
            name: "jwt_auth".into(),
            config: json!({
                "algorithm": "HS256",
                "secret": "secret123",
            }),
        };
        let plugin = factory.build(&spec).unwrap();

        let mut h = http::HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer invalid.token.here".parse().unwrap());
        let mut mock_headers = MockHeaderMap(h);
        let mut state = PluginState::default();
        let method = Method::GET;

        let mut ctx = RequestCtx {
            state: &mut state,
            path: "/test",
            host: Some("localhost"),
            method: &method,
            client_ip: None,
            headers: &mut mock_headers,
        };

        let res = plugin.on_request(&mut ctx).await.unwrap();
        if let PluginFlow::Respond(resp) = res {
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        } else {
            panic!("Expected Respond");
        }
    }
}
