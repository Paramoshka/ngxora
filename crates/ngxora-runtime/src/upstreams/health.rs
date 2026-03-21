use super::types::{CompiledHealthCheck, CompiledUpstreamServer, HealthCheckType};
use async_trait::async_trait;
use pingora::connectors::{TransportConnector, http::Connector as HttpConnector};
use pingora::http::RequestHeader;
use pingora::lb::Backend;
use pingora::lb::health_check::HealthCheck;
use pingora::upstreams::peer::HttpPeer;
use std::net::SocketAddr;

impl CompiledHealthCheck {
    pub fn build(&self) -> Result<Box<dyn HealthCheck + Send + Sync + 'static>, String> {
        match &self.check_type {
            HealthCheckType::Tcp => Ok(Box::new(NgxoraHealthCheck::Tcp(NgxoraTcpHealthCheck {
                consecutive_success: self.consecutive_success,
                consecutive_failure: self.consecutive_failure,
                timeout: self.timeout,
                connector: TransportConnector::new(None),
            }))),
            HealthCheckType::Http {
                host,
                path,
                use_tls,
            } => {
                let uri = path
                    .parse::<http::Uri>()
                    .map_err(|err| format!("invalid health_check path `{path}`: {err}"))?;
                let mut request =
                    RequestHeader::build("GET", path.as_bytes(), None).map_err(|err| {
                        format!("failed to build health_check request for `{path}`: {err}")
                    })?;
                request.set_uri(uri);
                request
                    .insert_header("Host", host.as_str())
                    .map_err(|err| format!("failed to build health_check host header: {err}"))?;

                Ok(Box::new(NgxoraHealthCheck::Http(NgxoraHttpHealthCheck {
                    consecutive_success: self.consecutive_success,
                    consecutive_failure: self.consecutive_failure,
                    timeout: self.timeout,
                    host: host.clone(),
                    use_tls: *use_tls,
                    request,
                    connector: HttpConnector::new(None),
                })))
            }
        }
    }
}

struct NgxoraTcpHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    timeout: std::time::Duration,
    connector: TransportConnector,
}

struct NgxoraHttpHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    timeout: std::time::Duration,
    host: String,
    use_tls: bool,
    request: RequestHeader,
    connector: HttpConnector<()>,
}

enum NgxoraHealthCheck {
    Tcp(NgxoraTcpHealthCheck),
    Http(NgxoraHttpHealthCheck),
}

fn backend_health_server(target: &Backend) -> pingora::Result<&CompiledUpstreamServer> {
    target.ext.get::<CompiledUpstreamServer>().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "health check backend is missing compiled upstream metadata",
        )
    })
}

async fn resolve_health_check_addr(server: &CompiledUpstreamServer) -> pingora::Result<SocketAddr> {
    tokio::net::lookup_host((server.host.as_str(), server.port))
        .await
        .map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!(
                    "failed to resolve upstream `{}` for health check: {err}",
                    server
                ),
            )
        })?
        .next()
        .ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("upstream `{server}` did not resolve to any address"),
            )
        })
}

impl NgxoraTcpHealthCheck {
    async fn check_backend(&self, target: &Backend) -> pingora::Result<()> {
        let server = backend_health_server(target)?;
        let addr = resolve_health_check_addr(server).await?;
        let mut peer = HttpPeer::new(addr, false, String::new());
        peer.options.connection_timeout = Some(self.timeout);
        self.connector.get_stream(&peer).await.map(|_| ())
    }

    fn backend_summary(&self, target: &Backend) -> String {
        backend_health_server(target)
            .map(ToString::to_string)
            .unwrap_or_else(|_| format!("{target:?}"))
    }
}

impl NgxoraHttpHealthCheck {
    async fn check_backend(&self, target: &Backend) -> pingora::Result<()> {
        let server = backend_health_server(target)?;
        let addr = resolve_health_check_addr(server).await?;
        let sni = if self.use_tls {
            self.host.clone()
        } else {
            String::new()
        };
        let mut peer = HttpPeer::new(addr, self.use_tls, sni);
        peer.options.connection_timeout = Some(self.timeout);
        peer.options.read_timeout = Some(self.timeout);

        let (mut session, _) = self.connector.get_http_session(&peer).await?;
        session
            .write_request_header(Box::new(self.request.clone()))
            .await?;
        session.finish_request_body().await?;
        session.set_read_timeout(Some(self.timeout));
        session.read_response_header().await?;

        let response = session.response_header().ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "health check response header is missing after read",
            )
        })?;
        if response.status != 200 {
            return Err(pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!(
                    "http health check to {} returned status {}",
                    server, response.status
                ),
            ));
        }

        while session.read_response_body().await?.is_some() {}

        Ok(())
    }

    fn backend_summary(&self, target: &Backend) -> String {
        backend_health_server(target)
            .map(|server| {
                format!(
                    "{} via {}://{}{}",
                    server,
                    if self.use_tls { "https" } else { "http" },
                    self.host,
                    self.request.uri
                )
            })
            .unwrap_or_else(|_| format!("{target:?}"))
    }
}

#[async_trait]
impl HealthCheck for NgxoraHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        match self {
            Self::Tcp(check) => {
                if success {
                    check.consecutive_success
                } else {
                    check.consecutive_failure
                }
            }
            Self::Http(check) => {
                if success {
                    check.consecutive_success
                } else {
                    check.consecutive_failure
                }
            }
        }
    }

    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        match self {
            Self::Tcp(check) => check.check_backend(target).await,
            Self::Http(check) => check.check_backend(target).await,
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        match self {
            Self::Tcp(check) => check.backend_summary(target),
            Self::Http(check) => check.backend_summary(target),
        }
    }
}
