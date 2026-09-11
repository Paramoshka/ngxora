//! Admin HTTP application.
//!
//! Serves `/metrics` (Prometheus exposition), `/healthz` (liveness), and
//! `/readyz` (configuration and TLS readiness) on one management listener.

use crate::control::RuntimeState;
use crate::server::router_ready;
use crate::upstreams::CompiledRouter;
use async_trait::async_trait;
use http::{Method, Response, StatusCode};
use pingora::apps::http_app::{HttpServer, ServeHttp};
use pingora::protocols::http::ServerSession;
use pingora_prometheus::PrometheusHttpApp;
use std::sync::Arc;

const HEALTHZ_PATH: &str = "/healthz";
const READYZ_PATH: &str = "/readyz";
const METRICS_PATH: &str = "/metrics";

/// Admin HTTP app multiplexing Prometheus metrics and a liveness endpoint.
pub struct AdminHttpApp {
    metrics: PrometheusHttpApp,
    state: Arc<RuntimeState>,
}

impl AdminHttpApp {
    pub fn new() -> Self {
        Self::with_state(Arc::new(RuntimeState::bootstrap(CompiledRouter::default())))
    }

    pub fn with_state(state: Arc<RuntimeState>) -> Self {
        Self {
            metrics: PrometheusHttpApp,
            state,
        }
    }
}

impl Default for AdminHttpApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of routing an admin request by path.
enum AdminRoute {
    Healthz,
    Readyz,
    Metrics,
    MethodNotAllowed,
    NotFound,
}

fn route_admin(method: &Method, path: &str) -> AdminRoute {
    if method != Method::GET && method != Method::HEAD {
        return AdminRoute::MethodNotAllowed;
    }

    match path {
        HEALTHZ_PATH => AdminRoute::Healthz,
        READYZ_PATH => AdminRoute::Readyz,
        METRICS_PATH => AdminRoute::Metrics,
        _ => AdminRoute::NotFound,
    }
}

#[async_trait]
impl ServeHttp for AdminHttpApp {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let method = http_session.req_header().method.clone();
        let path = http_session.req_header().uri.path();
        let mut response = respond_for_route(
            route_admin(&method, path),
            &self.metrics,
            &self.state,
            http_session,
        )
        .await;
        if method == Method::HEAD {
            response.body_mut().clear();
        }
        response
    }
}

async fn respond_for_route(
    route: AdminRoute,
    metrics: &PrometheusHttpApp,
    state: &RuntimeState,
    http_session: &mut ServerSession,
) -> Response<Vec<u8>> {
    match route {
        AdminRoute::Healthz => Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CONTENT_LENGTH, 2)
            .body(b"OK".to_vec())
            .unwrap(),
        AdminRoute::Readyz => match router_ready(&state.snapshot().router) {
            Ok(()) => Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/plain")
                .header(http::header::CONTENT_LENGTH, 2)
                .body(b"OK".to_vec())
                .unwrap(),
            Err(err) => {
                log::debug!("readiness check failed: {err}");
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .header(http::header::CONTENT_LENGTH, 9)
                    .body(b"NOT READY".to_vec())
                    .unwrap()
            }
        },
        AdminRoute::Metrics => {
            crate::metrics::replace_upstream_backend_readiness(
                state.snapshot().upstream_backend_readiness(),
            );
            metrics.response(http_session).await
        }
        AdminRoute::MethodNotAllowed => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(http::header::ALLOW, "GET, HEAD")
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(b"Method Not Allowed".to_vec())
            .unwrap(),
        AdminRoute::NotFound => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(b"Not Found".to_vec())
            .unwrap(),
    }
}

/// The [HttpServer] for [AdminHttpApp].
pub type AdminServer = HttpServer<AdminHttpApp>;

/// Build an [AdminServer] with gzip response compression enabled.
pub fn admin_server() -> AdminServer {
    admin_server_with_state(Arc::new(RuntimeState::bootstrap(CompiledRouter::default())))
}

pub fn admin_server_with_state(state: Arc<RuntimeState>) -> AdminServer {
    let mut server = AdminServer::new_app(AdminHttpApp::with_state(state));
    server.add_module(pingora::modules::http::compression::ResponseCompressionBuilder::enable(7));
    server
}

#[cfg(test)]
mod tests {
    use super::{AdminRoute, route_admin};
    use http::Method;

    #[test]
    fn route_healthz() {
        assert!(matches!(
            route_admin(&Method::GET, "/healthz"),
            AdminRoute::Healthz
        ));
    }

    #[test]
    fn route_readyz() {
        assert!(matches!(
            route_admin(&Method::GET, "/readyz"),
            AdminRoute::Readyz
        ));
    }

    #[test]
    fn route_metrics() {
        assert!(matches!(
            route_admin(&Method::HEAD, "/metrics"),
            AdminRoute::Metrics
        ));
    }

    #[test]
    fn route_unknown_path_is_not_found() {
        assert!(matches!(
            route_admin(&Method::GET, "/"),
            AdminRoute::NotFound
        ));
        assert!(matches!(
            route_admin(&Method::GET, "/foo"),
            AdminRoute::NotFound
        ));
    }

    #[test]
    fn route_rejects_non_read_methods() {
        assert!(matches!(
            route_admin(&Method::POST, "/metrics"),
            AdminRoute::MethodNotAllowed
        ));
    }

    #[tokio::test]
    async fn admin_metrics_uses_the_application_registry() {
        use super::AdminHttpApp;
        use pingora::apps::http_app::ServeHttp;
        use pingora::protocols::http::ServerSession;
        use tokio::io::AsyncWriteExt;

        let counter =
            prometheus::IntCounter::new("ngxora_admin_registry_test_total", "Registry wiring test")
                .unwrap();
        prometheus::default_registry()
            .register(Box::new(counter.clone()))
            .unwrap();
        counter.inc();
        let app = AdminHttpApp::new();
        for (method, path, status) in [
            ("GET", "/metrics", 200),
            ("HEAD", "/metrics", 200),
            ("GET", "/healthz", 200),
            ("GET", "/readyz", 503),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            client
                .write_all(
                    format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut session = ServerSession::new_http1(Box::new(server));
            session.read_request().await.unwrap();
            let response = app.response(&mut session).await;
            assert_eq!(response.status().as_u16(), status);
            if path == "/metrics" && method == "GET" {
                let body = std::str::from_utf8(response.body()).unwrap();
                assert!(body.contains("ngxora_admin_registry_test_total 1"));
                assert!(
                    response.headers()["content-type"]
                        .to_str()
                        .unwrap()
                        .contains("text/plain")
                );
            }
            if method == "HEAD" {
                assert!(response.body().is_empty());
            }
        }
    }
}
