//! Admin HTTP application.
//!
//! Serves `/metrics` (Prometheus exposition) and `/healthz` (liveness) on a
//! single listener so deployments only need one `--metrics-addr` port for
//! both Prometheus scrapes and k8s/docker liveness probes.

use async_trait::async_trait;
use http::{Response, StatusCode};
use pingora::apps::http_app::{HttpServer, ServeHttp};
use pingora::apps::prometheus_http_app::PrometheusHttpApp;
use pingora::protocols::http::ServerSession;

const HEALTHZ_PATH: &str = "/healthz";
const METRICS_PATH: &str = "/metrics";

/// Admin HTTP app multiplexing Prometheus metrics and a liveness endpoint.
pub struct AdminHttpApp {
    metrics: PrometheusHttpApp,
}

impl AdminHttpApp {
    pub fn new() -> Self {
        Self {
            metrics: PrometheusHttpApp,
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
    Metrics,
    NotFound,
}

fn route_admin(path: &str) -> AdminRoute {
    match path {
        HEALTHZ_PATH => AdminRoute::Healthz,
        METRICS_PATH => AdminRoute::Metrics,
        _ => AdminRoute::NotFound,
    }
}

#[async_trait]
impl ServeHttp for AdminHttpApp {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = http_session.req_header().uri.path();
        respond_for_route(route_admin(path), &self.metrics, http_session).await
    }
}

async fn respond_for_route(
    route: AdminRoute,
    metrics: &PrometheusHttpApp,
    http_session: &mut ServerSession,
) -> Response<Vec<u8>> {
    match route {
        AdminRoute::Healthz => Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CONTENT_LENGTH, 2)
            .body(b"OK".to_vec())
            .unwrap(),
        AdminRoute::Metrics => metrics.response(http_session).await,
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
    let mut server = AdminServer::new_app(AdminHttpApp::new());
    server.add_module(
        pingora::modules::http::compression::ResponseCompressionBuilder::enable(7),
    );
    server
}

#[cfg(test)]
mod tests {
    use super::{AdminRoute, route_admin};

    #[test]
    fn route_healthz() {
        assert!(matches!(route_admin("/healthz"), AdminRoute::Healthz));
    }

    #[test]
    fn route_metrics() {
        assert!(matches!(route_admin("/metrics"), AdminRoute::Metrics));
    }

    #[test]
    fn route_unknown_path_is_not_found() {
        assert!(matches!(route_admin("/"), AdminRoute::NotFound));
        assert!(matches!(route_admin("/foo"), AdminRoute::NotFound));
    }
}
