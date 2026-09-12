use crate::{control::RuntimeState, upstreams::DynamicProxy};
use async_trait::async_trait;
use pingora::{
    apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream},
    protocols::http::{ServerSession, v2::server::H2Options},
    server::{ShutdownWatch, configuration::ServerConf},
    services::listening::Service,
};
use pingora_proxy::HttpProxy;
use std::sync::Arc;

pub(crate) struct HeaderComplete(pub tokio::sync::oneshot::Sender<()>);

/// Set a header deadline before Pingora reads the request, including keepalive reuse.
pub struct ClientTimeoutProxy {
    pub(super) inner: Arc<HttpProxy<DynamicProxy>>,
    state: Arc<RuntimeState>,
}

pub fn http_proxy_service(
    conf: &Arc<ServerConf>,
    app: DynamicProxy,
    state: Arc<RuntimeState>,
) -> Service<ClientTimeoutProxy> {
    let mut inner = HttpProxy::new(app, conf.clone());
    inner.handle_init_modules();
    Service::new(
        "HTTP Proxy".into(),
        ClientTimeoutProxy {
            inner: Arc::new(inner),
            state,
        },
    )
}

#[async_trait]
impl HttpServerApp for ClientTimeoutProxy {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        let timeout = self
            .state
            .snapshot()
            .router
            .http_options
            .client_header_timeout;
        // H2 delivers complete headers before creating a stream session.
        if !matches!(session, ServerSession::H1(_)) {
            return self.inner.process_new_http(session, shutdown).await;
        }
        let Some(timeout) = timeout else {
            return self.inner.process_new_http(session, shutdown).await;
        };
        // Pingora has a built-in H1 read timeout. Disable it here: the deadline
        // below covers the complete header, even when bytes arrive slowly.
        session.set_read_timeout(None);
        if timeout.is_zero() {
            return self.inner.process_new_http(session, shutdown).await;
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        session.set_connection_user_context(Some(Box::new(HeaderComplete(sender))));
        let request = self.inner.process_new_http(session, shutdown);
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => return result,
            _ = tokio::time::sleep(timeout) => {
                log::warn!("client_header_timeout expired; closing HTTP/1 connection");
                return None;
            }
            _ = receiver => {}
        }
        request.await
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.inner.server_options()
    }
    fn h2_options(&self) -> Option<H2Options> {
        self.inner.h2_options()
    }
    async fn http_cleanup(&self) {
        self.inner.http_cleanup().await;
    }
}
