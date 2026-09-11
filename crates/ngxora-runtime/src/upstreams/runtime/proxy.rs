//! Pingora lifecycle: capture snapshot, enforce policy, select upstream, then stream the response.

use super::super::routing::listener_routes;
use super::super::types::{CompiledRouter, ListenKey, VirtualHostRoutes};
use super::limits::{restrict_client_max_body_size, update_received_body_bytes};
use super::response::{
    RequestHeaderEditor, apply_response_plugins, map_plugin_error, respond_from_plugin_flow,
    write_cached_response, write_route_response,
};
use super::selection::{
    location_allows_client, prefixed_upstream_uri, request_client_ip, select_backend_target,
    select_runtime_route,
};
use super::{
    DynamicProxy, ProxyContext, SelectedRoute, SelectedTarget, cache_store_allowed,
    runtime_config_error,
};
use crate::cache::{
    CacheBackend, build_cache_key, estimated_headers_size, is_cacheable, is_cacheable_request,
};
use crate::control::{ApplyResult, ConfigSnapshot, RuntimeSnapshot, RuntimeState};
use crate::le::ChallengeTokens;
use async_trait::async_trait;
use bytes::Bytes;
use ngxora_compile::ir::UpstreamHttpProtocol;
use ngxora_plugin_api::{LocalResponse, PluginFlow, RequestCtx, UpstreamRequestCtx};
use opentelemetry::trace::{Span, TraceContextExt};
use pingora::Result as PingoraResult;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::time::Duration;

impl DynamicProxy {
    async fn try_cache(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
        host: Option<&str>,
    ) -> PingoraResult<bool> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(false);
        };
        // Authentication, rate limiting, and other request plugins must run
        // before a cache hit can terminate the request.
        if is_cacheable_request(&session.req_header().method, &session.req_header().headers)
            && let Some(cache_cfg) = &selected.cache
        {
            let full_uri = session.req_header().uri.to_string();
            let cache_key = build_cache_key(
                &session.req_header().method,
                &full_uri,
                ctx.snapshot_generation,
                selected.route_id(),
                host.unwrap_or(""),
                cache_cfg,
            );
            if let Some(cached) = self.cache_backend.get(&cache_key, cache_cfg).await {
                ctx.cache_hit = true;
                write_cached_response(session, &cached).await?;
                return Ok(true);
            }
            ctx.cache_store_allowed = self.cache_backend.record_miss(&cache_key, cache_cfg);
            ctx.cache_key = Some(cache_key);
        }

        Ok(false)
    }

    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            cache_backend: CacheBackend::new(50 * 1024 * 1024), // 50MB default
            challenge_tokens: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn new_with_cache(state: Arc<RuntimeState>, cache_backend: CacheBackend) -> Self {
        Self {
            state,
            cache_backend,
            challenge_tokens: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Set the challenge token store (called after LE manager is created).
    pub fn set_challenge_tokens(&mut self, tokens: ChallengeTokens) {
        self.challenge_tokens = tokens;
    }

    pub fn from_router(routing: CompiledRouter) -> Self {
        Self::new(Arc::new(RuntimeState::bootstrap(routing)))
    }

    pub fn runtime_state(&self) -> &Arc<RuntimeState> {
        &self.state
    }

    /// Retrieve routes for a specific key (lock-free).
    pub fn get_routes(&self, key: &ListenKey) -> Option<Arc<VirtualHostRoutes>> {
        let snapshot = self.state.snapshot();
        listener_routes(&snapshot.router, key)
            .cloned()
            .map(Arc::new)
    }

    /// Replace the entire routing table if listener topology stays compatible.
    pub fn update_routing(&self, new_router: CompiledRouter) -> ApplyResult {
        self.state
            .apply_snapshot(ConfigSnapshot::new("runtime-update", new_router))
    }
}

#[async_trait]
impl ProxyHttp for DynamicProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    // Request plugins run in declaration order and may terminate the request
    // locally before any upstream peer is selected.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        // ── Tracing: extract parent context from downstream headers ──
        ctx.parent_ctx = crate::tracing::extract_context(&session.req_header().headers);
        let method = session.req_header().method.to_string();
        let path = session.req_header().uri.path().to_string();
        let span = crate::tracing::start_request_span(&method, &path, &ctx.parent_ctx);
        ctx.upstream_trace_ctx =
            opentelemetry::Context::new().with_remote_span_context(span.span_context().clone());
        ctx.span = Some(span);

        let snapshot = self.state.snapshot();
        session.set_keepalive(snapshot.router.http_options.downstream_keepalive_timeout);
        ctx.snapshot = Some(snapshot.clone());
        ctx.snapshot_generation = snapshot.generation;
        ctx.client_max_body_size = snapshot.router.http_options.client_max_body_size;
        ctx.received_body_bytes = 0;

        self.cache_backend
            .advance_generation(self.state.generation());

        if restrict_client_max_body_size(session, ctx).await? {
            return Ok(true);
        }

        // Let's Encrypt HTTP-01 challenge responder.
        if let Some(token) = session
            .req_header()
            .uri
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
            && !token.is_empty()
            && !token.contains('/')
            && let Some(key_auth) = self.challenge_tokens.get(token).map(|v| v.clone())
        {
            let mut response = LocalResponse::new(http::StatusCode::OK, "");
            response.headers.push((
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain"),
            ));
            response.body = key_auth.into_bytes().into();
            session.set_keepalive(None);
            write_route_response(session, ctx, response).await?;
            return Ok(true);
        }

        let Some((mut selected, host)) = select_runtime_route(&snapshot, session)? else {
            ctx.selected = None;
            return Ok(false);
        };

        ctx.selected = Some(selected.clone());
        let method = session.req_header().method.clone();
        let request_was_cacheable = is_cacheable_request(&method, &session.req_header().headers);
        if authorize_request(session, ctx, &selected, host.as_deref()).await? {
            return Ok(true);
        }

        if prepare_scp_request(session, ctx, &snapshot, &selected).await? {
            return Ok(true);
        }

        if request_was_cacheable && self.try_cache(session, ctx, host.as_deref()).await? {
            return Ok(true);
        }

        if let SelectedTarget::Pending(target) = &selected.target {
            selected.target = select_backend_target(&snapshot, selected.route_id, target, session)?;
            ctx.selected = Some(selected.clone());
        }
        respond_to_selected_target(session, ctx, &selected).await
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Classic WebSocket upgrades switch the downstream body stream into a
        // raw upgraded tunnel after the 101 response. That traffic must not be
        // counted against HTTP request body limits.
        if session.was_upgraded() {
            return Ok(());
        }

        update_received_body_bytes(
            &mut ctx.received_body_bytes,
            body.as_ref(),
            ctx.client_max_body_size,
        )
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(());
        };

        if let Some(rewrite) = &selected.url_rewrite {
            let uri = super::super::http_routes::rewrite_uri(
                &upstream_request.uri,
                rewrite.path.as_ref(),
                selected.matched_prefix.as_deref(),
            )
            .map_err(runtime_config_error)?;
            upstream_request.set_uri(uri);
            if let Some(hostname) = &rewrite.hostname {
                upstream_request.insert_header(http::header::HOST, hostname.as_str())?;
            }
        }
        if let SelectedTarget::Upstream(peer) = &selected.target
            && let Some(prefix) = peer.api_prefix.as_deref()
        {
            let uri = prefixed_upstream_uri(&upstream_request.uri, prefix)
                .map_err(|err| pingora::Error::explain(pingora::ErrorType::InternalError, err))?;
            upstream_request.set_uri(uri);
        }

        let mut headers = RequestHeaderEditor {
            inner: upstream_request,
        };

        for plugin in selected.plugins.iter() {
            let flow = plugin
                .on_upstream_request(&mut UpstreamRequestCtx {
                    state: &mut ctx.plugin_state,
                    headers: &mut headers,
                })
                .await
                .map_err(|err| map_plugin_error("upstream_request_filter", err))?;
            respond_from_plugin_flow(flow, "upstream_request_filter")?;
        }

        // ── Inject W3C TraceContext into upstream headers ──
        let mut trace_headers = http::HeaderMap::new();
        crate::tracing::inject_context(&ctx.upstream_trace_ctx, &mut trace_headers);
        for (name, value) in &trace_headers {
            upstream_request.insert_header(name, value)?;
        }
        if let Some(exchange) = &ctx.scp {
            upstream_request.set_uri(exchange.upstream_uri().map_err(|e| {
                pingora::Error::explain(pingora::ErrorType::HTTPStatus(e.status), e.detail)
            })?);
            exchange.request_headers(upstream_request)?;
        }

        Ok(())
    }

    /// Serve a stale cached response when upstream returns an error.
    ///
    /// Only activates when the location has `proxy_cache_stale_if_error`
    /// configured and a cached entry exists (TTL is ignored for stale).
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        proxy_error: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        self.cache_backend
            .advance_generation(self.state.generation());
        if let Some(profile) = ctx.scp_profile.clone() {
            use pingora::{ErrorSource, ErrorType};
            let error = match proxy_error.etype() {
                ErrorType::HTTPStatus(504) => super::super::scp::ScpError::target_unreachable(),
                ErrorType::HTTPStatus(status) => super::super::scp::ScpError::new(
                    *status,
                    "UNSPECIFIED_MSG_FAILURE",
                    "HTTP request failed",
                ),
                _ if proxy_error.esource() == &ErrorSource::Upstream => {
                    super::super::scp::ScpError::target_unreachable()
                }
                _ if proxy_error.esource() == &ErrorSource::Downstream => {
                    super::super::scp::ScpError::new(
                        400,
                        "UNSPECIFIED_MSG_FAILURE",
                        "Downstream request failed",
                    )
                }
                _ => super::super::scp::ScpError::new(
                    500,
                    "SYSTEM_FAILURE",
                    "Internal proxy failure",
                ),
            };
            crate::metrics::record_scp_event(&profile.config.name, error.cause);
            // Never append a ProblemDetails document to an already streaming response.
            if let Some(response) = session.response_written() {
                return pingora_proxy::FailToProxy {
                    can_reuse_downstream: false,
                    error_code: response.status.as_u16(),
                };
            }
            if let Err(write_error) =
                write_route_response(session, ctx, error.response(&profile.root.host)).await
            {
                log::debug!("SCP error response could not be delivered: {write_error}");
                if session.response_written().is_none()
                    && let Err(error) = session.respond_error(500).await
                {
                    log::debug!("failed to send fallback HTTP error: {error}");
                }
            }
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: session
                    .response_written()
                    .map_or(error.status, |r| r.status.as_u16()),
            };
        }
        if let Some(response) = session.response_written() {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: response.status.as_u16(),
            };
        }
        if proxy_error.esource() == &pingora::ErrorSource::Upstream {
            let cache = ctx
                .selected
                .as_ref()
                .and_then(|route| route.cache.as_ref())
                .filter(|cache| cache.stale_if_error.is_some());
            let cached = match (cache, &ctx.cache_key) {
                (Some(cache), Some(key)) => self.cache_backend.get_stale(key, cache).await,
                _ => None,
            };
            if let Some(mut cached) = cached {
                cached.headers.insert(
                    http::HeaderName::from_static("x-cache"),
                    http::HeaderValue::from_static("STALE"),
                );
                ctx.cache_hit = true;
                let can_reuse_downstream = match write_cached_response(session, &cached).await {
                    Ok(()) => true,
                    Err(error) => {
                        log::debug!("failed to send stale response: {error}");
                        false
                    }
                };
                return pingora_proxy::FailToProxy {
                    can_reuse_downstream,
                    error_code: cached.status.as_u16(),
                };
            }
        }
        let code = match proxy_error.etype() {
            pingora::ErrorType::HTTPStatus(code) => *code,
            _ => match proxy_error.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => 400,
                _ => 500,
            },
        };
        let status =
            http::StatusCode::from_u16(code).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
        let response = LocalResponse::new(status, "");
        if let Err(error) = write_route_response(session, ctx, response).await {
            log::debug!("failed to send HTTP error response: {error}");
            if session.response_written().is_none()
                && let Err(error) = session.respond_error(500).await
            {
                log::debug!("failed to send fallback HTTP error: {error}");
            }
        }
        pingora_proxy::FailToProxy {
            can_reuse_downstream: false,
            error_code: session
                .response_written()
                .map_or(code, |r| r.status.as_u16()),
        }
    }

    // Response plugins run in reverse order so they behave like unwind-style
    // middleware around the upstream exchange.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(());
        };

        let selected = selected.clone();
        apply_response_plugins(upstream_response, ctx).await?;
        let status = upstream_response.status;
        if let Some(exchange) = &ctx.scp {
            exchange.response_headers(upstream_response)?;
        }

        // Cacheability must be evaluated against the final response that the
        // client will actually receive after plugins mutate headers/status.
        if let (Some(_cache_key), Some(cache_cfg)) = (&ctx.cache_key, selected.cache.as_ref())
            && cache_store_allowed(cache_cfg, ctx.cache_store_allowed)
            && is_cacheable(status, &upstream_response.headers, cache_cfg)
        {
            let entry_overhead = estimated_headers_size(&upstream_response.headers)
                .saturating_add(128)
                .saturating_add(_cache_key.estimated_size());
            let body_limit = self
                .cache_backend
                .max_size(cache_cfg)
                .saturating_sub(entry_overhead);
            let content_length_fits = upstream_response
                .headers
                .get(http::header::CONTENT_LENGTH)
                .map(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|length| length <= body_limit)
                })
                .unwrap_or(true);

            if content_length_fits {
                ctx.cache_status = Some(status);
                ctx.cache_headers = Some(upstream_response.headers.clone());
                ctx.cache_body_limit = Some(body_limit);
            }
        }

        Ok(())
    }

    /// Collect upstream response body chunks for later caching in `logging`.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Option<Duration>> {
        let Some(body_limit) = ctx.cache_body_limit else {
            return Ok(None);
        };

        if let Some(chunk) = body.as_ref() {
            let next_size = (ctx.response_body_buf.len() as u64).saturating_add(chunk.len() as u64);
            if next_size > body_limit {
                ctx.cache_status = None;
                ctx.cache_headers = None;
                ctx.cache_body_limit = None;
                ctx.response_body_buf.clear();
                return Ok(None);
            }

            ctx.response_body_buf.extend_from_slice(chunk);
        }
        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        self.finish_request(session, e, ctx).await;
    }

    // Upstream selection is derived from the already resolved route; if the
    // request_filter path did not run, we resolve lazily here as a fallback.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let mut selected = if let Some(selected) = ctx.selected.as_ref().cloned() {
            selected
        } else {
            let snapshot = ctx
                .snapshot
                .clone()
                .unwrap_or_else(|| self.state.snapshot());
            ctx.snapshot = Some(snapshot.clone());
            ctx.snapshot_generation = snapshot.generation;
            let Some((selected, _host)) = select_runtime_route(&snapshot, session)? else {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::HTTPStatus(404),
                    "no location matched",
                ));
            };
            ctx.selected = Some(selected.clone());
            selected
        };

        if let SelectedTarget::Pending(target) = &selected.target {
            let snapshot = ctx
                .snapshot
                .clone()
                .unwrap_or_else(|| self.state.snapshot());
            selected.target = select_backend_target(&snapshot, selected.route_id, target, session)?;
            ctx.selected = Some(selected.clone());
        }
        let peer = match &selected.target {
            SelectedTarget::Scp(_) => {
                let exchange = ctx.scp.as_ref().ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        "SCP request was not authorized",
                    )
                })?;
                ctx.upstream_attempted = true;
                let tls = exchange.root.scheme == "https";
                // HttpPeer::new unwraps DNS failures. Resolve asynchronously and
                // bound the lookup before handing Pingora a concrete address.
                let address = tokio::time::timeout(
                    selected
                        .upstream_timeouts
                        .connect
                        .unwrap_or(Duration::from_secs(5)),
                    tokio::net::lookup_host((
                        exchange.backend.host.as_str(),
                        exchange.backend.port,
                    )),
                )
                .await
                .map_err(|_| {
                    pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(504),
                        "SCP target DNS timeout",
                    )
                })?
                .map_err(|e| {
                    pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(504),
                        format!("SCP target DNS failure: {e}"),
                    )
                })?
                .next()
                .ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(504),
                        "SCP target DNS returned no addresses",
                    )
                })?;
                let mut peer = HttpPeer::new(address, tls, exchange.root.host.clone());
                selected.configure_peer(
                    &mut peer,
                    ctx.snapshot_generation,
                    Some(if tls {
                        UpstreamHttpProtocol::H2
                    } else {
                        UpstreamHttpProtocol::H2c
                    }),
                )?;
                return Ok(Box::new(peer));
            }
            SelectedTarget::Upstream(peer) => peer,
            SelectedTarget::Return { .. }
            | SelectedTarget::Pending(_)
            | SelectedTarget::DirectResponse(_) => {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    "upstream_peer called on a return target — request_filter should have short-circuited",
                ));
            }
        };
        ctx.upstream_attempted = true;

        let mut http_peer =
            HttpPeer::new((peer.host.as_str(), peer.port), peer.tls, peer.sni.clone());
        selected.configure_peer(
            &mut http_peer,
            ctx.snapshot_generation,
            selected.upstream_protocol,
        )?;

        Ok(Box::new(http_peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut error: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        if let Some(exchange) = &mut ctx.scp {
            error.retry = exchange.retry_connect().into();
        }
        error
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        mut error: Box<pingora::Error>,
        ctx: &mut Self::CTX,
        reused: bool,
    ) -> Box<pingora::Error> {
        if ctx.scp_profile.is_some()
            || !session.req_header().method.is_idempotent()
            || session.as_ref().retry_buffer_truncated()
        {
            error.retry = false.into();
        } else {
            error = error.more_context(format!("Peer: {peer}"));
            error
                .retry
                .decide_reuse(reused && !session.as_ref().retry_buffer_truncated());
        }
        error
    }
}

async fn authorize_request(
    session: &mut Session,
    ctx: &mut ProxyContext,
    selected: &SelectedRoute,
    host: Option<&str>,
) -> PingoraResult<bool> {
    let path = session.req_header().uri.path().to_string();
    let method = session.req_header().method.clone();
    let client_ip = request_client_ip(session);
    if !location_allows_client(&selected.access_rules, client_ip) {
        session.set_keepalive(None);
        write_route_response(
            session,
            ctx,
            LocalResponse::new(http::StatusCode::FORBIDDEN, ""),
        )
        .await?;
        return Ok(true);
    }

    let mut headers = RequestHeaderEditor {
        inner: session.downstream_session.req_header_mut(),
    };

    for plugin in selected.plugins.iter() {
        let flow = plugin
            .on_request(&mut RequestCtx {
                state: &mut ctx.plugin_state,
                path: &path,
                host,
                method: &method,
                client_ip,
                headers: &mut headers,
            })
            .await
            .map_err(|err| map_plugin_error("request_filter", err))?;
        if let PluginFlow::Respond(response) = flow {
            session.set_keepalive(None);
            write_route_response(session, ctx, response).await?;
            return Ok(true);
        }
    }

    Ok(false)
}

async fn prepare_scp_request(
    session: &mut Session,
    ctx: &mut ProxyContext,
    snapshot: &RuntimeSnapshot,
    selected: &SelectedRoute,
) -> PingoraResult<bool> {
    let client_ip = request_client_ip(session);
    if let SelectedTarget::Scp(name) = &selected.target {
        let profile = snapshot.scp_profiles.get(name).cloned().ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "SCP profile missing in snapshot",
            )
        })?;
        ctx.scp_profile = Some(profile.clone());
        if session.req_header().version != http::Version::HTTP_2 {
            let error = super::super::scp::ScpError::new(
                505,
                "UNSPECIFIED_MSG_FAILURE",
                "SCP requires HTTP/2",
            );
            write_route_response(session, ctx, error.response(&profile.root.host)).await?;
            return Ok(true);
        }
        let request = super::super::scp::ScpRequest::parse(
            &session.req_header().headers,
            &session.req_header().method,
            &session.req_header().uri,
            &profile.root,
        );
        let result = match request {
            Ok(request) => {
                profile
                    .route(
                        request,
                        &session.req_header().headers,
                        client_ip
                            .map(|ip| ip.to_string())
                            .unwrap_or_default()
                            .as_bytes(),
                    )
                    .await
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(exchange) => {
                crate::metrics::record_scp_event(
                    name,
                    if exchange.request.bound {
                        "binding"
                    } else {
                        "route"
                    },
                );
                ctx.scp = Some(exchange);
            }
            Err(error) => {
                crate::metrics::record_scp_event(name, error.cause);
                write_route_response(session, ctx, error.response(&profile.root.host)).await?;
                return Ok(true);
            }
        }
    }

    Ok(false)
}

async fn respond_to_selected_target(
    session: &mut Session,
    ctx: &mut ProxyContext,
    selected: &SelectedRoute,
) -> PingoraResult<bool> {
    if let SelectedTarget::DirectResponse(status) = selected.target {
        let status = http::StatusCode::from_u16(status).map_err(runtime_config_error)?;
        write_route_response(session, ctx, LocalResponse::new(status, "")).await?;
        return Ok(true);
    }
    // Handle return/redirect targets
    if let SelectedTarget::Return { status, location } = &selected.target {
        let status_code = http::StatusCode::from_u16(*status).map_err(|_| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("invalid redirect status code: {status}"),
            )
        })?;

        let mut response = LocalResponse::new(status_code, "");
        response.headers.push((
            http::header::LOCATION,
            http::HeaderValue::from_str(location).map_err(|_| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("invalid redirect location: {location}"),
                )
            })?,
        ));

        session.set_keepalive(None);
        write_route_response(session, ctx, response).await?;
        return Ok(true);
    }

    Ok(false)
}
