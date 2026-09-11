//! Resolve routes and select backend targets against the captured snapshot.

use super::super::compile::proxy_pass_sni;
use super::super::routing::{ResolvedLocation, resolve_route};
use super::super::types::RouteTarget;
use super::{SelectedPeer, SelectedRoute, SelectedTarget, runtime_config_error};
use crate::control::RuntimeSnapshot;
use ngxora_compile::ir::UpstreamHashKey;
use pingora::Result as PingoraResult;
use pingora_proxy::Session;
use std::sync::atomic::Ordering;

pub(super) fn prefixed_upstream_uri(uri: &http::Uri, prefix: &str) -> Result<http::Uri, String> {
    let mut path_and_query = String::with_capacity(
        prefix
            .len()
            .saturating_add(uri.path_and_query().map_or(1, |value| value.as_str().len())),
    );
    path_and_query.push_str(prefix);
    path_and_query.push_str(uri.path());
    if let Some(query) = uri.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }

    path_and_query
        .parse()
        .map_err(|err| format!("failed to apply NRF apiPrefix `{prefix}`: {err}"))
}

impl SelectedRoute {
    fn from_resolved(
        snapshot: &RuntimeSnapshot,
        resolved: &ResolvedLocation<'_>,
        session: &Session,
    ) -> PingoraResult<Self> {
        let matched_prefix = match &resolved.location.matcher {
            super::super::types::CompiledMatcher::Http(ngxora_compile::ir::HttpMatch {
                path: ngxora_compile::ir::HttpPathMatch::PathPrefix(prefix),
                ..
            }) => Some(prefix.clone()),
            _ => None,
        };
        let scheme = if session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some()
        {
            "https"
        } else {
            "http"
        };
        let host = resolved.host.as_deref().unwrap_or("");
        let target = match &resolved.location.target {
            RouteTarget::Scp { profile } => SelectedTarget::Scp(profile.clone()),
            RouteTarget::Return { status, location } => SelectedTarget::Return {
                status: *status,
                location: super::super::http_routes::expand_return(
                    location,
                    host,
                    session
                        .req_header()
                        .uri
                        .path_and_query()
                        .map_or("/", |p| p.as_str()),
                    scheme,
                )
                .map_err(runtime_config_error)?,
            },
            RouteTarget::HttpRedirect(config) => {
                let port = session
                    .server_addr()
                    .and_then(|s| s.as_inet())
                    .map(|s| s.port())
                    .ok_or_else(|| runtime_config_error("missing listener port"))?;
                SelectedTarget::Return {
                    status: config.status,
                    location: super::super::http_routes::redirect_location(
                        config,
                        &session.req_header().uri,
                        host,
                        scheme,
                        port,
                        matched_prefix.as_deref(),
                    )
                    .map_err(runtime_config_error)?,
                }
            }
            RouteTarget::DirectResponse(status) => SelectedTarget::DirectResponse(*status),
            target => SelectedTarget::Pending(target.clone()),
        };

        let upstream_client_identity = match (
            resolved
                .location
                .upstream_ssl_options
                .client_certificate
                .as_ref(),
            resolved
                .location
                .upstream_ssl_options
                .client_certificate_key
                .as_ref(),
        ) {
            (Some(cert), Some(key)) => {
                Some(snapshot.client_identity(cert, key).ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        "compiled upstream client identity is missing at runtime",
                    )
                })?)
            }
            _ => None,
        };

        Ok(Self {
            url_rewrite: resolved.location.url_rewrite.clone(),
            matched_prefix,
            route_id: resolved.location.route_id,
            access_rules: resolved.location.access_rules.clone(),
            target,
            upstream_timeouts: resolved.location.upstream_timeouts,
            upstream_protocol: resolved.location.upstream_protocol,
            upstream_http2: resolved.location.upstream_http2,
            upstream_ssl_options: resolved.location.upstream_ssl_options.clone(),
            upstream_trusted_ca: resolved
                .location
                .upstream_ssl_options
                .trusted_certificate
                .as_ref()
                .map(|source| {
                    snapshot.trusted_ca(source).ok_or_else(|| {
                        pingora::Error::explain(
                            pingora::ErrorType::InternalError,
                            "compiled trusted upstream CA is missing at runtime",
                        )
                    })
                })
                .transpose()?,
            upstream_client_identity,
            plugins: snapshot.plugin_chain(resolved.location.route_id),
            cache: resolved.location.cache.clone().map(|mut cache| {
                cache.max_size = cache
                    .max_size
                    .or(snapshot.router.http_options.proxy_cache_max_size);
                cache
            }),
        })
    }
}

pub(super) fn select_runtime_route(
    snapshot: &RuntimeSnapshot,
    session: &Session,
) -> PingoraResult<Option<(SelectedRoute, Option<String>)>> {
    let Some(resolved) = resolve_route(&snapshot.router, session)? else {
        return Ok(None);
    };

    Ok(Some((
        SelectedRoute::from_resolved(snapshot, &resolved, session)?,
        resolved.host,
    )))
}

pub(super) fn select_backend_target(
    snapshot: &RuntimeSnapshot,
    route_id: u64,
    target: &RouteTarget,
    session: &Session,
) -> PingoraResult<SelectedTarget> {
    let unavailable =
        || pingora::Error::explain(pingora::ErrorType::HTTPStatus(503), "no available backends");
    match target {
        RouteTarget::WeightedBackends(backends) => {
            let total: u64 = backends.iter().map(|b| u64::from(b.weight)).sum();
            if total == 0 {
                return Err(unavailable());
            }
            let counter = snapshot
                .backend_counters
                .get(&route_id)
                .ok_or_else(|| runtime_config_error("missing backend selector"))?;
            let mut slot = counter.fetch_add(1, Ordering::Relaxed) % total;
            for backend in backends {
                if slot < u64::from(backend.weight) {
                    return select_backend_target(snapshot, route_id, &backend.target, session);
                }
                slot -= u64::from(backend.weight);
            }
            Err(runtime_config_error("invalid backend weight sum"))
        }
        RouteTarget::DirectResponse(status) => Ok(SelectedTarget::DirectResponse(*status)),
        RouteTarget::ProxyPass {
            host,
            port,
            tls,
            sni,
        } => Ok(SelectedTarget::Upstream(SelectedPeer {
            host: host.clone(),
            port: *port,
            tls: *tls,
            sni: sni.clone(),
            upstream_group: None,
            api_prefix: None,
        })),
        RouteTarget::UpstreamGroup { name, tls } => {
            let group = snapshot
                .upstream_group(name)
                .ok_or_else(|| runtime_config_error("missing upstream group"))?;
            let key = if group.uses_consistent_hash() {
                upstream_selection_key(group.hash_key(), session)?
            } else {
                Vec::new()
            };
            let backend = group.select(&key).ok_or_else(unavailable)?;
            Ok(SelectedTarget::Upstream(SelectedPeer {
                sni: proxy_pass_sni(&backend.host, *tls),
                host: backend.host,
                port: backend.port,
                tls: *tls,
                upstream_group: Some(name.trim_end_matches('.').to_ascii_lowercase()),
                api_prefix: backend.api_prefix,
            }))
        }
        _ => Err(runtime_config_error("invalid backend target")),
    }
}

pub(crate) fn upstream_selection_key(
    configured: Option<&UpstreamHashKey>,
    session: &Session,
) -> PingoraResult<Vec<u8>> {
    if let Some(UpstreamHashKey::Header(name)) = configured {
        let mut values = session.req_header().headers.get_all(name).iter();
        if let (Some(value), None) = (values.next(), values.next())
            && !value.as_bytes().is_empty()
        {
            return Ok(value.as_bytes().to_vec());
        }
    }

    request_client_ip(session)
        .map(|ip| ip.to_string().into_bytes())
        .ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::HTTPStatus(503),
                "consistent hash requires a request header key or socket client IP",
            )
        })
}

pub(super) fn request_client_ip(session: &Session) -> Option<std::net::IpAddr> {
    session
        .downstream_session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip())
}

pub(super) fn location_allows_client(
    rules: &[ngxora_compile::ir::LocationIpRule],
    client_ip: Option<std::net::IpAddr>,
) -> bool {
    if rules.is_empty() {
        return true;
    }

    let Some(ip) = client_ip else {
        return false;
    };

    for rule in rules {
        if rule.matches(&ip) {
            return rule.is_allow();
        }
    }

    false
}
