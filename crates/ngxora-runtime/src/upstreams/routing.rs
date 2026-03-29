use super::types::{
    CompiledLocation, CompiledMatcher, CompiledRouter, ListenKey, ServerRoutes, VirtualHostRoutes,
};
use crate::server::DownstreamTlsInfo;
use pingora::Result as PingoraResult;
use pingora_proxy::Session;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Match order mirrors nginx semantics:
// exact > longest ^~ prefix > first matching regex > longest plain prefix.
pub(crate) fn select_route_target<'a>(
    routes: &'a ServerRoutes,
    path: &str,
) -> Option<&'a CompiledLocation> {
    let mut best_prefix: Option<(&CompiledLocation, usize)> = None;
    let mut best_prefer_prefix: Option<(&CompiledLocation, usize)> = None;

    for location in &routes.locations {
        match &location.matcher {
            CompiledMatcher::Exact(p) if path == p => return Some(location),
            CompiledMatcher::Prefix(p) if path.starts_with(p) => {
                if best_prefix.is_none_or(|(_, len)| p.len() > len) {
                    best_prefix = Some((location, p.len()));
                }
            }
            CompiledMatcher::PreferPrefix(p) if path.starts_with(p) => {
                if best_prefer_prefix.is_none_or(|(_, len)| p.len() > len) {
                    best_prefer_prefix = Some((location, p.len()));
                }
            }
            _ => {}
        }
    }

    if let Some((location, _)) = best_prefer_prefix {
        return Some(location);
    }

    for location in &routes.locations {
        if let CompiledMatcher::Regex(regex) = &location.matcher {
            if regex.is_match(path) {
                return Some(location);
            }
        }
    }

    best_prefix.map(|(location, _)| location)
}

fn normalize_authority_host(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn invalid_host_header() -> Box<pingora::Error> {
    pingora::Error::explain(
        pingora::ErrorType::HTTPStatus(400),
        "invalid host header value",
    )
}

fn normalize_request_host(value: &str) -> PingoraResult<String> {
    if value.contains('@') || value.contains(',') {
        return Err(invalid_host_header());
    }

    let authority = value
        .parse::<http::uri::Authority>()
        .map_err(|_| invalid_host_header())?;
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err(invalid_host_header());
    }

    Ok(normalize_authority_host(host))
}

// Normalize the HTTP authority used for vhost routing and reject invalid
// header encodings up front.
fn request_host(session: &Session) -> PingoraResult<Option<String>> {
    let Some(host) = session.get_header("host") else {
        return Ok(None);
    };

    let host = host.to_str().map_err(|_| {
        pingora::Error::explain(
            pingora::ErrorType::HTTPStatus(400),
            "invalid host header encoding",
        )
    })?;

    Ok(Some(normalize_request_host(host)?))
}

fn downstream_sni(session: &Session) -> Option<String> {
    session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .and_then(|ssl| ssl.extension.get::<DownstreamTlsInfo>())
        .and_then(|info| info.sni.clone())
}

pub(crate) fn validate_sni_host_consistency(
    host: Option<&str>,
    sni: Option<&str>,
) -> PingoraResult<()> {
    if let (Some(host), Some(sni)) = (host, sni) {
        if host != sni {
            return Err(pingora::Error::explain(
                pingora::ErrorType::HTTPStatus(421),
                format!("tls sni `{sni}` does not match http host `{host}`"),
            ));
        }
    }

    Ok(())
}

fn request_is_tls(session: &Session) -> bool {
    session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .is_some()
}

// Listener lookup is based on the accepted downstream socket, not request
// headers, so shared :80/:443 sockets stay isolated correctly.
fn session_listen_key(session: &Session) -> PingoraResult<ListenKey> {
    let server_addr = session.server_addr().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "missing downstream server addr",
        )
    })?;

    let inet = server_addr.as_inet().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "downstream server addr is not inet (likely UDS)",
        )
    })?;

    Ok(ListenKey {
        addr: inet.ip(),
        port: inet.port(),
        ssl: request_is_tls(session),
    })
}

fn select_server_routes<'a>(
    vhosts: &'a VirtualHostRoutes,
    host: Option<&str>,
) -> Option<&'a ServerRoutes> {
    host.and_then(|value| vhosts.named.get(value))
        .or(vhosts.default.as_ref())
}

fn wildcard_listen_key(key: &ListenKey) -> ListenKey {
    ListenKey {
        addr: match key.addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        port: key.port,
        ssl: key.ssl,
    }
}

pub(crate) fn listener_routes<'a>(
    router: &'a CompiledRouter,
    listen_key: &ListenKey,
) -> Option<&'a VirtualHostRoutes> {
    router.listeners.get(listen_key).or_else(|| {
        let wildcard = wildcard_listen_key(listen_key);
        (wildcard != *listen_key)
            .then_some(wildcard)
            .and_then(|key| router.listeners.get(&key))
    })
}

#[derive(Debug)]
pub(super) struct ResolvedLocation<'a> {
    pub(super) location: &'a CompiledLocation,
    pub(super) host: Option<String>,
}

// Route resolution first pins the accepted listener, then enforces TLS
// authority consistency, and only after that chooses the vhost + location.
pub(super) fn resolve_route<'a>(
    router: &'a CompiledRouter,
    session: &Session,
) -> PingoraResult<Option<ResolvedLocation<'a>>> {
    let listen_key = session_listen_key(session)?;

    let Some(vhosts) = listener_routes(router, &listen_key) else {
        return Ok(None);
    };

    let host = request_host(session)?;
    let sni = listen_key.ssl.then(|| downstream_sni(session)).flatten();
    validate_sni_host_consistency(host.as_deref(), sni.as_deref())?;

    let routing_host = host.clone().or(sni);

    let Some(server_routes) = select_server_routes(vhosts, routing_host.as_deref()) else {
        return Ok(None);
    };

    let path = session.req_header().uri.path();
    let Some(location) = select_route_target(server_routes, path) else {
        return Ok(None);
    };

    Ok(Some(ResolvedLocation { location, host }))
}

#[cfg(test)]
mod tests {
    use super::normalize_request_host;

    #[test]
    fn normalize_request_host_strips_port_and_trailing_dot() {
        assert_eq!(
            normalize_request_host("Example.COM:443.").expect("host parses"),
            "example.com"
        );
    }

    #[test]
    fn normalize_request_host_accepts_ipv6_authority() {
        assert_eq!(
            normalize_request_host("[2001:db8::1]:8443").expect("host parses"),
            "2001:db8::1"
        );
    }

    #[test]
    fn normalize_request_host_rejects_userinfo() {
        let err = normalize_request_host("user@example.com").expect_err("userinfo is invalid");
        assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(400));
    }

    #[test]
    fn normalize_request_host_rejects_multi_host_values() {
        let err =
            normalize_request_host("example.com, other.example.com").expect_err("list is invalid");
        assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(400));
    }
}
