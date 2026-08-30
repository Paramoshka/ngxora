use super::types::{
    CompiledHealthCheck, CompiledLocation, CompiledMatcher, CompiledNrfDiscovery, CompiledRouter,
    CompiledUpstreamGroup, CompiledUpstreamServer, HealthCheckType, HttpRuntimeOptions, ListenKey,
    ListenerProtocolConfig, ListenerTlsConfig, ListenerTlsSettings, RouteTarget, ServerRoutes,
};
use ngxora_compile::ir::{
    DownstreamTlsOptions, Http, KeepaliveTimeout, Listen, Location, LocationDirective,
    NrfDiscovery, PemSource, ProxyPassTarget, Server, SslProvider, Switch, TlsIdentity,
    UpstreamBlock, UpstreamHealthCheck, UpstreamHealthCheckType, UpstreamHttpProtocol,
    UpstreamSelectionPolicy, UpstreamServer, UpstreamSslOptions, UpstreamTimeouts,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

impl CompiledRouter {
    pub fn from_http(http: &Http) -> Result<Self, String> {
        if matches!(http.tcp_nodelay, Switch::Off) {
            return Err(
                "tcp_nodelay off is not supported: Pingora enables TCP_NODELAY on accepted downstream sockets"
                    .into(),
            );
        }

        let mut router = Self {
            upstreams: compile_upstreams(&http.upstreams)?,
            http_options: HttpRuntimeOptions {
                downstream_keepalive_timeout: downstream_keepalive_timeout_secs(
                    &http.keepalive_timeout,
                ),
                keepalive_requests: http.keepalive_requests,
                client_max_body_size: http.client_max_body_size,
                proxy_cache_max_size: http.proxy_cache_max_size,
                tcp_nodelay: matches!(http.tcp_nodelay, Switch::On),
                allow_connect_method_proxying: matches!(
                    http.allow_connect_method_proxying,
                    Switch::On
                ),
                h2c: matches!(http.h2c, Switch::On),
            },
            le_config: http.ssl_provider.clone(),
            ..Self::default()
        };
        let mut next_route_id = 1;

        for server in &http.servers {
            router.add_server(server, &mut next_route_id)?;
        }

        Ok(router)
    }

    fn add_server(&mut self, server: &Server, next_route_id: &mut u64) -> Result<(), String> {
        if matches!(server.tls, Some(SslProvider::LetsEncrypt)) && server.server_names.len() != 1 {
            return Err(
                "ssl listener with LetsEncrypt currently supports exactly one server_name; split aliases into separate server blocks or use a manual certificate"
                    .into(),
            );
        }

        let routes = ServerRoutes {
            locations: compile_locations(&server.locations, &self.upstreams, next_route_id)?,
        };

        for listen in &server.listens {
            let listen_key = ListenKey::from(listen);
            self.merge_listener_protocols(&listen_key, listen)?;
            let listener = self.listeners.entry(listen_key.clone()).or_default();

            for name in &server.server_names {
                listener
                    .named
                    .insert(name.to_ascii_lowercase(), routes.clone());
            }

            if listen.default_server
                || (server.server_names.is_empty() && listener.default.is_none())
            {
                listener.default = Some(routes.clone());
            }

            if listen.ssl {
                self.merge_listener_tls_settings(&listen_key, &server.tls_options)?;
                let listener_tls =
                    self.listener_tls
                        .entry(listen_key)
                        .or_insert_with(|| ListenerTlsConfig {
                            settings: ListenerTlsSettings::from(&server.tls_options),
                            ..ListenerTlsConfig::default()
                        });

                if let Some(provider) = server.tls.as_ref() {
                    let tls_identity = match provider {
                        SslProvider::Custom(tls) => tls.clone(),
                        SslProvider::LetsEncrypt => {
                            let cache_dir = self
                                .le_config
                                .as_ref()
                                .and_then(|c| c.cache_dir.clone())
                                .unwrap_or_else(|| PathBuf::from("/var/lib/ngxora/certs"));
                            // Use the first server_name as the primary domain.
                            let domain = server.server_names.first().cloned().unwrap_or_default();
                            TlsIdentity {
                                cert: PemSource::Path(
                                    cache_dir.join(&domain).join("fullchain.pem"),
                                ),
                                key: PemSource::Path(cache_dir.join(&domain).join("privkey.pem")),
                            }
                        }
                    };

                    for name in &server.server_names {
                        listener_tls
                            .named
                            .insert(name.to_ascii_lowercase(), tls_identity.clone());
                    }

                    if listen.default_server
                        || listener_tls.default.is_none()
                        || server.server_names.is_empty()
                    {
                        listener_tls.default = Some(tls_identity.clone());
                    }
                }
            }
        }

        Ok(())
    }

    fn merge_listener_protocols(&mut self, key: &ListenKey, listen: &Listen) -> Result<(), String> {
        let config = ListenerProtocolConfig {
            http2: listen.http2,
            http2_only: listen.http2_only,
        };
        if let Some(current) = self.listener_protocols.get(key) {
            if current != &config {
                return Err(format!(
                    "listener {} has conflicting protocol settings across server blocks",
                    listen_key_addr(key)
                ));
            }
            return Ok(());
        }

        self.listener_protocols.insert(key.clone(), config);
        Ok(())
    }

    fn merge_listener_tls_settings(
        &mut self,
        key: &ListenKey,
        options: &DownstreamTlsOptions,
    ) -> Result<(), String> {
        let settings = ListenerTlsSettings::from(options);
        if let Some(current) = self.listener_tls.get(key).map(|tls| &tls.settings) {
            if current != &settings {
                return Err(format!(
                    "listener {} has conflicting TLS settings across server blocks",
                    listen_key_addr(key)
                ));
            }
            return Ok(());
        }

        self.listener_tls.insert(
            key.clone(),
            ListenerTlsConfig {
                settings,
                ..ListenerTlsConfig::default()
            },
        );
        Ok(())
    }
}

fn normalize_upstream_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn compile_upstream_server(server: &UpstreamServer) -> Result<CompiledUpstreamServer, String> {
    if server.host.trim().is_empty() {
        return Err("upstream server host cannot be empty".into());
    }
    if server.port == 0 {
        return Err(format!(
            "upstream server `{}` port must be greater than zero",
            server.host
        ));
    }

    Ok(CompiledUpstreamServer {
        host: server.host.clone(),
        port: server.port,
        weight: server.weight,
        api_prefix: None,
    })
}

fn compile_upstream_health_check(
    health_check: &UpstreamHealthCheck,
) -> Result<CompiledHealthCheck, String> {
    if health_check.timeout.is_zero() {
        return Err("health_check timeout must be greater than zero".into());
    }
    if health_check.interval.is_zero() {
        return Err("health_check interval must be greater than zero".into());
    }
    if health_check.consecutive_success == 0 {
        return Err("health_check consecutive_success must be greater than zero".into());
    }
    if health_check.consecutive_failure == 0 {
        return Err("health_check consecutive_failure must be greater than zero".into());
    }

    let check_type = match &health_check.check_type {
        UpstreamHealthCheckType::Tcp => HealthCheckType::Tcp,
        UpstreamHealthCheckType::Http {
            host,
            path,
            use_tls,
        } => {
            if host.trim().is_empty() {
                return Err("health_check http host cannot be empty".into());
            }
            let uri = path
                .parse::<http::Uri>()
                .map_err(|err| format!("invalid health_check path `{path}`: {err}"))?;
            if uri.scheme().is_some() || uri.authority().is_some() || !path.starts_with('/') {
                return Err(format!(
                    "health_check path `{path}` must be an origin-form path starting with `/`"
                ));
            }
            HealthCheckType::Http {
                host: host.clone(),
                path: path.clone(),
                use_tls: *use_tls,
            }
        }
    };

    Ok(CompiledHealthCheck {
        check_type,
        timeout: health_check.timeout,
        interval: health_check.interval,
        consecutive_success: health_check.consecutive_success,
        consecutive_failure: health_check.consecutive_failure,
    })
}

fn compile_nrf_discovery(discovery: &NrfDiscovery) -> Result<CompiledNrfDiscovery, String> {
    let api_root = url::Url::parse(&discovery.api_root)
        .map_err(|err| format!("nrf_discovery api_root is invalid: {err}"))?;
    if !matches!(api_root.scheme(), "http" | "https") {
        return Err("nrf_discovery api_root must use http or https".into());
    }
    if api_root.host_str().is_none() || api_root.cannot_be_a_base() {
        return Err("nrf_discovery api_root must be an absolute HTTP URL".into());
    }
    if api_root.query().is_some() || api_root.fragment().is_some() {
        return Err("nrf_discovery api_root must not contain a query or fragment".into());
    }
    if discovery.timeout.is_zero() {
        return Err("nrf_discovery timeout must be greater than zero".into());
    }
    if discovery.stale_if_error.is_zero() {
        return Err("nrf_discovery stale_if_error must be greater than zero".into());
    }
    match (
        &discovery.tls_options.client_certificate,
        &discovery.tls_options.client_certificate_key,
    ) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(
                "nrf_discovery ssl_certificate and ssl_certificate_key must be configured together"
                    .into(),
            );
        }
    }

    Ok(CompiledNrfDiscovery {
        api_root,
        target_nf_type: discovery.target_nf_type.trim().to_ascii_uppercase(),
        requester_nf_type: discovery.requester_nf_type.trim().to_ascii_uppercase(),
        service_name: discovery.service_name.trim().to_string(),
        endpoint_scheme: discovery.endpoint_scheme,
        timeout: discovery.timeout,
        stale_if_error: discovery.stale_if_error,
        tls_options: discovery.tls_options.clone(),
    })
}

fn compile_upstreams(
    upstreams: &[UpstreamBlock],
) -> Result<HashMap<String, CompiledUpstreamGroup>, String> {
    let mut compiled = HashMap::with_capacity(upstreams.len());

    for upstream in upstreams {
        let name = normalize_upstream_name(&upstream.name);
        if name.is_empty() {
            return Err("upstream name cannot be empty".into());
        }
        if upstream.servers.is_empty() && upstream.nrf_discovery.is_none() {
            return Err(format!(
                "upstream `{}` must define at least one server or nrf_discovery",
                upstream.name
            ));
        }
        if !upstream.servers.is_empty() && upstream.nrf_discovery.is_some() {
            return Err(format!(
                "upstream `{}` cannot combine server directives with nrf_discovery",
                upstream.name
            ));
        }
        if upstream.nrf_discovery.is_some() && upstream.health_check.is_none() {
            return Err(format!(
                "upstream `{}` with nrf_discovery must define health_check",
                upstream.name
            ));
        }
        let total_weight = upstream.servers.iter().try_fold(0u32, |total, server| {
            if server.weight == 0 {
                return Err(format!(
                    "upstream `{}` backend `{}:{}` weight must be greater than zero",
                    upstream.name, server.host, server.port
                ));
            }
            Ok(total + u32::from(server.weight))
        })?;
        if total_weight > u32::from(u16::MAX) {
            return Err(format!(
                "upstream `{}` total backend weight must not exceed {}",
                upstream.name,
                u16::MAX
            ));
        }
        if upstream.hash_key.is_some() && upstream.policy != UpstreamSelectionPolicy::ConsistentHash
        {
            return Err(format!(
                "upstream `{}` hash_key requires policy consistent_hash",
                upstream.name
            ));
        }
        if let Some(ngxora_compile::ir::UpstreamHashKey::Header(name)) = &upstream.hash_key {
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                format!(
                    "upstream `{}` hash_key has invalid HTTP header name `{name}`",
                    upstream.name
                )
            })?;
        }

        let group = CompiledUpstreamGroup {
            name: upstream.name.clone(),
            policy: upstream.policy,
            hash_key: upstream.hash_key.clone(),
            servers: upstream
                .servers
                .iter()
                .map(compile_upstream_server)
                .collect::<Result<Vec<_>, _>>()?,
            nrf_discovery: upstream
                .nrf_discovery
                .as_ref()
                .map(compile_nrf_discovery)
                .transpose()?,
            health_check: upstream
                .health_check
                .as_ref()
                .map(compile_upstream_health_check)
                .transpose()?,
        };

        if compiled.insert(name.clone(), group).is_some() {
            return Err(format!("upstream `{}` is duplicated", upstream.name));
        }
    }

    Ok(compiled)
}

fn listen_key_addr(key: &ListenKey) -> String {
    std::net::SocketAddr::new(key.addr, key.port).to_string()
}

pub(super) fn proxy_pass_sni(host: &str, tls: bool) -> String {
    if tls && host.parse::<IpAddr>().is_err() {
        host.to_string()
    } else {
        String::new()
    }
}

fn proxy_pass_tls(scheme: &str) -> Option<bool> {
    match scheme {
        "http" => Some(false),
        "https" => Some(true),
        _ => None,
    }
}

fn upstream_group_from_url<'a>(
    url: &url::Url,
    upstreams: &'a HashMap<String, CompiledUpstreamGroup>,
) -> Option<&'a CompiledUpstreamGroup> {
    if url.port().is_some() {
        return None;
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }

    let host = normalize_upstream_name(url.host_str()?);
    upstreams.get(&host)
}

fn set_timeout_once(
    slot: &mut Option<std::time::Duration>,
    value: std::time::Duration,
    directive: &str,
) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{directive} is duplicated in the same location"));
    }

    Ok(())
}

fn route_target_from_directive(
    directive: &LocationDirective,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
) -> Result<Option<RouteTarget>, String> {
    match directive {
        LocationDirective::ProxyPass(ProxyPassTarget::Url(url)) => {
            if let Some(group) = upstream_group_from_url(url, upstreams) {
                let tls = proxy_pass_tls(url.scheme())
                    .ok_or_else(|| format!("unsupported proxy_pass scheme `{}`", url.scheme()))?;
                validate_nrf_route_scheme(group, tls)?;
                return Ok(Some(RouteTarget::UpstreamGroup {
                    name: group.name.clone(),
                    tls,
                }));
            }

            let Some(host) = url.host_str().map(ToString::to_string) else {
                return Ok(None);
            };
            let Some(port) = url.port_or_known_default() else {
                return Ok(None);
            };
            let tls = match proxy_pass_tls(url.scheme()) {
                Some(value) => value,
                None => return Ok(None),
            };

            Ok(Some(RouteTarget::ProxyPass {
                sni: proxy_pass_sni(&host, tls),
                host,
                port,
                tls,
            }))
        }

        LocationDirective::ProxyPass(ProxyPassTarget::UpstreamGroup { name, tls }) => {
            let normalized = normalize_upstream_name(name);
            let group = upstreams
                .get(&normalized)
                .ok_or_else(|| format!("proxy_pass references unknown upstream `{name}`"))?;
            validate_nrf_route_scheme(group, *tls)?;
            Ok(Some(RouteTarget::UpstreamGroup {
                name: group.name.clone(),
                tls: *tls,
            }))
        }

        LocationDirective::Return { status, location } => Ok(Some(RouteTarget::Return {
            status: *status,
            location: location.clone(),
        })),

        _ => Ok(None),
    }
}

fn validate_nrf_route_scheme(group: &CompiledUpstreamGroup, tls: bool) -> Result<(), String> {
    let Some(discovery) = group.nrf_discovery.as_ref() else {
        return Ok(());
    };
    let expects_tls = matches!(
        discovery.endpoint_scheme,
        ngxora_compile::ir::NrfEndpointScheme::Https
    );
    if tls != expects_tls {
        return Err(format!(
            "proxy_pass scheme for NRF upstream `{}` must match endpoint_scheme {}",
            group.name,
            if expects_tls { "https" } else { "http" }
        ));
    }
    Ok(())
}

fn route_target(
    location: &Location,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
) -> Result<Option<RouteTarget>, String> {
    location
        .directives
        .iter()
        .find_map(
            |directive| match route_target_from_directive(directive, upstreams) {
                Ok(Some(target)) => Some(Ok(target)),
                Ok(None) => None,
                Err(err) => Some(Err(err)),
            },
        )
        .transpose()
}

fn compile_upstream_timeouts(location: &Location) -> Result<UpstreamTimeouts, String> {
    let mut timeouts = UpstreamTimeouts::default();

    for directive in &location.directives {
        match directive {
            LocationDirective::ProxyConnectTimeout(value) => {
                set_timeout_once(&mut timeouts.connect, *value, "proxy_connect_timeout")?;
            }
            LocationDirective::ProxyReadTimeout(value) => {
                set_timeout_once(&mut timeouts.read, *value, "proxy_read_timeout")?;
            }
            LocationDirective::ProxyWriteTimeout(value) => {
                set_timeout_once(&mut timeouts.write, *value, "proxy_write_timeout")?;
            }
            _ => {}
        }
    }

    Ok(timeouts)
}

fn compile_upstream_protocol(
    location: &Location,
    target: &RouteTarget,
) -> Result<Option<UpstreamHttpProtocol>, String> {
    let mut protocol = None;

    for directive in &location.directives {
        if let LocationDirective::ProxyUpstreamProtocol(value) = directive {
            if protocol.replace(*value).is_some() {
                return Err("proxy_upstream_protocol is duplicated in the same location".into());
            }
        }
    }

    if let Some(protocol) = protocol {
        let target_uses_tls = match target {
            RouteTarget::ProxyPass { tls, .. } | RouteTarget::UpstreamGroup { tls, .. } => *tls,
            RouteTarget::Return { .. } => return Ok(None),
        };

        match protocol {
            UpstreamHttpProtocol::H1 => {}
            UpstreamHttpProtocol::H2 if !target_uses_tls => {
                return Err(
                    "proxy_upstream_protocol h2 requires TLS upstream; use https proxy_pass or h2c"
                        .into(),
                );
            }
            UpstreamHttpProtocol::H2c if target_uses_tls => {
                return Err(
                    "proxy_upstream_protocol h2c requires plaintext upstream; use http proxy_pass"
                        .into(),
                );
            }
            _ => {}
        }
    }

    Ok(protocol)
}

fn compile_upstream_ssl_options(location: &Location) -> Result<UpstreamSslOptions, String> {
    let mut options = UpstreamSslOptions::default();
    let mut seen_cert = false;
    let mut seen_key = false;

    for directive in &location.directives {
        match directive {
            LocationDirective::ProxySslVerify(switch) => {
                options.verify_cert = *switch;
            }
            LocationDirective::ProxySslTrustedCertificate(pem_source) => {
                options.trusted_certificate = Some(pem_source.clone());
            }
            LocationDirective::ProxySslCertificate(pem_source) => {
                if seen_cert {
                    return Err("proxy_ssl_certificate is duplicated in the same location".into());
                }
                seen_cert = true;
                options.client_certificate = Some(pem_source.clone());
            }
            LocationDirective::ProxySslCertificateKey(pem_source) => {
                if seen_key {
                    return Err(
                        "proxy_ssl_certificate_key is duplicated in the same location".into(),
                    );
                }
                seen_key = true;
                options.client_certificate_key = Some(pem_source.clone());
            }
            _ => {}
        }
    }

    // mTLS to upstream requires both the client certificate and its private key.
    match (
        options.client_certificate.is_some(),
        options.client_certificate_key.is_some(),
    ) {
        (true, false) => {
            return Err("proxy_ssl_certificate requires proxy_ssl_certificate_key".into());
        }
        (false, true) => {
            return Err("proxy_ssl_certificate_key requires proxy_ssl_certificate".into());
        }
        _ => {}
    }

    Ok(options)
}

fn compile_location(
    location: &Location,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
    next_route_id: &mut u64,
) -> Result<Option<CompiledLocation>, String> {
    let mut action_count = 0;
    for directive in &location.directives {
        match directive {
            LocationDirective::ProxyPass(_) | LocationDirective::Return { .. } => {
                action_count += 1;
            }
            LocationDirective::Root(_) => return Err("root is not supported at runtime".into()),
            LocationDirective::TryFiles(_) => {
                return Err("try_files is not supported at runtime".into());
            }
            _ => {}
        }
    }
    if action_count != 1 {
        return Err("location must contain exactly one proxy_pass or return directive".into());
    }

    let Some(target) = route_target(location, upstreams)? else {
        return Ok(None);
    };
    let upstream_protocol = compile_upstream_protocol(location, &target)?;

    let compiled = CompiledLocation {
        route_id: *next_route_id,
        matcher: CompiledMatcher::try_from(&location.matcher)?,
        access_rules: location.access_rules.clone(),
        target,
        upstream_timeouts: compile_upstream_timeouts(location)?,
        upstream_protocol,
        upstream_ssl_options: compile_upstream_ssl_options(location)?,
        plugins: location.plugins.clone(),
        cache: location.cache.clone(),
    };
    *next_route_id += 1;
    Ok(Some(compiled))
}

// Only locations with an actionable upstream target are kept. Regex validation
// also happens here, so broken snapshots fail before they are applied.
fn compile_locations(
    locations: &[Location],
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
    next_route_id: &mut u64,
) -> Result<Vec<CompiledLocation>, String> {
    locations
        .iter()
        .map(|location| compile_location(location, upstreams, next_route_id))
        .filter_map(|result| match result {
            Ok(Some(location)) => Some(Ok(location)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

pub(crate) fn downstream_keepalive_timeout_secs(timeout: &KeepaliveTimeout) -> Option<u64> {
    match timeout {
        KeepaliveTimeout::Off => None,
        KeepaliveTimeout::Timeout { idle, .. } => {
            let millis = idle.as_millis();
            if millis == 0 {
                None
            } else {
                let secs = millis.div_ceil(1_000);
                u64::try_from(secs).ok()
            }
        }
    }
}
