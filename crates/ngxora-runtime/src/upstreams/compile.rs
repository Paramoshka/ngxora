use super::types::{
    CompiledHealthCheck, CompiledLocation, CompiledMatcher, CompiledRouter, CompiledUpstreamGroup,
    CompiledUpstreamServer, HealthCheckType, HttpRuntimeOptions, ListenKey, ListenerProtocolConfig,
    ListenerTlsConfig, ListenerTlsSettings, RouteTarget, ServerRoutes,
};
use ngxora_compile::ir::{
    DownstreamTlsOptions, Http, KeepaliveTimeout, Listen, Location, LocationDirective,
    ProxyPassTarget, Server, Switch, UpstreamBlock, UpstreamHealthCheck, UpstreamHealthCheckType,
    UpstreamHttpProtocol, UpstreamServer, UpstreamSslOptions, UpstreamTimeouts,
};
use std::collections::HashMap;
use std::net::IpAddr;

impl CompiledRouter {
    pub fn from_http(http: &Http) -> Result<Self, String> {
        let mut router = Self {
            upstreams: compile_upstreams(&http.upstreams)?,
            http_options: HttpRuntimeOptions {
                downstream_keepalive_timeout: downstream_keepalive_timeout_secs(
                    &http.keepalive_timeout,
                ),
                keepalive_requests: http.keepalive_requests,
                client_max_body_size: http.client_max_body_size,
                tcp_nodelay: matches!(http.tcp_nodelay, Switch::On),
                allow_connect_method_proxying: matches!(
                    http.allow_connect_method_proxying,
                    Switch::On
                ),
                h2c: matches!(http.h2c, Switch::On),
            },
            ..Self::default()
        };
        let mut next_route_id = 1;

        for server in &http.servers {
            router.add_server(server, &mut next_route_id)?;
        }

        Ok(router)
    }

    fn add_server(&mut self, server: &Server, next_route_id: &mut u64) -> Result<(), String> {
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

                if let Some(tls) = server.tls.as_ref() {
                    for name in &server.server_names {
                        listener_tls
                            .named
                            .insert(name.to_ascii_lowercase(), tls.clone());
                    }

                    if listen.default_server
                        || listener_tls.default.is_none()
                        || server.server_names.is_empty()
                    {
                        listener_tls.default = Some(tls.clone());
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

fn compile_upstreams(
    upstreams: &[UpstreamBlock],
) -> Result<HashMap<String, CompiledUpstreamGroup>, String> {
    let mut compiled = HashMap::with_capacity(upstreams.len());

    for upstream in upstreams {
        let name = normalize_upstream_name(&upstream.name);
        if name.is_empty() {
            return Err("upstream name cannot be empty".into());
        }
        if upstream.servers.is_empty() {
            return Err(format!(
                "upstream `{}` must define at least one server",
                upstream.name
            ));
        }

        let group = CompiledUpstreamGroup {
            name: upstream.name.clone(),
            policy: upstream.policy,
            servers: upstream
                .servers
                .iter()
                .map(compile_upstream_server)
                .collect::<Result<Vec<_>, _>>()?,
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
            Ok(Some(RouteTarget::UpstreamGroup {
                name: group.name.clone(),
                tls: *tls,
            }))
        }
        _ => Ok(None),
    }
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

    for directive in &location.directives {
        match directive {
            LocationDirective::ProxySslVerify(switch) => {
                options.verify_cert = *switch;
            }
            LocationDirective::ProxySslTrustedCertificate(pem_source) => {
                options.trusted_certificate = Some(pem_source.clone());
            }
            _ => {}
        }
    }

    Ok(options)
}

fn compile_location(
    location: &Location,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
    next_route_id: &mut u64,
) -> Result<Option<CompiledLocation>, String> {
    let Some(target) = route_target(location, upstreams)? else {
        return Ok(None);
    };
    let upstream_protocol = compile_upstream_protocol(location, &target)?;

    let compiled = CompiledLocation {
        route_id: *next_route_id,
        matcher: CompiledMatcher::try_from(&location.matcher)?,
        target,
        upstream_timeouts: compile_upstream_timeouts(location)?,
        upstream_protocol,
        upstream_ssl_options: compile_upstream_ssl_options(location)?,
        plugins: location.plugins.clone(),
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
