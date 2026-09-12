//! Decode protobuf into IR, then compile through the shared validation boundary.

use super::http_routes::{
    direct_status, http_match_from_proto, http_redirect_from_proto, modifier_from_proto,
};
use super::proto;
use super::proto::{
    CacheKeyMode as ProtoCacheKeyMode, ConfigSnapshot as ProtoConfigSnapshot,
    Listener as ProtoListener, Match as ProtoMatch, NrfDiscovery as ProtoNrfDiscovery,
    NrfEndpointScheme as ProtoNrfEndpointScheme, Plugin as ProtoPlugin, Redirect as ProtoRedirect,
    Route as ProtoRoute, RouteCache as ProtoRouteCache, Switch as ProtoSwitch,
    Upstream as ProtoUpstream, UpstreamBackend as ProtoUpstreamBackend,
    UpstreamGroup as ProtoUpstreamGroup, UpstreamHashKey as ProtoUpstreamHashKey,
    UpstreamHealthCheck as ProtoUpstreamHealthCheck,
    UpstreamHttpProtocol as ProtoUpstreamHttpProtocol, VirtualHost as ProtoVirtualHost,
};
use super::tls::{
    le_config_from_proto, listener_tls_options_from_proto, tls_identity_from_proto,
    upstream_tls_options_from_proto,
};
use super::values::{
    duration_from_millis, keepalive_timeout_from_proto, none_if_zero, none_if_zero_u64,
    switch_from_bool, upstream_selection_policy_from_proto,
};
use crate::control::ConfigSnapshot as RuntimeConfigSnapshot;
use crate::upstreams::CompiledRouter;
use ngxora_compile::ir as http_ir;
use ngxora_compile::ir::{
    CacheConfig, CacheKeyMode, DownstreamTlsOptions, Http, Listen, Location, LocationDirective,
    LocationMatcher, NrfDiscovery, NrfEndpointScheme, ProxyPassTarget, Server, SslProvider, Switch,
    UpstreamBlock, UpstreamHashKey, UpstreamHealthCheck, UpstreamHealthCheckType,
    UpstreamHttpProtocol, UpstreamServer,
};
use ngxora_plugin_api::PluginSpec;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

// Converts the wire snapshot into the existing IR/CompiledRouter pipeline so
// config validation stays in one place.
pub(super) fn runtime_snapshot_from_proto(
    snapshot: ProtoConfigSnapshot,
) -> Result<RuntimeConfigSnapshot, String> {
    let http = http_from_proto_snapshot(&snapshot)?;
    let router = CompiledRouter::from_http(&http)?;

    Ok(RuntimeConfigSnapshot::new(snapshot.version, router))
}

// Reconstruct the shared IR shape from the wire snapshot so protobuf input goes
// through the same validation and compilation path as other config sources.
fn http_from_proto_snapshot(snapshot: &ProtoConfigSnapshot) -> Result<Http, String> {
    let options = snapshot.http.clone().unwrap_or_default();
    let listener_defs = listener_defs(&snapshot.listeners)?;
    let mut servers = Vec::with_capacity(snapshot.virtual_hosts.len());

    for virtual_host in &snapshot.virtual_hosts {
        let listener = listener_defs.get(&virtual_host.listener).ok_or_else(|| {
            format!(
                "virtual host references unknown listener `{}`",
                virtual_host.listener
            )
        })?;
        servers.push(server_from_proto_virtual_host(listener, virtual_host)?);
    }

    Ok(Http {
        scp_profiles: snapshot
            .scp_profiles
            .iter()
            .map(|p| ngxora_compile::ir::ScpProfile {
                name: p.name.clone(),
                api_root: p.api_root.clone(),
                discovery_upstreams: p.discovery_upstreams.clone(),
                allowed_target_api_roots: p.allowed_target_api_roots.clone(),
            })
            .collect(),
        upstreams: upstreams_from_proto(&snapshot.upstreams)?,
        servers,
        keepalive_timeout: keepalive_timeout_from_proto(
            options.downstream_keepalive_timeout_seconds,
        ),
        keepalive_requests: none_if_zero(options.keepalive_requests),
        client_max_body_size: none_if_zero_u64(options.client_max_body_size_bytes),
        real_ip: options
            .real_ip
            .as_ref()
            .map(super::client_policy::real_ip_from_proto)
            .transpose()?,
        client_header_timeout: options.client_header_timeout_ms.map(Duration::from_millis),
        client_body_timeout: options.client_body_timeout_ms.map(Duration::from_millis),
        send_timeout: options.send_timeout_ms.map(Duration::from_millis),
        // Pingora enables TCP_NODELAY on accepted downstream sockets, and
        // proto3 bool cannot distinguish "unset" from explicit false.
        tcp_nodelay: Switch::On,
        allow_connect_method_proxying: switch_from_bool(options.allow_connect_method_proxying),
        h2c: switch_from_bool(options.h2c),
        http2: options
            .http2
            .as_ref()
            .map(|h2| ngxora_compile::ir::Http2Options {
                max_concurrent_streams: h2.max_concurrent_streams,
                max_header_list_size: h2.max_header_list_size,
                stream_window_size: h2.stream_window_size,
                connection_window_size: h2.connection_window_size,
            })
            .unwrap_or_default(),
        proxy_cache_max_size: none_if_zero_u64(options.proxy_cache_max_size_bytes),
        ssl_provider: snapshot.le_config.as_ref().map(le_config_from_proto),
        geoip: snapshot
            .geoip
            .as_ref()
            .map(|config| {
                Ok::<_, String>(http_ir::GeoIpConfig {
                    database: config.database.clone().into(),
                    reload_interval: Duration::from_millis(
                        config.reload_interval_ms.unwrap_or(5000),
                    ),
                    trusted_proxies: config
                        .trusted_proxies
                        .iter()
                        .map(|raw| {
                            raw.parse()
                                .or_else(|_| raw.parse::<IpAddr>().map(Into::into))
                                .map_err(|_| format!("invalid geoip trusted_proxy `{raw}`"))
                        })
                        .collect::<Result<_, _>>()?,
                })
            })
            .transpose()?,
    })
}

pub(super) fn upstreams_from_proto(
    upstreams: &[ProtoUpstreamGroup],
) -> Result<Vec<UpstreamBlock>, String> {
    upstreams
        .iter()
        .map(|upstream| {
            let name = upstream.name.trim();
            if name.is_empty() {
                return Err("upstream group name cannot be empty".into());
            }

            let servers = upstream
                .backends
                .iter()
                .map(upstream_backend_from_proto)
                .collect::<Result<Vec<_>, _>>()?;
            if servers.is_empty() && upstream.nrf_discovery.is_none() && !upstream.allow_empty {
                return Err(format!(
                    "upstream group `{name}` must define at least one backend or nrf_discovery"
                ));
            }
            if !servers.is_empty() && upstream.nrf_discovery.is_some() {
                return Err(format!(
                    "upstream group `{name}` cannot combine backends with nrf_discovery"
                ));
            }

            Ok(UpstreamBlock {
                allow_empty: upstream.allow_empty,
                name: name.to_string(),
                policy: upstream_selection_policy_from_proto(upstream.policy)?,
                hash_key: upstream
                    .hash_key
                    .as_ref()
                    .map(upstream_hash_key_from_proto)
                    .transpose()?,
                servers,
                nrf_discovery: upstream
                    .nrf_discovery
                    .as_ref()
                    .map(nrf_discovery_from_proto)
                    .transpose()?,
                health_check: upstream
                    .health_check
                    .as_ref()
                    .map(upstream_health_check_from_proto)
                    .transpose()?,
            })
        })
        .collect()
}

fn nrf_discovery_from_proto(value: &ProtoNrfDiscovery) -> Result<NrfDiscovery, String> {
    let required = |value: &str, field: &str| {
        let value = value.trim();
        if value.is_empty() {
            Err(format!("nrf_discovery {field} is required"))
        } else {
            Ok(value.to_string())
        }
    };

    let endpoint_scheme = match ProtoNrfEndpointScheme::try_from(value.endpoint_scheme)
        .unwrap_or(ProtoNrfEndpointScheme::Unspecified)
    {
        ProtoNrfEndpointScheme::Http => NrfEndpointScheme::Http,
        ProtoNrfEndpointScheme::Https => NrfEndpointScheme::Https,
        ProtoNrfEndpointScheme::Unspecified => {
            return Err("nrf_discovery endpoint_scheme is required".into());
        }
    };

    Ok(NrfDiscovery {
        api_root: required(&value.api_root, "api_root")?,
        target_nf_type: required(&value.target_nf_type, "target_nf_type")?,
        requester_nf_type: required(&value.requester_nf_type, "requester_nf_type")?,
        service_name: required(&value.service_name, "service_name")?,
        endpoint_scheme,
        timeout: Duration::from_millis(if value.timeout_ms == 0 {
            3_000
        } else {
            value.timeout_ms
        }),
        stale_if_error: Duration::from_millis(if value.stale_if_error_ms == 0 {
            60_000
        } else {
            value.stale_if_error_ms
        }),
        tls_options: upstream_tls_options_from_proto(value.tls_options.as_ref())?
            .unwrap_or_default(),
    })
}

// ListenerDef normalizes wire listeners into one listener record that can be
// reused while rebuilding server blocks from virtual hosts.
fn listener_defs(listeners: &[ProtoListener]) -> Result<HashMap<String, ListenerDef>, String> {
    let mut defs = HashMap::with_capacity(listeners.len());

    for listener in listeners {
        let name = listener.name.trim();
        if name.is_empty() {
            return Err("listener name cannot be empty".into());
        }
        if defs.contains_key(name) {
            return Err(format!("listener `{name}` is duplicated"));
        }

        defs.insert(name.to_string(), ListenerDef::try_from(listener)?);
    }

    Ok(defs)
}

// Convert one wire virtual host back into the IR server shape expected by the
// shared CompiledRouter builder.
fn server_from_proto_virtual_host(
    listener: &ListenerDef,
    virtual_host: &ProtoVirtualHost,
) -> Result<Server, String> {
    if listener.listen.ssl && virtual_host.tls.is_none() {
        return Err(format!(
            "virtual host on listener `{}` requires a TLS binding",
            listener.name
        ));
    }
    if !listener.listen.ssl && virtual_host.tls.is_some() {
        return Err(format!(
            "virtual host on listener `{}` cannot define TLS binding on a plaintext listener",
            listener.name
        ));
    }

    Ok(Server {
        server_names: virtual_host.server_names.clone(),
        locations: virtual_host
            .routes
            .iter()
            .map(location_from_proto_route)
            .collect::<Result<Vec<_>, _>>()?,
        listens: vec![Listen {
            default_server: virtual_host.default_server,
            ..listener.listen.clone()
        }],
        tls: virtual_host
            .tls
            .as_ref()
            .map(tls_identity_from_proto)
            .transpose()?
            .map(SslProvider::Custom),
        tls_options: listener.tls_options.clone(),
    })
}

fn location_from_proto_route(route: &ProtoRoute) -> Result<Location, String> {
    let matcher = matcher_from_proto(route.r#match.as_ref())?;
    let mut directives = Vec::with_capacity(7);

    if let Some(timeouts) = route.timeouts.as_ref() {
        if let Some(duration) = duration_from_millis(timeouts.connect_timeout_ms) {
            directives.push(LocationDirective::ProxyConnectTimeout(duration));
        }
        if let Some(duration) = duration_from_millis(timeouts.read_timeout_ms) {
            directives.push(LocationDirective::ProxyReadTimeout(duration));
        }
        if let Some(duration) = duration_from_millis(timeouts.write_timeout_ms) {
            directives.push(LocationDirective::ProxyWriteTimeout(duration));
        }
    }

    if let Some(tls_options) = upstream_tls_options_from_proto(route.tls_options.as_ref())? {
        directives.push(LocationDirective::ProxySslVerify(tls_options.verify_cert));
        if let Some(trusted_certificate) = tls_options.trusted_certificate {
            directives.push(LocationDirective::ProxySslTrustedCertificate(
                trusted_certificate,
            ));
        }
        if let Some(client_certificate) = tls_options.client_certificate {
            directives.push(LocationDirective::ProxySslCertificate(client_certificate));
        }
        if let Some(client_certificate_key) = tls_options.client_certificate_key {
            directives.push(LocationDirective::ProxySslCertificateKey(
                client_certificate_key,
            ));
        }
    }

    if let Some(protocol) = upstream_http_protocol_from_proto(route.upstream_protocol)? {
        directives.push(LocationDirective::ProxyUpstreamProtocol(protocol));
    }

    if let Some(h2) = &route.upstream_http2 {
        if let Some(value) = h2.max_concurrent_streams {
            directives.push(LocationDirective::ProxyHttp2MaxConcurrentStreams(value));
        }
        if let Some(value) = h2.stream_window_size {
            directives.push(LocationDirective::ProxyHttp2StreamWindowSize(value));
        }
        if let Some(value) = h2.connection_window_size {
            directives.push(LocationDirective::ProxyHttp2ConnectionWindowSize(value));
        }
    }

    let action = route
        .action
        .as_ref()
        .ok_or_else(|| "route action is required".to_string())?;
    match action {
        proto::route::Action::WeightedBackends(backends) => {
            let backends = backends
                .backends
                .iter()
                .map(|b| {
                    let target = match b
                        .target
                        .as_ref()
                        .ok_or("weighted backend target is required")?
                    {
                        proto::weighted_backend::Target::Upstream(upstream) => {
                            http_ir::BackendTarget::Upstream(proxy_pass_target_from_proto(
                                upstream,
                            )?)
                        }
                        proto::weighted_backend::Target::DirectResponse(response) => {
                            http_ir::BackendTarget::Response(direct_status(response.status)?)
                        }
                    };
                    Ok(http_ir::WeightedBackend {
                        weight: b.weight.unwrap_or(1),
                        target,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            directives.push(LocationDirective::WeightedBackends(backends));
        }
        proto::route::Action::DirectResponse(response) => directives.push(
            LocationDirective::DirectResponse(direct_status(response.status)?),
        ),
        proto::route::Action::HttpRedirect(config) => directives.push(
            LocationDirective::HttpRedirect(http_redirect_from_proto(config)?),
        ),
        proto::route::Action::ScpProfile(name) => {
            directives.push(LocationDirective::ScpPass(name.clone()))
        }
        proto::route::Action::Upstream(upstream) => {
            directives.push(LocationDirective::ProxyPass(proxy_pass_target_from_proto(
                upstream,
            )?));
        }
        proto::route::Action::Redirect(redirect) => {
            directives.push(return_directive_from_proto(redirect)?);
        }
    }

    if let Some(rewrite) = &route.url_rewrite {
        directives.push(LocationDirective::UrlRewrite(http_ir::UrlRewrite {
            hostname: rewrite.hostname.clone(),
            path: rewrite.path.as_ref().map(modifier_from_proto).transpose()?,
        }));
    }
    if let Some(value) = route.client_max_body_size_bytes {
        directives.push(LocationDirective::ClientMaxBodySize(value));
    }
    if let Some(value) = route.client_body_timeout_ms {
        directives.push(LocationDirective::ClientBodyTimeout(Duration::from_millis(
            value,
        )));
    }
    if let Some(value) = route.send_timeout_ms {
        directives.push(LocationDirective::SendTimeout(Duration::from_millis(value)));
    }
    if !route.allowed_methods.is_empty() {
        directives.push(LocationDirective::AllowMethods(
            route.allowed_methods.clone(),
        ));
    }
    Ok(Location {
        matcher,
        directives,
        access_rules: route
            .access_rules
            .iter()
            .map(super::client_policy::access_from_proto)
            .collect::<Result<_, _>>()?,
        plugins: route
            .plugins
            .iter()
            .map(plugin_spec_from_proto)
            .collect::<Result<Vec<_>, _>>()?,
        cache: route_cache_from_proto(route.cache.as_ref())?,
    })
}

fn upstream_backend_from_proto(backend: &ProtoUpstreamBackend) -> Result<UpstreamServer, String> {
    if backend.host.trim().is_empty() {
        return Err("upstream backend host cannot be empty".into());
    }
    if backend.port == 0 {
        return Err(format!(
            "upstream backend `{}` port must be greater than zero",
            backend.host
        ));
    }

    Ok(UpstreamServer {
        host: backend.host.clone(),
        port: u16::try_from(backend.port)
            .map_err(|_| format!("upstream backend `{}` port is out of range", backend.host))?,
        weight: if backend.weight == 0 {
            1
        } else {
            u16::try_from(backend.weight).map_err(|_| {
                format!("upstream backend `{}` weight is out of range", backend.host)
            })?
        },
    })
}

fn upstream_hash_key_from_proto(value: &ProtoUpstreamHashKey) -> Result<UpstreamHashKey, String> {
    match value.source.as_ref() {
        Some(proto::upstream_hash_key::Source::ClientIp(true)) => Ok(UpstreamHashKey::ClientIp),
        Some(proto::upstream_hash_key::Source::ClientIp(false)) => {
            Err("upstream hash_key client_ip must be true".into())
        }
        Some(proto::upstream_hash_key::Source::Header(name)) => {
            http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("upstream hash_key has invalid HTTP header name `{name}`"))?;
            Ok(UpstreamHashKey::Header(name.clone()))
        }
        None => Err("upstream hash_key source is required".into()),
    }
}

fn upstream_health_check_from_proto(
    health_check: &ProtoUpstreamHealthCheck,
) -> Result<UpstreamHealthCheck, String> {
    let kind = health_check
        .kind
        .as_ref()
        .ok_or_else(|| "upstream health_check kind is required".to_string())?;
    let timeout = duration_from_millis(health_check.timeout_ms)
        .ok_or_else(|| "upstream health_check timeout must be greater than zero".to_string())?;
    let interval = duration_from_millis(health_check.interval_ms)
        .ok_or_else(|| "upstream health_check interval must be greater than zero".to_string())?;
    let consecutive_success = usize::try_from(health_check.consecutive_success)
        .map_err(|_| "upstream health_check consecutive_success is out of range".to_string())?;
    let consecutive_failure = usize::try_from(health_check.consecutive_failure)
        .map_err(|_| "upstream health_check consecutive_failure is out of range".to_string())?;
    if consecutive_success == 0 {
        return Err("upstream health_check consecutive_success must be greater than zero".into());
    }
    if consecutive_failure == 0 {
        return Err("upstream health_check consecutive_failure must be greater than zero".into());
    }

    let check_type = match kind {
        proto::upstream_health_check::Kind::Tcp(_) => UpstreamHealthCheckType::Tcp,
        proto::upstream_health_check::Kind::Http(http) => {
            if http.host.trim().is_empty() {
                return Err("upstream health_check http host cannot be empty".into());
            }
            if http.path.is_empty() {
                return Err("upstream health_check http path cannot be empty".into());
            }
            UpstreamHealthCheckType::Http {
                host: http.host.clone(),
                path: http.path.clone(),
                use_tls: http.use_tls,
            }
        }
    };

    Ok(UpstreamHealthCheck {
        check_type,
        timeout,
        interval,
        consecutive_success,
        consecutive_failure,
    })
}

fn matcher_from_proto(value: Option<&ProtoMatch>) -> Result<LocationMatcher, String> {
    let matcher = value.ok_or_else(|| "route match is required".to_string())?;
    let kind = matcher
        .kind
        .as_ref()
        .ok_or_else(|| "route match kind is required".to_string())?;

    match kind {
        proto::r#match::Kind::Http(matcher) => {
            Ok(LocationMatcher::Http(http_match_from_proto(matcher)))
        }
        proto::r#match::Kind::Prefix(path) => Ok(LocationMatcher::Prefix(path.clone())),
        proto::r#match::Kind::Exact(path) => Ok(LocationMatcher::Exact(path.clone())),
        proto::r#match::Kind::PreferPrefix(path) => Ok(LocationMatcher::PreferPrefix(path.clone())),
        proto::r#match::Kind::Regex(regex) => Ok(LocationMatcher::Regex {
            case_insensitive: regex.case_insensitive,
            pattern: regex.pattern.clone(),
        }),
        proto::r#match::Kind::Named(name) => Ok(LocationMatcher::Named(name.clone())),
    }
}

fn proxy_pass_target_from_proto(upstream: &ProtoUpstream) -> Result<ProxyPassTarget, String> {
    let tls = match upstream.scheme.as_str() {
        "http" => false,
        "https" => true,
        _ => return Err(format!("unsupported upstream scheme `{}`", upstream.scheme)),
    };

    let has_direct = !upstream.host.trim().is_empty() || upstream.port != 0;
    let has_group = !upstream.upstream_group.trim().is_empty();
    if has_direct && has_group {
        return Err("route upstream must set either host/port or upstream_group, not both".into());
    }

    if has_group {
        return Ok(ProxyPassTarget::UpstreamGroup {
            name: upstream.upstream_group.clone(),
            tls,
        });
    }

    if upstream.host.trim().is_empty() {
        return Err("upstream host cannot be empty".into());
    }
    if upstream.port == 0 {
        return Err("upstream port must be greater than zero".into());
    }

    let raw = format!("{}://{}:{}", upstream.scheme, upstream.host, upstream.port);
    let url = Url::parse(&raw).map_err(|err| format!("invalid upstream URL `{raw}`: {err}"))?;
    Ok(ProxyPassTarget::Url(url))
}

fn return_directive_from_proto(redirect: &ProtoRedirect) -> Result<LocationDirective, String> {
    let status = u16::try_from(redirect.status)
        .map_err(|_| format!("redirect status {} is out of range", redirect.status))?;
    if !(300..=399).contains(&status) {
        return Err(format!(
            "redirect status {status} is not a redirect (expected 3xx)"
        ));
    }
    if redirect.location.is_empty() {
        return Err("redirect location cannot be empty".into());
    }

    Ok(LocationDirective::Return {
        status,
        location: redirect.location.clone(),
    })
}

fn route_cache_from_proto(cache: Option<&ProtoRouteCache>) -> Result<Option<CacheConfig>, String> {
    let Some(cache) = cache else {
        return Ok(None);
    };

    let mut config = CacheConfig::default();
    if matches!(
        ProtoSwitch::try_from(cache.enabled)
            .map_err(|_| format!("unknown cache enabled switch value `{}`", cache.enabled))?,
        ProtoSwitch::Off
    ) {
        config.enabled = false;
    }

    config.max_size = none_if_zero_u64(cache.max_size_bytes);
    config.ttl = duration_from_millis(cache.ttl_ms).or(config.ttl);
    config.stale_if_error = duration_from_millis(cache.stale_if_error_ms);
    config.cache_key = cache_key_mode_from_proto(cache.key_mode)?;
    config.min_uses = none_if_zero(cache.min_uses)
        .map(|value| {
            usize::try_from(value).map_err(|_| "cache min_uses is out of range".to_string())
        })
        .transpose()?;

    if !cache.valid_statuses.is_empty() {
        config.valid_statuses = cache
            .valid_statuses
            .iter()
            .map(|status| {
                u16::try_from(*status)
                    .map_err(|_| format!("cache valid status {} is out of range", status))
            })
            .collect::<Result<Vec<_>, _>>()?;
    }

    Ok(Some(config))
}

fn cache_key_mode_from_proto(value: i32) -> Result<CacheKeyMode, String> {
    match ProtoCacheKeyMode::try_from(value)
        .map_err(|_| format!("unknown cache key mode value `{value}`"))?
    {
        ProtoCacheKeyMode::Unspecified | ProtoCacheKeyMode::Uri => Ok(CacheKeyMode::Uri),
        ProtoCacheKeyMode::UriAndMethod => Ok(CacheKeyMode::UriAndMethod),
        ProtoCacheKeyMode::NormalizedUri => Ok(CacheKeyMode::NormalizedUri),
    }
}

fn plugin_spec_from_proto(plugin: &ProtoPlugin) -> Result<PluginSpec, String> {
    if plugin.name.trim().is_empty() {
        return Err("plugin name cannot be empty".into());
    }

    let config = if plugin.json_config.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&plugin.json_config)
            .map_err(|err| format!("invalid plugin JSON for `{}`: {err}", plugin.name))?
    };

    Ok(PluginSpec {
        name: plugin.name.clone(),
        config,
    })
}

fn upstream_http_protocol_from_proto(value: i32) -> Result<Option<UpstreamHttpProtocol>, String> {
    match ProtoUpstreamHttpProtocol::try_from(value)
        .map_err(|_| format!("unknown upstream HTTP protocol value `{value}`"))?
    {
        ProtoUpstreamHttpProtocol::Unspecified => Ok(None),
        ProtoUpstreamHttpProtocol::H1 => Ok(Some(UpstreamHttpProtocol::H1)),
        ProtoUpstreamHttpProtocol::H2 => Ok(Some(UpstreamHttpProtocol::H2)),
        ProtoUpstreamHttpProtocol::H2c => Ok(Some(UpstreamHttpProtocol::H2c)),
    }
}

#[derive(Clone)]
struct ListenerDef {
    name: String,
    listen: Listen,
    tls_options: DownstreamTlsOptions,
}

impl TryFrom<&ProtoListener> for ListenerDef {
    type Error = String;

    // Listener-level transport settings are validated here before any virtual
    // hosts are materialized.
    fn try_from(value: &ProtoListener) -> Result<Self, Self::Error> {
        let addr: IpAddr = value
            .address
            .parse()
            .map_err(|err| format!("invalid listener address `{}`: {err}", value.address))?;
        let port = u16::try_from(value.port)
            .map_err(|_| format!("invalid listener port `{}`", value.port))?;
        let tls_options = listener_tls_options_from_proto(value.tls_options.as_ref())?;

        if !value.tls && tls_options != DownstreamTlsOptions::default() {
            return Err(format!(
                "listener `{}` defines TLS options but tls=false",
                value.name
            ));
        }

        Ok(Self {
            name: value.name.clone(),
            listen: Listen {
                addr,
                port,
                ssl: value.tls,
                default_server: false,
                http2: value.http2,
                http2_only: value.http2_only,
            },
            tls_options,
        })
    }
}
