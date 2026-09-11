//! Export the active compiled snapshot as protobuf.

use super::http_routes::{http_match_to_proto, modifier_to_proto};
use super::proto;
use super::proto::{
    CacheKeyMode as ProtoCacheKeyMode, ConfigSnapshot as ProtoConfigSnapshot,
    HttpOptions as ProtoHttpOptions, Listener as ProtoListener, Match as ProtoMatch,
    NrfDiscovery as ProtoNrfDiscovery, NrfEndpointScheme as ProtoNrfEndpointScheme,
    Plugin as ProtoPlugin, Redirect as ProtoRedirect, Regex as ProtoRegex, Route as ProtoRoute,
    RouteCache as ProtoRouteCache, RouteTimeouts as ProtoRouteTimeouts, Upstream as ProtoUpstream,
    UpstreamBackend as ProtoUpstreamBackend, UpstreamGroup as ProtoUpstreamGroup,
    UpstreamHashKey as ProtoUpstreamHashKey, UpstreamHealthCheck as ProtoUpstreamHealthCheck,
    UpstreamHttpHealthCheck as ProtoUpstreamHttpHealthCheck,
    UpstreamHttpProtocol as ProtoUpstreamHttpProtocol,
    UpstreamTcpHealthCheck as ProtoUpstreamTcpHealthCheck, VirtualHost as ProtoVirtualHost,
};
use super::tls::{
    proto_le_config_from_ir, proto_listener_tls_options_from_runtime,
    proto_tls_binding_from_runtime, proto_upstream_tls_options_from_runtime,
};
use super::values::{
    duration_to_millis, proto_switch_from_runtime, proto_upstream_selection_policy_from_runtime,
};
use crate::control::RuntimeSnapshot;
use crate::upstreams::{
    CompiledLocation, CompiledMatcher, HttpRuntimeOptions, ListenKey, RouteTarget, ServerRoutes,
    VirtualHostRoutes,
};
use ngxora_compile::ir::{
    CacheConfig, CacheKeyMode, NrfEndpointScheme, Switch, TlsIdentity, UpstreamHashKey,
    UpstreamHttpProtocol, UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use std::collections::{BTreeMap, HashMap};

// Export the active runtime snapshot back to the protobuf shape used by the
// local control-plane. This path is primarily for GetSnapshot and tests.
pub(super) fn proto_snapshot_from_runtime(
    snapshot: &RuntimeSnapshot,
) -> Result<ProtoConfigSnapshot, String> {
    let mut listener_keys = snapshot
        .router
        .listeners
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    listener_keys.sort();

    let listener_names = listener_names(&listener_keys);
    let listeners = listener_keys
        .iter()
        .map(|key| proto_listener_from_runtime(snapshot, key, &listener_names))
        .collect::<Result<Vec<_>, _>>()?;

    let mut virtual_hosts = Vec::new();
    for key in &listener_keys {
        let routes = snapshot
            .router
            .listeners
            .get(key)
            .ok_or_else(|| "listener disappeared while building snapshot".to_string())?;
        let listener_name = listener_names
            .get(key)
            .cloned()
            .ok_or_else(|| "listener name mapping is incomplete".to_string())?;
        let tls = snapshot.router.listener_tls.get(key);
        virtual_hosts.extend(proto_virtual_hosts_from_runtime(
            &listener_name,
            routes,
            tls,
        )?);
    }

    Ok(ProtoConfigSnapshot {
        scp_profiles: {
            let mut profiles = snapshot.router.scp_profiles.values().collect::<Vec<_>>();
            profiles.sort_by(|a, b| a.name.cmp(&b.name));
            profiles
                .into_iter()
                .map(|p| proto::ScpProfile {
                    name: p.name.clone(),
                    api_root: p.api_root.clone(),
                    discovery_upstreams: p.discovery_upstreams.clone(),
                    allowed_target_api_roots: p.allowed_target_api_roots.clone(),
                })
                .collect()
        },
        version: snapshot.version.clone(),
        http: Some(proto_http_options_from_runtime(
            &snapshot.router.http_options,
        )),
        listeners,
        virtual_hosts,
        upstreams: proto_upstreams_from_runtime(&snapshot.router.upstreams),
        le_config: snapshot
            .router
            .le_config
            .as_ref()
            .map(proto_le_config_from_ir),
    })
}

fn proto_upstreams_from_runtime(
    upstreams: &HashMap<String, crate::upstreams::CompiledUpstreamGroup>,
) -> Vec<ProtoUpstreamGroup> {
    let mut groups = upstreams.values().cloned().collect::<Vec<_>>();
    groups.sort_by(|left, right| left.name.cmp(&right.name));

    groups
        .into_iter()
        .map(|group| ProtoUpstreamGroup {
            allow_empty: group.allow_empty,
            name: group.name,
            backends: group
                .servers
                .into_iter()
                .map(|server| ProtoUpstreamBackend {
                    host: server.host,
                    port: u32::from(server.port),
                    weight: u32::from(server.weight),
                })
                .collect(),
            policy: proto_upstream_selection_policy_from_runtime(group.policy) as i32,
            health_check: group
                .health_check
                .as_ref()
                .map(proto_upstream_health_check_from_runtime),
            hash_key: group
                .hash_key
                .as_ref()
                .map(proto_upstream_hash_key_from_runtime),
            nrf_discovery: group
                .nrf_discovery
                .as_ref()
                .map(proto_nrf_discovery_from_runtime),
        })
        .collect()
}

fn proto_nrf_discovery_from_runtime(
    value: &crate::upstreams::CompiledNrfDiscovery,
) -> ProtoNrfDiscovery {
    ProtoNrfDiscovery {
        api_root: value.api_root.to_string().trim_end_matches('/').to_string(),
        target_nf_type: value.target_nf_type.clone(),
        requester_nf_type: value.requester_nf_type.clone(),
        service_name: value.service_name.clone(),
        endpoint_scheme: match value.endpoint_scheme {
            NrfEndpointScheme::Http => ProtoNrfEndpointScheme::Http as i32,
            NrfEndpointScheme::Https => ProtoNrfEndpointScheme::Https as i32,
        },
        timeout_ms: value.timeout.as_millis().try_into().unwrap_or(u64::MAX),
        stale_if_error_ms: value
            .stale_if_error
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        tls_options: Some(proto_upstream_tls_options_from_runtime(&value.tls_options)),
    }
}

fn proto_upstream_hash_key_from_runtime(value: &UpstreamHashKey) -> ProtoUpstreamHashKey {
    let source = match value {
        UpstreamHashKey::ClientIp => proto::upstream_hash_key::Source::ClientIp(true),
        UpstreamHashKey::Header(name) => proto::upstream_hash_key::Source::Header(name.clone()),
    };
    ProtoUpstreamHashKey {
        source: Some(source),
    }
}

fn proto_upstream_health_check_from_runtime(
    value: &crate::upstreams::CompiledHealthCheck,
) -> ProtoUpstreamHealthCheck {
    let kind = match &value.check_type {
        crate::upstreams::HealthCheckType::Tcp => {
            proto::upstream_health_check::Kind::Tcp(ProtoUpstreamTcpHealthCheck {})
        }
        crate::upstreams::HealthCheckType::Http {
            host,
            path,
            use_tls,
        } => proto::upstream_health_check::Kind::Http(ProtoUpstreamHttpHealthCheck {
            host: host.clone(),
            path: path.clone(),
            use_tls: *use_tls,
        }),
    };

    ProtoUpstreamHealthCheck {
        kind: Some(kind),
        timeout_ms: value.timeout.as_millis().try_into().unwrap_or(u64::MAX),
        interval_ms: value.interval.as_millis().try_into().unwrap_or(u64::MAX),
        consecutive_success: value.consecutive_success.try_into().unwrap_or(u32::MAX),
        consecutive_failure: value.consecutive_failure.try_into().unwrap_or(u32::MAX),
    }
}

fn listener_names(keys: &[ListenKey]) -> BTreeMap<ListenKey, String> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| (key.clone(), format!("listener-{}", index + 1)))
        .collect()
}

fn proto_listener_from_runtime(
    snapshot: &RuntimeSnapshot,
    key: &ListenKey,
    names: &BTreeMap<ListenKey, String>,
) -> Result<ProtoListener, String> {
    let protocol = snapshot
        .router
        .listener_protocols
        .get(key)
        .cloned()
        .unwrap_or_default();
    let tls_options = snapshot
        .router
        .listener_tls
        .get(key)
        .map(|tls| proto_listener_tls_options_from_runtime(&tls.settings));

    Ok(ProtoListener {
        name: names
            .get(key)
            .cloned()
            .ok_or_else(|| "listener name mapping is incomplete".to_string())?,
        address: key.addr.to_string(),
        port: u32::from(key.port),
        tls: key.ssl,
        http2: protocol.http2,
        http2_only: protocol.http2_only,
        tls_options,
    })
}

// Virtual hosts are re-expanded from the compiled router because runtime state
// stores listener -> named/default server routes rather than the original wire
// list.
fn proto_virtual_hosts_from_runtime(
    listener_name: &str,
    routes: &VirtualHostRoutes,
    tls: Option<&crate::upstreams::ListenerTlsConfig>,
) -> Result<Vec<ProtoVirtualHost>, String> {
    let mut virtual_hosts = Vec::new();

    for (host, server_routes) in sorted_named_routes(&routes.named) {
        let identity = tls
            .and_then(|cfg| cfg.named.get(host))
            .cloned()
            .or_else(|| tls.and_then(|cfg| cfg.default.clone()));

        merge_or_push_virtual_host(
            &mut virtual_hosts,
            listener_name,
            false,
            host.clone(),
            server_routes,
            identity,
        )?;
    }

    if let Some(default_routes) = routes.default.as_ref() {
        let default_tls = tls.and_then(|cfg| cfg.default.clone());
        let default_routes_proto = proto_routes_from_runtime(default_routes)?;
        let default_tls_proto = default_tls.as_ref().map(proto_tls_binding_from_runtime);

        if let Some(current) = virtual_hosts.iter_mut().find(|current| {
            current.listener == listener_name
                && current.routes == default_routes_proto
                && current.tls == default_tls_proto
        }) {
            current.default_server = true;
        } else {
            virtual_hosts.push(ProtoVirtualHost {
                listener: listener_name.to_string(),
                server_names: Vec::new(),
                default_server: true,
                tls: default_tls_proto,
                routes: default_routes_proto,
            });
        }
    }

    Ok(virtual_hosts)
}

fn merge_or_push_virtual_host(
    out: &mut Vec<ProtoVirtualHost>,
    listener_name: &str,
    default_server: bool,
    host: String,
    routes: &ServerRoutes,
    identity: Option<TlsIdentity>,
) -> Result<(), String> {
    let tls = identity.as_ref().map(proto_tls_binding_from_runtime);
    let routes = proto_routes_from_runtime(routes)?;

    if let Some(current) = out.iter_mut().find(|current| {
        current.listener == listener_name
            && current.default_server == default_server
            && current.tls == tls
            && current.routes == routes
    }) {
        current.server_names.push(host);
        current.server_names.sort();
        return Ok(());
    }

    out.push(ProtoVirtualHost {
        listener: listener_name.to_string(),
        server_names: vec![host],
        default_server,
        tls,
        routes,
    });
    Ok(())
}

fn proto_routes_from_runtime(routes: &ServerRoutes) -> Result<Vec<ProtoRoute>, String> {
    routes
        .locations
        .iter()
        .map(proto_route_from_runtime)
        .collect()
}

fn proto_route_from_runtime(route: &CompiledLocation) -> Result<ProtoRoute, String> {
    Ok(ProtoRoute {
        url_rewrite: route.url_rewrite.as_ref().map(|rewrite| proto::UrlRewrite {
            hostname: rewrite.hostname.clone(),
            path: rewrite.path.as_ref().map(modifier_to_proto),
        }),
        r#match: Some(proto_match_from_runtime(&route.matcher)),
        action: Some(proto_route_action_from_runtime(&route.target)?),
        timeouts: Some(proto_timeouts_from_runtime(&route.upstream_timeouts)),
        plugins: route
            .plugins
            .iter()
            .map(proto_plugin_from_runtime)
            .collect::<Result<Vec<_>, _>>()?,
        tls_options: Some(proto_upstream_tls_options_from_runtime(
            &route.upstream_ssl_options,
        )),
        upstream_protocol: proto_upstream_http_protocol_from_runtime(route.upstream_protocol)
            as i32,
        cache: route.cache.as_ref().map(proto_route_cache_from_runtime),
    })
}

fn proto_match_from_runtime(matcher: &CompiledMatcher) -> ProtoMatch {
    let kind = match matcher {
        CompiledMatcher::Http(matcher) => proto::r#match::Kind::Http(http_match_to_proto(matcher)),
        CompiledMatcher::Prefix(path) => proto::r#match::Kind::Prefix(path.clone()),
        CompiledMatcher::Exact(path) => proto::r#match::Kind::Exact(path.clone()),
        CompiledMatcher::PreferPrefix(path) => proto::r#match::Kind::PreferPrefix(path.clone()),
        CompiledMatcher::Regex(regex) => proto::r#match::Kind::Regex(ProtoRegex {
            pattern: regex.pattern.clone(),
            case_insensitive: regex.case_insensitive,
        }),
        CompiledMatcher::Named(name) => proto::r#match::Kind::Named(name.clone()),
    };

    ProtoMatch { kind: Some(kind) }
}

fn proto_route_action_from_runtime(target: &RouteTarget) -> Result<proto::route::Action, String> {
    Ok(match target {
        RouteTarget::DirectResponse(status) => {
            proto::route::Action::DirectResponse(proto::DirectResponse {
                status: u32::from(*status),
            })
        }
        RouteTarget::HttpRedirect(config) => {
            proto::route::Action::HttpRedirect(proto::HttpRedirect {
                status: u32::from(config.status),
                scheme: config.scheme.clone(),
                hostname: config.hostname.clone(),
                port: config.port.map(u32::from),
                path: config.path.as_ref().map(modifier_to_proto),
            })
        }
        RouteTarget::WeightedBackends(backends) => {
            proto::route::Action::WeightedBackends(proto::WeightedBackends {
                backends: backends
                    .iter()
                    .map(|b| {
                        let target = match &b.target {
                            RouteTarget::DirectResponse(status) => {
                                proto::weighted_backend::Target::DirectResponse(
                                    proto::DirectResponse {
                                        status: u32::from(*status),
                                    },
                                )
                            }
                            RouteTarget::ProxyPass { .. } | RouteTarget::UpstreamGroup { .. } => {
                                let proto::route::Action::Upstream(upstream) =
                                    proto_route_action_from_runtime(&b.target)?
                                else {
                                    return Err("invalid compiled upstream target".into());
                                };
                                proto::weighted_backend::Target::Upstream(upstream)
                            }
                            _ => {
                                return Err(
                                    "weighted backend must be an upstream or direct response"
                                        .into(),
                                );
                            }
                        };
                        Ok(proto::WeightedBackend {
                            weight: Some(b.weight),
                            target: Some(target),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            })
        }
        RouteTarget::Scp { profile } => proto::route::Action::ScpProfile(profile.clone()),
        RouteTarget::ProxyPass {
            host, port, tls, ..
        } => proto::route::Action::Upstream(ProtoUpstream {
            scheme: if *tls { "https" } else { "http" }.into(),
            host: host.clone(),
            port: u32::from(*port),
            upstream_group: String::new(),
        }),
        RouteTarget::UpstreamGroup { name, tls } => proto::route::Action::Upstream(ProtoUpstream {
            scheme: if *tls { "https" } else { "http" }.into(),
            host: String::new(),
            port: 0,
            upstream_group: name.clone(),
        }),
        RouteTarget::Return { status, location } => proto::route::Action::Redirect(ProtoRedirect {
            status: u32::from(*status),
            location: location.clone(),
        }),
    })
}

fn proto_route_cache_from_runtime(value: &CacheConfig) -> ProtoRouteCache {
    ProtoRouteCache {
        enabled: proto_switch_from_runtime(if value.enabled {
            Switch::On
        } else {
            Switch::Off
        }) as i32,
        max_size_bytes: value.max_size.unwrap_or(0),
        ttl_ms: duration_to_millis(value.ttl),
        stale_if_error_ms: duration_to_millis(value.stale_if_error),
        key_mode: proto_cache_key_mode_from_runtime(value.cache_key.clone()) as i32,
        min_uses: value
            .min_uses
            .and_then(|uses| u32::try_from(uses).ok())
            .unwrap_or(0),
        valid_statuses: value
            .valid_statuses
            .iter()
            .map(|status| u32::from(*status))
            .collect(),
    }
}

fn proto_upstream_http_protocol_from_runtime(
    value: Option<UpstreamHttpProtocol>,
) -> ProtoUpstreamHttpProtocol {
    match value {
        None => ProtoUpstreamHttpProtocol::Unspecified,
        Some(UpstreamHttpProtocol::H1) => ProtoUpstreamHttpProtocol::H1,
        Some(UpstreamHttpProtocol::H2) => ProtoUpstreamHttpProtocol::H2,
        Some(UpstreamHttpProtocol::H2c) => ProtoUpstreamHttpProtocol::H2c,
    }
}

fn proto_cache_key_mode_from_runtime(value: CacheKeyMode) -> ProtoCacheKeyMode {
    match value {
        CacheKeyMode::Uri => ProtoCacheKeyMode::Uri,
        CacheKeyMode::UriAndMethod => ProtoCacheKeyMode::UriAndMethod,
        CacheKeyMode::NormalizedUri => ProtoCacheKeyMode::NormalizedUri,
    }
}

fn proto_timeouts_from_runtime(timeouts: &UpstreamTimeouts) -> ProtoRouteTimeouts {
    ProtoRouteTimeouts {
        connect_timeout_ms: duration_to_millis(timeouts.connect),
        read_timeout_ms: duration_to_millis(timeouts.read),
        write_timeout_ms: duration_to_millis(timeouts.write),
    }
}

fn proto_plugin_from_runtime(plugin: &PluginSpec) -> Result<ProtoPlugin, String> {
    Ok(ProtoPlugin {
        name: plugin.name.clone(),
        json_config: serde_json::to_string(&plugin.config)
            .map_err(|err| format!("failed to serialize plugin `{}` config: {err}", plugin.name))?,
    })
}

fn proto_http_options_from_runtime(options: &HttpRuntimeOptions) -> ProtoHttpOptions {
    ProtoHttpOptions {
        downstream_keepalive_timeout_seconds: options.downstream_keepalive_timeout.unwrap_or(0),
        tcp_nodelay: options.tcp_nodelay,
        keepalive_requests: options.keepalive_requests.unwrap_or(0),
        allow_connect_method_proxying: options.allow_connect_method_proxying,
        h2c: options.h2c,
        client_max_body_size_bytes: options.client_max_body_size.unwrap_or(0),
        proxy_cache_max_size_bytes: options.proxy_cache_max_size.unwrap_or(0),
    }
}

fn sorted_named_routes(routes: &HashMap<String, ServerRoutes>) -> Vec<(&String, &ServerRoutes)> {
    let mut entries = routes.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(left, _)| *left);
    entries
}
