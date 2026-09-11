//! Host and nginx location precedence.

use crate::upstreams::{
    CompiledLocation, CompiledMatcher, CompiledRegex, CompiledRouter, RouteTarget, ServerRoutes,
    VirtualHostRoutes, listener_routes, select_route_target, validate_sni_host_consistency,
};
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, ProxyPassTarget, Server,
    UpstreamSslOptions, UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

pub(super) fn target(id: &str) -> RouteTarget {
    RouteTarget::ProxyPass {
        host: format!("{id}.example.com"),
        port: 80,
        tls: false,
        sni: String::new(),
    }
}

pub(super) fn location(matcher: CompiledMatcher, id: &str) -> CompiledLocation {
    CompiledLocation {
        url_rewrite: None,
        route_id: 1,
        matcher,
        access_rules: Vec::new(),
        target: target(id),
        upstream_timeouts: UpstreamTimeouts::default(),
        upstream_protocol: None,
        upstream_http2: Default::default(),
        upstream_ssl_options: UpstreamSslOptions::default(),
        plugins: Vec::<PluginSpec>::new(),
        cache: None,
    }
}

fn regex(pattern: &str, case_insensitive: bool) -> CompiledMatcher {
    CompiledMatcher::Regex(
        CompiledRegex::new(pattern.to_string(), case_insensitive).expect("regex compiles"),
    )
}

fn selected_host<'a>(routes: &'a ServerRoutes, path: &str) -> Option<&'a str> {
    match select_route_target(routes, path) {
        Some(CompiledLocation {
            url_rewrite: None,
            target: RouteTarget::ProxyPass { host, .. },
            ..
        }) => Some(host.as_str()),
        Some(_) => None,
        None => None,
    }
}

#[test]
fn exact_match_wins() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/".into()), "prefix"),
            location(CompiledMatcher::Exact("/app".into()), "exact"),
            location(regex("^/app$", false), "regex"),
        ],
    };

    assert_eq!(selected_host(&routes, "/app"), Some("exact.example.com"));
}

#[test]
fn prefer_prefix_blocks_regex() {
    let routes = ServerRoutes {
        locations: vec![
            location(
                CompiledMatcher::PreferPrefix("/images/".into()),
                "prefer-prefix",
            ),
            location(regex("\\.(png|jpg)$", false), "regex"),
        ],
    };

    assert_eq!(
        selected_host(&routes, "/images/logo.png"),
        Some("prefer-prefix.example.com")
    );
}

#[test]
fn first_matching_regex_wins_over_plain_prefix() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/api/".into()), "prefix"),
            location(regex("^/api/v[0-9]+/", false), "regex-1"),
            location(regex("^/api/", false), "regex-2"),
        ],
    };

    assert_eq!(
        selected_host(&routes, "/api/v1/users"),
        Some("regex-1.example.com")
    );
}

#[test]
fn longest_plain_prefix_is_used_when_no_regex_matches() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/".into()), "root"),
            location(CompiledMatcher::Prefix("/api/".into()), "api"),
            location(CompiledMatcher::Prefix("/api/internal/".into()), "internal"),
            location(regex("^/admin/", false), "regex"),
        ],
    };

    assert_eq!(
        selected_host(&routes, "/api/internal/users"),
        Some("internal.example.com")
    );
}

#[test]
fn named_location_is_not_selected_for_request_path() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Named("fallback".into()), "named"),
            location(CompiledMatcher::Prefix("/".into()), "prefix"),
        ],
    };

    assert_eq!(selected_host(&routes, "/"), Some("prefix.example.com"));
}

#[test]
fn wildcard_listener_routes_match_concrete_local_addr() {
    let wildcard = crate::upstreams::ListenKey {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 8080,
        ssl: false,
    };
    let concrete = crate::upstreams::ListenKey {
        addr: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 10)),
        port: 8080,
        ssl: false,
    };
    let router = CompiledRouter {
        listeners: HashMap::from([(
            wildcard,
            VirtualHostRoutes {
                named: HashMap::new(),
                default: Some(ServerRoutes {
                    locations: vec![location(CompiledMatcher::Prefix("/".into()), "wildcard")],
                }),
            },
        )]),
        ..CompiledRouter::default()
    };

    let routes = listener_routes(&router, &concrete).expect("wildcard listener should match");
    assert_eq!(
        selected_host(routes.default.as_ref().expect("default routes"), "/"),
        Some("wildcard.example.com")
    );
}

#[test]
fn validate_sni_host_consistency_rejects_mismatch() {
    let err = validate_sni_host_consistency(Some("api.example.com"), Some("edge.example.com"))
        .expect_err("expected mismatch to fail");

    assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(421));
}

#[test]
fn compiled_router_rejects_invalid_location_regex() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Regex {
                    case_insensitive: false,
                    pattern: "(".into(),
                },
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected invalid regex to fail");
    assert!(err.contains("invalid location regex"));
}
