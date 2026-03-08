use super::{
    downstream_keepalive_timeout_secs, select_route_target, validate_sni_host_consistency,
    CompiledLocation, CompiledMatcher, CompiledRegex, CompiledRouter, RouteTarget, ServerRoutes,
};
use ngxora_plugin_api::PluginSpec;
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher, Server,
};
use std::time::Duration;

fn target(id: &str) -> RouteTarget {
    RouteTarget::ProxyPass {
        host: format!("{id}.example.com"),
        port: 80,
        tls: false,
        sni: String::new(),
    }
}

fn location(matcher: CompiledMatcher, id: &str) -> CompiledLocation {
    CompiledLocation {
        route_id: 1,
        matcher,
        target: target(id),
        plugins: Vec::<PluginSpec>::new(),
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
            target: RouteTarget::ProxyPass { host, .. },
            ..
        }) => Some(host.as_str()),
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
fn downstream_keepalive_timeout_maps_off_to_none() {
    assert_eq!(downstream_keepalive_timeout_secs(&KeepaliveTimeout::Off), None);
}

#[test]
fn downstream_keepalive_timeout_rounds_up_subsecond_values() {
    assert_eq!(
        downstream_keepalive_timeout_secs(&KeepaliveTimeout::Timeout {
            idle: Duration::from_millis(1_500),
            header: None,
        }),
        Some(2)
    );
}

#[test]
fn downstream_keepalive_timeout_treats_zero_idle_as_disabled() {
    assert_eq!(
        downstream_keepalive_timeout_secs(&KeepaliveTimeout::Timeout {
            idle: Duration::ZERO,
            header: Some(Duration::from_secs(10)),
        }),
        None
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
                directives: vec![LocationDirective::ProxyPass(
                    "http://127.0.0.1:8080".parse().unwrap(),
                )],
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected invalid regex to fail");
    assert!(err.contains("invalid location regex"));
}
