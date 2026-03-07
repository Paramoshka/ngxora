use super::{select_route_target, CompiledLocation, CompiledMatcher, RouteTarget, ServerRoutes};

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
        matcher,
        target: target(id),
    }
}

fn selected_host<'a>(routes: &'a ServerRoutes, path: &str) -> Option<&'a str> {
    match select_route_target(routes, path) {
        Some(RouteTarget::ProxyPass { host, .. }) => Some(host.as_str()),
        None => None,
    }
}

#[test]
fn exact_match_wins() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/".into()), "prefix"),
            location(CompiledMatcher::Exact("/app".into()), "exact"),
            location(
                CompiledMatcher::Regex {
                    case_insensitive: false,
                    pattern: "^/app$".into(),
                },
                "regex",
            ),
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
            location(
                CompiledMatcher::Regex {
                    case_insensitive: false,
                    pattern: "\\.(png|jpg)$".into(),
                },
                "regex",
            ),
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
            location(
                CompiledMatcher::Regex {
                    case_insensitive: false,
                    pattern: "^/api/v[0-9]+/".into(),
                },
                "regex-1",
            ),
            location(
                CompiledMatcher::Regex {
                    case_insensitive: false,
                    pattern: "^/api/".into(),
                },
                "regex-2",
            ),
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
            location(
                CompiledMatcher::Regex {
                    case_insensitive: false,
                    pattern: "^/admin/".into(),
                },
                "regex",
            ),
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
