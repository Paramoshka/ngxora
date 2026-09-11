//! Limits, access rules, plugins and transport options.

use crate::upstreams::{
    CompiledRouter, apply_upstream_http_protocol, apply_upstream_timeouts,
    content_length_limit_exceeded, downstream_keepalive_timeout_secs, update_received_body_bytes,
};
use bytes::Bytes;
use ipnet::IpNet;
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationIpRule, LocationMatcher,
    ProxyPassTarget, Server, Switch, UpstreamHttpProtocol, UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use pingora::http::ResponseHeader;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, duplex};

#[test]
fn downstream_keepalive_timeout_maps_off_to_none() {
    assert_eq!(
        downstream_keepalive_timeout_secs(&KeepaliveTimeout::Off),
        None
    );
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
fn compiled_router_parses_proxy_timeouts() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxyConnectTimeout(Duration::from_secs(2)),
                    LocationDirective::ProxyReadTimeout(Duration::from_secs(15)),
                    LocationDirective::ProxyWriteTimeout(Duration::from_secs(20)),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "http://127.0.0.1:8080".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let location = &router
        .listeners
        .values()
        .next()
        .expect("listener present")
        .default
        .as_ref()
        .expect("default route present")
        .locations[0];

    assert_eq!(
        location.upstream_timeouts,
        UpstreamTimeouts {
            connect: Some(Duration::from_secs(2)),
            read: Some(Duration::from_secs(15)),
            write: Some(Duration::from_secs(20)),
        }
    );
}

#[test]
fn compiled_router_parses_proxy_upstream_protocol() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/grpc".into()),
                directives: vec![
                    LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2c),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "http://127.0.0.1:50051".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let location = &router
        .listeners
        .values()
        .next()
        .expect("listener present")
        .default
        .as_ref()
        .expect("default route present")
        .locations[0];

    assert_eq!(location.upstream_protocol, Some(UpstreamHttpProtocol::H2c));
}

#[test]
fn compiled_router_maps_client_max_body_size_into_runtime_options() {
    let mut http = Http {
        client_max_body_size: Some(10 * 1024 * 1024),
        ..Http::default()
    };
    http.servers.push(Server {
        listens: vec![Listen {
            default_server: true,
            ..Listen::default()
        }],
        ..Server::default()
    });

    let router = CompiledRouter::from_http(&http).expect("router compiles");

    assert_eq!(
        router.http_options.client_max_body_size,
        Some(10 * 1024 * 1024)
    );
}

#[test]
fn compiled_router_rejects_tcp_nodelay_off() {
    let mut http = Http {
        tcp_nodelay: Switch::Off,
        ..Http::default()
    };
    http.servers.push(Server {
        listens: vec![Listen {
            default_server: true,
            ..Listen::default()
        }],
        ..Server::default()
    });

    let err = CompiledRouter::from_http(&http).expect_err("expected tcp_nodelay off rejection");
    assert!(err.contains("tcp_nodelay off is not supported"));
}

#[test]
fn content_length_limit_exceeded_rejects_large_body() {
    let header = http::HeaderValue::from_static("10485761");

    assert_eq!(
        content_length_limit_exceeded(Some(&header), Some(10 * 1024 * 1024)),
        Some(true)
    );
}

#[test]
fn update_received_body_bytes_tracks_streamed_body() {
    let mut received = 0;

    update_received_body_bytes(&mut received, Some(&Bytes::from_static(b"hello")), Some(10))
        .expect("first chunk fits");
    update_received_body_bytes(&mut received, Some(&Bytes::from_static(b"rust")), Some(10))
        .expect("second chunk fits");

    assert_eq!(received, 9);
}

#[test]
fn update_received_body_bytes_rejects_overflowing_stream() {
    let mut received = 8;
    let err = update_received_body_bytes(
        &mut received,
        Some(&Bytes::from_static(b"toolong")),
        Some(10),
    )
    .expect_err("expected body limit to be enforced");

    assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(413));
}

#[tokio::test]
async fn request_body_filter_ignores_upgraded_websocket_stream() {
    let (mut client, server) = duplex(1024);
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
        )
        .await
        .expect("write upgrade request");

    let mut session = Session::new_h1(Box::new(server));
    session.read_request().await.expect("read request");

    let mut switching_protocols =
        ResponseHeader::build(http::StatusCode::SWITCHING_PROTOCOLS, None)
            .expect("build 101 response");
    switching_protocols.set_version(http::Version::HTTP_11);
    session
        .write_response_header(Box::new(switching_protocols), false)
        .await
        .expect("write 101 response");
    assert!(session.was_upgraded());

    let proxy = crate::upstreams::DynamicProxy::from_router(CompiledRouter::default());
    let mut ctx = crate::upstreams::ProxyContext {
        client_max_body_size: Some(1),
        ..Default::default()
    };
    let mut body = Some(Bytes::from_static(b"hello"));

    ProxyHttp::request_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
        .await
        .expect("upgraded body should bypass http body limits");

    assert_eq!(body, Some(Bytes::from_static(b"hello")));
    assert_eq!(ctx.received_body_bytes, 0);
}

#[test]
fn compiled_router_preserves_location_access_rules() {
    let allow = "10.0.0.0/8".parse::<IpNet>().expect("test network");
    let deny = "192.0.2.1/32"
        .parse::<IpNet>()
        .expect("192.0.2.1/32 is valid");

    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                access_rules: vec![LocationIpRule::Deny(deny), LocationIpRule::Allow(allow)],
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let location = &router
        .listeners
        .values()
        .next()
        .expect("listener present")
        .default
        .as_ref()
        .expect("default route present")
        .locations[0];

    assert_eq!(
        location.access_rules,
        vec![LocationIpRule::Deny(deny), LocationIpRule::Allow(allow)]
    );
}

#[test]
fn compiled_router_preserves_location_plugins() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
                access_rules: Vec::new(),
                plugins: vec![PluginSpec {
                    name: "headers".into(),
                    config: json!({
                        "response": {
                            "add": [
                                { "name": "X-Proxy", "value": "ngxora" }
                            ]
                        }
                    }),
                }],
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let location = &router
        .listeners
        .values()
        .next()
        .expect("listener present")
        .default
        .as_ref()
        .expect("default route present")
        .locations[0];

    assert_eq!(location.plugins, http.servers[0].locations[0].plugins);
}

#[test]
fn apply_upstream_timeouts_maps_zero_to_none() {
    let mut peer = HttpPeer::new(("127.0.0.1", 8080), false, String::new());
    apply_upstream_timeouts(
        &mut peer,
        UpstreamTimeouts {
            connect: Some(Duration::ZERO),
            read: Some(Duration::from_secs(10)),
            write: Some(Duration::from_secs(5)),
        },
    );

    assert_eq!(peer.options.connection_timeout, None);
    assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(10)));
    assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(5)));
}

#[test]
fn apply_upstream_http_protocol_sets_peer_http_version() {
    let mut peer = HttpPeer::new(("127.0.0.1", 50051), true, String::new());

    apply_upstream_http_protocol(&mut peer, Some(UpstreamHttpProtocol::H2));
    assert_eq!(peer.options.alpn.get_min_http_version(), 2);
    assert_eq!(peer.options.alpn.get_max_http_version(), 2);

    apply_upstream_http_protocol(&mut peer, Some(UpstreamHttpProtocol::H1));
    assert_eq!(peer.options.alpn.get_min_http_version(), 1);
    assert_eq!(peer.options.alpn.get_max_http_version(), 1);
}
