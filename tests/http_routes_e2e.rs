use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use ngxora_runtime::grpc::proto::{self as p, control_plane_client::ControlPlaneClient};
use std::{
    net::TcpListener as StdListener,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tonic::transport::{Channel, Endpoint};

struct Proxy {
    child: Child,
    _temp: tempfile::TempDir,
    port: u16,
    client: ControlPlaneClient<Channel>,
    snapshot: p::ConfigSnapshot,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.child.kill().expect("stop test proxy");
        self.child.wait().expect("reap test proxy");
    }
}

impl Proxy {
    async fn start(extra_servers: &str) -> Self {
        Self::start_with_http("", extra_servers).await
    }

    async fn start_with_http(http_options: &str, extra_servers: &str) -> Self {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let config = temp.path().join("ngxora.conf");
        std::fs::write(
            &config,
            format!(
                r#"http {{ h2c on; {http_options}
            server {{ listen 127.0.0.1:{port} default_server; server_name test.local;
                location / {{ return 302 https://bootstrap.example/; }}
            }} {}
        }}"#,
                extra_servers.replace("PORT", &port.to_string())
            ),
        )
        .unwrap();
        drop(listener);
        // Exercise the packaged binary with the same suite when requested.
        let binary = std::env::var_os("NGXORA_TEST_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_ngxora").into());
        let child = Command::new(binary)
            .arg("--grpc-uds")
            .arg(&socket)
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut proxy = Self {
            child,
            _temp: temp,
            port,
            client: ControlPlaneClient::new(
                Endpoint::from_static("http://localhost").connect_lazy(),
            ),
            snapshot: Default::default(),
        };
        for _ in 0..100 {
            let socket = socket.clone();
            if let Ok(channel) = Endpoint::from_static("http://localhost")
                .connect_with_connector(tower::service_fn(move |_| {
                    let socket = socket.clone();
                    async move { UnixStream::connect(socket).await.map(TokioIo::new) }
                }))
                .await
            {
                proxy.client = ControlPlaneClient::new(channel);
                proxy.snapshot = proxy
                    .client
                    .get_snapshot(p::GetSnapshotRequest {})
                    .await
                    .unwrap()
                    .into_inner();
                for _ in 0..100 {
                    if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                        return proxy;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                panic!("proxy HTTP listener did not start");
            }
            assert!(
                proxy.child.try_wait().unwrap().is_none(),
                "proxy exited during startup"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("proxy control socket did not start");
    }

    async fn apply(&mut self, routes: Vec<p::Route>) {
        self.snapshot.virtual_hosts[0].routes = routes;
        self.snapshot.version.push('x');
        let result = self
            .client
            .apply_snapshot(self.snapshot.clone())
            .await
            .unwrap()
            .into_inner();
        assert!(result.applied, "{}", result.message);
        assert!(!result.restart_required);
    }

    async fn request(
        &self,
        method: &str,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        h2: bool,
    ) -> (u16, hyper::HeaderMap, String) {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.request_inner(method, host, path, headers, h2),
        )
        .await
        .expect("HTTP request completed within 5 seconds")
    }

    async fn request_inner(
        &self,
        method: &str,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        h2: bool,
    ) -> (u16, hyper::HeaderMap, String) {
        let stream = TokioIo::new(TcpStream::connect(("127.0.0.1", self.port)).await.unwrap());
        let mut request = Request::builder()
            .method(method)
            .uri(if h2 {
                format!("http://{host}{path}")
            } else {
                path.into()
            })
            .header("host", host);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Empty::<Bytes>::new()).unwrap();
        let response = if h2 {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), stream)
                    .await
                    .unwrap();
            tokio::spawn(async move {
                connection.await.expect("HTTP/2 client connection");
            });
            sender.send_request(request).await.unwrap()
        } else {
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(stream).await.unwrap();
            tokio::spawn(async move {
                connection.await.expect("HTTP/1 client connection");
            });
            sender.send_request(request).await.unwrap()
        };
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }
}

fn route(path: &str, status: u32) -> p::Route {
    p::Route {
        r#match: Some(p::Match {
            kind: Some(p::r#match::Kind::Http(p::HttpMatch {
                path: Some(p::http_match::Path::PathPrefix(path.into())),
                ..Default::default()
            })),
        }),
        action: Some(p::route::Action::DirectResponse(p::DirectResponse {
            status,
        })),
        ..Default::default()
    }
}

fn matcher(route: &mut p::Route) -> &mut p::HttpMatch {
    match route.r#match.as_mut().unwrap().kind.as_mut().unwrap() {
        p::r#match::Kind::Http(matcher) => matcher,
        _ => panic!("expected HTTP matcher"),
    }
}

fn header_plugin() -> p::Plugin {
    p::Plugin {
        name: "headers".into(),
        json_config: r#"{"response":{"add":[{"name":"X-Review","value":"yes"}]}}"#.into(),
    }
}

fn backend(port: u16) -> p::Upstream {
    p::Upstream {
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port: port.into(),
        ..Default::default()
    }
}

async fn echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(|request: Request<Incoming>| async move {
                            let body = format!(
                                "{} {}",
                                request.uri(),
                                request.headers().get("host").unwrap().to_str().unwrap()
                            );
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from(body),
                            )))
                        }),
                    )
                    .await
                    .expect("echo backend connection");
            });
        }
    });
    (port, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_redirect_templates_and_local_response_headers() {
    let mut proxy = Proxy::start("").await;
    let closed = StdListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut redirect = route("/redirect", 200);
    redirect.r#match = Some(p::Match {
        kind: Some(p::r#match::Kind::Prefix("/redirect".into())),
    });
    redirect.action = Some(p::route::Action::Redirect(p::Redirect {
        status: 301,
        location: "https://$host$request_uri".into(),
    }));
    redirect.plugins = vec![header_plugin()];
    let mut down = redirect.clone();
    down.r#match = Some(p::Match {
        kind: Some(p::r#match::Kind::Prefix("/down".into())),
    });
    down.action = Some(p::route::Action::Upstream(backend(closed_port)));
    proxy.apply(vec![redirect, down]).await;
    for h2 in [false, true] {
        assert_eq!(
            proxy
                .request("GET", "test.local", "/missing", &[], h2)
                .await
                .0,
            404
        );
        let (status, headers, _) = proxy.request("GET", "test.local", "/down", &[], h2).await;
        assert_eq!(status, 502);
        assert_eq!(headers["x-review"], "yes");
        let (status, headers, _) = proxy
            .request("GET", "test.local", "/redirect?a=1", &[], h2)
            .await;
        assert_eq!(status, 301);
        assert_eq!(headers["location"], "https://test.local/redirect?a=1");
        assert_eq!(headers.get_all("x-review").iter().count(), 1);
        assert_eq!(
            proxy
                .request("HEAD", "test.local", "/redirect", &[], h2)
                .await
                .2,
            ""
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn http_matching_and_wildcard_fallback() {
    let mut proxy = Proxy::start("").await;
    let base = route("/foo/", 200);
    let mut header = route("/foo", 201);
    matcher(&mut header).headers = vec![p::ExactCondition {
        name: "X-Tenant".into(),
        value: "a".into(),
    }];
    let mut method = route("/foo", 202);
    matcher(&mut method).method = Some("POST".into());
    let mut query = header.clone();
    query.action = Some(p::route::Action::DirectResponse(p::DirectResponse {
        status: 203,
    }));
    matcher(&mut query).query_params = vec![p::ExactCondition {
        name: "q".into(),
        value: "a b".into(),
    }];
    let mut exact = route("/foo", 204);
    matcher(&mut exact).path = Some(p::http_match::Path::Exact("/foo/exact".into()));
    let listener = proxy.snapshot.listeners[0].name.clone();
    proxy.snapshot.virtual_hosts.push(p::VirtualHost {
        listener,
        server_names: vec!["*.local".into()],
        routes: vec![route("/wild", 206)],
        ..Default::default()
    });
    proxy.apply(vec![base, header, method, query, exact]).await;
    for h2 in [false, true] {
        for path in ["/foo", "/foo/", "/foo/bar"] {
            assert_eq!(
                proxy.request("GET", "test.local", path, &[], h2).await.0,
                200
            );
        }
        assert_eq!(
            proxy
                .request("GET", "test.local", "/foobar", &[], h2)
                .await
                .0,
            404
        );
        assert_eq!(
            proxy
                .request("GET", "test.local", "/foo", &[("x-tenant", "a")], h2)
                .await
                .0,
            201
        );
        assert_eq!(
            proxy
                .request("POST", "test.local", "/foo", &[("x-tenant", "a")], h2)
                .await
                .0,
            202
        );
        assert_eq!(
            proxy
                .request(
                    "GET",
                    "test.local",
                    "/foo?q=a%20b&q=bad",
                    &[("x-tenant", "a")],
                    h2
                )
                .await
                .0,
            203
        );
        assert_eq!(
            proxy
                .request("POST", "test.local", "/foo/exact", &[("x-tenant", "a")], h2)
                .await
                .0,
            204
        );
        assert_eq!(
            proxy.request("GET", "test.local", "/wild", &[], h2).await.0,
            206
        );
        assert_eq!(
            proxy.request("GET", "a.b.local", "/wild", &[], h2).await.0,
            206
        );
        assert_eq!(proxy.request("GET", "local", "/wild", &[], h2).await.0, 404);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn weighted_backends_empty_groups_and_live_updates() {
    let mut proxy = Proxy::start("").await;
    let (port, task) = echo_backend().await;
    proxy.snapshot.upstreams = vec![p::UpstreamGroup {
        name: "service".into(),
        allow_empty: true,
        ..Default::default()
    }];
    let mut weighted = route("/", 200);
    let choices = vec![
        p::WeightedBackend {
            weight: Some(9),
            target: Some(p::weighted_backend::Target::Upstream(p::Upstream {
                scheme: "http".into(),
                upstream_group: "service".into(),
                ..Default::default()
            })),
        },
        p::WeightedBackend {
            weight: Some(1),
            target: Some(p::weighted_backend::Target::DirectResponse(
                p::DirectResponse { status: 500 },
            )),
        },
        p::WeightedBackend {
            weight: Some(0),
            target: Some(p::weighted_backend::Target::DirectResponse(
                p::DirectResponse { status: 418 },
            )),
        },
    ];
    weighted.action = Some(p::route::Action::WeightedBackends(p::WeightedBackends {
        backends: choices.clone(),
    }));
    for ready in [true, false, true] {
        proxy.snapshot.upstreams[0].backends = if ready {
            vec![p::UpstreamBackend {
                host: "127.0.0.1".into(),
                port: port.into(),
                weight: 1,
            }]
        } else {
            vec![]
        };
        proxy.apply(vec![weighted.clone()]).await;
        let mut statuses = Vec::new();
        for _ in 0..20 {
            statuses.push(proxy.request("GET", "test.local", "/", &[], false).await.0);
        }
        assert_eq!(
            statuses
                .iter()
                .filter(|&&s| s == if ready { 200 } else { 503 })
                .count(),
            18
        );
        assert_eq!(statuses.iter().filter(|&&s| s == 500).count(), 2);
    }
    let exported = proxy
        .client
        .get_snapshot(p::GetSnapshotRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exported.virtual_hosts[0].routes[0].action, weighted.action);
    let mut equal = choices.clone();
    equal[0].weight = None;
    weighted.action = Some(p::route::Action::WeightedBackends(p::WeightedBackends {
        backends: equal,
    }));
    proxy.apply(vec![weighted.clone()]).await;
    let mut successes = 0;
    for _ in 0..20 {
        match proxy.request("GET", "test.local", "/", &[], false).await.0 {
            200 => successes += 1,
            500 => {}
            status => panic!("unexpected backend status {status}"),
        }
    }
    assert_eq!(successes, 10);
    let mut disabled = choices.clone();
    for choice in &mut disabled {
        choice.weight = Some(0);
    }
    weighted.action = Some(p::route::Action::WeightedBackends(p::WeightedBackends {
        backends: disabled,
    }));
    proxy.apply(vec![weighted]).await;
    assert_eq!(
        proxy.request("GET", "test.local", "/", &[], true).await.0,
        503
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn structured_redirect_rewrite_and_snapshot_rejection() {
    let mut proxy = Proxy::start("").await;
    let (port, task) = echo_backend().await;
    let modifier = p::PathModifier {
        kind: Some(p::path_modifier::Kind::ReplacePrefixMatch("/new".into())),
    };
    let mut rewrite = route("/old", 200);
    rewrite.action = Some(p::route::Action::Upstream(backend(port)));
    rewrite.url_rewrite = Some(p::UrlRewrite {
        hostname: Some("backend.example".into()),
        path: Some(modifier.clone()),
    });
    let mut redirect = route("/redirect", 200);
    redirect.action = Some(p::route::Action::HttpRedirect(p::HttpRedirect {
        scheme: Some("https".into()),
        hostname: Some("new.example".into()),
        path: Some(modifier),
        ..Default::default()
    }));
    proxy.apply(vec![rewrite.clone(), redirect]).await;
    for h2 in [false, true] {
        let (status, _, body) = proxy
            .request("GET", "test.local", "/old/a%2Fb?q=%2F", &[], h2)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, "/new/a%2Fb?q=%2F backend.example");
        let (status, headers, _) = proxy
            .request("GET", "test.local", "/redirect/a?q=1", &[], h2)
            .await;
        assert_eq!(status, 302);
        assert_eq!(headers["location"], "https://new.example/new/a?q=1");
    }
    let before = proxy
        .client
        .get_snapshot(p::GetSnapshotRequest {})
        .await
        .unwrap()
        .into_inner();
    let applied = proxy
        .client
        .apply_snapshot(before.clone())
        .await
        .unwrap()
        .into_inner();
    assert!(applied.applied);
    matcher(&mut rewrite).path = Some(p::http_match::Path::Exact("/old".into()));
    let mut invalid = before.clone();
    invalid.virtual_hosts[0].routes = vec![rewrite];
    assert!(proxy.client.apply_snapshot(invalid).await.is_err());
    assert_eq!(
        proxy
            .client
            .get_snapshot(p::GetSnapshotRequest {})
            .await
            .unwrap()
            .into_inner(),
        before
    );
    let next = proxy
        .client
        .apply_snapshot(before)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(next.active_generation, applied.active_generation + 1);
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_and_cors_respond_before_backend_selection() {
    let mut proxy = Proxy::start("").await;
    proxy.snapshot.upstreams = vec![p::UpstreamGroup {
        name: "empty".into(),
        allow_empty: true,
        ..Default::default()
    }];
    let mut protected = route("/", 200);
    protected.action = Some(p::route::Action::Upstream(p::Upstream {
        scheme: "http".into(),
        upstream_group: "empty".into(),
        ..Default::default()
    }));
    protected.plugins = vec![
        p::Plugin {
            name: "cors".into(),
            json_config: r#"{"allow_origin":"https://client.example","allow_methods":"GET"}"#
                .into(),
        },
        p::Plugin {
            name: "basic-auth".into(),
            json_config: r#"{"username":"user","password":"pass"}"#.into(),
        },
        header_plugin(),
    ];
    proxy.apply(vec![protected]).await;
    for h2 in [false, true] {
        let (status, headers, body) = proxy
            .request(
                "OPTIONS",
                "test.local",
                "/",
                &[
                    ("origin", "https://client.example"),
                    ("access-control-request-method", "GET"),
                ],
                h2,
            )
            .await;
        assert_eq!(status, 204);
        assert_eq!(
            headers["access-control-allow-origin"],
            "https://client.example"
        );
        assert_eq!(headers["x-review"], "yes");
        assert!(!headers.contains_key("content-length"));
        assert!(body.is_empty());
        let (status, headers, body) = proxy.request("GET", "test.local", "/", &[], h2).await;
        assert_eq!(status, 401);
        assert_eq!(body, "Unauthorized");
        assert_eq!(headers.get_all("x-review").iter().count(), 1);
        assert!(headers.contains_key("www-authenticate"));
        assert_eq!(
            proxy.request("HEAD", "test.local", "/", &[], h2).await.2,
            ""
        );
        assert_eq!(
            proxy
                .request(
                    "GET",
                    "test.local",
                    "/",
                    &[("authorization", "Basic dXNlcjpwYXNz")],
                    h2
                )
                .await
                .0,
            503
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_hit_and_stale_do_not_repeat_response_plugins() {
    let mut proxy = Proxy::start("").await;
    let (port, task) = echo_backend().await;
    let mut cached = route("/", 200);
    cached.action = Some(p::route::Action::Upstream(backend(port)));
    cached.plugins = vec![header_plugin()];
    cached.cache = Some(p::RouteCache {
        ttl_ms: 500,
        stale_if_error_ms: 60_000,
        ..Default::default()
    });
    proxy.apply(vec![cached]).await;
    // H2 uses an absolute URI; the existing exact-URI cache keeps it separate
    // from H1's origin-form URI. Warm both keys before taking the backend down.
    for h2 in [false, true] {
        for _ in 0..3 {
            let (status, headers, body) =
                proxy.request("GET", "test.local", "/cache", &[], h2).await;
            assert_eq!(status, 200);
            assert_eq!(headers.get_all("x-review").iter().count(), 1);
            assert_eq!(body, "/cache test.local");
        }
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(550)).await;
    for h2 in [false, true] {
        let (status, headers, body) = proxy.request("GET", "test.local", "/cache", &[], h2).await;
        assert_eq!(status, 200);
        assert_eq!(headers["x-cache"], "STALE");
        assert_eq!(headers.get_all("x-review").iter().count(), 1);
        assert_eq!(body, "/cache test.local");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_failure_does_not_append_an_error_to_a_started_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut proxy = Proxy::start("").await;
    let mut forwarding = route("/", 200);
    forwarding.action = Some(p::route::Action::Upstream(backend(port)));
    proxy.apply(vec![forwarding]).await;
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(response.matches("HTTP/1.1").count(), 1);
    assert!(!response.contains("502"));
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn text_config_preserves_nginx_prefix_and_applies_access_rules_to_returns() {
    let proxy = Proxy::start(
        r#"server {
        listen 127.0.0.1:PORT;
        server_name *.example.test;
        location /foo {
            headers { response_add X-Review yes; }
            return 301 https://$host$request_uri;
        }
        location /denied { deny all; return 302 https://example.test/; }
    }"#,
    )
    .await;
    for h2 in [false, true] {
        let (status, headers, _) = proxy
            .request("GET", "a.example.test", "/foobar?q=1", &[], h2)
            .await;
        assert_eq!(status, 301);
        assert_eq!(headers["location"], "https://a.example.test/foobar?q=1");
        assert_eq!(headers["x-review"], "yes");
        assert_eq!(
            proxy
                .request("GET", "a.example.test", "/denied", &[], h2)
                .await
                .0,
            403
        );
    }
}

async fn tls_backend(h2: bool) -> (u16, String, tokio::task::JoinHandle<()>) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = identity.cert.pem();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.signing_key.serialize_der(),
    ));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.der().clone()], key)
        .unwrap();
    config.alpn_protocols = vec![if h2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("localhost", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            connections.spawn(async move {
                // Negative cases intentionally reject the certificate during handshake.
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(|_: Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"trusted backend",
                    ))))
                });
                let result = if h2 {
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                } else {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                };
                if let Err(error) = result {
                    eprintln!("TLS test backend connection ended: {error}");
                }
            });
        }
    });
    (port, pem, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_pool_isolates_route_trust_and_live_ca_rotation() {
    for h2 in [false, true] {
        let (port, trusted_ca, task) = tls_backend(h2).await;
        let unrelated_ca = rcgen::generate_simple_self_signed(vec!["unrelated.example".into()])
            .unwrap()
            .cert
            .pem();
        let mut proxy = Proxy::start("").await;
        let mut trusted = route("/trusted", 200);
        trusted.action = Some(p::route::Action::Upstream(p::Upstream {
            scheme: "https".into(),
            host: "localhost".into(),
            ..backend(port)
        }));
        trusted.upstream_protocol = if h2 {
            p::UpstreamHttpProtocol::H2 as i32
        } else {
            p::UpstreamHttpProtocol::H1 as i32
        };
        trusted.tls_options = Some(p::UpstreamTlsOptions {
            verify: p::Switch::On as i32,
            trusted_certificate: Some(p::PemSource {
                source: Some(p::pem_source::Source::InlinePem(trusted_ca.clone())),
            }),
            ..Default::default()
        });
        let mut untrusted = trusted.clone();
        matcher(&mut untrusted).path = Some(p::http_match::Path::PathPrefix("/untrusted".into()));
        untrusted.tls_options.as_mut().unwrap().trusted_certificate = Some(p::PemSource {
            source: Some(p::pem_source::Source::InlinePem(unrelated_ca.clone())),
        });
        proxy.apply(vec![trusted.clone(), untrusted.clone()]).await;
        for _ in 0..2 {
            assert_eq!(
                proxy
                    .request("GET", "test.local", "/trusted", &[], false)
                    .await
                    .0,
                200
            );
        }
        assert_eq!(
            proxy
                .request("GET", "test.local", "/untrusted", &[], false)
                .await
                .0,
            502
        );
        trusted.tls_options = untrusted.tls_options;
        proxy.apply(vec![trusted.clone()]).await;
        assert_eq!(
            proxy
                .request("GET", "test.local", "/trusted", &[], false)
                .await
                .0,
            502
        );
        trusted.tls_options.as_mut().unwrap().trusted_certificate = Some(p::PemSource {
            source: Some(p::pem_source::Source::InlinePem(trusted_ca)),
        });
        proxy.apply(vec![trusted]).await;
        assert_eq!(
            proxy
                .request("GET", "test.local", "/trusted", &[], false)
                .await
                .0,
            200
        );
        task.abort();
    }
}

#[path = "http2/mod.rs"]
mod http2;

#[tokio::test]
async fn pingora_upgrade_sanitizes_headers_and_preserves_websocket_tunnels() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            // First request is a regular HTTP request; second upgrades to WebSocket.
            for websocket in [false, true] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let headers = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(!headers.contains("x-remove:"));
                assert!(!headers.contains("proxy-connection:"));
                assert!(headers.contains("x-keep: yes"));
                if websocket {
                    assert!(headers.contains("upgrade: websocket"));
                    assert!(headers.contains("connection: upgrade"));
                    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
                    // Valid masked WebSocket text frame containing "hi".
                    let mut frame = [0; 8];
                    stream.read_exact(&mut frame).await.unwrap();
                    assert_eq!(&frame, b"\x81\x82\x01\x02\x03\x04\x69\x6b");
                    stream.write_all(b"\x81\x02hi").await.unwrap();
                } else {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await.unwrap();
                }
            }
        });
        let mut proxy = Proxy::start("").await;
        let mut configured = route("/", 200);
        configured.action = Some(p::route::Action::Upstream(backend(port)));
        proxy.apply(vec![configured]).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close, X-Remove\r\nX-Remove: secret\r\nProxy-Connection: keep-alive\r\nX-Keep: yes\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"OK"));
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: Upgrade, X-Remove\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX-Remove: secret\r\nX-Keep: yes\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(client.read_u8().await.unwrap());
        }
        assert!(response.starts_with(b"HTTP/1.1 101"));
        client.write_all(b"\x81\x82\x01\x02\x03\x04\x69\x6b").await.unwrap();
        let mut frame = [0; 4];
        client.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x81\x02hi");
        upstream.await.unwrap();
    }).await.expect("HTTP/WebSocket proxy stalled");
}
