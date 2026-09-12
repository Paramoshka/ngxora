use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread")]
async fn acl_survives_get_apply_and_uses_trusted_client_ip() {
    let mut proxy = Proxy::start_with_http(
        "set_real_ip_from 127.0.0.1;",
        r#"
        server { listen 127.0.0.1:PORT; server_name acl.local;
            location / {
                deny 192.0.2.1; allow 192.0.2.0/24; allow 2001:db8::/32; deny all;
                return 302 https://allowed.example/;
            }
        }"#,
    )
    .await;
    for _ in 0..2 {
        for h2 in [false, true] {
            for (xff, expected) in [
                ("192.0.2.1", 403),
                ("192.0.2.2", 302),
                ("2001:db8::1", 302),
                ("203.0.113.1", 403),
                ("192.0.2.2, 203.0.113.1", 403),
                ("192.0.2.2, bad", 403),
            ] {
                assert_eq!(
                    proxy
                        .request("GET", "acl.local", "/", &[("x-forwarded-for", xff)], h2)
                        .await
                        .0,
                    expected
                );
            }
            assert_eq!(
                proxy
                    .request(
                        "GET",
                        "acl.local",
                        "/",
                        &[
                            ("x-forwarded-for", "192.0.2.2"),
                            ("x-forwarded-for", "192.0.2.3")
                        ],
                        h2
                    )
                    .await
                    .0,
                403
            );
        }
        let snapshot = proxy
            .client
            .get_snapshot(p::GetSnapshotRequest {})
            .await
            .unwrap()
            .into_inner();
        assert!(
            snapshot
                .virtual_hosts
                .iter()
                .any(|v| v.routes.iter().any(|r| r.access_rules.len() == 4))
        );
        assert!(
            proxy
                .client
                .apply_snapshot(snapshot)
                .await
                .unwrap()
                .into_inner()
                .applied
        );
    }
    let mut bad = proxy.snapshot.clone();
    bad.virtual_hosts
        .iter_mut()
        .find(|v| v.server_names.contains(&"acl.local".into()))
        .unwrap()
        .routes[0]
        .access_rules[0]
        .action = 99;
    assert!(proxy.client.apply_snapshot(bad).await.is_err());
    assert_eq!(
        proxy.request("GET", "acl.local", "/", &[], false).await.0,
        403
    );
    // Removing trust must stop accepting spoofable forwarding headers immediately.
    proxy
        .snapshot
        .http
        .as_mut()
        .unwrap()
        .real_ip
        .as_mut()
        .unwrap()
        .trusted_proxies
        .clear();
    assert!(
        proxy
            .client
            .apply_snapshot(proxy.snapshot.clone())
            .await
            .unwrap()
            .into_inner()
            .applied
    );
    assert_eq!(
        proxy
            .request(
                "GET",
                "acl.local",
                "/",
                &[("x-forwarded-for", "192.0.2.2")],
                false
            )
            .await
            .0,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn methods_are_enforced_before_local_responses_and_plugins() {
    let mut proxy = Proxy::start("").await;
    let mut policy = route("/", 200);
    policy.allowed_methods = vec!["GET".into(), "HEAD".into()];
    policy.plugins = vec![header_plugin()];
    proxy.apply(vec![policy]).await;
    for h2 in [false, true] {
        for method in ["GET", "HEAD"] {
            assert_eq!(
                proxy.request(method, "test.local", "/", &[], h2).await.0,
                200
            );
        }
        for method in ["POST", "OPTIONS", "DELETE"] {
            let (status, headers, _) = proxy.request(method, "test.local", "/", &[], h2).await;
            assert_eq!(status, 405);
            assert_eq!(headers["allow"], "GET, HEAD");
        }
    }
    proxy.snapshot.virtual_hosts[0].routes[0]
        .allowed_methods
        .clear();
    proxy
        .apply(proxy.snapshot.virtual_hosts[0].routes.clone())
        .await;
    assert_eq!(
        proxy.request("POST", "test.local", "/", &[], false).await.0,
        200
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_separates_clients_behind_a_trusted_proxy() {
    let mut proxy = Proxy::start_with_http("set_real_ip_from 127.0.0.1;", "").await;
    let mut policy = route("/", 200);
    policy.plugins = vec![p::Plugin {
        name: "rate-limit".into(),
        json_config: r#"{"max_requests_per_second":1}"#.into(),
    }];
    proxy.apply(vec![policy]).await;
    assert_eq!(
        proxy
            .request(
                "GET",
                "test.local",
                "/",
                &[("x-forwarded-for", "192.0.2.1")],
                false
            )
            .await
            .0,
        200
    );
    assert_eq!(
        proxy
            .request(
                "GET",
                "test.local",
                "/",
                &[("x-forwarded-for", "192.0.2.2")],
                false
            )
            .await
            .0,
        200
    );
    assert_eq!(
        proxy
            .request(
                "GET",
                "test.local",
                "/",
                &[("x-forwarded-for", "192.0.2.1")],
                false
            )
            .await
            .0,
        429
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_ip_is_shared_with_headers_geoip_and_access_logs() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(|request: Request<Incoming>| async move {
                    let body = format!(
                        "{}|{}|{}",
                        request.headers()["x-real-ip"].to_str().unwrap(),
                        request.headers()["x-forwarded-for"].to_str().unwrap(),
                        request.headers()["x-geoip-country-iso"].to_str().unwrap()
                    );
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
                }),
            )
            .await
            .unwrap();
    });
    let database = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");
    let mut proxy = Proxy::start_with_http(
        &format!(
            "set_real_ip_from 127.0.0.1; geoip {{ database {}; }}",
            database.display()
        ),
        "",
    )
    .await;
    let mut policy = route("/", 200);
    policy.action = Some(p::route::Action::Upstream(backend(port)));
    policy.plugins = vec![p::Plugin { name: "headers".into(), json_config:
        r#"{"forward_client_ip":true,"request":{"set":[{"name":"X-Forwarded-For","value":"1.1.1.1"}]}}"#.into() }];
    proxy.apply(vec![policy]).await;
    let (status, _, body) = proxy
        .request(
            "GET",
            "test.local",
            "/identity",
            &[("x-forwarded-for", "89.160.20.128")],
            false,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, "89.160.20.128|89.160.20.128, 127.0.0.1|SE");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let log = std::fs::read_to_string(proxy._temp.path().join("access.log")).unwrap();
            if let Some(entry) = log
                .lines()
                .filter_map(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                .find(|j| j["path"] == "/identity")
            {
                assert_eq!(entry["client_ip"], "89.160.20.128");
                assert!(
                    entry["peer_addr"]
                        .as_str()
                        .unwrap()
                        .starts_with("127.0.0.1:")
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn send_timeout_resets_a_blocked_http2_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        // A downstream timeout intentionally cancels this response.
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(|_: Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                        vec![b'x'; 2 * 1024 * 1024],
                    ))))
                }),
            )
            .await;
    });
    let mut proxy = Proxy::start("").await;
    let mut policy = route("/", 200);
    policy.action = Some(p::route::Action::Upstream(backend(port)));
    policy.send_timeout_ms = Some(100);
    proxy.apply(vec![policy]).await;
    let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(1024)
        .initial_connection_window_size(1024)
        .handshake::<_, Bytes>(stream)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let (response, _) = sender
        .send_request(
            Request::builder()
                .uri("http://test.local/")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    // Do not replenish flow-control capacity: the server must time out its write.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match body.data().await {
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
                None => panic!("blocked response completed without a send timeout"),
            }
        }
    })
    .await
    .unwrap();
    driver.abort();
    upstream.abort();
}

async fn body_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(|request: Request<Incoming>| async move {
                            let body = request.into_body().collect().await?.to_bytes();
                            Ok::<_, hyper::Error>(Response::new(Full::new(body)))
                        }),
                    )
                    .await;
            });
        }
    });
    (port, task)
}

async fn raw_request(port: u16, request: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn route_body_limits_override_global_and_enforce_chunked_bodies() {
    let (port, task) = body_backend().await;
    let mut proxy = Proxy::start_with_http("client_max_body_size 4;", "").await;
    let mut base = route("/", 200);
    base.action = Some(p::route::Action::Upstream(backend(port)));
    let mut larger = base.clone();
    matcher(&mut larger).path = Some(p::http_match::Path::PathPrefix("/large".into()));
    larger.client_max_body_size_bytes = Some(8);
    let mut unlimited = larger.clone();
    matcher(&mut unlimited).path = Some(p::http_match::Path::PathPrefix("/unlimited".into()));
    unlimited.client_max_body_size_bytes = Some(0);
    proxy.apply(vec![base, larger, unlimited]).await;
    for (path, expected) in [("/", 413), ("/large", 200), ("/unlimited", 200)] {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: test.local\r\nContent-Length: 8\r\nConnection: close\r\n\r\n12345678"
        );
        let response = raw_request(proxy.port, request.as_bytes()).await;
        assert!(
            response.starts_with(format!("HTTP/1.1 {expected}").as_bytes()),
            "{response:?}"
        );
    }
    let response = raw_request(proxy.port, b"POST / HTTP/1.1\r\nHost: test.local\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\n123\r\n3\r\n456\r\n0\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 413"));
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn header_and_body_timeouts_close_stalled_clients() {
    let (port, task) = body_backend().await;
    let mut proxy = Proxy::start_with_http(
        "h2c off; client_header_timeout 150ms; client_body_timeout 150ms;",
        "",
    )
    .await;
    let mut policy = route("/", 200);
    policy.action = Some(p::route::Action::Upstream(backend(port)));
    proxy.apply(vec![policy]).await;
    let response = raw_request(proxy.port, b"GET / HTTP/1.1\r\nHost: test.local\r\n").await;
    assert!(response.is_empty());
    let start = std::time::Instant::now();
    let response = raw_request(
        proxy.port,
        b"POST / HTTP/1.1\r\nHost: test.local\r\nContent-Length: 8\r\nConnection: close\r\n\r\n12",
    )
    .await;
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(response.starts_with(b"HTTP/1.1 408"));
    // The header timer must stop after headers, even for a longer valid request.
    proxy.snapshot.virtual_hosts[0].routes[0].client_body_timeout_ms = Some(1000);
    proxy
        .apply(proxy.snapshot.virtual_hosts[0].routes.clone())
        .await;
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    stream.write_all(b"POST / HTTP/1.1\r\nHost: test.local\r\nContent-Length: 4\r\nConnection: close\r\n\r\n12").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stream.write_all(b"34").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"1234"));
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn header_deadline_also_applies_to_keepalive_reuse() {
    let (port, upstream) = body_backend().await;
    let mut proxy = Proxy::start_with_http("h2c off; client_header_timeout 150ms;", "").await;
    let mut policy = route("/", 200);
    policy.action = Some(p::route::Action::Upstream(backend(port)));
    proxy.apply(vec![policy]).await;
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n")
        .await
        .unwrap();
    let mut headers = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\n")
        .await
        .unwrap();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert!(tail.is_empty());
    upstream.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn sighup_reloads_includes_and_retains_last_good_snapshot() {
    let proxy = Proxy::start("").await;
    let config = proxy._temp.path().join("ngxora.conf");
    let include = proxy._temp.path().join("routes.conf");
    std::fs::write(
        &include,
        "location / { return 302 https://reloaded.example/; }",
    )
    .unwrap();
    let valid = format!(
        "http {{ h2c on; server {{ listen 127.0.0.1:{} default_server; server_name test.local; include routes.conf; }} }}",
        proxy.port
    );
    std::fs::write(&config, &valid).unwrap();
    let reload = || {
        assert!(
            Command::new("kill")
                .args(["-HUP", &proxy.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    };
    reload();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if proxy.request("GET", "test.local", "/", &[], false).await.1["location"]
                == "https://reloaded.example/"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    for invalid in [
        "broken config".to_string(),
        valid.replace(&format!(":{}", proxy.port), ":0"),
    ] {
        std::fs::write(&config, invalid).unwrap();
        reload();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            proxy.request("GET", "test.local", "/", &[], false).await.1["location"],
            "https://reloaded.example/"
        );
    }
    std::fs::write(&config, valid).unwrap();
    std::fs::write(
        &include,
        "location / { deny all; return 302 https://reloaded.example/; }",
    )
    .unwrap();
    reload();
    tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.request("GET", "test.local", "/", &[], false).await.0 != 403 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
