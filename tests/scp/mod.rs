use super::*;
use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest;
use std::collections::HashSet;

const NF_A: &str = "11111111-1111-4111-8111-111111111111";
const NF_B: &str = "22222222-2222-4222-8222-222222222222";
const SERVICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

struct ScpProcess {
    _child: ChildGuard,
    log_path: std::path::PathBuf,
}

impl Drop for ScpProcess {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "SCP stderr: {}",
                std::fs::read_to_string(&self.log_path).unwrap_or_default()
            );
        }
    }
}

fn spawn_ngxora(config: &str) -> (tempfile::TempDir, ScpProcess) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ngxora.conf");
    let log_path = temp.path().join("stderr.log");
    std::fs::write(&path, config).unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg("--check")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let child = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg(path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log_path).unwrap()))
        .spawn()
        .unwrap();
    (
        temp,
        ScpProcess {
            _child: ChildGuard(child),
            log_path,
        },
    )
}

#[derive(Clone)]
struct Producer {
    addr: SocketAddr,
    calls: Arc<AtomicUsize>,
    disconnect: Arc<AtomicBool>,
    stop_accepting: Arc<Notify>,
}

async fn producer(nf: &'static str) -> Producer {
    producer_with_tls(nf, None).await
}

async fn producer_with_tls(nf: &'static str, acceptor: Option<TlsAcceptor>) -> Producer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let producer = Producer {
        addr: listener.local_addr().unwrap(),
        calls: Arc::new(AtomicUsize::new(0)),
        disconnect: Arc::new(AtomicBool::new(false)),
        stop_accepting: Arc::new(Notify::new()),
    };
    let state = producer.clone();
    let resources = Arc::new(Mutex::new(HashSet::new()));
    tokio::spawn(async move {
        loop {
            let (socket, _) = tokio::select! {
                socket = listener.accept() => socket.unwrap(),
                _ = state.stop_accepting.notified() => break,
            };
            let state = state.clone();
            let resources = resources.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let state = state.clone();
                    let resources = resources.clone();
                    async move {
                        state.calls.fetch_add(1, Ordering::SeqCst);
                        let uri = request.uri().clone();
                        let headers = request
                            .headers()
                            .iter()
                            .map(|(n, v)| {
                                (
                                    n.as_str().to_string(),
                                    serde_json::Value::String(v.to_str().unwrap().to_string()),
                                )
                            })
                            .collect::<serde_json::Map<_, _>>();
                        let method = request.method().clone();
                        let body = request
                            .into_body()
                            .collect()
                            .await
                            .map_err(std::io::Error::other)?
                            .to_bytes();
                        if state.disconnect.load(Ordering::SeqCst) {
                            return Err(std::io::Error::other(
                                "simulated reset after accepting request",
                            ));
                        }
                        let mut response = Response::builder().header(
                            "3gpp-sbi-binding",
                            format!("bl=nfservice-instance; nfinst={nf}; nfservinst={SERVICE}"),
                        );
                        if method == hyper::Method::POST {
                            resources.lock().unwrap().insert("42");
                            response = response.status(201).header(
                                "location",
                                format!(
                                    "http://{}/operator/edge/nsmf-pdusession/v1/resources/42",
                                    state.addr
                                ),
                            );
                        }
                        let resource = resources.lock().unwrap().contains("42");
                        Ok::<_, std::io::Error>(response.body(Full::new(Bytes::from(serde_json::json!({
                            "nf": nf, "uri": uri.to_string(), "headers": headers, "body": String::from_utf8_lossy(&body), "resource":resource
                        }).to_string()))).unwrap())
                    }
                });
                if let Some(acceptor) = acceptor {
                    if let Ok(socket) = acceptor.accept(socket).await {
                        assert_eq!(socket.get_ref().1.server_name(), Some("nf.test"));
                        let _ = http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(socket), service)
                            .await;
                    }
                } else {
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                }
            });
        }
    });
    producer
}

async fn client(port: u16) -> SendRequest<Full<Bytes>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(socket) => {
                let (sender, connection) = hyper::client::conn::http2::handshake(
                    TokioExecutor::new(),
                    TokioIo::new(socket),
                )
                .await
                .unwrap();
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                return sender;
            }
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "SCP did not start: {error}"
                );
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }
    }
}

async fn send(
    sender: &mut SendRequest<Full<Bytes>>,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, hyper::HeaderMap, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("http://127.0.0.1:{port}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(
            request
                .body(Full::new(Bytes::from_static(b"test-body")))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.version(), Version::HTTP_2);
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("status {} non-JSON response: {:?}", parts.status, bytes));
    (parts.status.as_u16(), parts.headers, json)
}

fn config(port: u16, nrf: Option<SocketAddr>, target: Option<SocketAddr>) -> String {
    let discovery = nrf.map(|nrf| format!(r#"
      upstream smf {{
        nrf_discovery {{ api_root http://{nrf}/nnrf-disc/v1; target_nf_type SMF; requester_nf_type AMF;
          service_name nsmf-pdusession; endpoint_scheme http; timeout 2s; stale_if_error 1s; }}
        health_check {{ type tcp; timeout 200ms; interval 1s; consecutive_success 1; consecutive_failure 1; }}
      }}
    "#)).unwrap_or_default();
    let discovery_ref = if nrf.is_some() {
        "discovery_upstream smf;"
    } else {
        ""
    };
    let target = target
        .map(|addr| format!("allow_target_api_root http://{addr}/operator/edge;"))
        .unwrap_or_default();
    format!(
        r#"http {{ h2c on;
      {discovery}
      scp core {{ api_root http://127.0.0.1:{port}/scp; {discovery_ref} {target} }}
      server {{ listen 127.0.0.1:{port}; location /scp/ {{ scp_pass core; }} }}
    }}"#
    )
}

fn selectors() -> [(&'static str, &'static str); 3] {
    [
        ("3gpp-sbi-discovery-target-nf-type", "SMF"),
        ("3gpp-sbi-discovery-requester-nf-type", "AMF"),
        ("3gpp-sbi-discovery-service-names", "nsmf-pdusession"),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_routing_preserves_http2_path_headers_and_rejects_untrusted_requests() {
    let producer = producer(NF_A).await;
    let port = unused_loopback_port();
    let (_temp, _process) = spawn_ngxora(&config(port, None, Some(producer.addr)));
    let mut client = client(port).await;
    let target = format!("http://{}/operator/edge", producer.addr);
    let (status, _, body) = send(
        &mut client,
        port,
        "POST",
        "/scp/nsmf-pdusession/v1/a%20b?x=%2F&ck=secret&x=2",
        &[("3gpp-sbi-target-apiroot", &target)],
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(
        body["uri"],
        format!(
            "http://{}/operator/edge/nsmf-pdusession/v1/a%20b?x=%2F&x=2",
            producer.addr
        )
    );
    assert_eq!(body["body"], "test-body");
    assert!(body["headers"].get("3gpp-sbi-target-apiroot").is_none());
    let baseline = producer.calls.load(Ordering::SeqCst);
    let (status, _) = http1_get_with_headers(
        SocketAddr::from(([127, 0, 0, 1], port)),
        "/scp/callback",
        &[("3gpp-sbi-target-apiroot", target.as_str())],
    )
    .await
    .unwrap();
    assert_eq!(status, 505);
    for (headers, expected) in [
        (vec![("3gpp-sbi-target-apiroot", "http://127.0.0.1:1")], 403),
        (
            vec![
                ("3gpp-sbi-target-apiroot", target.as_str()),
                ("3gpp-sbi-target-apiroot", target.as_str()),
            ],
            400,
        ),
        (
            vec![
                ("3gpp-sbi-target-apiroot", target.as_str()),
                ("3gpp-sbi-discovery-snssais", "[]"),
            ],
            400,
        ),
        (
            vec![
                ("3gpp-sbi-target-apiroot", target.as_str()),
                ("3gpp-sbi-max-forward-hops", "0"),
            ],
            508,
        ),
    ] {
        let (status, headers, body) = send(
            &mut client,
            port,
            "GET",
            "/scp/nsmf-pdusession/v1/resource",
            &headers,
        )
        .await;
        assert_eq!(status, expected, "{body}");
        assert_eq!(headers["content-type"], "application/problem+json");
        assert_eq!(body["status"], expected);
    }
    assert_eq!(producer.calls.load(Ordering::SeqCst), baseline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn discovery_and_binding_work_across_two_independent_scp_processes() {
    let a = producer(NF_A).await;
    let b = producer(NF_B).await;
    let mock = MockNrf::new();
    mock.set_mode(NrfMode::Services(vec![
        MockService {
            nf_instance_id: NF_A,
            service_instance_id: SERVICE,
            priority: 10,
            capacity: 1,
            endpoints: vec![a.addr],
        },
        MockService {
            nf_instance_id: NF_B,
            service_instance_id: SERVICE,
            priority: 10,
            capacity: 1,
            endpoints: vec![b.addr],
        },
    ]))
    .await;
    let nrf = spawn_mock_nrf(mock.clone()).await;
    let port_a = unused_loopback_port();
    let port_b = unused_loopback_port();
    let (_ta, _pa) = spawn_ngxora(&config(port_a, Some(nrf), None));
    let (_tb, _pb) = spawn_ngxora(&config(port_b, Some(nrf), None));
    let mut ca = client(port_a).await;
    let mut cb = client(port_b).await;
    let (status, headers, created) = send(
        &mut ca,
        port_a,
        "POST",
        "/scp/nsmf-pdusession/v1/resources",
        &selectors(),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let binding = headers["3gpp-sbi-binding"].to_str().unwrap();
    let mut request_headers = selectors().to_vec();
    request_headers.push(("3gpp-sbi-routing-binding", binding));
    let (status, _, read) = send(
        &mut cb,
        port_b,
        "GET",
        "/scp/nsmf-pdusession/v1/resources/42",
        &request_headers,
    )
    .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["nf"], created["nf"]);
    assert_eq!(read["resource"], true);
    assert!(read["headers"].get("3gpp-sbi-routing-binding").is_none());
    let mut seen = HashSet::new();
    for _ in 0..8 {
        let (status, headers, body) = send(
            &mut ca,
            port_a,
            "GET",
            "/scp/nsmf-pdusession/v1/resources",
            &selectors(),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            headers["3gpp-sbi-producer-id"],
            format!(
                "nfinst={}; nfservinst={SERVICE}",
                body["nf"].as_str().unwrap()
            )
        );
        seen.insert(body["nf"].as_str().unwrap().to_string());
    }
    assert_eq!(seen.len(), 2);
    let requests = mock.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|(version, uri)| *version == Version::HTTP_2
                && uri.contains("target-nf-instance-id=")
                && uri.contains("requester-nf-type=AMF"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn cold_discovery_is_coalesced_and_errors_are_distinct() {
    let producer = producer(NF_A).await;
    let mock = MockNrf::new();
    mock.set_mode(NrfMode::Endpoint(producer.addr)).await;
    let nrf = spawn_mock_nrf(mock.clone()).await;
    let port = unused_loopback_port();
    let (_temp, _process) = spawn_ngxora(&config(port, Some(nrf), None));
    let client = client(port).await;
    // requester ID makes this distinct from the configured background query.
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let mut client = client.clone();
        tasks.push(tokio::spawn(async move {
            let mut headers = selectors().to_vec();
            headers.push(("3gpp-sbi-discovery-requester-nf-instance-id", NF_B));
            let (status, _, body) = send(
                &mut client,
                port,
                "GET",
                "/scp/nsmf-pdusession/v1/resources",
                &headers,
            )
            .await;
            assert_eq!(status, 200, "{body}");
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(
        mock.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, uri)| uri.contains("requester-nf-instance-id="))
            .count(),
        1
    );
    let mut client = client;
    let target = format!("http://{}/operator/edge", producer.addr);
    let (status, _, body) = send(
        &mut client,
        port,
        "GET",
        "/scp/callbacks/42",
        &[("3gpp-sbi-target-apiroot", &target)],
    )
    .await;
    assert_eq!(status, 200, "cached discovered root rejected: {body}");
    let (status, _, body) = send(
        &mut client,
        port,
        "GET",
        "/scp/nsmf-pdusession/v9/resources",
        &selectors(),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["cause"], "INVALID_API");
    let mut headers = selectors().to_vec();
    headers.push(("3gpp-sbi-discovery-target-nf-instance-id", NF_B));
    let (status, _, body) = send(
        &mut client,
        port,
        "GET",
        "/scp/nsmf-pdusession/v1/resources",
        &headers,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["cause"], "NF_DISCOVERY_FAILURE");
    mock.set_mode(NrfMode::Error).await;
    let mut headers = selectors().to_vec();
    headers.push(("3gpp-sbi-discovery-requester-nf-instance-id", SERVICE));
    let (status, _, body) = send(
        &mut client,
        port,
        "GET",
        "/scp/nsmf-pdusession/v1/resources",
        &headers,
    )
    .await;
    assert_eq!(status, 504);
    assert_eq!(body["cause"], "NRF_NOT_REACHABLE");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (status, _, body) = send(
        &mut client,
        port,
        "GET",
        "/scp/callbacks/42",
        &[("3gpp-sbi-target-apiroot", &target)],
    )
    .await;
    assert_eq!(status, 504, "expired known target misclassified: {body}");
    assert_eq!(body["cause"], "NRF_NOT_REACHABLE");
    let (status, _, body) = send(
        &mut client,
        port,
        "GET",
        "/scp/nsmf-pdusession/v1/resources",
        &selectors(),
    )
    .await;
    assert_eq!(status, 504);
    assert_eq!(body["cause"], "NRF_NOT_REACHABLE");
    mock.set_mode(NrfMode::Endpoint(producer.addr)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let (status, _, body) = send(
            &mut client,
            port,
            "GET",
            "/scp/nsmf-pdusession/v1/resources",
            &selectors(),
        )
        .await;
        if status == 200 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "did not recover: {body}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_post_is_never_replayed_on_reused_http2_connection() {
    let producer = producer(NF_A).await;
    let port = unused_loopback_port();
    let (_temp, _process) = spawn_ngxora(&config(port, None, Some(producer.addr)));
    let mut client = client(port).await;
    let target = format!("http://{}/operator/edge", producer.addr);
    let headers = [("3gpp-sbi-target-apiroot", target.as_str())];
    assert_eq!(
        send(&mut client, port, "GET", "/scp/ready", &headers)
            .await
            .0,
        200
    );
    producer.disconnect.store(true, Ordering::SeqCst);
    let before = producer.calls.load(Ordering::SeqCst);
    let (status, _, body) = send(&mut client, port, "POST", "/scp/resources", &headers).await;
    assert_eq!(status, 504, "{body}");
    assert_eq!(producer.calls.load(Ordering::SeqCst), before + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn delegated_discovery_uses_mtls_and_nf_fqdn_when_connecting_to_an_ip() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = test_ca("SBI server CA");
    let client_ca = test_ca("SBI client CA");
    let nf = signed_identity(
        &ca.issuer,
        vec!["nf.test".into()],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let nrf_identity = signed_identity(
        &ca.issuer,
        vec!["127.0.0.1".into()],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client_identity = signed_identity(
        &client_ca.issuer,
        vec!["scp.test".into()],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let mut roots = RootCertStore::empty();
    roots.add(client_ca.certificate_der.clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![nf.certificate_der.clone(), ca.certificate_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(nf.key_der)),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let producer = producer_with_tls(NF_A, Some(TlsAcceptor::from(Arc::new(server)))).await;
    let mock = MockNrf::new();
    mock.set_mode(NrfMode::Json(serde_json::json!({"validityPeriod":30,"nfInstances":[{
        "nfInstanceId":NF_A,"nfType":"SMF","nfStatus":"REGISTERED","nfServiceList":{
            (SERVICE):{"serviceInstanceId":SERVICE,"serviceName":"nsmf-pdusession","nfServiceStatus":"REGISTERED",
                "scheme":"https","fqdn":"nf.test","versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],
                "apiPrefix":"/operator/edge","ipEndPoints":[{"ipv4Address":"127.0.0.1","port":producer.addr.port()}]}
        }}]}))).await;
    let nrf = spawn_mtls_mock_nrf(mock.clone(), &nrf_identity, &ca, &client_ca).await;
    let files = tempfile::tempdir().unwrap();
    let ca_path = files.path().join("ca.pem");
    let cert_path = files.path().join("client.pem");
    let key_path = files.path().join("client.key");
    let wrong_ca_path = files.path().join("untrusted-ca.pem");
    std::fs::write(&wrong_ca_path, &client_ca.certificate_pem).unwrap();
    std::fs::write(&ca_path, &ca.certificate_pem).unwrap();
    std::fs::write(&cert_path, &client_identity.certificate_pem).unwrap();
    std::fs::write(&key_path, &client_identity.key_pem).unwrap();
    let port = unused_loopback_port();
    let config=config(port,Some(nrf),None)
        .replace(&format!("http://{nrf}"),&format!("https://{nrf}"))
        .replace("endpoint_scheme http;",&format!("endpoint_scheme https; ssl_trusted_certificate {}; ssl_certificate {}; ssl_certificate_key {};",ca_path.display(),cert_path.display(),key_path.display()))
        .replace("scp_pass core;",&format!("scp_pass core; proxy_ssl_trusted_certificate {}; proxy_ssl_certificate {}; proxy_ssl_certificate_key {};",ca_path.display(),cert_path.display(),key_path.display()));
    let (_temp, _process) = spawn_ngxora(&config);
    let mut tls_client = client(port).await;
    let (status, _, body) = send(
        &mut tls_client,
        port,
        "GET",
        "/scp/nsmf-pdusession/v1/resources",
        &selectors(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["uri"],
        format!(
            "https://nf.test:{}/operator/edge/nsmf-pdusession/v1/resources",
            producer.addr.port()
        )
    );
    assert_eq!(producer.calls.load(Ordering::SeqCst), 1);
    assert!(
        mock.requests
            .lock()
            .unwrap()
            .iter()
            .all(|(v, _)| *v == Version::HTTP_2)
    );
    for rejected_config in [
        config.replace(
            &format!("proxy_ssl_trusted_certificate {};", ca_path.display()),
            &format!("proxy_ssl_trusted_certificate {};", wrong_ca_path.display()),
        ),
        config.replace(
            &format!(
                "proxy_ssl_certificate {}; proxy_ssl_certificate_key {};",
                cert_path.display(),
                key_path.display()
            ),
            "",
        ),
    ] {
        let other_port = unused_loopback_port();
        let rejected_config = rejected_config.replace(
            &format!("127.0.0.1:{port}"),
            &format!("127.0.0.1:{other_port}"),
        );
        let (_temp, _process) = spawn_ngxora(&rejected_config);
        let mut rejected_client = client(other_port).await;
        let (status, _, body) = send(
            &mut rejected_client,
            other_port,
            "POST",
            "/scp/nsmf-pdusession/v1/resources",
            &selectors(),
        )
        .await;
        assert_eq!(status, 504, "{body}");
        assert_eq!(body["cause"], "TARGET_NF_NOT_REACHABLE");
        assert_eq!(
            producer.calls.load(Ordering::SeqCst),
            1,
            "untrusted connection reached NF HTTP handler"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn cancelling_one_cold_request_does_not_cancel_shared_discovery() {
    let producer = producer(NF_A).await;
    let mock = MockNrf::new();
    let nrf = spawn_mock_nrf(mock.clone()).await;
    let port = unused_loopback_port();
    let (_temp, _process) = spawn_ngxora(&config(port, Some(nrf), None));
    let mut first = client(port).await;
    let task = tokio::spawn(async move {
        let mut headers = selectors().to_vec();
        headers.push(("3gpp-sbi-discovery-requester-nf-instance-id", NF_B));
        send(
            &mut first,
            port,
            "GET",
            "/scp/nsmf-pdusession/v1/resources",
            &headers,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if mock
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(_, uri)| uri.contains("requester-nf-instance-id="))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut second = client(port).await;
    mock.set_mode(NrfMode::Endpoint(producer.addr)).await;
    let mut headers = selectors().to_vec();
    headers.push(("3gpp-sbi-discovery-requester-nf-instance-id", NF_B));
    let (status, _, body) = send(
        &mut second,
        port,
        "GET",
        "/scp/nsmf-pdusession/v1/resources",
        &headers,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        mock.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, uri)| uri.contains("requester-nf-instance-id="))
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn connect_failure_reselects_before_sending_post() {
    let a = producer(NF_A).await;
    let b = producer(NF_B).await;
    let mock = MockNrf::new();
    mock.set_mode(NrfMode::Services(vec![
        MockService {
            nf_instance_id: NF_A,
            service_instance_id: SERVICE,
            priority: 10,
            capacity: 1,
            endpoints: vec![a.addr],
        },
        MockService {
            nf_instance_id: NF_B,
            service_instance_id: SERVICE,
            priority: 10,
            capacity: 1,
            endpoints: vec![b.addr],
        },
    ]))
    .await;
    let nrf = spawn_mock_nrf(mock).await;
    let port = unused_loopback_port();
    let config = config(port, Some(nrf), None).replace("interval 1s;", "interval 60s;");
    let (_temp, _process) = spawn_ngxora(&config);
    let mut client = client(port).await;
    // No headers exercises the unambiguous configured discovery default.
    let (status, headers, warm) = send(
        &mut client,
        port,
        "GET",
        "/scp/nsmf-pdusession/v1/resources",
        &[],
    )
    .await;
    assert_eq!(status, 200, "{warm}");
    assert!(headers.contains_key("3gpp-sbi-target-apiroot"));
    let (unused, used) = if warm["nf"] == NF_A {
        (&b, &a)
    } else {
        (&a, &b)
    };
    assert_eq!(unused.calls.load(Ordering::SeqCst), 0);
    unused.stop_accepting.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while tokio::net::TcpStream::connect(unused.addr).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (status, _, body) = send(
        &mut client,
        port,
        "POST",
        "/scp/nsmf-pdusession/v1/resources",
        &[],
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["nf"], warm["nf"]);
    assert_eq!(used.calls.load(Ordering::SeqCst), 2);
    assert_eq!(unused.calls.load(Ordering::SeqCst), 0);
}
