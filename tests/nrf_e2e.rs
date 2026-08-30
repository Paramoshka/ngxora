use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock};
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
enum NrfMode {
    Hold,
    Endpoint(SocketAddr),
    Services(Vec<MockService>),
    Error,
}

#[derive(Clone)]
struct MockService {
    nf_instance_id: &'static str,
    service_instance_id: &'static str,
    priority: u16,
    capacity: u16,
    endpoints: Vec<SocketAddr>,
}

#[derive(Clone)]
struct MockNrf {
    mode: Arc<RwLock<NrfMode>>,
    changed: Arc<Notify>,
    requests: Arc<Mutex<Vec<(Version, String)>>>,
    error_requests: Arc<AtomicUsize>,
}

impl MockNrf {
    fn new() -> Self {
        Self {
            mode: Arc::new(RwLock::new(NrfMode::Hold)),
            changed: Arc::new(Notify::new()),
            requests: Arc::new(Mutex::new(Vec::new())),
            error_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn set_mode(&self, mode: NrfMode) {
        *self.mode.write().await = mode;
        self.changed.notify_waiters();
    }

    async fn response(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        self.requests
            .lock()
            .unwrap()
            .push((request.version(), request.uri().to_string()));

        loop {
            let changed = self.changed.notified();
            match self.mode.read().await.clone() {
                NrfMode::Hold => changed.await,
                NrfMode::Endpoint(addr) => {
                    let body = serde_json::json!({
                        "validityPeriod": 2,
                        "nfInstances": [{
                            "nfInstanceId": "11111111-1111-4111-8111-111111111111",
                            "nfStatus": "REGISTERED",
                            "nfServices": [{
                                "serviceInstanceId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                "serviceName": "nsmf-pdusession",
                                "scheme": "http",
                                "nfServiceStatus": "REGISTERED",
                                "priority": 10,
                                "capacity": 1,
                                "apiPrefix": "/operator/edge/",
                                "ipEndPoints": [{
                                    "ipv4Address": addr.ip().to_string(),
                                    "port": addr.port()
                                }]
                            }]
                        }]
                    })
                    .to_string();
                    return Response::builder()
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap();
                }
                NrfMode::Services(services) => {
                    let nf_instances = services
                        .into_iter()
                        .map(|service| {
                            let endpoints = service
                                .endpoints
                                .into_iter()
                                .map(|addr| {
                                    serde_json::json!({
                                        "ipv4Address": addr.ip().to_string(),
                                        "port": addr.port()
                                    })
                                })
                                .collect::<Vec<_>>();
                            serde_json::json!({
                                "nfInstanceId": service.nf_instance_id,
                                "nfStatus": "REGISTERED",
                                "nfServices": [{
                                    "serviceInstanceId": service.service_instance_id,
                                    "serviceName": "nsmf-pdusession",
                                    "scheme": "http",
                                    "nfServiceStatus": "REGISTERED",
                                    "priority": service.priority,
                                    "capacity": service.capacity,
                                    "apiPrefix": "/operator/edge/",
                                    "ipEndPoints": endpoints
                                }]
                            })
                        })
                        .collect::<Vec<_>>();
                    let body = serde_json::json!({
                        "validityPeriod": 30,
                        "nfInstances": nf_instances
                    })
                    .to_string();
                    return Response::builder()
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap();
                }
                NrfMode::Error => {
                    self.error_requests.fetch_add(1, Ordering::SeqCst);
                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::from_static(b"NRF unavailable")))
                        .unwrap();
                }
            }
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_ngxora(config: &str) -> (tempfile::TempDir, ChildGuard) {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("ngxora.conf");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ngxora process");
    (temp, ChildGuard(child))
}

async fn spawn_mock_nrf(mock: MockNrf) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mock = mock.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let mock = mock.clone();
                    async move { Ok::<_, std::convert::Infallible>(mock.response(request).await) }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    addr
}

struct TestCertificateAuthority {
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

struct TestIdentity {
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
    key_pem: String,
    key_der: Vec<u8>,
}

fn test_ca(common_name: &str) -> TestCertificateAuthority {
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().expect("CA key");
    let certificate = params.self_signed(&key).expect("CA certificate");

    TestCertificateAuthority {
        certificate_pem: certificate.pem(),
        certificate_der: certificate.der().clone(),
        issuer: Issuer::new(params, key),
    }
}

fn signed_identity(
    issuer: &Issuer<'static, KeyPair>,
    names: Vec<String>,
    usage: ExtendedKeyUsagePurpose,
) -> TestIdentity {
    let mut params = CertificateParams::new(names).expect("identity params");
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().expect("identity key");
    let certificate = params
        .signed_by(&key, issuer)
        .expect("identity certificate");

    TestIdentity {
        certificate_pem: certificate.pem(),
        certificate_der: certificate.der().clone(),
        key_pem: key.serialize_pem(),
        key_der: key.serialize_der(),
    }
}

async fn spawn_mtls_mock_nrf(
    mock: MockNrf,
    server_identity: &TestIdentity,
    server_ca: &TestCertificateAuthority,
    client_ca: &TestCertificateAuthority,
) -> SocketAddr {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(client_ca.certificate_der.clone())
        .expect("client CA");
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("client certificate verifier");
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_identity.key_der.clone()));
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![
                server_identity.certificate_der.clone(),
                server_ca.certificate_der.clone(),
            ],
            private_key,
        )
        .expect("mTLS server certificate");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let mock = mock.clone();
            tokio::spawn(async move {
                let Ok(socket) = acceptor.accept(socket).await else {
                    return;
                };
                let service = service_fn(move |request| {
                    let mock = mock.clone();
                    async move { Ok::<_, std::convert::Infallible>(mock.response(request).await) }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    addr
}

async fn spawn_producer(
    name: &'static str,
) -> (
    SocketAddr,
    Arc<Mutex<Vec<String>>>,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let healthy = Arc::new(AtomicBool::new(true));
    let health_checks = Arc::new(AtomicUsize::new(0));
    let observed_requests = Arc::clone(&requests);
    let observed_health = Arc::clone(&healthy);
    let observed_health_checks = Arc::clone(&health_checks);
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let requests = Arc::clone(&observed_requests);
            let healthy = Arc::clone(&observed_health);
            let health_checks = Arc::clone(&observed_health_checks);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let is_health_check = request.uri().path() == "/health";
                    if is_health_check {
                        health_checks.fetch_add(1, Ordering::SeqCst);
                    } else {
                        requests.lock().unwrap().push(request.uri().to_string());
                    }
                    let status = if is_health_check && !healthy.load(Ordering::SeqCst) {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::OK
                    };
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from_static(name.as_bytes())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (addr, requests, healthy, health_checks)
}

fn unused_loopback_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_response(
    addr: SocketAddr,
    path: &str,
    status: StatusCode,
    body: Option<&str>,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let last = match http1_get(addr, path).await {
            Ok((actual_status, actual_body)) => {
                if actual_status == status.as_u16()
                    && body.is_none_or(|expected| actual_body.contains(expected))
                {
                    return;
                }
                format!("status={actual_status}, body={actual_body:?}")
            }
            Err(error)
                if status == StatusCode::SERVICE_UNAVAILABLE
                    && error == "connection closed without an HTTP response" =>
            {
                return;
            }
            Err(error) => error,
        };
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {status} from {addr}{path}: {last}",
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn http1_get(addr: SocketAddr, path: &str) -> Result<(u16, String), String> {
    http1_get_with_headers(addr, path, &[]).await
}

async fn http1_get_with_headers(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, String), String> {
    let mut stream =
        tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| "connect timed out".to_string())?
            .map_err(|error| format!("connect failed: {error}"))?;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("write failed: {error}"))?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|error| format!("read failed: {error}"))?;
    let response = String::from_utf8_lossy(&response);
    if response.is_empty() {
        return Err("connection closed without an HTTP response".to_string());
    }
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid HTTP response: {response:?}"))?;
    let body = response
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
        .to_string();
    Ok((status, body))
}

async fn wait_for_counter(
    counter: &AtomicUsize,
    minimum: usize,
    timeout: Duration,
    description: &str,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    while counter.load(Ordering::SeqCst) < minimum {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_process_discovers_nrf_over_h2_mtls() {
    let server_ca = test_ca("NRF server CA");
    let client_ca = test_ca("NRF client CA");
    let server_identity = signed_identity(
        &server_ca.issuer,
        vec!["127.0.0.1".into()],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client_identity = signed_identity(
        &client_ca.issuer,
        vec!["ngxora-nrf-client".into()],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let mock = MockNrf::new();
    let nrf_addr =
        spawn_mtls_mock_nrf(mock.clone(), &server_identity, &server_ca, &client_ca).await;
    let (producer, producer_requests, _, _) = spawn_producer("mtls-producer").await;
    mock.set_mode(NrfMode::Endpoint(producer)).await;
    let proxy_port = unused_loopback_port();
    let temp = tempfile::tempdir().unwrap();
    let ca_path = temp.path().join("nrf-ca.pem");
    let client_cert_path = temp.path().join("nrf-client.pem");
    let client_key_path = temp.path().join("nrf-client.key");
    std::fs::write(&ca_path, &server_ca.certificate_pem).unwrap();
    std::fs::write(&client_cert_path, &client_identity.certificate_pem).unwrap();
    std::fs::write(&client_key_path, &client_identity.key_pem).unwrap();
    let config = format!(
        r#"
http {{
  upstream smf_pool {{
    nrf_discovery {{
      api_root https://{nrf_addr}/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme http;
      timeout 2s;
      stale_if_error 2s;
      ssl_verify on;
      ssl_trusted_certificate {};
      ssl_certificate {};
      ssl_certificate_key {};
    }}
    health_check {{
      type tcp;
      timeout 1s;
      interval 1s;
      consecutive_success 1;
      consecutive_failure 1;
    }}
  }}
  server {{
    listen 127.0.0.1:{proxy_port} default_server;
    location / {{ proxy_pass http://smf_pool; }}
  }}
}}
"#,
        ca_path.display(),
        client_cert_path.display(),
        client_key_path.display()
    );
    let config_path = temp.path().join("ngxora.conf");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ngxora process");
    let _child = ChildGuard(child);
    let request_path = "/nsmf-pdusession/v1/session?trace=mtls";

    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        Some("mtls-producer"),
        Duration::from_secs(8),
    )
    .await;

    let requests = mock.requests.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|(version, uri)| {
        *version == Version::HTTP_2
            && uri.contains("target-nf-type=SMF")
            && uri.contains("requester-nf-type=SCP")
            && uri.contains("service-names=nsmf-pdusession")
    }));
    let producer_requests = producer_requests.lock().unwrap();
    assert!(!producer_requests.is_empty());
    assert!(
        producer_requests
            .iter()
            .all(|path| { path == "/operator/edge/nsmf-pdusession/v1/session?trace=mtls" })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_process_discovers_refreshes_and_expires_nrf_backends() {
    let mock = MockNrf::new();
    let nrf_addr = spawn_mock_nrf(mock.clone()).await;
    let (producer_a, producer_a_requests, _, _) = spawn_producer("producer-a").await;
    let (producer_b, producer_b_requests, _, _) = spawn_producer("producer-b").await;
    let proxy_port = unused_loopback_port();
    let request_path = "/nsmf-pdusession/v1/session?trace=e2e";
    let config = format!(
        r#"
http {{
  upstream smf_pool {{
    nrf_discovery {{
      api_root http://{nrf_addr}/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme http;
      timeout 1s;
      stale_if_error 2s;
    }}
    health_check {{
      type tcp;
      timeout 1s;
      interval 1s;
      consecutive_success 1;
      consecutive_failure 1;
    }}
  }}
  server {{
    listen 127.0.0.1:{proxy_port} default_server;
    location / {{ proxy_pass http://smf_pool; }}
  }}
}}
"#
    );
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("ngxora.conf");
    std::fs::write(&config_path, config).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ngxora process");
    let _child = ChildGuard(child);

    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::SERVICE_UNAVAILABLE,
        None,
        Duration::from_secs(5),
    )
    .await;

    mock.set_mode(NrfMode::Endpoint(producer_a)).await;
    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        Some("producer-a"),
        Duration::from_secs(8),
    )
    .await;

    mock.set_mode(NrfMode::Endpoint(producer_b)).await;
    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        Some("producer-b"),
        Duration::from_secs(8),
    )
    .await;

    mock.set_mode(NrfMode::Error).await;
    wait_for_counter(
        &mock.error_requests,
        1,
        Duration::from_secs(5),
        "NRF error request",
    )
    .await;
    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        Some("producer-b"),
        Duration::from_secs(1),
    )
    .await;

    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::SERVICE_UNAVAILABLE,
        None,
        Duration::from_secs(8),
    )
    .await;

    mock.set_mode(NrfMode::Endpoint(producer_a)).await;
    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        Some("producer-a"),
        Duration::from_secs(8),
    )
    .await;

    let requests = mock.requests.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(
        requests
            .iter()
            .all(|(version, _)| *version == Version::HTTP_2)
    );
    assert!(requests.iter().all(|(_, uri)| {
        uri.contains("/nnrf-disc/v1/nf-instances?")
            && uri.contains("target-nf-type=SMF")
            && uri.contains("requester-nf-type=SCP")
            && uri.contains("service-names=nsmf-pdusession")
    }));

    let expected_upstream_path = "/operator/edge/nsmf-pdusession/v1/session?trace=e2e";
    for producer_requests in [&producer_a_requests, &producer_b_requests] {
        let producer_requests = producer_requests.lock().unwrap();
        assert!(!producer_requests.is_empty());
        assert!(
            producer_requests
                .iter()
                .all(|path| path == expected_upstream_path),
            "unexpected producer requests: {producer_requests:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_process_refreshes_nrf_snapshot_under_load_without_traffic_gap() {
    let mock = MockNrf::new();
    let nrf_addr = spawn_mock_nrf(mock.clone()).await;
    let (producer_a, _, _, _) = spawn_producer("refresh-a").await;
    let (producer_b, _, _, _) = spawn_producer("refresh-b").await;
    let proxy_port = unused_loopback_port();
    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let request_path = "/nsmf-pdusession/v1/session?trace=refresh";
    let config = format!(
        r#"
http {{
  upstream smf_pool {{
    nrf_discovery {{
      api_root http://{nrf_addr}/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme http;
      timeout 1s;
      stale_if_error 2s;
    }}
    health_check {{
      type tcp;
      timeout 1s;
      interval 1s;
      consecutive_success 1;
      consecutive_failure 1;
    }}
  }}
  server {{
    listen 127.0.0.1:{proxy_port} default_server;
    location / {{ proxy_pass http://smf_pool; }}
  }}
}}
"#
    );
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("ngxora.conf");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ngxora process");
    let _child = ChildGuard(child);

    mock.set_mode(NrfMode::Endpoint(producer_a)).await;
    wait_for_response(
        proxy_addr,
        request_path,
        StatusCode::OK,
        Some("refresh-a"),
        Duration::from_secs(8),
    )
    .await;

    let running = Arc::new(AtomicBool::new(true));
    let failures = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let running = Arc::clone(&running);
        let failures = Arc::clone(&failures);
        let observed = Arc::clone(&observed);
        workers.push(tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                match http1_get(proxy_addr, request_path).await {
                    Ok((status, body))
                        if status == StatusCode::OK.as_u16()
                            && (body.contains("refresh-a") || body.contains("refresh-b")) =>
                    {
                        observed.lock().unwrap().push(body);
                    }
                    Ok((status, body)) => {
                        failures
                            .lock()
                            .unwrap()
                            .push(format!("status={status}, body={body:?}"));
                        break;
                    }
                    Err(err) => {
                        failures.lock().unwrap().push(err);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    mock.set_mode(NrfMode::Endpoint(producer_b)).await;
    wait_for_response(
        proxy_addr,
        request_path,
        StatusCode::OK,
        Some("refresh-b"),
        Duration::from_secs(8),
    )
    .await;
    mock.set_mode(NrfMode::Endpoint(producer_a)).await;
    wait_for_response(
        proxy_addr,
        request_path,
        StatusCode::OK,
        Some("refresh-a"),
        Duration::from_secs(8),
    )
    .await;

    running.store(false, Ordering::SeqCst);
    for worker in workers {
        worker.await.unwrap();
    }
    let failures = failures.lock().unwrap();
    assert!(failures.is_empty(), "traffic failures: {failures:?}");
    let observed = observed.lock().unwrap();
    assert!(observed.iter().any(|body| body.contains("refresh-a")));
    assert!(observed.iter().any(|body| body.contains("refresh-b")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_process_applies_random_and_consistent_hash_to_nrf_services() {
    let mock = MockNrf::new();
    let nrf_addr = spawn_mock_nrf(mock.clone()).await;
    let (service_a, _, _, _) = spawn_producer("policy-a").await;
    let (service_b, _, _, _) = spawn_producer("policy-b").await;
    mock.set_mode(NrfMode::Services(vec![
        MockService {
            nf_instance_id: "31111111-1111-4111-8111-111111111111",
            service_instance_id: "daaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            priority: 1,
            capacity: 1,
            endpoints: vec![service_a],
        },
        MockService {
            nf_instance_id: "32222222-2222-4222-8222-222222222222",
            service_instance_id: "dbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            priority: 1,
            capacity: 1,
            endpoints: vec![service_b],
        },
    ]))
    .await;

    let random_port = unused_loopback_port();
    let consistent_port = unused_loopback_port();
    let config = |port: u16, policy: &str, hash_key: &str| {
        format!(
            r#"
http {{
  upstream smf_pool {{
    policy {policy};
    {hash_key}
    nrf_discovery {{
      api_root http://{nrf_addr}/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme http;
      timeout 1s;
      stale_if_error 2s;
    }}
    health_check {{
      type tcp;
      timeout 1s;
      interval 1s;
      consecutive_success 1;
      consecutive_failure 1;
    }}
  }}
  server {{
    listen 127.0.0.1:{port} default_server;
    location / {{ proxy_pass http://smf_pool; }}
  }}
}}
"#
        )
    };
    let (_random_temp, _random_child) = spawn_ngxora(&config(random_port, "random", ""));
    let (_consistent_temp, _consistent_child) = spawn_ngxora(&config(
        consistent_port,
        "consistent_hash",
        "hash_key header X-Subscriber-ID;",
    ));
    let random_addr = SocketAddr::from(([127, 0, 0, 1], random_port));
    let consistent_addr = SocketAddr::from(([127, 0, 0, 1], consistent_port));
    let request_path = "/nsmf-pdusession/v1/session?trace=policy";
    wait_for_response(
        random_addr,
        request_path,
        StatusCode::OK,
        None,
        Duration::from_secs(8),
    )
    .await;
    wait_for_response(
        consistent_addr,
        request_path,
        StatusCode::OK,
        None,
        Duration::from_secs(8),
    )
    .await;

    let mut random_a = false;
    let mut random_b = false;
    for _ in 0..512 {
        let (status, body) = http1_get(random_addr, request_path).await.unwrap();
        assert_eq!(status, StatusCode::OK.as_u16());
        match body.as_str() {
            "policy-a" => random_a = true,
            "policy-b" => random_b = true,
            other => panic!("unexpected random backend {other:?}"),
        }
    }
    assert!(
        random_a && random_b,
        "random policy did not reach both services"
    );

    let fixed_headers = [("X-Subscriber-ID", "subscriber-fixed")];
    let (fixed_status, fixed_service) =
        http1_get_with_headers(consistent_addr, request_path, &fixed_headers)
            .await
            .unwrap();
    assert_eq!(fixed_status, StatusCode::OK.as_u16());
    assert!(matches!(fixed_service.as_str(), "policy-a" | "policy-b"));
    for _ in 0..32 {
        let (status, body) = http1_get_with_headers(consistent_addr, request_path, &fixed_headers)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK.as_u16());
        assert_eq!(body, fixed_service);
    }

    let mut consistent_a = false;
    let mut consistent_b = false;
    for index in 0..512 {
        let subscriber = format!("subscriber-{index}");
        let headers = [("X-Subscriber-ID", subscriber.as_str())];
        let (status, body) = http1_get_with_headers(consistent_addr, request_path, &headers)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK.as_u16());
        match body.as_str() {
            "policy-a" => consistent_a = true,
            "policy-b" => consistent_b = true,
            other => panic!("unexpected consistent-hash backend {other:?}"),
        }
        if consistent_a && consistent_b {
            break;
        }
    }
    assert!(
        consistent_a && consistent_b,
        "consistent hash did not map keys to both services"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_process_selects_nrf_services_by_priority_capacity_and_health() {
    let mock = MockNrf::new();
    let nrf_addr = spawn_mock_nrf(mock.clone()).await;
    let (service_a_1, requests_a_1, health_a_1, health_checks_a_1) =
        spawn_producer("service-a-1").await;
    let (service_a_2, requests_a_2, health_a_2, health_checks_a_2) =
        spawn_producer("service-a-2").await;
    let (service_b, requests_b, health_b, health_checks_b) = spawn_producer("service-b").await;
    let (standby, standby_requests, _, _) = spawn_producer("standby").await;
    let proxy_port = unused_loopback_port();
    let request_path = "/nsmf-pdusession/v1/session?trace=selection";
    let config = format!(
        r#"
http {{
  upstream smf_pool {{
    policy round_robin;
    nrf_discovery {{
      api_root http://{nrf_addr}/nnrf-disc/v1;
      target_nf_type SMF;
      requester_nf_type SCP;
      service_name nsmf-pdusession;
      endpoint_scheme http;
      timeout 1s;
      stale_if_error 2s;
    }}
    health_check {{
      type http;
      host localhost;
      path /health;
      timeout 1s;
      interval 1s;
      consecutive_success 1;
      consecutive_failure 1;
    }}
  }}
  server {{
    listen 127.0.0.1:{proxy_port} default_server;
    location / {{ proxy_pass http://smf_pool; }}
  }}
}}
"#
    );
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("ngxora.conf");
    std::fs::write(&config_path, config).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ngxora"))
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ngxora process");
    let _child = ChildGuard(child);

    mock.set_mode(NrfMode::Services(vec![
        MockService {
            nf_instance_id: "21111111-1111-4111-8111-111111111111",
            service_instance_id: "baaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            priority: 1,
            capacity: 3,
            endpoints: vec![service_a_1, service_a_2],
        },
        MockService {
            nf_instance_id: "22222222-2222-4222-8222-222222222222",
            service_instance_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            priority: 1,
            capacity: 1,
            endpoints: vec![service_b],
        },
        MockService {
            nf_instance_id: "23333333-3333-4333-8333-333333333333",
            service_instance_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            priority: 20,
            capacity: 1,
            endpoints: vec![standby],
        },
    ]))
    .await;
    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        None,
        Duration::from_secs(8),
    )
    .await;

    for requests in [&requests_a_1, &requests_a_2, &requests_b, &standby_requests] {
        requests.lock().unwrap().clear();
    }
    for _ in 0..40 {
        let (status, _) = http1_get(SocketAddr::from(([127, 0, 0, 1], proxy_port)), request_path)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK.as_u16());
    }

    assert_eq!(requests_a_1.lock().unwrap().len(), 15);
    assert_eq!(requests_a_2.lock().unwrap().len(), 15);
    assert_eq!(requests_b.lock().unwrap().len(), 10);
    assert!(standby_requests.lock().unwrap().is_empty());

    let next_health_check = health_checks_a_1.load(Ordering::SeqCst) + 1;
    health_a_1.store(false, Ordering::SeqCst);
    wait_for_counter(
        &health_checks_a_1,
        next_health_check,
        Duration::from_secs(3),
        "failed endpoint health check",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for requests in [&requests_a_1, &requests_a_2, &requests_b, &standby_requests] {
        requests.lock().unwrap().clear();
    }
    for _ in 0..40 {
        let (status, _) = http1_get(SocketAddr::from(([127, 0, 0, 1], proxy_port)), request_path)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK.as_u16());
    }
    assert!(requests_a_1.lock().unwrap().is_empty());
    assert_eq!(requests_a_2.lock().unwrap().len(), 30);
    assert_eq!(requests_b.lock().unwrap().len(), 10);
    assert!(standby_requests.lock().unwrap().is_empty());

    let next_a_2_health_check = health_checks_a_2.load(Ordering::SeqCst) + 1;
    let next_b_health_check = health_checks_b.load(Ordering::SeqCst) + 1;
    health_a_2.store(false, Ordering::SeqCst);
    health_b.store(false, Ordering::SeqCst);
    wait_for_counter(
        &health_checks_a_2,
        next_a_2_health_check,
        Duration::from_secs(3),
        "second failed endpoint health check",
    )
    .await;
    wait_for_counter(
        &health_checks_b,
        next_b_health_check,
        Duration::from_secs(3),
        "failed peer service health check",
    )
    .await;
    wait_for_response(
        SocketAddr::from(([127, 0, 0, 1], proxy_port)),
        request_path,
        StatusCode::OK,
        Some("standby"),
        Duration::from_secs(6),
    )
    .await;

    let expected_upstream_path = "/operator/edge/nsmf-pdusession/v1/session?trace=selection";
    for requests in [&requests_a_1, &requests_a_2, &requests_b, &standby_requests] {
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|path| path == expected_upstream_path)
        );
    }
}
