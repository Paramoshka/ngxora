use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock};

#[derive(Clone)]
enum NrfMode {
    Hold,
    Endpoint(SocketAddr),
    Error,
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
                            "nfStatus": "REGISTERED",
                            "nfServices": [{
                                "serviceName": "nsmf-pdusession",
                                "scheme": "http",
                                "nfServiceStatus": "REGISTERED",
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

async fn spawn_producer(name: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed_requests = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let requests = Arc::clone(&observed_requests);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    requests.lock().unwrap().push(request.uri().to_string());
                    async move {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            Bytes::from_static(name.as_bytes()),
                        )))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (addr, requests)
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
    let mut stream =
        tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| "connect timed out".to_string())?
            .map_err(|error| format!("connect failed: {error}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
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

async fn wait_for_counter(counter: &AtomicUsize, minimum: usize, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while counter.load(Ordering::SeqCst) < minimum {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for NRF error request"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_process_discovers_refreshes_and_expires_nrf_backends() {
    let mock = MockNrf::new();
    let nrf_addr = spawn_mock_nrf(mock.clone()).await;
    let (producer_a, producer_a_requests) = spawn_producer("producer-a").await;
    let (producer_b, producer_b_requests) = spawn_producer("producer-b").await;
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
    wait_for_counter(&mock.error_requests, 1, Duration::from_secs(5)).await;
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
