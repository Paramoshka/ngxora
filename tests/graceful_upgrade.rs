//! Characterization of stock Pingora's process handoff, including its failure modes.
#![cfg(target_os = "linux")]

use http_body_util::{BodyExt, Empty};
use hyper::{Request, body::Bytes};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    net::TcpListener as ReservedPort,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

struct Process {
    child: Child,
    log: PathBuf,
}

impl Process {
    fn start(dir: &Path, name: &str, config: &str, upgrade: bool, extra: &[String]) -> Self {
        let config_path = dir.join(format!("{name}.conf"));
        std::fs::write(&config_path, config).unwrap();
        let log = dir.join(format!("{name}.log"));
        let output = std::fs::File::create(&log).unwrap();
        let binary = std::env::var_os("NGXORA_TEST_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_ngxora").into());
        let mut command = Command::new(binary);
        command
            .args(["--upgrade-sock"])
            .arg(dir.join("upgrade.sock"))
            .args(extra)
            .arg(config_path)
            .env("RUST_LOG", "info")
            .stdout(output.try_clone().unwrap())
            .stderr(Stdio::from(output));
        if upgrade {
            command.arg("--upgrade");
        }
        Self {
            child: command.spawn().unwrap(),
            log,
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }

    fn signal(&mut self, signal: &str) {
        assert!(self.child.try_wait().unwrap().is_none(), "{}", self.logs());
        assert!(
            Command::new("kill")
                .args([signal, &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    async fn logged(&mut self, message: &str) {
        timeout(Duration::from_secs(45), async {
            loop {
                if self.logs().contains(message) {
                    return;
                }
                assert!(self.child.try_wait().unwrap().is_none(), "{}", self.logs());
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {message}: {}", self.logs()));
    }

    async fn exited(&mut self, limit: Duration) -> std::process::ExitStatus {
        timeout(limit, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("process did not exit: {}", self.logs()))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Reap only this test's child, including on assertion failure.
        self.child.kill().expect("stop test process");
        self.child.wait().expect("reap test process");
    }
}

fn reserve() -> ReservedPort {
    ReservedPort::bind("127.0.0.1:0").unwrap()
}
fn port(listener: &ReservedPort) -> u16 {
    listener.local_addr().unwrap().port()
}

fn server(port: u16, label: &str, extra: &str) -> String {
    format!(
        "server {{ listen 127.0.0.1:{port}; server_name localhost; {extra} location / {{ return 302 https://{label}.example/; }} }}"
    )
}

async fn headers(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await?);
        assert!(bytes.len() < 65536, "oversized test headers");
    }
    Ok(String::from_utf8(bytes).unwrap())
}

async fn request(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    path: &str,
) -> std::io::Result<String> {
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    headers(&mut stream).await
}

async fn http(port: u16, path: &str) -> Result<String, String> {
    timeout(Duration::from_secs(2), async {
        request(TcpStream::connect(("127.0.0.1", port)).await?, path).await
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

async fn ready(process: &mut Process, port: u16, label: &str) {
    timeout(Duration::from_secs(15), async {
        loop {
            if http(port, "/").await.is_ok_and(|r| r.contains(label)) {
                return;
            }
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "{}",
                process.logs()
            );
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("HTTP not ready: {}", process.logs()));
}

async fn receiver_ready(process: &mut Process, dir: &Path) {
    timeout(Duration::from_secs(3), async {
        while !dir.join("upgrade.sock").exists() {
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "{}",
                process.logs()
            );
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("upgrade receiver did not bind");
}

fn tls_config(dir: &Path) -> (String, rustls::ClientConfig) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, identity.cert.pem()).unwrap();
    std::fs::write(&key, identity.signing_key.serialize_pem()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(identity.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        format!(
            "ssl_certificate {}; ssl_certificate_key {};",
            cert.display(),
            key.display()
        ),
        client,
    )
}

async fn tls(
    port: u16,
    config: &rustls::ClientConfig,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    timeout(Duration::from_secs(3), async {
        tokio_rustls::TlsConnector::from(Arc::new(config.clone()))
            .connect(
                "localhost".try_into().unwrap(),
                TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            )
            .await
            .unwrap()
    })
    .await
    .expect("TLS handshake stalled")
}

#[tokio::test]
async fn handoff_preserves_requests_h2_websocket_and_metrics() {
    timeout(Duration::from_secs(350), async {
        let dir = tempfile::tempdir().unwrap();
        let http_reserved = reserve();
        let https_reserved = reserve();
        let metrics_reserved = reserve();
        let (p, s, m) = (port(&http_reserved), port(&https_reserved), port(&metrics_reserved));
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let (tls_settings, mut client_tls) = tls_config(dir.path());
        client_tls.alpn_protocols = vec![b"h2".to_vec()];
        let slow = format!("location /slow {{ proxy_pass http://127.0.0.1:{upstream_port}; }} location /ws {{ proxy_pass http://127.0.0.1:{upstream_port}; }}");
        let config = |label| format!("http {{ {} server {{ listen 127.0.0.1:{s} ssl http2; server_name localhost; {tls_settings} {slow} location / {{ return 302 https://{label}.example/; }} }} }}", server(p, label, &slow));
        let metrics = ["--metrics-addr".into(), format!("127.0.0.1:{m}")];
        drop((http_reserved, https_reserved, metrics_reserved));
        let mut old = Process::start(dir.path(), "old", &config("old"), false, &metrics);
        ready(&mut old, p, "old.example").await;
        assert!(http(m, "/metrics").await.unwrap().contains("200"));

        let mut slow_h1 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        slow_h1.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
        let (mut backend_h1, _) = upstream.accept().await.unwrap();
        headers(&mut backend_h1).await.unwrap();

        let (mut h2, driver) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(), TokioIo::new(tls(s, &client_tls).await)
        ).await.unwrap();
        let driver = tokio::spawn(driver);
        let slow_h2 = h2.send_request(Request::builder().uri("https://localhost/slow").body(Empty::new()).unwrap());
        let slow_h2 = tokio::spawn(slow_h2);
        let (mut backend_h2, _) = timeout(Duration::from_secs(5), upstream.accept()).await.expect("HTTP/2 request did not reach upstream").unwrap();
        headers(&mut backend_h2).await.unwrap();

        let mut ws = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        ws.write_all(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
        let (mut backend_ws, _) = upstream.accept().await.unwrap();
        headers(&mut backend_ws).await.unwrap();
        backend_ws.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
        assert!(headers(&mut ws).await.unwrap().contains("101"));

        let mut new = Process::start(dir.path(), "new", &config("new"), true, &metrics);
        receiver_ready(&mut new, dir.path()).await;
        old.signal("-QUIT");
        // During Pingora's overlap both generations may accept. No request may fail.
        let traffic = tokio::spawn(async move {
            for _ in 0..100 {
                let response = http(p, "/").await.unwrap();
                assert!(response.contains("old.example") || response.contains("new.example"));
                assert!(http(m, "/metrics").await.unwrap().contains("200"));
                sleep(Duration::from_millis(100)).await;
            }
        });
        old.logged("Broadcast graceful shutdown complete").await;
        ready(&mut new, p, "new.example").await;
        assert!(!slow_h2.is_finished(), "old HTTP/2 request ended before backend replied");
        for backend in [&mut backend_h1, &mut backend_h2] {
            backend.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await.unwrap();
        }
        assert!(headers(&mut slow_h1).await.unwrap().contains("200"));
        let mut body = [0; 2];
        slow_h1.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"OK");
        let response = slow_h2.await.unwrap().unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "OK");
        ws.write_all(b"\x81\x82\x01\x02\x03\x04\x69\x6b").await.unwrap();
        let mut frame = [0; 8];
        backend_ws.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x81\x82\x01\x02\x03\x04\x69\x6b");
        backend_ws.write_all(b"\x81\x02hi").await.unwrap();
        let mut reply = [0; 4];
        ws.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"\x81\x02hi");
        drop((ws, backend_ws, slow_h1, backend_h1, backend_h2, h2));
        driver.abort();
        traffic.await.unwrap();
        client_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        assert!(request(tls(s, &client_tls).await, "/").await.unwrap().contains("new.example"));
        eprintln!("handoff preserved HTTP/1, TLS HTTP/2, WebSocket and metrics; waiting for old process exit");
        // Keep one real default-duration shutdown check: cleanup must work without SIGKILL.
        assert!(old.exited(Duration::from_secs(320)).await.success());
        assert!(http(p, "/").await.unwrap().contains("new.example"));
        new.signal("-INT");
        new.exited(Duration::from_secs(10)).await;
        for port in [p, s, m] {
            ReservedPort::bind(("127.0.0.1", port)).expect("listener FD leaked after process exit");
        }
    }).await.expect("graceful handoff stalled");
}

#[tokio::test]
async fn handoff_changes_ports_and_http_tls_on_same_socket() {
    timeout(Duration::from_secs(45), async {
        let dir = tempfile::tempdir().unwrap();
        let reservations = [reserve(), reserve(), reserve()];
        let [same, removed, added] = reservations.each_ref().map(port);
        let (settings, client) = tls_config(dir.path());
        let mut old = Process::start(dir.path(), "old", &format!("http {{ {} {} }}", server(same, "old", ""), server(removed, "removed", "")), false, &[]);
        drop(reservations);
        ready(&mut old, same, "old.example").await;
        let config = format!("http {{ server {{ listen 127.0.0.1:{same} ssl; server_name localhost; {settings} location / {{ return 302 https://tls.example/; }} }} {} }}", server(added, "added", ""));
        let mut new = Process::start(dir.path(), "new", &config, true, &[]);
        receiver_ready(&mut new, dir.path()).await;
        old.signal("-QUIT");
        old.logged("Broadcast graceful shutdown complete").await;
        ready(&mut new, added, "added.example").await;
        assert!(request(tls(same, &client).await, "/").await.unwrap().contains("tls.example"));
        assert!(http(removed, "/").await.is_err(), "removed port still serves traffic");
        old.signal("-KILL");
        old.exited(Duration::from_secs(5)).await;
        ReservedPort::bind(("127.0.0.1", removed)).expect("new process retained removed socket");
        let mut third = Process::start(dir.path(), "third", &format!("http {{ {} }}", server(same, "plain", "")), true, &[]);
        receiver_ready(&mut third, dir.path()).await;
        new.signal("-QUIT");
        new.logged("Broadcast graceful shutdown complete").await;
        ready(&mut third, same, "plain.example").await;
    }).await.expect("transport replacement stalled");
}

#[tokio::test]
async fn invalid_config_is_rejected_before_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let reserved = reserve();
    let p = port(&reserved);
    drop(reserved);
    let config = format!("http {{ {} }}", server(p, "old", ""));
    let mut old = Process::start(dir.path(), "old", &config, false, &[]);
    ready(&mut old, p, "old.example").await;
    let mut new = Process::start(dir.path(), "new", "invalid config {", true, &[]);
    assert!(!new.exited(Duration::from_secs(5)).await.success());
    assert!(!dir.path().join("upgrade.sock").exists());
    assert!(http(p, "/").await.unwrap().contains("old.example"));
}

#[tokio::test]
async fn failed_handoffs_do_not_roll_back_in_stock_pingora() {
    // Characterization, not desired production behavior: each scenario loses service.
    for failure in [
        "no receiver",
        "receiver dies before transfer",
        "receiver dies after transfer",
        "occupied new port",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let reserved = reserve();
        let p = port(&reserved);
        drop(reserved);
        let config = format!("http {{ {} }}", server(p, "old", ""));
        let mut old = Process::start(dir.path(), "old", &config, false, &[]);
        ready(&mut old, p, "old.example").await;
        let occupied = reserve();
        let next = if failure == "occupied new port" {
            format!(
                "http {{ {} {} }}",
                server(p, "new", ""),
                server(port(&occupied), "occupied", "")
            )
        } else {
            config.clone()
        };
        let mut new =
            (failure != "no receiver").then(|| Process::start(dir.path(), "new", &next, true, &[]));
        if let Some(new) = new.as_mut() {
            receiver_ready(new, dir.path()).await;
            if failure == "receiver dies before transfer" {
                new.signal("-KILL");
                new.exited(Duration::from_secs(5)).await;
            }
        }
        old.signal("-QUIT");
        if failure == "receiver dies after transfer" {
            old.logged("listener sockets sent").await;
            let new = new.as_mut().unwrap();
            new.signal("-KILL");
            new.exited(Duration::from_secs(5)).await;
        }
        old.logged("Broadcast graceful shutdown complete").await;
        if failure == "occupied new port" {
            new.as_mut()
                .unwrap()
                .logged("Failed to build listeners")
                .await;
        }
        assert!(
            http(p, "/").await.is_err(),
            "expected observed outage for {failure}"
        );
        assert!(
            old.child.try_wait().unwrap().is_none(),
            "old process should still be draining"
        );
        eprintln!("confirmed stock Pingora outage: {failure}");
    }
}

#[tokio::test]
async fn grpc_uds_is_not_transferred_with_proxy_listeners() {
    use ngxora_runtime::grpc::proto::{
        GetSnapshotRequest, control_plane_client::ControlPlaneClient,
    };
    use tonic::transport::Endpoint;

    let dir = tempfile::tempdir().unwrap();
    let reserved = reserve();
    let p = port(&reserved);
    drop(reserved);
    let grpc = [
        "--grpc-uds".into(),
        dir.path().join("grpc.sock").to_str().unwrap().into(),
    ];
    let mut old = Process::start(
        dir.path(),
        "old",
        &format!("http {{ {} }}", server(p, "old", "")),
        false,
        &grpc,
    );
    ready(&mut old, p, "old.example").await;
    let connect = || {
        let socket = dir.path().join("grpc.sock");
        async move {
            Endpoint::from_static("http://localhost")
                .connect_with_connector(tower::service_fn(move |_| {
                    let socket = socket.clone();
                    async move {
                        tokio::net::UnixStream::connect(socket)
                            .await
                            .map(TokioIo::new)
                    }
                }))
                .await
        }
    };
    let mut old_client = ControlPlaneClient::new(connect().await.unwrap());
    assert!(
        old_client
            .get_snapshot(GetSnapshotRequest {})
            .await
            .unwrap()
            .into_inner()
            .version
            .ends_with("old.conf")
    );
    let mut new = Process::start(
        dir.path(),
        "new",
        &format!("http {{ {} }}", server(p, "new", "")),
        true,
        &grpc,
    );
    receiver_ready(&mut new, dir.path()).await;
    old.signal("-QUIT");
    old.logged("Broadcast graceful shutdown complete").await;
    ready(&mut new, p, "new.example").await;
    let mut new_client = ControlPlaneClient::new(connect().await.unwrap());
    assert!(
        new_client
            .get_snapshot(GetSnapshotRequest {})
            .await
            .unwrap()
            .into_inner()
            .version
            .ends_with("new.conf")
    );
    // The existing controller channel is still attached to the draining generation.
    assert!(
        old_client
            .get_snapshot(GetSnapshotRequest {})
            .await
            .unwrap()
            .into_inner()
            .version
            .ends_with("old.conf")
    );
}

#[tokio::test]
async fn grpc_tcp_bind_failure_does_not_stop_new_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let reservations = [reserve(), reserve()];
    let [p, grpc_port] = reservations.each_ref().map(port);
    let _ = tls_config(dir.path());
    let grpc = [
        "--grpc-addr".into(),
        format!("127.0.0.1:{grpc_port}"),
        "--grpc-tls-cert".into(),
        dir.path().join("cert.pem").to_str().unwrap().into(),
        "--grpc-tls-key".into(),
        dir.path().join("key.pem").to_str().unwrap().into(),
        "--grpc-client-ca".into(),
        dir.path().join("cert.pem").to_str().unwrap().into(),
    ];
    drop(reservations);
    let mut old = Process::start(
        dir.path(),
        "old",
        &format!("http {{ {} }}", server(p, "old", "")),
        false,
        &grpc,
    );
    ready(&mut old, p, "old.example").await;
    TcpStream::connect(("127.0.0.1", grpc_port)).await.unwrap();
    let mut new = Process::start(
        dir.path(),
        "new",
        &format!("http {{ {} }}", server(p, "new", "")),
        true,
        &grpc,
    );
    receiver_ready(&mut new, dir.path()).await;
    old.signal("-QUIT");
    old.logged("Broadcast graceful shutdown complete").await;
    ready(&mut new, p, "new.example").await;
    new.logged("gRPC control plane stopped").await;
    assert!(!old.logs().contains("gRPC control plane stopped"));
    // A live data plane therefore does not prove that the new control plane is ready.
}
