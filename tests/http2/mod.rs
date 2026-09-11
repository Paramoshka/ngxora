use super::{Proxy, backend, p, route};
use bytes::Bytes;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Inspect actual wire settings, rather than only the configured builder values.
fn settings(bytes: &[u8]) -> (BTreeMap<u16, u32>, u32) {
    let mut bytes = bytes.strip_prefix(PREFACE).unwrap_or(bytes);
    let mut settings = BTreeMap::new();
    let mut connection_credit = 65535;
    while bytes.len() >= 9 {
        let len = ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize;
        if bytes.len() < 9 + len {
            break;
        }
        let payload = &bytes[9..9 + len];
        if bytes[3] == 4 && bytes[4] == 0 {
            for setting in payload.chunks_exact(6) {
                settings.insert(
                    u16::from_be_bytes(setting[..2].try_into().unwrap()),
                    u32::from_be_bytes(setting[2..].try_into().unwrap()),
                );
            }
        }
        if bytes[3] == 8 && bytes[5..9] == [0, 0, 0, 0] {
            connection_credit += u32::from_be_bytes(payload.try_into().unwrap());
        }
        bytes = &bytes[9 + len..];
    }
    (settings, connection_credit)
}

async fn downstream_settings<T: AsyncRead + AsyncWrite + Unpin>(
    mut io: T,
    connection_window: u32,
) -> BTreeMap<u16, u32> {
    io.write_all(PREFACE).await.unwrap();
    io.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut header = [0; 9];
            io.read_exact(&mut header).await.unwrap();
            let len =
                ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
            let mut payload = vec![0; len];
            io.read_exact(&mut payload).await.unwrap();
            frames.extend_from_slice(&header);
            frames.extend_from_slice(&payload);
            let (settings, credit) = settings(&frames);
            if !settings.is_empty() && credit == connection_window {
                return settings;
            }
        }
    })
    .await
    .expect("downstream HTTP/2 settings timeout")
}

#[tokio::test]
async fn downstream_defaults_and_custom_settings_reach_h2c_and_tls() {
    let proxy = Proxy::start("").await;
    let defaults = downstream_settings(
        TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap(),
        65535,
    )
    .await;
    assert_eq!(defaults.get(&3), Some(&100));
    assert_eq!(defaults.get(&6), Some(&65536));
    drop(proxy);

    let cert = rcgen::generate_simple_self_signed(vec!["test.local".into()]).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tls_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let tls_server = format!(
        "server {{ listen 127.0.0.1:{tls_port} ssl http2; server_name test.local; ssl_certificate {}; ssl_certificate_key {}; location / {{ return 302 https://bootstrap.example/; }} }}",
        cert_path.display(),
        key_path.display()
    );
    let proxy = Proxy::start_with_http("http2_max_concurrent_streams 7; http2_max_header_list_size 32k; http2_stream_window_size 128k; http2_connection_window_size 256k;", &tls_server).await;
    let plain = downstream_settings(
        TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap(),
        262144,
    )
    .await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            "test.local".try_into().unwrap(),
            TcpStream::connect(("127.0.0.1", tls_port)).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let encrypted = downstream_settings(tls, 262144).await;
    assert_eq!(plain, encrypted);
    assert_eq!(plain.get(&3), Some(&7));
    assert_eq!(plain.get(&6), Some(&32768));
    assert_eq!(plain.get(&4), Some(&131072));
}

struct RecordingIo {
    stream: TcpStream,
    received: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for RecordingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.received
                .lock()
                .unwrap()
                .extend_from_slice(&buf.filled()[start..]);
        }
        result
    }
}

impl AsyncWrite for RecordingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn send_body(stream: &mut h2::SendStream<Bytes>, mut body: Bytes, end_stream: bool) {
    while !body.is_empty() {
        stream.reserve_capacity(body.len());
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        let len = capacity.min(body.len());
        if len == 0 {
            continue;
        }
        let chunk = body.split_to(len);
        stream
            .send_data(chunk, end_stream && body.is_empty())
            .unwrap();
    }
}

async fn read_body(mut body: h2::RecvStream, expect_trailers: bool) -> Vec<u8> {
    let mut result = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        result.extend_from_slice(&chunk);
    }
    let trailers = body.trailers().await.unwrap();
    if expect_trailers {
        let trailers = trailers.expect("gRPC trailers must survive proxying");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    }
    result
}

#[tokio::test]
async fn upstream_windows_multiplexing_and_live_generation_rotation() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let gate = release.clone();
        let server = tokio::spawn(async move {
            let mut connection_id = 0;
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                connection_id += 1;
                let id = connection_id;
                let received = Arc::new(Mutex::new(Vec::new()));
                let io = RecordingIo {
                    stream,
                    received: received.clone(),
                };
                let accepted_tx = accepted_tx.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let mut conn = h2::server::Builder::new()
                        .max_concurrent_streams(10)
                        .handshake(io)
                        .await
                        .unwrap();
                    while let Some(request) = conn.accept().await {
                        let (request, mut respond) = request.unwrap();
                        assert_eq!(request.headers().get("te").unwrap(), "trailers");
                        assert_eq!(
                            request.headers().get("content-type").unwrap(),
                            "application/grpc"
                        );
                        accepted_tx.send((id, received.clone())).unwrap();
                        let gate = gate.clone();
                        tokio::spawn(async move {
                            let uploaded = read_body(request.into_body(), false).await;
                            let permit = gate.acquire().await.unwrap();
                            permit.forget();
                            let mut stream = respond
                                .send_response(
                                    hyper::Response::builder()
                                        .header("content-type", "application/grpc")
                                        .body(())
                                        .unwrap(),
                                    false,
                                )
                                .unwrap();
                            // Exceeds the configured 32 KiB receive window.
                            let body = if uploaded.is_empty() {
                                Bytes::from(vec![b'x'; 128 * 1024])
                            } else {
                                Bytes::from(uploaded)
                            };
                            send_body(&mut stream, body, false).await;
                            let mut trailers = hyper::HeaderMap::new();
                            trailers.insert("grpc-status", "0".parse().unwrap());
                            stream.send_trailers(trailers).unwrap();
                        });
                    }
                });
            }
        });
        let mut proxy = Proxy::start_with_http(
            "http2_stream_window_size 32k; http2_connection_window_size 128k;",
            "",
        )
        .await;
        let mut upstream = route("/", 200);
        upstream.action = Some(p::route::Action::Upstream(backend(port)));
        upstream.upstream_protocol = p::UpstreamHttpProtocol::H2c as i32;
        upstream.upstream_http2 = Some(p::UpstreamHttp2Options {
            max_concurrent_streams: Some(2),
            stream_window_size: Some(32768),
            connection_window_size: Some(131072),
        });
        proxy.apply(vec![upstream.clone()]).await;
        let (client, connection) =
            h2::client::handshake(TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap())
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            connection.await.unwrap();
        });
        let mut client = client.ready().await.unwrap();
        let request = || {
            hyper::Request::builder()
                .uri("http://test.local/")
                .header("te", "trailers")
                .header("content-type", "application/grpc")
                .body(())
                .unwrap()
        };
        let (first, _) = client.send_request(request(), true).unwrap();
        let (id, wire) = accepted_rx.recv().await.unwrap();
        let (actual, credit) = settings(&wire.lock().unwrap());
        assert_eq!(actual.get(&4), Some(&32768));
        assert_eq!(credit, 131072);
        // Establish one upstream connection first, then prove a second stream reuses it.
        let (second, _) = client.send_request(request(), true).unwrap();
        let (second_id, _) = accepted_rx.recv().await.unwrap();
        assert_eq!(id, second_id);
        // A third request exceeds the per-connection limit and needs a different connection.
        let (third, _) = client.send_request(request(), true).unwrap();
        let (third_id, _) = accepted_rx.recv().await.unwrap();
        assert_ne!(id, third_id);
        release.add_permits(3);
        // Drain multiplexed responses together: an unread sibling can consume
        // all connection-level receive credit and block the stream being read.
        let drains = [first, second, third].map(|response| {
            tokio::spawn(async move { read_body(response.await.unwrap().into_body(), true).await })
        });
        for drain in drains {
            assert_eq!(drain.await.unwrap(), vec![b'x'; 128 * 1024]);
        }
        upstream.upstream_http2.as_mut().unwrap().stream_window_size = Some(65536);
        upstream
            .upstream_http2
            .as_mut()
            .unwrap()
            .connection_window_size = Some(262144);
        proxy.apply(vec![upstream]).await;
        let (response, mut upload) = client
            .send_request(
                hyper::Request::builder()
                    .method("POST")
                    .uri("http://test.local/")
                    .header("te", "trailers")
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let (new_id, wire) = accepted_rx.recv().await.unwrap();
        assert!(new_id > third_id);
        let (actual, credit) = settings(&wire.lock().unwrap());
        assert_eq!(actual.get(&4), Some(&65536));
        assert_eq!(credit, 262144);
        send_body(&mut upload, Bytes::from(vec![b'y'; 256 * 1024]), true).await;
        release.add_permits(1);
        assert_eq!(
            read_body(response.await.unwrap().into_body(), true).await,
            vec![b'y'; 256 * 1024]
        );
        driver.abort();
        server.abort();
    })
    .await
    .expect("HTTP/2 flow control or multiplexing stalled");
}
