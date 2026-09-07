//! UDS permissions and authenticated HTTP/2 transport.

use crate::control::{ConfigSnapshot, InProcessControlPlane, RuntimeState};
#[cfg(unix)]
use crate::grpc::set_uds_permissions;
use crate::grpc::{GrpcControlPlane, GrpcTlsConfig, grpc_runtime, grpc_server, proto};
use crate::upstreams::{
    CompiledRouter, apply_upstream_http_protocol, apply_upstream_ssl_options,
    build_runtime_client_identities, build_runtime_trusted_cas,
};
use bytes::Bytes;
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, PemSource, ProxyPassTarget, Server,
    Switch, UpstreamHttpProtocol,
};
use pingora::connectors::http::Connector;
use pingora::http::RequestHeader;
use pingora::protocols::http::client::HttpSession;
use pingora::upstreams::peer::HttpPeer;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::sync::Arc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

#[cfg(unix)]
#[test]
fn grpc_uds_permissions_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let file = tempfile::NamedTempFile::new().expect("create temporary socket placeholder");
    set_uds_permissions(file.path()).expect("set UDS permissions");
    let mode = std::fs::metadata(file.path())
        .expect("read UDS metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn tcp_grpc_requires_trusted_mtls_client_and_server() {
    grpc_runtime()
        .expect("create gRPC test runtime")
        .block_on(async {
            let server_ca = test_ca("ngxora-server-ca");
            let controller_ca = test_ca("ngxora-controller-ca");
            let untrusted_ca = test_ca("untrusted-ca");
            let server = signed_identity(
                &server_ca.issuer,
                vec!["localhost".into()],
                ExtendedKeyUsagePurpose::ServerAuth,
            );
            let trusted_controller = signed_identity(
                &controller_ca.issuer,
                vec!["controller".into()],
                ExtendedKeyUsagePurpose::ClientAuth,
            );
            let untrusted_controller = signed_identity(
                &untrusted_ca.issuer,
                vec!["untrusted-controller".into()],
                ExtendedKeyUsagePurpose::ClientAuth,
            );

            let tls = GrpcTlsConfig::from_pem(
                &server.certificate,
                &server.key,
                &controller_ca.certificate,
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test listener");
            let addr = listener.local_addr().expect("read listener address");
            let control = InProcessControlPlane::new(Arc::new(RuntimeState::new(
                ConfigSnapshot::new("test-v1", CompiledRouter::default()),
            )));
            let server_task = tokio::spawn(
                grpc_server(&tls)
                    .expect("build mTLS server")
                    .add_service(proto::control_plane_server::ControlPlaneServer::new(
                        GrpcControlPlane::new(control),
                    ))
                    .serve_with_incoming(TcpListenerStream::new(listener)),
            );

            let snapshot = request_snapshot(
                addr.port(),
                &server_ca.certificate,
                Some(&trusted_controller),
            )
            .await
            .expect("trusted controller is accepted");
            assert_eq!(snapshot.version, "test-v1");

            assert!(
                request_snapshot(addr.port(), &server_ca.certificate, None)
                    .await
                    .is_err()
            );
            assert!(
                request_snapshot(
                    addr.port(),
                    &server_ca.certificate,
                    Some(&untrusted_controller),
                )
                .await
                .is_err()
            );
            assert!(
                request_snapshot(
                    addr.port(),
                    &untrusted_ca.certificate,
                    Some(&trusted_controller),
                )
                .await
                .is_err()
            );
            assert!(plaintext_snapshot(addr.port()).await.is_err());

            server_task.abort();
        });
}

#[cfg(feature = "openssl")]
#[test]
fn pingora_connector_reaches_mock_service_over_h2_mtls_with_trailers() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    grpc_runtime()
        .expect("create gRPC test runtime")
        .block_on(async {
            let server_ca = test_ca("mock-sbi-server-ca");
            let client_ca = test_ca("mock-sbi-client-ca");
            let server_identity = signed_identity(
                &server_ca.issuer,
                vec!["localhost".into()],
                ExtendedKeyUsagePurpose::ServerAuth,
            );
            let client_identity = signed_identity(
                &client_ca.issuer,
                vec!["ngxora-sbi-client".into()],
                ExtendedKeyUsagePurpose::ClientAuth,
            );
            let server_chain = format!("{}{}", server_identity.certificate, server_ca.certificate);
            let tls = GrpcTlsConfig::from_pem(
                &server_chain,
                &server_identity.key,
                &client_ca.certificate,
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock SBI listener");
            let addr = listener.local_addr().expect("mock SBI address");
            let control = InProcessControlPlane::new(Arc::new(RuntimeState::new(
                ConfigSnapshot::new("mock-sbi-v1", CompiledRouter::default()),
            )));
            let server_task = tokio::spawn(
                grpc_server(&tls)
                    .expect("build mock SBI mTLS server")
                    .add_service(proto::control_plane_server::ControlPlaneServer::new(
                        GrpcControlPlane::new(control),
                    ))
                    .serve_with_incoming(TcpListenerStream::new(listener)),
            );

            let ca_source = PemSource::InlinePem(server_ca.certificate.clone());
            let cert_source = PemSource::InlinePem(client_identity.certificate.clone());
            let key_source = PemSource::InlinePem(client_identity.key.clone());
            let router = CompiledRouter::from_http(&Http {
                servers: vec![Server {
                    listens: vec![Listen {
                        default_server: true,
                        ..Listen::default()
                    }],
                    locations: vec![Location {
                        matcher: LocationMatcher::Prefix("/".into()),
                        directives: vec![
                            LocationDirective::ProxySslTrustedCertificate(ca_source.clone()),
                            LocationDirective::ProxySslCertificate(cert_source.clone()),
                            LocationDirective::ProxySslCertificateKey(key_source.clone()),
                            LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2),
                            LocationDirective::ProxyPass(ProxyPassTarget::Url(
                                format!("https://localhost:{}", addr.port())
                                    .parse()
                                    .expect("mock SBI URL"),
                            )),
                        ],
                        access_rules: Vec::new(),
                        plugins: Vec::new(),
                        cache: None,
                    }],
                    ..Server::default()
                }],
                ..Http::default()
            })
            .expect("compile mock SBI client route");
            let trusted_cas = build_runtime_trusted_cas(&router).expect("load mock SBI CA");
            let identities =
                build_runtime_client_identities(&router).expect("load mock SBI client identity");
            let identity_key = crate::upstreams::ClientIdentityKey {
                cert: cert_source,
                key: key_source,
            };

            let mut peer = HttpPeer::new(("127.0.0.1", addr.port()), true, "localhost".into());
            apply_upstream_http_protocol(&mut peer, Some(UpstreamHttpProtocol::H2));
            apply_upstream_ssl_options(
                &mut peer,
                &ngxora_compile::ir::UpstreamSslOptions {
                    verify_cert: Switch::Off,
                    trusted_certificate: Some(ca_source.clone()),
                    client_certificate: Some(identity_key.cert.clone()),
                    client_certificate_key: Some(identity_key.key.clone()),
                },
                trusted_cas.get(&ca_source),
                identities.get(&identity_key),
            );

            let connector = Connector::new(None);
            let (mut session, _) = connector
                .get_http_session(&peer)
                .await
                .expect("connect to mock SBI service over mTLS");
            assert!(session.as_http2().is_some());

            let mut request =
                RequestHeader::build("POST", b"/ngxora.control.v1.ControlPlane/GetSnapshot", None)
                    .expect("build gRPC request");
            request
                .insert_header("host", "localhost")
                .expect("set authority");
            request
                .insert_header("content-type", "application/grpc")
                .expect("set content type");
            request
                .insert_header("te", "trailers")
                .expect("request trailers");
            session
                .write_request_header(Box::new(request))
                .await
                .expect("write gRPC request header");
            session
                .write_request_body(Bytes::from_static(&[0, 0, 0, 0, 0]), true)
                .await
                .expect("write empty protobuf message");
            session
                .read_response_header()
                .await
                .expect("read mock SBI response header");
            assert_eq!(
                session.response_header().expect("response header").status,
                200
            );
            while session
                .read_response_body()
                .await
                .expect("read mock SBI response body")
                .is_some()
            {}
            let trailers = match &mut session {
                HttpSession::H2(session) => session
                    .read_trailers()
                    .await
                    .expect("read mock SBI trailers")
                    .expect("gRPC trailers"),
                _ => panic!("expected HTTP/2 session"),
            };
            assert_eq!(trailers.get("grpc-status").expect("grpc status"), "0");

            server_task.abort();
        });
}

struct TestCertificateAuthority {
    certificate: String,
    issuer: Issuer<'static, KeyPair>,
}

struct TestIdentity {
    certificate: String,
    key: String,
}

fn test_ca(common_name: &str) -> TestCertificateAuthority {
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().expect("CA key");
    let certificate = params.self_signed(&key).expect("CA certificate").pem();

    TestCertificateAuthority {
        certificate,
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
        .expect("identity certificate")
        .pem();

    TestIdentity {
        certificate,
        key: key.serialize_pem(),
    }
}

async fn request_snapshot(
    port: u16,
    server_ca: &str,
    client_identity: Option<&TestIdentity>,
) -> Result<proto::ConfigSnapshot, tonic::Status> {
    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(server_ca));
    if let Some(identity) = client_identity {
        tls = tls.identity(Identity::from_pem(&identity.certificate, &identity.key));
    }
    let endpoint = Endpoint::from_shared(format!("https://localhost:{port}"))
        .expect("valid endpoint")
        .tls_config(tls)
        .expect("valid TLS client configuration");
    let channel = endpoint
        .connect()
        .await
        .map_err(|err| tonic::Status::unknown(err.to_string()))?;
    let mut client = proto::control_plane_client::ControlPlaneClient::new(channel);
    client
        .get_snapshot(proto::GetSnapshotRequest {})
        .await
        .map(|response| response.into_inner())
}

async fn plaintext_snapshot(port: u16) -> Result<proto::ConfigSnapshot, tonic::Status> {
    let channel = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .expect("valid endpoint")
        .connect()
        .await
        .map_err(|err| tonic::Status::unknown(err.to_string()))?;
    let mut client = proto::control_plane_client::ControlPlaneClient::new(channel);
    client
        .get_snapshot(proto::GetSnapshotRequest {})
        .await
        .map(|response| response.into_inner())
}
