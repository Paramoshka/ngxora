use ngxora_compile::ir::Ir;
use ngxora_config::{Ast, include::IncludeResolver};
use ngxora_runtime::control::{
    ConfigSnapshot, InProcessControlPlane, RuntimeNrfDiscovery, RuntimeState,
    RuntimeUpstreamHealthChecks,
};
use ngxora_runtime::grpc::{GrpcTlsConfig, spawn_control_plane, spawn_control_plane_uds};
use ngxora_runtime::le::{self, LeReconcilerService};
use ngxora_runtime::metrics::spawn_metrics_service_with_state;
use ngxora_runtime::server::bind_listeners_from_state;
use ngxora_runtime::upstreams::{CompiledRouter, DynamicProxy};
use pingora::server::Server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Debug)]
struct CliArgs {
    config_path: PathBuf,
    check_only: bool,
    grpc_addr: Option<SocketAddr>,
    grpc_uds: Option<PathBuf>,
    grpc_tls: Option<GrpcTlsFiles>,
    metrics_addr: Option<SocketAddr>,
    otel_endpoint: Option<String>,
    unsafe_admin_listen: bool,
}

#[derive(Debug)]
struct GrpcTlsFiles {
    certificate: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
}

fn main() -> ExitCode {
    env_logger::init();

    // Install the rustls crypto provider early — needed by background services
    // running in Pingora worker threads.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = match parse_cli_args(env::args_os()) {
        Ok(Some(cli)) => cli,
        Ok(None) => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: CliArgs) -> Result<(), String> {
    let router = load_router(&cli.config_path)?;
    let version = format!("file:{}", cli.config_path.display());
    let state = Arc::new(RuntimeState::new(ConfigSnapshot::new(version, router)));
    let control = InProcessControlPlane::new(Arc::clone(&state));
    let snapshot = control.get_snapshot();

    if cli.check_only {
        println!(
            "config OK: version={} generation={} listeners={}",
            snapshot.version,
            snapshot.generation,
            snapshot.router.listeners.len()
        );
        return Ok(());
    }

    let grpc_tls = cli.grpc_tls.as_ref().map(load_grpc_tls).transpose()?;

    let mut server = Server::new(None::<Opt>)
        .map_err(|err| format!("failed to create pingora server: {err}"))?;
    server.bootstrap();

    // Configure OpenTelemetry if an endpoint is given (exporter built lazily).
    if let Some(ref endpoint) = cli.otel_endpoint {
        ngxora_runtime::tracing::configure(endpoint, "ngxora");
        println!("OpenTelemetry tracing enabled, exporting to {endpoint}");
    }

    let mut dynamic_proxy = DynamicProxy::new(Arc::clone(control.state()));

    // Shared token store for Let's Encrypt HTTP-01 challenges.
    let le_tokens: le::ChallengeTokens = Arc::new(dashmap::DashMap::new());
    dynamic_proxy.set_challenge_tokens(Arc::clone(&le_tokens));

    // Keep the LE lifecycle service running even before LE is configured so
    // later live snapshots can enable issuance without a process restart.
    let le_service = background_service(
        "le-reconciler",
        LeReconcilerService::new(Arc::clone(&state), le_tokens),
    );
    server.add_service(le_service);

    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, dynamic_proxy);
    let upstream_health_checks = background_service(
        "upstream health checks",
        RuntimeUpstreamHealthChecks::new(Arc::clone(&state)),
    );
    let nrf_discovery = background_service(
        "NRF discovery",
        RuntimeNrfDiscovery::new(Arc::clone(&state)),
    );
    bind_listeners_from_state(&mut proxy, Arc::clone(control.state()))
        .map_err(|err| format!("failed to bind listeners from config: {err}"))?;

    println!(
        "starting ngxora with {} listeners from {}",
        snapshot.router.listeners.len(),
        cli.config_path.display()
    );

    if let Some(addr) = cli.grpc_addr {
        let tls = grpc_tls.ok_or_else(|| {
            "internal error: missing validated gRPC TLS configuration for TCP listener".to_string()
        })?;
        spawn_control_plane(addr, control.clone(), tls)?;
        println!("gRPC control plane listening with mTLS on {addr}");
    }

    if let Some(path) = cli.grpc_uds {
        spawn_control_plane_uds(path.clone(), control.clone())?;
        println!("gRPC control plane listening on unix://{}", path.display());
    }

    if let Some(addr) = cli.metrics_addr {
        if cli.unsafe_admin_listen && !addr.ip().is_loopback() {
            eprintln!(
                "WARNING: unauthenticated admin HTTP is exposed on non-loopback address {addr}"
            );
        }
        spawn_metrics_service_with_state(&mut server, addr, Arc::clone(&state))
            .map_err(|err| format!("failed to spawn metrics service: {err}"))?;
        println!("Prometheus metrics listening on {addr}");
    }

    server.add_service(proxy);
    server.add_service(upstream_health_checks);
    server.add_service(nrf_discovery);
    server.run_forever();
}

fn load_grpc_tls(files: &GrpcTlsFiles) -> Result<GrpcTlsConfig, String> {
    let certificate = std::fs::read(&files.certificate).map_err(|err| {
        format!(
            "failed to read gRPC server certificate {}: {err}",
            files.certificate.display()
        )
    })?;
    let key = std::fs::read(&files.key).map_err(|err| {
        format!(
            "failed to read gRPC server key {}: {err}",
            files.key.display()
        )
    })?;
    let client_ca = std::fs::read(&files.client_ca).map_err(|err| {
        format!(
            "failed to read gRPC controller client CA {}: {err}",
            files.client_ca.display()
        )
    })?;

    Ok(GrpcTlsConfig::from_pem(certificate, key, client_ca))
}

fn load_router(path: &Path) -> Result<CompiledRouter, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read config {}: {err}", path.display()))?;
    let ast = Ast::parse_config(&text)
        .map_err(|err| format!("failed to parse config {}: {}", path.display(), err.message))?;
    let root_dir = path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let ast = IncludeResolver::new(&ast, root_dir)
        .resolve(&ast)
        .map_err(|err| {
            format!(
                "failed to resolve includes in {}: {}",
                path.display(),
                err.message
            )
        })?;
    let ir = Ir::from_ast(&ast)
        .map_err(|err| format!("failed to lower config {}: {}", path.display(), err.message))?;
    ir.validate().map_err(|err| {
        format!(
            "failed to validate config {}: {}",
            path.display(),
            err.message
        )
    })?;
    let http = ir
        .http
        .ok_or_else(|| format!("config {} does not contain an http block", path.display()))?;

    if http.servers.is_empty() {
        return Err(format!(
            "config {} does not contain any server blocks",
            path.display()
        ));
    }

    CompiledRouter::from_http(&http).map_err(|err| {
        format!(
            "failed to compile router from config {}: {err}",
            path.display()
        )
    })
}

fn parse_cli_args<I, T>(args: I) -> Result<Option<CliArgs>, String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut grpc_addr: Option<SocketAddr> = None;
    let mut grpc_uds: Option<PathBuf> = None;
    let mut grpc_certificate: Option<PathBuf> = None;
    let mut grpc_key: Option<PathBuf> = None;
    let mut grpc_client_ca: Option<PathBuf> = None;
    let mut metrics_addr: Option<SocketAddr> = None;
    let mut otel_endpoint: Option<String> = None;
    let mut unsafe_admin_listen = false;

    let mut args = args.into_iter().skip(1).map(Into::into);
    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--check" => check_only = true,
            "--unsafe-admin-listen" => unsafe_admin_listen = true,
            "--grpc-addr" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--grpc-addr requires a socket address".to_string())?;
                let value = value.to_string_lossy();
                let addr = value
                    .parse()
                    .map_err(|err| format!("invalid --grpc-addr `{value}`: {err}"))?;
                grpc_addr = Some(addr);
            }
            "--grpc-uds" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--grpc-uds requires a filesystem path".to_string())?;
                grpc_uds = Some(PathBuf::from(value));
            }
            "--grpc-tls-cert" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--grpc-tls-cert requires a PEM file path".to_string())?;
                if grpc_certificate.replace(PathBuf::from(value)).is_some() {
                    return Err("--grpc-tls-cert specified more than once".into());
                }
            }
            "--grpc-tls-key" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--grpc-tls-key requires a PEM file path".to_string())?;
                if grpc_key.replace(PathBuf::from(value)).is_some() {
                    return Err("--grpc-tls-key specified more than once".into());
                }
            }
            "--grpc-client-ca" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--grpc-client-ca requires a PEM file path".to_string())?;
                if grpc_client_ca.replace(PathBuf::from(value)).is_some() {
                    return Err("--grpc-client-ca specified more than once".into());
                }
            }
            "--metrics-addr" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--metrics-addr requires a socket address".to_string())?;
                let value = value.to_string_lossy();
                let addr = value
                    .parse()
                    .map_err(|err| format!("invalid --metrics-addr `{value}`: {err}"))?;
                if metrics_addr.replace(addr).is_some() {
                    return Err("--metrics-addr specified more than once".into());
                }
            }
            "--otel-endpoint" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--otel-endpoint requires a URL".to_string())?;
                if otel_endpoint
                    .replace(value.to_string_lossy().into_owned())
                    .is_some()
                {
                    return Err("--otel-endpoint specified more than once".into());
                }
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}"));
            }
            _ => {
                if config_path.replace(PathBuf::from(arg)).is_some() {
                    return Err("expected exactly one config path".into());
                }
            }
        }
    }

    let Some(config_path) = config_path else {
        return Err("missing config path".into());
    };

    if grpc_addr.is_some() && grpc_uds.is_some() {
        return Err("use either --grpc-addr or --grpc-uds, not both".into());
    }
    if unsafe_admin_listen && metrics_addr.is_none() {
        return Err("--unsafe-admin-listen requires --metrics-addr".into());
    }
    let grpc_tls = match (grpc_certificate, grpc_key, grpc_client_ca) {
        (None, None, None) => None,
        (Some(certificate), Some(key), Some(client_ca)) => Some(GrpcTlsFiles {
            certificate,
            key,
            client_ca,
        }),
        _ => {
            return Err(
                "--grpc-addr requires --grpc-tls-cert, --grpc-tls-key, and --grpc-client-ca".into(),
            );
        }
    };
    if grpc_addr.is_some() && grpc_tls.is_none() {
        return Err(
            "--grpc-addr requires --grpc-tls-cert, --grpc-tls-key, and --grpc-client-ca".into(),
        );
    }
    if grpc_uds.is_some() && grpc_tls.is_some() {
        return Err("gRPC TLS file flags can only be used with --grpc-addr".into());
    }
    if grpc_addr.is_none() && grpc_tls.is_some() {
        return Err("gRPC TLS file flags require --grpc-addr".into());
    }
    if metrics_addr.is_some_and(|addr| !addr.ip().is_loopback()) && !unsafe_admin_listen {
        return Err("non-loopback --metrics-addr requires explicit --unsafe-admin-listen".into());
    }

    Ok(Some(CliArgs {
        config_path,
        check_only,
        grpc_addr,
        grpc_uds,
        grpc_tls,
        metrics_addr,
        otel_endpoint,
        unsafe_admin_listen,
    }))
}

fn print_usage() {
    eprintln!(
        "Usage: ngxora [--check] [--metrics-addr <host:port> [--unsafe-admin-listen]] [--otel-endpoint <url>] [--grpc-addr <host:port> --grpc-tls-cert <pem> --grpc-tls-key <pem> --grpc-client-ca <pem> | --grpc-uds <path>] <config-path>"
    );
}

#[cfg(test)]
mod tests {
    use super::parse_cli_args;

    #[test]
    fn tcp_grpc_requires_all_mtls_files() {
        let err = parse_cli_args([
            "ngxora",
            "--grpc-addr",
            "0.0.0.0:50051",
            "--grpc-tls-cert",
            "server.pem",
            "config.conf",
        ])
        .expect_err("incomplete TLS configuration is rejected");

        assert!(err.contains("--grpc-addr requires"));
    }

    #[test]
    fn tcp_grpc_accepts_non_loopback_with_mtls() {
        let cli = parse_cli_args([
            "ngxora",
            "--grpc-addr",
            "0.0.0.0:50051",
            "--grpc-tls-cert",
            "server.pem",
            "--grpc-tls-key",
            "server.key",
            "--grpc-client-ca",
            "controller-ca.pem",
            "config.conf",
        ])
        .expect("valid mTLS TCP listener")
        .expect("not help");

        assert_eq!(cli.grpc_addr.expect("TCP address").port(), 50051);
        assert!(cli.grpc_tls.is_some());
    }

    #[test]
    fn uds_rejects_tcp_tls_files() {
        let err = parse_cli_args([
            "ngxora",
            "--grpc-uds",
            "/tmp/ngxora.sock",
            "--grpc-tls-cert",
            "server.pem",
            "--grpc-tls-key",
            "server.key",
            "--grpc-client-ca",
            "controller-ca.pem",
            "config.conf",
        ])
        .expect_err("UDS must not accept TCP TLS files");

        assert!(err.contains("only be used with --grpc-addr"));
    }
}
