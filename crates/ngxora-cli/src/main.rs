use ngxora_compile::ir::Ir;
use ngxora_config::{Ast, include::IncludeResolver};
use ngxora_runtime::control::{ConfigSnapshot, InProcessControlPlane, RuntimeState};
use ngxora_runtime::server::bind_listeners_from_state;
use ngxora_runtime::upstreams::{CompiledRouter, DynamicProxy};
use pingora::server::Server;
use pingora::server::configuration::Opt;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

struct CliArgs {
    config_path: PathBuf,
    check_only: bool,
}

fn main() -> ExitCode {
    env_logger::init();

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

    let mut server = Server::new(None::<Opt>)
        .map_err(|err| format!("failed to create pingora server: {err}"))?;
    server.bootstrap();

    let mut proxy = pingora_proxy::http_proxy_service(
        &server.configuration,
        DynamicProxy::new(Arc::clone(control.state())),
    );
    bind_listeners_from_state(&mut proxy, Arc::clone(control.state()))
        .map_err(|err| format!("failed to bind listeners from config: {err}"))?;

    println!(
        "starting ngxora with {} listeners from {}",
        snapshot.router.listeners.len(),
        cli.config_path.display()
    );

    server.add_service(proxy);
    server.run_forever();
}

fn load_router(path: &Path) -> Result<CompiledRouter, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read config {}: {err}", path.display()))?;
    let ast = Ast::parse_config(&text)
        .map_err(|err| format!("failed to parse config {}: {}", path.display(), err.message))?;
    let ast = IncludeResolver::new(&ast).resolve(&ast).map_err(|err| {
        format!(
            "failed to resolve includes in {}: {}",
            path.display(),
            err.message
        )
    })?;
    let ir = Ir::from_ast(&ast)
        .map_err(|err| format!("failed to lower config {}: {}", path.display(), err.message))?;
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

    let args = args.into_iter().skip(1).map(Into::into);
    for arg in args {
        let arg = arg;
        match arg.to_string_lossy().as_ref() {
            "--check" => check_only = true,
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

    Ok(Some(CliArgs {
        config_path,
        check_only,
    }))
}

fn print_usage() {
    eprintln!("Usage: ngxora [--check] <config-path>");
}
