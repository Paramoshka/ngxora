use ngxora_runtime::control::{ConfigSnapshot, InProcessControlPlane};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use std::path::PathBuf;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::Mutex;

pub struct ConfigReload {
    path: PathBuf,
    control: InProcessControlPlane,
    signal: Mutex<Signal>,
}

impl ConfigReload {
    pub fn new(path: PathBuf, control: InProcessControlPlane) -> Result<Self, String> {
        // Register before listeners start, so an early SIGHUP cannot terminate the process.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to create reload runtime: {e}"))?;
        let _guard = runtime.enter();
        let signal =
            signal(SignalKind::hangup()).map_err(|e| format!("failed to register SIGHUP: {e}"))?;
        Ok(Self {
            path,
            control,
            signal: Mutex::new(signal),
        })
    }
}

#[async_trait::async_trait]
impl BackgroundService for ConfigReload {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut signal = self.signal.lock().await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                event = signal.recv() => {
                    if event.is_none() {
                        eprintln!("config reload: SIGHUP stream closed");
                        return;
                    }
                }
            }
            let path = self.path.clone();
            let control = self.control.clone();
            let result = tokio::task::spawn_blocking(move || {
                let router = super::load_router(&path)?;
                let version = format!("file:{}", path.display());
                Ok::<_, String>(control.apply_snapshot(ConfigSnapshot::new(version, router)))
            })
            .await;
            match result {
                Ok(Ok(result)) if result.applied => eprintln!(
                    "config reload: applied generation {}",
                    result.active_generation
                ),
                Ok(Ok(result)) => eprintln!("config reload rejected: {}", result.message),
                Ok(Err(error)) => eprintln!("config reload rejected: {error}"),
                Err(error) => eprintln!("config reload failed: {error}"),
            }
        }
    }
}
