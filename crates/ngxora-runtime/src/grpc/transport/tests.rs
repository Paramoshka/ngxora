use super::*;

#[tokio::test]
async fn tcp_bind_retries_until_address_is_released() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    let task =
        tokio::spawn(async move { bind_retry("test TCP", true, || TcpListener::bind(addr)).await });
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!task.is_finished());
    drop(occupied);
    let listener = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(listener.local_addr().unwrap(), addr);
}

#[tokio::test]
async fn permanent_errors_and_normal_startup_do_not_retry() {
    for (retry, kind) in [
        (true, io::ErrorKind::PermissionDenied),
        (false, io::ErrorKind::AddrInUse),
    ] {
        let mut attempts = 0;
        let result = bind_retry::<(), _, _>("test", retry, || {
            attempts += 1;
            std::future::ready(Err(io::Error::from(kind)))
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), kind);
        assert_eq!(attempts, 1);
    }
}

#[tokio::test]
async fn shutdown_interrupts_bind_retry() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    let (phases, receiver) = broadcast::channel(8);
    let task = tokio::spawn(until_shutdown(receiver, async move {
        let _listener = bind_retry("test", true, || TcpListener::bind(addr))
            .await
            .unwrap();
        panic!("bind must remain blocked");
    }));
    tokio::time::sleep(Duration::from_millis(50)).await;
    phases
        .send(ExecutionPhase::GracefulUpgradeTransferringFds)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn lifecycle_closure_and_lag_stop_api() {
    let (sender, receiver) = broadcast::channel(1);
    sender
        .send(ExecutionPhase::GracefulUpgradeTransferringFds)
        .unwrap();
    sender.send(ExecutionPhase::Running).unwrap();
    tokio::time::timeout(Duration::from_secs(1), stopping(receiver))
        .await
        .unwrap();
    let (sender, receiver) = broadcast::channel(1);
    drop(sender);
    tokio::time::timeout(Duration::from_secs(1), stopping(receiver))
        .await
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn uds_waits_for_owner_then_recovers_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let (listener, ownership) = uds::bind(&path).await.unwrap();
    assert!(matches!(uds::bind(&path).await, Err(e) if e.kind() == io::ErrorKind::AddrInUse));
    drop(listener);
    drop(ownership);
    assert!(!path.exists());
    assert!(dir.path().join("control.sock.lock").exists());
    let stale = tokio::net::UnixListener::bind(&path).unwrap();
    drop(stale);
    let (listener, ownership) = uds::bind(&path).await.unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(listener);
    drop(ownership);
    assert!(!path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn uds_does_not_remove_live_socket_file_or_symlink() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    // A server from before the locking protocol still owns its live socket.
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();
    assert!(matches!(uds::bind(&path).await, Err(e) if e.kind() == io::ErrorKind::AddrInUse));
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    drop(listener);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, "keep").unwrap();
    assert!(uds::bind(&path).await.is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
    let alias = dir.path().join("alias.sock");
    symlink(&path, &alias).unwrap();
    assert!(uds::bind(&alias).await.is_err());
    assert!(
        std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn old_uds_cleanup_preserves_replacement() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let (old, ownership) = uds::bind(&path).await.unwrap();
    std::fs::remove_file(&path).unwrap();
    let replacement = tokio::net::UnixListener::bind(&path).unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();
    drop(old);
    drop(ownership);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    tokio::net::UnixStream::connect(&path).await.unwrap();
    drop(replacement);
}

#[cfg(unix)]
#[tokio::test]
async fn stopping_uds_runtime_closes_existing_connections_and_releases_lock() {
    use crate::control::{ConfigSnapshot, RuntimeState};
    use crate::upstreams::CompiledRouter;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let control = InProcessControlPlane::new(Arc::new(RuntimeState::new(ConfigSnapshot::new(
        "v1",
        CompiledRouter::default(),
    ))));
    let (phases, receiver) = broadcast::channel(8);
    let thread = spawn_control_plane_uds(path.clone(), control, receiver, false).unwrap();
    let mut client = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(client) = tokio::net::UnixStream::connect(&path).await {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    phases.send(ExecutionPhase::GracefulTerminate).unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || thread.join().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::ConnectionReset);
    assert!(!path.exists());
    let (_listener, _ownership) = uds::bind(&path).await.unwrap();
}
