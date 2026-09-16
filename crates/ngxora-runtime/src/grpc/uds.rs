use std::{
    fs::{DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::net::{UnixListener, UnixStream};

pub(super) struct Ownership {
    _lock: File,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for Ownership {
    fn drop(&mut self) {
        // Same-UID processes must honor the lock. Preserve replacements visible at this check.
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta)
                if meta.file_type().is_socket()
                    && meta.dev() == self.device
                    && meta.ino() == self.inode =>
            {
                if let Err(err) = std::fs::remove_file(&self.path) {
                    eprintln!("failed to remove gRPC UDS {}: {err}", self.path.display());
                }
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => eprintln!(
                "failed to inspect gRPC UDS {} during shutdown: {err}",
                self.path.display()
            ),
        }
    }
}

pub(super) async fn bind(path: &Path) -> io::Result<(UnixListener, Ownership)> {
    let path = private_socket_path(path)?;
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    match std::fs::symlink_metadata(&lock_path) {
        Ok(meta) if !meta.is_file() => {
            return Err(io::Error::other("gRPC UDS lock path is not a regular file"));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)?;
    lock.try_lock().map_err(|err| match err {
        std::fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::AddrInUse,
            "gRPC UDS is owned by another process",
        ),
        std::fs::TryLockError::Error(err) => err,
    })?;
    prepare_path(&path).await?;
    let listener = UnixListener::bind(&path)?;
    let meta = std::fs::symlink_metadata(&path)?;
    let ownership = Ownership {
        _lock: lock,
        path: path.to_path_buf(),
        device: meta.dev(),
        inode: meta.ino(),
    };
    set_uds_permissions(&path)?;
    Ok((listener, ownership))
}

fn private_socket_path(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "gRPC UDS requires a socket filename",
        )
    })?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let parent = std::fs::canonicalize(parent)?;
    // SAFETY: geteuid takes no arguments and has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let meta = std::fs::metadata(&parent)?;
    if meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "gRPC UDS directory {} must be owned by uid {uid} and accessible only to its owner (0700)",
                parent.display()
            ),
        ));
    }
    // A private directory can still be renamed by an untrusted ancestor's owner.
    // Sticky shared ancestors (e.g. /tmp) protect entries owned by other users.
    for ancestor in parent.ancestors().skip(1) {
        let meta = std::fs::metadata(ancestor)?;
        if (meta.uid() != uid && meta.uid() != 0)
            || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "gRPC UDS directory has an unsafe ancestor: {}",
                    ancestor.display()
                ),
            ));
        }
    }
    Ok(parent.join(name))
}

async fn prepare_path(path: &Path) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !meta.file_type().is_socket() {
        return Err(io::Error::other(
            "gRPC UDS path already exists and is not a socket",
        ));
    }
    match tokio::time::timeout(Duration::from_millis(250), UnixStream::connect(path)).await {
        Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
            let current = std::fs::symlink_metadata(path)?;
            if current.dev() != meta.dev() || current.ino() != meta.ino() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "gRPC UDS changed during bind",
                ));
            }
            std::fs::remove_file(path)
        }
        Ok(Err(err)) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        // The listener may close while our probe is queued. Do not unlink on a reset:
        // retry and require an explicit ConnectionRefused before treating it as stale.
        Ok(Err(err))
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Err(io::Error::new(io::ErrorKind::AddrInUse, err))
        }
        Ok(Err(err)) => Err(err),
        Ok(Ok(_)) | Err(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "gRPC UDS listener is still active",
        )),
    }
}

pub(crate) fn set_uds_permissions(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
