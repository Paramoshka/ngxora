//! In-memory GeoIP lookups and background replacement of a local MaxMind database.

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use maxminddb::{Reader, geoip2};
use ngxora_compile::ir::GeoIpConfig;
use pingora::{
    http::RequestHeader, server::ShutdownWatch, services::background::BackgroundService,
};
use serde::Serialize;
use std::{
    fs,
    net::IpAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

const HEADERS: [&str; 3] = ["x-geoip-city", "x-geoip-country", "x-geoip-country-iso"];

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct GeoIpRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_country_iso: Option<String>,
}

impl GeoIpRecord {
    fn values(&self) -> [Option<&str>; 3] {
        [
            self.geoip_city.as_deref(),
            self.geoip_country.as_deref(),
            self.geoip_country_iso.as_deref(),
        ]
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileStamp {
    modified: SystemTime,
    len: u64,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}

fn file_stamp(path: &Path) -> Result<FileStamp, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("database path is not a regular file".into());
    }
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    Ok(FileStamp {
        modified: metadata.modified().map_err(|error| error.to_string())?,
        len: metadata.len(),
        #[cfg(unix)]
        identity: (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ),
    })
}

#[derive(Default)]
struct ReloadState {
    loaded: Option<FileStamp>,
    last_error: Option<String>,
}

pub(crate) struct GeoIp {
    config: GeoIpConfig,
    reader: ArcSwapOption<Reader<Vec<u8>>>,
    reload: Mutex<ReloadState>,
    lookup_error_logged: AtomicBool,
}

impl GeoIp {
    pub(crate) fn new(config: GeoIpConfig) -> Self {
        let geoip = Self {
            config,
            reader: ArcSwapOption::empty(),
            reload: Mutex::new(ReloadState::default()),
            lookup_error_logged: AtomicBool::new(false),
        };
        geoip.refresh();
        geoip
    }

    fn load_changed(&self, state: &mut ReloadState) -> Result<(), String> {
        let stamp = file_stamp(&self.config.database)?;
        if state.loaded.as_ref() == Some(&stamp) {
            return Ok(());
        }
        let reader =
            Reader::open_readfile(&self.config.database).map_err(|error| error.to_string())?;
        match reader.metadata().database_type.as_str() {
            "GeoIP2-City" | "GeoLite2-City" | "GeoIP2-Country" | "GeoLite2-Country" => {}
            other => {
                return Err(format!(
                    "unsupported database type `{other}`: expected City or Country"
                ));
            }
        }
        reader.verify().map_err(|error| error.to_string())?;
        if file_stamp(&self.config.database)? != stamp {
            return Err("database changed while reading; retrying on the next poll".into());
        }
        self.reader.store(Some(Arc::new(reader)));
        self.lookup_error_logged.store(false, Ordering::Relaxed);
        state.loaded = Some(stamp);
        log::info!("GeoIP database loaded: {}", self.config.database.display());
        Ok(())
    }

    fn refresh(&self) {
        let mut state = match self.reload.lock() {
            Ok(state) => state,
            Err(_) => {
                log::error!(
                    "GeoIP reload state poisoned: {}",
                    self.config.database.display()
                );
                return;
            }
        };
        match self.load_changed(&mut state) {
            Ok(()) => state.last_error = None,
            Err(error) => {
                if state.last_error.as_ref() != Some(&error) {
                    log::warn!(
                        "GeoIP database {}: {error}; retaining last working database if available",
                        self.config.database.display()
                    );
                }
                state.last_error = Some(error);
            }
        }
    }

    pub(crate) fn lookup_request(
        &self,
        peer: Option<IpAddr>,
        headers: &http::HeaderMap,
    ) -> GeoIpRecord {
        // Duplicate XFF fields are ambiguous; fall back to the socket peer.
        let forwarded = if headers.get_all("x-forwarded-for").iter().count() == 1 {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
        } else {
            None
        };
        let ip = ngxora_plugin_api::client_ip::resolve_chain(
            peer,
            forwarded,
            &self.config.trusted_proxies,
        )
        .and_then(|chain| chain.first().copied());
        self.lookup_ip(ip)
    }

    pub(crate) fn lookup_ip(&self, ip: Option<IpAddr>) -> GeoIpRecord {
        let reader = self.reader.load();
        let (Some(ip), Some(reader)) = (ip, reader.as_ref()) else {
            return GeoIpRecord::default();
        };
        match lookup(reader, ip) {
            Ok(record) => record,
            Err(error) => {
                if !self.lookup_error_logged.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "GeoIP lookup failed in {}: {error}",
                        self.config.database.display()
                    );
                }
                GeoIpRecord::default()
            }
        }
    }
}

fn lookup(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Result<GeoIpRecord, String> {
    let city = reader
        .lookup(ip)
        .and_then(|result| result.decode::<geoip2::City>())
        .map_err(|error| error.to_string())?;
    let Some(city) = city else {
        return Ok(GeoIpRecord::default());
    };
    let record = GeoIpRecord {
        geoip_city: city
            .city
            .names
            .english
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        geoip_country: city
            .country
            .names
            .english
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        geoip_country_iso: city
            .country
            .iso_code
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    };
    for value in record.values().into_iter().flatten() {
        http::HeaderValue::from_str(value)
            .map_err(|error| format!("invalid GeoIP header value: {error}"))?;
    }
    Ok(record)
}

pub(crate) fn remove_headers(request: &mut RequestHeader) {
    for name in HEADERS {
        request.remove_header(name);
    }
}

pub(crate) fn set_headers(
    request: &mut RequestHeader,
    record: &GeoIpRecord,
) -> pingora::Result<()> {
    remove_headers(request);
    for (name, value) in HEADERS.into_iter().zip(record.values()) {
        if let Some(value) = value {
            request.insert_header(name, value)?;
        }
    }
    Ok(())
}

pub struct GeoIpService {
    state: Arc<crate::control::RuntimeState>,
}

impl GeoIpService {
    pub fn new(state: Arc<crate::control::RuntimeState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl BackgroundService for GeoIpService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(geoip) = &self.state.geoip else {
            return;
        };
        let mut interval = tokio::time::interval(geoip.config.reload_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                _ = interval.tick() => {
                    let geoip = Arc::clone(geoip);
                    if let Err(error) = tokio::task::spawn_blocking(move || geoip.refresh()).await {
                        log::error!("GeoIP reload task failed: {error}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
