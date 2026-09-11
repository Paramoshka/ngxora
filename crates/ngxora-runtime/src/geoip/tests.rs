use super::*;
use std::time::Duration;

const CITY: &[u8] = include_bytes!("../../../../tests/fixtures/geoip/GeoIP2-City-Test.mmdb");
const COUNTRY: &[u8] = include_bytes!("../../../../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");

fn config(path: &Path) -> GeoIpConfig {
    GeoIpConfig {
        database: path.to_owned(),
        reload_interval: Duration::from_millis(10),
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
    }
}

fn request(geoip: &GeoIp, ip: &str) -> GeoIpRecord {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-for", ip.parse().unwrap());
    geoip.lookup_request(Some("127.0.0.1".parse().unwrap()), &headers)
}

#[test]
fn city_country_ipv4_ipv6_and_missing_records() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("geo.mmdb");
    for (bytes, has_city) in [(CITY, true), (COUNTRY, false)] {
        fs::write(&path, bytes).unwrap();
        let geoip = GeoIp::new(config(&path));
        let record = request(&geoip, "89.160.20.128");
        assert_eq!(record.geoip_country_iso.as_deref(), Some("SE"));
        assert_eq!(record.geoip_country.as_deref(), Some("Sweden"));
        assert_eq!(record.geoip_city.is_some(), has_city);
        assert_eq!(
            request(&geoip, "2001:218::").geoip_country_iso.as_deref(),
            Some("JP")
        );
        assert_eq!(request(&geoip, "127.0.0.1"), GeoIpRecord::default());
        assert_eq!(
            geoip.lookup_request(None, &http::HeaderMap::new()),
            GeoIpRecord::default()
        );
    }
}

#[test]
fn unsupported_database_and_directory_fail_open_then_recover() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("geo.mmdb");
    fs::create_dir(&path).unwrap();
    let geoip = GeoIp::new(config(&path));
    assert!(geoip.reader.load().is_none());
    fs::remove_dir(&path).unwrap();
    let mut unsupported = CITY.to_vec();
    let offset = unsupported
        .windows(b"GeoIP2-City".len())
        .position(|value| value == b"GeoIP2-City")
        .unwrap();
    unsupported[offset..offset + b"Unused-City".len()].copy_from_slice(b"Unused-City");
    fs::write(&path, unsupported).unwrap();
    geoip.refresh();
    assert!(geoip.reader.load().is_none());
    assert!(
        geoip
            .reload
            .lock()
            .unwrap()
            .last_error
            .as_ref()
            .unwrap()
            .contains("unsupported database type")
    );
    fs::write(&path, CITY).unwrap();
    geoip.refresh();
    assert_eq!(
        request(&geoip, "89.160.20.128")
            .geoip_country_iso
            .as_deref(),
        Some("SE")
    );
    assert!(geoip.reload.lock().unwrap().last_error.is_none());
}

#[test]
fn forwarded_addresses_only_follow_trusted_chain() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("geo.mmdb");
    fs::write(&path, CITY).unwrap();
    let geoip = GeoIp::new(config(&path));
    assert_eq!(
        request(&geoip, "2001:218::, 89.160.20.128, 127.0.0.1")
            .geoip_country_iso
            .as_deref(),
        Some("SE")
    );
    for raw in ["bad, 89.160.20.128", "", "89.160.20.128:80"] {
        assert_eq!(request(&geoip, raw), GeoIpRecord::default());
    }
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-for", "89.160.20.128".parse().unwrap());
    assert_eq!(
        geoip.lookup_request(Some("127.0.0.2".parse().unwrap()), &headers),
        GeoIpRecord::default()
    );
    headers.append("x-forwarded-for", "2001:218::".parse().unwrap());
    assert_eq!(
        geoip.lookup_request(Some("127.0.0.1".parse().unwrap()), &headers),
        GeoIpRecord::default()
    );
}

#[test]
fn file_recovery_and_replacement_preserve_concurrent_readers() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("geo.mmdb");
    let geoip = Arc::new(GeoIp::new(config(&path)));
    assert_eq!(request(&geoip, "89.160.20.128"), GeoIpRecord::default());
    fs::write(&path, b"broken").unwrap();
    geoip.refresh();
    assert!(geoip.reader.load().is_none());
    fs::write(&path, CITY).unwrap();
    geoip.refresh();
    let old_reader = geoip.reader.load_full().unwrap();
    assert!(request(&geoip, "89.160.20.128").geoip_city.is_some());
    let task_geoip = Arc::clone(&geoip);
    let thread = std::thread::spawn(move || {
        for _ in 0..1000 {
            assert_eq!(
                request(&task_geoip, "89.160.20.128")
                    .geoip_country_iso
                    .as_deref(),
                Some("SE")
            );
        }
    });
    fs::write(&path, b"broken").unwrap();
    geoip.refresh();
    assert!(Arc::ptr_eq(&old_reader, &geoip.reader.load_full().unwrap()));
    fs::remove_file(&path).unwrap();
    geoip.refresh();
    assert!(request(&geoip, "89.160.20.128").geoip_city.is_some());
    let replacement = temp.path().join("replacement");
    fs::write(&replacement, COUNTRY).unwrap();
    fs::rename(&replacement, &path).unwrap();
    geoip.refresh();
    assert!(request(&geoip, "89.160.20.128").geoip_city.is_none());
    assert!(
        lookup(&old_reader, "89.160.20.128".parse().unwrap())
            .unwrap()
            .geoip_city
            .is_some()
    );
    thread.join().unwrap();
    let reader = geoip.reader.load_full().unwrap();
    geoip.refresh();
    assert!(Arc::ptr_eq(&reader, &geoip.reader.load_full().unwrap()));
}

#[tokio::test]
async fn watcher_loads_appearing_file_and_stops_on_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("geo.mmdb");
    let router = crate::upstreams::CompiledRouter {
        geoip: Some(config(&path)),
        ..Default::default()
    };
    let state = Arc::new(crate::control::RuntimeState::bootstrap(router));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let service = GeoIpService::new(Arc::clone(&state));
    let task = tokio::spawn(async move { service.start(shutdown_rx).await });
    fs::write(&path, CITY).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.geoip.as_ref().unwrap().reader.load().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn owned_headers_replace_spoofed_values_and_skip_missing_fields() {
    let mut headers = RequestHeader::build("GET", b"/", None).unwrap();
    for name in HEADERS {
        headers.insert_header(name, "spoofed").unwrap();
    }
    let record = GeoIpRecord {
        geoip_country_iso: Some("SE".into()),
        ..Default::default()
    };
    set_headers(&mut headers, &record).unwrap();
    assert_eq!(headers.headers["x-geoip-country-iso"], "SE");
    assert!(!headers.headers.contains_key("x-geoip-city"));
    assert!(!headers.headers.contains_key("x-geoip-country"));
    assert_eq!(
        serde_json::to_value(record).unwrap(),
        serde_json::json!({"geoip_country_iso": "SE"})
    );
    set_headers(&mut headers, &GeoIpRecord::default()).unwrap();
    assert!(!headers.headers.contains_key("x-geoip-country-iso"));
}
