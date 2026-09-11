use super::*;
use serde_json::{Value, json};

const CITY: &[u8] = include_bytes!("../fixtures/geoip/GeoIP2-City-Test.mmdb");
const COUNTRY: &[u8] = include_bytes!("../fixtures/geoip/GeoIP2-Country-Test.mmdb");

async fn backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(|request: Request<Incoming>| async move {
                            let data: serde_json::Map<String, Value> = request
                                .headers()
                                .iter()
                                .filter(|(name, _)| name.as_str().starts_with("x-geoip-"))
                                .map(|(name, value)| {
                                    (
                                        name.to_string(),
                                        json!(std::str::from_utf8(value.as_bytes()).unwrap()),
                                    )
                                })
                                .collect();
                            let mut response = Response::new(Full::new(Bytes::from(
                                serde_json::to_vec(&data).unwrap(),
                            )));
                            // Only /cached is deliberately independent of GeoIP.
                            if request.uri().path() == "/cached" {
                                *response.body_mut() = Full::new(Bytes::from_static(b"cached"));
                            } else {
                                response
                                    .headers_mut()
                                    .insert("vary", "X-GeoIP-Country-ISO".parse().unwrap());
                            }
                            Ok::<_, std::convert::Infallible>(response)
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    (port, task)
}

async fn geo_request(proxy: &Proxy, ip: &str, h2: bool) -> Value {
    let (status, _, body) = proxy
        .request(
            "GET",
            "test.local",
            "/geo",
            &[
                ("x-forwarded-for", ip),
                ("x-geoip-city", "spoofed"),
                ("x-geoip-country", "spoofed"),
                ("x-geoip-country-iso", "XX"),
            ],
            h2,
        )
        .await;
    assert_eq!(status, 200);
    serde_json::from_str(&body).unwrap()
}

async fn wait_for_country(proxy: &Proxy, has_city: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let data = geo_request(proxy, "89.160.20.128", false).await;
            if data["x-geoip-country-iso"] == "SE" && data.get("x-geoip-city").is_some() == has_city
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn geoip_reload_headers_access_logs_and_cache() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("geo.mmdb");
    let mut proxy = Proxy::start_with_http(
        &format!(
            "geoip {{ database {}; reload_interval 20ms; trusted_proxy 127.0.0.1; }}",
            database.display()
        ),
        "",
    )
    .await;
    let (port, task) = backend().await;
    let mut target = route("/", 200);
    target.action = Some(p::route::Action::Upstream(super::backend(port)));
    target.cache = Some(p::RouteCache {
        ttl_ms: 60_000,
        ..Default::default()
    });
    target.plugins = vec![p::Plugin {
        name: "headers".into(),
        json_config: json!({
            "request": {"set": [{"name": "x-forwarded-for", "value": "2001:218::"}]},
            "upstream_request": {"set": [{"name": "x-geoip-country-iso", "value": "spoofed-by-plugin"}]}
        }).to_string(),
    }];
    proxy.apply(vec![target]).await;
    assert_eq!(geo_request(&proxy, "89.160.20.128", false).await, json!({}));
    std::fs::write(&database, CITY).unwrap();
    wait_for_country(&proxy, true).await;
    for h2 in [false, true] {
        let se = geo_request(&proxy, "89.160.20.128", h2).await;
        assert_eq!(se["x-geoip-country"], "Sweden");
        assert!(se["x-geoip-city"].is_string());
        assert_eq!(
            geo_request(&proxy, "2001:218::", h2).await["x-geoip-country-iso"],
            "JP"
        );
        assert_eq!(geo_request(&proxy, "garbage", h2).await, json!({}));
        assert_eq!(geo_request(&proxy, "127.0.0.1", h2).await, json!({}));
    }
    std::fs::write(&database, b"partial database").unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(geo_request(&proxy, "89.160.20.128", false).await["x-geoip-city"].is_string());
    std::fs::remove_file(&database).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        geo_request(&proxy, "89.160.20.128", false).await["x-geoip-country-iso"],
        "SE"
    );
    let replacement = temp.path().join("replacement.mmdb");
    std::fs::write(&replacement, COUNTRY).unwrap();
    std::fs::rename(&replacement, &database).unwrap();
    wait_for_country(&proxy, false).await;
    for ip in ["89.160.20.128", "2001:218::"] {
        let (status, _, body) = proxy
            .request(
                "GET",
                "test.local",
                "/cached",
                &[("x-forwarded-for", ip)],
                false,
            )
            .await;
        assert_eq!((status, body.as_str()), (200, "cached"));
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let logs = std::fs::read_to_string(proxy._temp.path().join("access.log")).unwrap();
            let entries: Vec<Value> = logs
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            if let Some(hit) = entries
                .iter()
                .find(|line| line["path"] == "/cached" && line["cache_status"] == "hit")
            {
                assert_eq!(hit["geoip_country_iso"], "JP");
                assert!(hit.get("geoip_city").is_none());
                assert!(entries.iter().any(
                    |line| line["geoip_country_iso"] == "SE" && line["geoip_city"].is_string()
                ));
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn geoip_ignores_forwarded_ip_without_trusted_proxy() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("geo.mmdb");
    std::fs::write(&database, CITY).unwrap();
    let mut proxy =
        Proxy::start_with_http(&format!("geoip {{ database {}; }}", database.display()), "").await;
    let (port, task) = backend().await;
    let mut target = route("/", 200);
    target.action = Some(p::route::Action::Upstream(super::backend(port)));
    proxy.apply(vec![target]).await;
    assert_eq!(geo_request(&proxy, "89.160.20.128", false).await, json!({}));
    task.abort();
}
