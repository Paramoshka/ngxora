use ipnet::IpNet;
use std::net::IpAddr;

/// Resolved before request plugins can mutate forwarding headers.
#[derive(Debug, Clone)]
pub struct ResolvedClientIp {
    pub chain: Option<Vec<IpAddr>>,
}

pub fn resolve_headers(
    peer: Option<IpAddr>,
    headers: &http::HeaderMap,
    header: &str,
    trusted_proxies: &[IpNet],
    recursive: bool,
) -> Option<Vec<IpAddr>> {
    let peer = peer?;
    let fallback = || Some(vec![peer]);
    if !trusted_proxies.iter().any(|n| n.contains(&peer))
        || headers.get_all(header).iter().count() != 1
    {
        return fallback();
    }
    let Some(raw) = headers.get(header).and_then(|h| h.to_str().ok()) else {
        return fallback();
    };
    if header.eq_ignore_ascii_case("x-real-ip") {
        return raw
            .trim()
            .parse::<IpAddr>()
            .ok()
            .map(|ip| vec![ip, peer])
            .or_else(fallback);
    }
    if recursive {
        return resolve_chain(Some(peer), Some(raw), trusted_proxies);
    }
    let Ok(chain) = raw
        .split(',')
        .map(|s| s.trim().parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return fallback();
    };
    chain.last().map(|ip| vec![*ip, peer]).or_else(fallback)
}

/// Keep only the forwarded chain vouched for by trusted peers, in client-first order.
pub fn resolve_chain(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted_proxies: &[IpNet],
) -> Option<Vec<IpAddr>> {
    let peer = peer?;
    let trusted = |ip: &IpAddr| trusted_proxies.iter().any(|network| network.contains(ip));
    if !trusted(&peer) {
        return Some(vec![peer]);
    }
    let Some(raw) = forwarded_for else {
        return Some(vec![peer]);
    };
    let Ok(mut forwarded) = raw
        .split(',')
        .map(|ip| ip.trim().parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return Some(vec![peer]);
    };
    let mut current = peer;
    let mut chain = vec![peer];
    while trusted(&current) {
        let Some(next) = forwarded.pop() else { break };
        current = next;
        chain.push(current);
    }
    chain.reverse();
    Some(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_headers_reject_spoofing_and_ambiguity() {
        let trusted = vec![
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.0.2.1, 198.51.100.2, 10.0.0.2".parse().unwrap(),
        );
        let peer = "10.0.0.1".parse().unwrap();
        let chain =
            resolve_headers(Some(peer), &headers, "X-Forwarded-For", &trusted, true).unwrap();
        assert_eq!(chain[0], "198.51.100.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            resolve_headers(Some(peer), &headers, "X-Forwarded-For", &trusted, false).unwrap()[0],
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );
        let untrusted = "203.0.113.10".parse().unwrap();
        assert_eq!(
            resolve_headers(Some(untrusted), &headers, "X-Forwarded-For", &trusted, true),
            Some(vec![untrusted])
        );
        headers.append("x-forwarded-for", "192.0.2.99".parse().unwrap());
        assert_eq!(
            resolve_headers(Some(peer), &headers, "X-Forwarded-For", &trusted, true),
            Some(vec![peer])
        );
        for invalid in ["unknown", "192.0.2.1, bad", "", "192.0.2.1,"] {
            headers.insert("x-forwarded-for", invalid.parse().unwrap());
            assert_eq!(
                resolve_headers(Some(peer), &headers, "X-Forwarded-For", &trusted, true),
                Some(vec![peer])
            );
        }
        headers.insert("x-real-ip", "2001:db8:1::1".parse().unwrap());
        assert_eq!(
            resolve_headers(Some(peer), &headers, "X-Real-IP", &trusted, true).unwrap()[0],
            "2001:db8:1::1".parse::<IpAddr>().unwrap()
        );
        headers.insert("x-real-ip", "192.0.2.1, 192.0.2.2".parse().unwrap());
        assert_eq!(
            resolve_headers(Some(peer), &headers, "X-Real-IP", &trusted, true),
            Some(vec![peer])
        );
        assert_eq!(
            resolve_headers(None, &headers, "X-Real-IP", &trusted, true),
            None
        );
    }
}
