use ipnet::IpNet;
use std::net::IpAddr;

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
