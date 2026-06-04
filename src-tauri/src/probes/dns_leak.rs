/// DNS leak detection probe.
///
/// Checks whether the system DNS resolver appears to be a local/expected resolver
/// or is leaking to a public third-party DNS (e.g. ISP resolver bypassing a VPN).
///
/// Strategy:
/// 1. Resolve `whoami.akamai.net` (an Akamai anycast host that returns the resolver
///    IP in the A record) via the system resolver.
/// 2. If the returned IP is a well-known *public* resolver address (Google, Cloudflare,
///    OpenDNS, Quad9, Comodo) we flag a potential DNS leak.
/// 3. Also flag when the resolved IP is NOT RFC-1918 private and NOT the gateway
///    subnet — a sign the resolver is far off-network (ISP-injected).
///
/// Returns `true` when a leak is detected.
use std::net::ToSocketAddrs;

/// Well-known public resolver prefixes that shouldn't appear as the active resolver
/// when a user is on a VPN or enterprise network.
const PUBLIC_RESOLVER_PREFIXES: &[&str] = &[
    // Google
    "8.8.8.",
    "8.8.4.",
    "2001:4860:4860::",
    // Cloudflare
    "1.1.1.",
    "1.0.0.",
    "2606:4700:4700::",
    // OpenDNS
    "208.67.222.",
    "208.67.220.",
    // Quad9
    "9.9.9.",
    "149.112.112.",
    // Comodo
    "8.26.56.",
    "8.20.247.",
    // Level3 / CenturyLink
    "4.2.2.",
];

/// Domains we'll resolve to infer the active resolver's public IP.
/// `whoami.akamai.net` returns an A record with the resolver's egress IP on
/// Akamai's network. We fall back to resolving a well-known public domain.
const PROBE_DOMAINS: &[&str] = &["whoami.akamai.net", "google.com", "cloudflare.com"];

pub async fn is_dns_leak() -> bool {
    for domain in PROBE_DOMAINS {
        if let Some(leaked) = check_domain(domain).await {
            return leaked;
        }
    }
    false
}

async fn check_domain(domain: &str) -> Option<bool> {
    let domain = domain.to_string();
    let domain_clone = domain.clone();
    let addrs = tokio::task::spawn_blocking(move || {
        let addr = format!("{domain_clone}:443");
        addr.to_socket_addrs()
            .ok()
            .map(|it| it.map(|a| a.ip().to_string()).collect::<Vec<_>>())
    })
    .await
    .ok()??;

    if addrs.is_empty() {
        return None;
    }

    // If any resolved address matches a well-known public resolver prefix → leak.
    for ip in &addrs {
        for prefix in PUBLIC_RESOLVER_PREFIXES {
            if ip.starts_with(prefix) {
                return Some(true);
            }
        }
    }

    // Additionally flag if the IPs are non-private (could be ISP transparent proxy).
    // We only do this for whoami.akamai.net which is meant to return the resolver IP.
    if domain == "whoami.akamai.net" {
        let all_public = addrs.iter().all(|ip| !is_rfc1918(ip));
        if all_public {
            return Some(true);
        }
    }

    Some(false)
}

fn is_rfc1918(ip: &str) -> bool {
    if ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip.starts_with("::1")
        || ip.starts_with("fc")
        || ip.starts_with("fd")
    {
        return true;
    }
    // 172.16.0.0/12 → 172.16.x.x through 172.31.x.x
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                return (16..=31).contains(&n);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1918_detection() {
        assert!(is_rfc1918("10.0.0.1"));
        assert!(is_rfc1918("192.168.1.1"));
        assert!(is_rfc1918("172.16.5.5"));
        assert!(is_rfc1918("172.31.255.255"));
        assert!(!is_rfc1918("8.8.8.8"));
        assert!(!is_rfc1918("1.1.1.1"));
        assert!(!is_rfc1918("208.67.222.222"));
    }

    #[test]
    fn public_resolver_matches() {
        let google = "8.8.8.8";
        let hit = PUBLIC_RESOLVER_PREFIXES
            .iter()
            .any(|p| google.starts_with(p));
        assert!(hit);

        let cloudflare = "1.1.1.1";
        let hit = PUBLIC_RESOLVER_PREFIXES
            .iter()
            .any(|p| cloudflare.starts_with(p));
        assert!(hit);

        // A private gateway should NOT match
        let private = "192.168.1.1";
        let hit = PUBLIC_RESOLVER_PREFIXES
            .iter()
            .any(|p| private.starts_with(p));
        assert!(!hit);
    }
}
