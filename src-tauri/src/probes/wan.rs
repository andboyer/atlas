//! WAN / ISP intelligence probe.
//!
//! Fetches public IPv4 + IPv6 + ASN + geo from `https://ipapi.co/json/`
//! (free tier, no API key required). Returns `None` if the device is
//! offline or the API is unreachable — never blocks the overall scan.
//!
//! IPv6 status is probed separately against `https://ifconfig.co/ip` via
//! IPv6-only DNS resolution to determine dual-stack availability.

use crate::types::WanInfo;
use serde::Deserialize;
use std::time::Duration;

const IPAPI_URL: &str = "https://ipapi.co/json/";
const IPV6_PROBE_URL: &str = "https://api6.ipify.org";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct IpApiResponse {
    ip: Option<String>,
    asn: Option<String>,
    org: Option<String>,
    country_code: Option<String>,
    city: Option<String>,
    region_code: Option<String>,
}

pub async fn probe_wan() -> Option<WanInfo> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("atlas/0.1")
        .build()
        .ok()?;

    // IPv4 + geo + ASN via ipapi.co
    let mut info = match client.get(IPAPI_URL).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<IpApiResponse>().await {
            Ok(body) => WanInfo {
                public_ipv4: body.ip.clone(),
                public_ipv6: None,
                asn: parse_asn(body.asn.as_deref()),
                isp: body.org.clone(),
                country: body.country_code.clone(),
                region: format_region(body.city.as_deref(), body.region_code.as_deref()),
                dual_stack: false,
            },
            Err(_) => WanInfo::empty(),
        },
        _ => WanInfo::empty(),
    };

    // Best-effort IPv6 probe (independent endpoint).
    if let Ok(resp) = client.get(IPV6_PROBE_URL).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                let trimmed = body.trim();
                if looks_like_ipv6(trimmed) {
                    info.public_ipv6 = Some(trimmed.to_string());
                }
            }
        }
    }

    info.dual_stack = info.public_ipv4.is_some() && info.public_ipv6.is_some();

    if info.public_ipv4.is_none() && info.public_ipv6.is_none() {
        return None;
    }
    Some(info)
}

impl WanInfo {
    fn empty() -> Self {
        Self {
            public_ipv4: None,
            public_ipv6: None,
            asn: None,
            isp: None,
            country: None,
            region: None,
            dual_stack: false,
        }
    }
}

fn parse_asn(s: Option<&str>) -> Option<u32> {
    // ipapi.co returns "AS7922" — strip the prefix.
    let s = s?.trim_start_matches("AS").trim_start_matches("as");
    s.parse().ok()
}

fn format_region(city: Option<&str>, region: Option<&str>) -> Option<String> {
    match (city, region) {
        (Some(c), Some(r)) if !c.is_empty() && !r.is_empty() => Some(format!("{c}, {r}")),
        (Some(c), _) if !c.is_empty() => Some(c.to_string()),
        (_, Some(r)) if !r.is_empty() => Some(r.to_string()),
        _ => None,
    }
}

fn looks_like_ipv6(s: &str) -> bool {
    // Cheap check: IPv6 has at least two colons. ipify-v6 occasionally returns
    // an IPv4 address if the request egressed over v4 fallback, so guard.
    s.matches(':').count() >= 2 && !s.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asn_with_prefix() {
        assert_eq!(parse_asn(Some("AS7922")), Some(7922));
        assert_eq!(parse_asn(Some("as13335")), Some(13335));
        assert_eq!(parse_asn(Some("7922")), Some(7922));
        assert_eq!(parse_asn(None), None);
        assert_eq!(parse_asn(Some("not-an-asn")), None);
    }

    #[test]
    fn formats_region_pairs() {
        assert_eq!(
            format_region(Some("Seattle"), Some("WA")),
            Some("Seattle, WA".to_string())
        );
        assert_eq!(format_region(Some("Seattle"), None), Some("Seattle".to_string()));
        assert_eq!(format_region(None, None), None);
    }

    #[test]
    fn ipv6_heuristic() {
        assert!(looks_like_ipv6("2001:db8::1"));
        assert!(looks_like_ipv6("fe80::1"));
        assert!(!looks_like_ipv6("8.8.8.8"));
        assert!(!looks_like_ipv6("garbage with no colons"));
    }
}
