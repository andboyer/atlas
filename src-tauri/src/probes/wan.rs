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
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const IPAPI_URL: &str = "https://ipapi.co/json/";
const IPV4_PROBE_URL: &str = "https://api4.ipify.org";
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

    // IPv4 + geo + ASN via ipapi.co. Note: ipapi.co echoes back whichever
    // address the request egressed from — on a dual-stack host that can be an
    // IPv6 address, so classify the returned IP rather than assuming IPv4.
    let mut info = match client.get(IPAPI_URL).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<IpApiResponse>().await {
            Ok(body) => {
                let (v4, v6) = classify_ip(body.ip.as_deref());
                WanInfo {
                    public_ipv4: v4,
                    public_ipv6: v6,
                    asn: parse_asn(body.asn.as_deref()),
                    isp: body.org.clone(),
                    country: body.country_code.clone(),
                    region: format_region(body.city.as_deref(), body.region_code.as_deref()),
                    dual_stack: false,
                }
            }
            Err(_) => WanInfo::empty(),
        },
        _ => WanInfo::empty(),
    };

    // If we still don't have an IPv4 address (e.g. the geo lookup egressed over
    // IPv6 on a dual-stack host), ask an IPv4-only endpoint directly so the
    // "Public IPv4" field never shows an IPv6 address.
    if info.public_ipv4.is_none() {
        if let Ok(resp) = client.get(IPV4_PROBE_URL).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    let trimmed = body.trim();
                    if trimmed.parse::<Ipv4Addr>().is_ok() {
                        info.public_ipv4 = Some(trimmed.to_string());
                    }
                }
            }
        }
    }

    // Best-effort IPv6 probe (independent endpoint).
    if info.public_ipv6.is_none() {
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

/// Classify a public-IP string returned by a geo/echo endpoint into
/// `(ipv4, ipv6)`. These endpoints reflect whichever address the request
/// egressed from, so on a dual-stack host an "IPv4" lookup can come back as
/// IPv6 — this keeps each address in its correct field.
fn classify_ip(s: Option<&str>) -> (Option<String>, Option<String>) {
    match s.map(str::trim).and_then(|s| s.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(v4)) => (Some(v4.to_string()), None),
        Some(IpAddr::V6(v6)) => (None, Some(v6.to_string())),
        None => (None, None),
    }
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
        assert_eq!(
            format_region(Some("Seattle"), None),
            Some("Seattle".to_string())
        );
        assert_eq!(format_region(None, None), None);
    }

    #[test]
    fn ipv6_heuristic() {
        assert!(looks_like_ipv6("2001:db8::1"));
        assert!(looks_like_ipv6("fe80::1"));
        assert!(!looks_like_ipv6("8.8.8.8"));
        assert!(!looks_like_ipv6("garbage with no colons"));
    }

    #[test]
    fn classifies_ip_into_correct_family() {
        assert_eq!(
            classify_ip(Some("203.0.113.7")),
            (Some("203.0.113.7".to_string()), None)
        );
        assert_eq!(
            classify_ip(Some(" 2606:4700:4700::1111 ")),
            (None, Some("2606:4700:4700::1111".to_string()))
        );
        assert_eq!(classify_ip(Some("not-an-ip")), (None, None));
        assert_eq!(classify_ip(None), (None, None));
    }
}
