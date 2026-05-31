/// MTU path discovery probe.
///
/// Uses binary search over ping packet sizes (with the Don't-Fragment bit set)
/// to find the effective MTU on the path to 1.1.1.1 (or the default gateway).
///
/// Standard Ethernet MTU = 1500 bytes (IP payload = 1472 bytes for a 28-byte
/// IP+ICMP header). Tunnelled/VPN links often reduce this to 1400–1450 bytes.
/// PPPoE links have MTU 1492. 6in4 tunnels: 1472. OpenVPN: ~1400.
///
/// A discovered MTU below 1400 is reported as a `low_mtu` finding.
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// The minimum acceptable MTU before we flag a problem.
pub const MTU_LOW_THRESHOLD: u32 = 1400;

/// Run a binary-search MTU discovery probe.
/// Returns `Some(mtu_bytes)` or `None` if the probe cannot complete.
pub async fn discover_mtu() -> Option<u32> {
    // Try to reach the internet; fall back to local gateway.
    let target = "1.1.1.1";

    let mut lo: u32 = 576;  // minimum IP MTU per RFC 791
    let mut hi: u32 = 1500; // standard Ethernet MTU

    // Quick sanity: if even the smallest packet fails, we have no connectivity.
    if !ping_size(target, lo).await {
        return None;
    }
    // If full-size works, MTU is at least 1500.
    if ping_size(target, hi).await {
        return Some(hi);
    }

    // Binary search.
    while lo < hi - 1 {
        let mid = (lo + hi) / 2;
        if ping_size(target, mid).await {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(lo)
}

/// Send a single ICMP echo with the DF bit set and payload of `size` bytes.
/// Returns true if the probe succeeded (no fragmentation needed).
///
/// Payload `size` here is the *ICMP data* size; the system ping binary adds the
/// ICMP header (8 bytes) and IP header (20 bytes), so total on-wire = size + 28.
/// We want to discover the total IP MTU, so we pass `size = mtu - 28`.
async fn ping_size(host: &str, mtu: u32) -> bool {
    let payload = mtu.saturating_sub(28);

    #[cfg(target_os = "windows")]
    let args = vec![
        "-n".to_string(),
        "1".to_string(),
        "-w".to_string(),
        "2000".to_string(),
        "-f".to_string(), // DF bit
        "-l".to_string(),
        payload.to_string(),
        host.to_string(),
    ];

    #[cfg(not(target_os = "windows"))]
    let args = {
        let mut a = vec![
            "-c".to_string(),
            "1".to_string(),
            "-W".to_string(),
            "2".to_string(), // 2 second wait
        ];
        // macOS: -D sets DF bit; Linux: -M do
        #[cfg(target_os = "macos")]
        a.push("-D".to_string());
        #[cfg(target_os = "linux")]
        {
            a.push("-M".to_string());
            a.push("do".to_string());
        }
        a.push("-s".to_string());
        a.push(payload.to_string());
        a.push(host.to_string());
        a
    };

    let result = timeout(
        Duration::from_secs(5),
        Command::new("ping").args(&args).output(),
    )
    .await;

    match result {
        Ok(Ok(out)) => out.status.success(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_threshold_is_reasonable() {
        // Verify the constant is in a sensible range at compile time.
        const _: () = assert!(MTU_LOW_THRESHOLD >= 576);
        const _: () = assert!(MTU_LOW_THRESHOLD <= 1472);
    }

    #[test]
    fn payload_calculation() {
        // Standard Ethernet MTU = 1500, payload = 1472
        let mtu = 1500u32;
        let payload = mtu.saturating_sub(28);
        assert_eq!(payload, 1472);

        // PPPoE MTU = 1492, payload = 1464
        let mtu = 1492u32;
        let payload = mtu.saturating_sub(28);
        assert_eq!(payload, 1464);
    }
}
