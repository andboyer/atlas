use crate::process_util::NoConsoleExt;
use crate::types::ReachabilityStats;
use anyhow::Result;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Run the full reachability sweep. When `iface` is `Some`, the gateway is
/// resolved as the next-hop on the named interface's default route and every
/// ping is source-bound to that interface. The internet/DNS probes are still
/// iface-pinned so the operator can compare "what does this NIC see" cleanly.
/// `None` means "use whatever the kernel picks" — the historical behaviour.
pub async fn collect(iface: Option<&str>) -> Result<ReachabilityStats> {
    let iface = normalise_iface(iface);
    let gateway = default_gateway_for_iface(iface.as_deref()).await;

    // Run the four network probes concurrently — sequential execution previously
    // summed to ~20s+ (10-packet ping_loss alone is ~10s) which hung the UI.
    let gw_for_ping = gateway.clone();
    let iface_for_join = iface.clone();
    let (gateway_latency, internet_latency, dns_latency, packet_loss) = tokio::join!(
        async {
            match gw_for_ping {
                Some(ip) => ping_via(&ip, 3, iface_for_join.as_deref()).await,
                None => None,
            }
        },
        ping_via("1.1.1.1", 3, iface.as_deref()),
        dns_resolve_ms("apple.com"),
        ping_loss_via("1.1.1.1", 5, iface.as_deref()),
    );

    Ok(ReachabilityStats {
        gateway_ip: gateway,
        gateway_latency_ms: gateway_latency,
        internet_latency_ms: internet_latency,
        dns_latency_ms: dns_latency,
        packet_loss_pct: packet_loss,
    })
}

/// Trim + drop empty / "auto" so callers can pipe whatever the UI gave us.
fn normalise_iface(iface: Option<&str>) -> Option<String> {
    iface
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
        .map(str::to_string)
}

/// Kept for callers that don't yet thread a pinned NIC (discovery scan,
/// historical paths). Resolves the kernel's default-route gateway.
pub async fn default_gateway() -> Option<String> {
    default_gateway_for_iface(None).await
}

/// When `iface` is `Some(name)`, returns the next-hop gateway of the
/// default route *scoped to that interface*. Falls back to the global
/// default gateway when the iface-scoped lookup yields nothing (stale
/// picker selection, unplugged USB-Ethernet, etc.) so the call never
/// returns None just because the operator picked an idle NIC.
pub async fn default_gateway_for_iface(iface: Option<&str>) -> Option<String> {
    if let Some(name) = iface {
        if let Some(gw) = gateway_for_iface(name).await {
            return Some(gw);
        }
        tracing::debug!(
            target: "reachability",
            iface = %name,
            "iface-scoped default gateway not found, falling back to global default",
        );
    }
    global_default_gateway().await
}

#[cfg(target_os = "macos")]
async fn global_default_gateway() -> Option<String> {
    let out = Command::new("route")
        .no_console()
        .args(["-n", "get", "default"])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(rest) = line.trim().strip_prefix("gateway: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
async fn global_default_gateway() -> Option<String> {
    let out = Command::new("ip")
        .no_console()
        .args(["route", "show", "default"])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let first = s.lines().next()?;
    let mut parts = first.split_whitespace();
    loop {
        match parts.next()? {
            "via" => return parts.next().map(|s| s.to_string()),
            _ => continue,
        }
    }
}

#[cfg(target_os = "windows")]
async fn global_default_gateway() -> Option<String> {
    let out = Command::new("powershell")
        .no_console()
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "macos")]
async fn gateway_for_iface(iface: &str) -> Option<String> {
    // `-ifscope <name>` asks routed for the default route scoped to that
    // interface specifically. macOS keeps a separate default route per
    // active interface when multiple are up (Wi-Fi + Ethernet), so this
    // is the right knob — `route -n get default` alone returns whichever
    // one currently has the lowest metric.
    let out = Command::new("route")
        .no_console()
        .args(["-n", "get", "-ifscope", iface, "default"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(rest) = line.trim().strip_prefix("gateway: ") {
            let gw = rest.trim();
            if !gw.is_empty() {
                return Some(gw.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
async fn gateway_for_iface(iface: &str) -> Option<String> {
    // `ip route show default dev <name>` filters the default routes to
    // the named device. Output: `default via X.Y.Z.W dev <name> ...`.
    let out = Command::new("ip")
        .no_console()
        .args(["route", "show", "default", "dev", iface])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let first = s.lines().next()?;
    let mut parts = first.split_whitespace();
    while let Some(tok) = parts.next() {
        if tok == "via" {
            return parts.next().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "windows")]
async fn gateway_for_iface(iface: &str) -> Option<String> {
    // PowerShell quoting: callers may pass an alias with a space ("Wi-Fi
    // 2"). Embedding the value in single quotes inside the script is
    // safe as long as the alias itself contains no single quote — true
    // for every Windows InterfaceAlias the OS will accept.
    let script = format!(
        "(Get-NetRoute -InterfaceAlias '{}' -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        iface.replace('\'', "")
    );
    let out = Command::new("powershell")
        .no_console()
        .args(["-NoProfile", "-Command", &script])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Average round-trip in ms over `count` probes using the system ping binary.
pub async fn ping(host: &str, count: u32) -> Option<f32> {
    ping_via(host, count, None).await
}

pub async fn ping_loss(host: &str, count: u32) -> Option<f32> {
    ping_loss_via(host, count, None).await
}

/// Same as [`ping`] but source-bound to the named interface. The pin
/// matters whenever the operator has multiple active default routes —
/// e.g. Wi-Fi + USB-Ethernet — and wants the gateway-latency tile to
/// reflect the NIC they're troubleshooting, not whichever route happens
/// to win the kernel's metric tie-break this second.
pub async fn ping_via(host: &str, count: u32, iface: Option<&str>) -> Option<f32> {
    let out = run_ping_via(host, count, iface).await?;
    parse_ping_avg(&out)
}

pub async fn ping_loss_via(host: &str, count: u32, iface: Option<&str>) -> Option<f32> {
    let out = run_ping_via(host, count, iface).await?;
    parse_ping_loss(&out)
}

async fn run_ping_via(host: &str, count: u32, iface: Option<&str>) -> Option<String> {
    let iface = normalise_iface(iface);
    let mut cmd = Command::new("ping");
    cmd.no_console();
    // Per-platform per-packet wait. The flag means very different things:
    //   macOS  `-W 1000` → 1000 ms (per packet)
    //   Linux  `-W 1`    → 1 s     (per packet — accepts seconds only)
    //   Windows `-w 1000` → 1000 ms (per packet)
    // Mixing those up turns Linux `-W 1000` into a 1000-second wait per
    // packet which silently caps probes at the outer 15s timeout and makes
    // every reachability sample look broken.
    #[cfg(target_os = "windows")]
    cmd.args(["-n", &count.to_string(), "-w", "1000"]);
    #[cfg(target_os = "macos")]
    cmd.args(["-c", &count.to_string(), "-W", "1000"]);
    #[cfg(all(unix, not(target_os = "macos")))]
    cmd.args(["-c", &count.to_string(), "-W", "1"]);

    // Pin to the chosen NIC. The flag and lookup approach differ per OS:
    //   Linux   `-I <name>` — iputils-ping binds to the iface by name.
    //   macOS   `-S <ipv4>` — bind source addr; `-b` is for multicast only.
    //   Windows `-S <ipv4>` — same source-addr knob `tracert` uses.
    // macOS / Windows both need the iface's IPv4 resolved via the existing
    // `probes::iface::find_by_name` helper; if the picker selection is
    // stale or the NIC has no IPv4 yet (DHCP racing the scan), we silently
    // omit the pin and let the kernel pick the default route. That mirrors
    // how traceroute already tolerates stale picker selections.
    if let Some(ref name) = iface {
        #[cfg(target_os = "linux")]
        {
            cmd.args(["-I", name.as_str()]);
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            if let Some(info) = crate::probes::iface::find_by_name(name) {
                if let Some(ip) = info.ipv4.as_deref() {
                    cmd.args(["-S", ip]);
                } else {
                    tracing::debug!(
                        target: "reachability",
                        iface = %name,
                        "iface has no IPv4 yet; ping running on default route",
                    );
                }
            } else {
                tracing::debug!(
                    target: "reachability",
                    iface = %name,
                    "iface not found; ping running on default route",
                );
            }
        }
    }

    cmd.arg(host);

    let out = timeout(Duration::from_secs(15), cmd.output())
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse_ping_avg(s: &str) -> Option<f32> {
    // macOS:           round-trip min/avg/max/stddev = 1.234/5.678/9.012/0.345 ms
    // Linux (iputils): rtt min/avg/max/mdev = 1.234/5.678/9.012/0.345 ms
    // Windows:         Average = 5ms (in milliseconds)
    if let Some(line) = s.lines().find(|l| l.contains("min/avg/max")) {
        if let Some(eq) = line.find('=') {
            let rest = line[eq + 1..].trim();
            let nums = rest.split_whitespace().next().unwrap_or("");
            let mut parts = nums.split('/');
            let _min = parts.next();
            if let Some(avg) = parts.next() {
                return avg.trim().parse::<f32>().ok();
            }
        }
    }
    if let Some(line) = s.lines().find(|l| l.contains("Average")) {
        let digits: String = line
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        return digits.parse::<f32>().ok();
    }
    None
}

fn parse_ping_loss(s: &str) -> Option<f32> {
    // macOS/Linux: "3 packets transmitted, 3 packets received, 0.0% packet loss"
    // Windows:     "Lost = 0 (0% loss)"
    if let Some(line) = s.lines().find(|l| l.contains("packet loss")) {
        let pct: String = line
            .split(',')
            .find(|p| p.contains("packet loss"))?
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        return pct.parse::<f32>().ok();
    }
    if let Some(line) = s.lines().find(|l| l.contains("Lost =")) {
        let after = line.split("Lost =").nth(1)?;
        let pct: String = after
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .skip_while(|c| c.is_ascii_digit() || *c == ' ' || *c == '(')
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        return pct.parse::<f32>().ok();
    }
    None
}

pub async fn dns_resolve_ms(host: &str) -> Option<f32> {
    let host = host.to_string();
    let started = Instant::now();
    // Bound to ~5s — system to_socket_addrs has no native timeout and can hang
    // on a flaky resolver, which would block the whole reachability join.
    let resolved = timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let addr = format!("{host}:443");
            addr.to_socket_addrs()
                .ok()
                .and_then(|mut it| it.next())
                .is_some()
        }),
    )
    .await
    .ok()?
    .ok()?;
    if resolved {
        Some(started.elapsed().as_secs_f32() * 1000.0)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_ping_avg() {
        let sample = "round-trip min/avg/max/stddev = 1.234/5.678/9.012/0.345 ms";
        assert_eq!(parse_ping_avg(sample), Some(5.678));
    }

    #[test]
    fn parses_unix_ping_loss() {
        let sample = "3 packets transmitted, 3 packets received, 0.0% packet loss\n";
        assert_eq!(parse_ping_loss(sample), Some(0.0));
    }

    #[test]
    fn parses_iputils_ping_avg() {
        let sample = "rtt min/avg/max/mdev = 1.234/5.678/9.012/0.345 ms";
        assert_eq!(parse_ping_avg(sample), Some(5.678));
    }
}
