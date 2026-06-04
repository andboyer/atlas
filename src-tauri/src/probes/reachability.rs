use crate::process_util::NoConsoleExt;
use crate::types::ReachabilityStats;
use anyhow::Result;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub async fn collect() -> Result<ReachabilityStats> {
    let gateway = default_gateway().await;

    // Run the four network probes concurrently — sequential execution previously
    // summed to ~20s+ (10-packet ping_loss alone is ~10s) which hung the UI.
    let gw_for_ping = gateway.clone();
    let (gateway_latency, internet_latency, dns_latency, packet_loss) = tokio::join!(
        async {
            match gw_for_ping {
                Some(ip) => ping(&ip, 3).await,
                None => None,
            }
        },
        ping("1.1.1.1", 3),
        dns_resolve_ms("apple.com"),
        ping_loss("1.1.1.1", 5),
    );

    Ok(ReachabilityStats {
        gateway_ip: gateway,
        gateway_latency_ms: gateway_latency,
        internet_latency_ms: internet_latency,
        dns_latency_ms: dns_latency,
        packet_loss_pct: packet_loss,
    })
}

pub async fn default_gateway() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
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
    {
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
    {
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
}

/// Average round-trip in ms over `count` probes using the system ping binary.
pub async fn ping(host: &str, count: u32) -> Option<f32> {
    let out = run_ping(host, count).await?;
    parse_ping_avg(&out)
}

pub async fn ping_loss(host: &str, count: u32) -> Option<f32> {
    let out = run_ping(host, count).await?;
    parse_ping_loss(&out)
}

async fn run_ping(host: &str, count: u32) -> Option<String> {
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
    cmd.args(["-n", &count.to_string(), "-w", "1000", host]);
    #[cfg(target_os = "macos")]
    cmd.args(["-c", &count.to_string(), "-W", "1000", host]);
    #[cfg(all(unix, not(target_os = "macos")))]
    cmd.args(["-c", &count.to_string(), "-W", "1", host]);

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
