//! IP-layer route trace from this host to an internet target. Shells
//! out to the platform's native `traceroute` / `tracert` binary because
//! issuing the raw ICMP / UDP probes ourselves would require either
//! `cap_net_raw` (Linux), `setuid` (macOS) or `Administrator` (Windows)
//! — the system binaries are already set up for that, and we'd rather
//! pay the fork+exec cost than ship a privileged helper.
//!
//! **Why this can't show L2 switches.** A switch forwards Ethernet
//! frames at L2 without decrementing the IP TTL, so it's invisible to
//! every form of IP traceroute by design. The only switch we can ever
//! identify is the directly-attached one, via LLDP / CDP (see
//! `probes::lldp` — surfaced as a deep probe in the AV tab). Anything
//! beyond that is a fundamental limit of the OSI model, not a missing
//! feature.

use crate::process_util::NoConsoleExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// One hop in an IP-layer route trace. `idx` is the TTL value used to
/// elicit the response (1-based, matching every `traceroute` / `tracert`
/// implementation). `ip` / `hostname` may both be `None` when every probe
/// at this TTL timed out — that hop is then a black-hole router (common
/// for ISP backbones that rate-limit ICMP-time-exceeded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub idx: u8,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f32>,
    /// `true` when this hop did not respond within the per-hop wait
    /// budget (`* * *` line on Unix, `Request timed out.` on Windows).
    /// Distinct from `ip == None && rtt_ms == None` only in intent —
    /// callers can show a different glyph for a known-silent hop vs.
    /// a parser fallback.
    pub timed_out: bool,
}

/// Probe configuration. Hard caps every dimension so the function can
/// never exceed `(per_hop_wait * max_hops * queries_per_hop) + 2s`
/// of wall time regardless of network conditions.
#[derive(Debug, Clone, Copy)]
pub struct TraceConfig {
    pub max_hops: u8,
    pub per_hop_wait_secs: u8,
    pub queries_per_hop: u8,
}

impl Default for TraceConfig {
    fn default() -> Self {
        // 12 hops × 1s × 1 probe = ~12s worst case. Most real-world
        // traces to 1.1.1.1 complete in 2-4 hops × 50-100ms each.
        Self {
            max_hops: 12,
            per_hop_wait_secs: 1,
            queries_per_hop: 1,
        }
    }
}

/// Run a bounded traceroute to `target` and parse the hops. Always
/// returns; on any failure (binary missing, spawn error, kernel error,
/// total timeout) returns an empty vec so the caller can show a clear
/// "no hops" state without an error code path.
pub async fn traceroute(target: &str, cfg: TraceConfig) -> Vec<TraceHop> {
    let overall = Duration::from_secs(
        (cfg.per_hop_wait_secs as u64) * (cfg.max_hops as u64) * (cfg.queries_per_hop as u64) + 4,
    );

    let mut cmd = Command::new(binary());
    cmd.no_console();
    apply_args(&mut cmd, target, &cfg);

    let out = match timeout(overall, cmd.output()).await {
        Ok(Ok(o)) => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse(&stdout)
}

#[cfg(target_os = "windows")]
fn binary() -> &'static str {
    "tracert"
}

#[cfg(not(target_os = "windows"))]
fn binary() -> &'static str {
    "traceroute"
}

#[cfg(target_os = "windows")]
fn apply_args(cmd: &mut Command, target: &str, cfg: &TraceConfig) {
    // `tracert` per-hop timeout is in ms; no -q flag (always 3 probes).
    let wait_ms = (cfg.per_hop_wait_secs as u32) * 1000;
    cmd.args([
        "-d",
        "-h",
        &cfg.max_hops.to_string(),
        "-w",
        &wait_ms.to_string(),
        target,
    ]);
}

#[cfg(not(target_os = "windows"))]
fn apply_args(cmd: &mut Command, target: &str, cfg: &TraceConfig) {
    cmd.args([
        "-n",
        "-m",
        &cfg.max_hops.to_string(),
        "-w",
        &cfg.per_hop_wait_secs.to_string(),
        "-q",
        &cfg.queries_per_hop.to_string(),
        target,
    ]);
}

/// Cross-platform parser. Each `traceroute` / `tracert` flavour has its
/// own format but they all share two invariants we exploit:
///   1. The first non-whitespace token on every hop line is the hop
///      index (1-based integer).
///   2. The IP appears later on the same line in either bare or
///      parenthesised form, OR the entire line is some flavour of
///      "timed out" / "* * *" placeholder.
pub fn parse(text: &str) -> Vec<TraceHop> {
    let mut out: Vec<TraceHop> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let first = match parts.next() {
            Some(p) => p,
            None => continue,
        };
        let idx: u8 = match first.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Collect the remainder for deeper parsing. `tracert`'s "Request
        // timed out." spans multiple tokens so we re-stringify.
        let rest = line[first.len()..].trim();

        // Timed-out hop detection (Unix: `* * *` / `*`; Windows:
        // "Request timed out."). When at least one probe replied
        // we still want the IP, so only treat the hop as timed-out
        // when no IP appears anywhere on the line.
        let ip_opt = first_ipv4(rest);
        if ip_opt.is_none() {
            out.push(TraceHop {
                idx,
                ip: None,
                hostname: None,
                rtt_ms: None,
                timed_out: true,
            });
            continue;
        }

        let rtt = first_ms(rest);
        out.push(TraceHop {
            idx,
            ip: ip_opt,
            hostname: None,
            rtt_ms: rtt,
            timed_out: false,
        });
    }
    out
}

/// Find the first IPv4 literal in a line. Tolerates parenthesised form
/// (`(10.0.0.1)`) and trailing punctuation.
fn first_ipv4(s: &str) -> Option<String> {
    for tok in s.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if tok.is_empty() {
            continue;
        }
        if tok.chars().filter(|c| *c == '.').count() != 3 {
            continue;
        }
        let mut ok = true;
        for octet in tok.split('.') {
            match octet.parse::<u16>() {
                Ok(n) if n <= 255 && !octet.is_empty() => {}
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Some(tok.to_string());
        }
    }
    None
}

/// Find the first round-trip time in a line, in milliseconds. Handles:
///   - `1.234 ms`  (Unix, with `-q 1`)
///   - `1 ms`      (Windows; tracert reports integer ms)
///   - `<1 ms`     (Windows when RTT < 1 ms — treated as 0.5 ms)
fn first_ms(s: &str) -> Option<f32> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for "ms" anchored to a number to the left.
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"ms" {
            // Walk backwards to the start of the number.
            let mut j = i;
            while j > 0 && bytes[j - 1] == b' ' {
                j -= 1;
            }
            let end = j;
            while j > 0 {
                let c = bytes[j - 1];
                if c.is_ascii_digit() || c == b'.' || c == b'<' {
                    j -= 1;
                } else {
                    break;
                }
            }
            if j < end {
                let num = std::str::from_utf8(&bytes[j..end]).ok()?;
                if let Some(stripped) = num.strip_prefix('<') {
                    return stripped.trim().parse::<f32>().ok().map(|v| v.min(0.5));
                }
                if let Ok(v) = num.trim().parse::<f32>() {
                    return Some(v);
                }
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bsd_traceroute_with_n_flag() {
        let sample = "traceroute to 1.1.1.1 (1.1.1.1), 64 hops max, 52 byte packets\n\
                       1  10.0.0.1  1.234 ms\n\
                       2  * * *\n\
                       3  192.168.1.1  2.345 ms\n";
        let hops = parse(sample);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].idx, 1);
        assert_eq!(hops[0].ip.as_deref(), Some("10.0.0.1"));
        assert!((hops[0].rtt_ms.unwrap() - 1.234).abs() < 0.001);
        assert!(!hops[0].timed_out);
        assert_eq!(hops[1].idx, 2);
        assert!(hops[1].ip.is_none());
        assert!(hops[1].timed_out);
        assert_eq!(hops[2].ip.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parses_windows_tracert() {
        let sample = "\
Tracing route to 1.1.1.1 over a maximum of 30 hops\n\
\n\
  1     1 ms     1 ms     1 ms  10.0.0.1\n\
  2     *        *        *     Request timed out.\n\
  3     2 ms     2 ms     2 ms  192.168.1.1\n\
\n\
Trace complete.\n";
        let hops = parse(sample);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(hops[0].rtt_ms, Some(1.0));
        assert!(hops[1].timed_out);
        assert_eq!(hops[2].ip.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parses_windows_sub_ms() {
        let sample = "  1     <1 ms    <1 ms    <1 ms  10.0.0.1\n";
        let hops = parse(sample);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].rtt_ms, Some(0.5));
    }

    #[test]
    fn parses_linux_traceroute_parenthesised_ip() {
        // Some iputils builds print "10.0.0.1 (10.0.0.1)" without -n.
        let sample = " 1  10.0.0.1 (10.0.0.1)  1.234 ms\n";
        let hops = parse(sample);
        assert_eq!(hops[0].ip.as_deref(), Some("10.0.0.1"));
        assert!((hops[0].rtt_ms.unwrap() - 1.234).abs() < 0.001);
    }

    #[test]
    fn ignores_non_hop_lines() {
        let sample = "traceroute: Warning: 1.1.1.1 has multiple addresses\n\
                       header line we don't care about\n\
                       1  10.0.0.1  1.234 ms\n";
        let hops = parse(sample);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].idx, 1);
    }
}
