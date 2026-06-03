//! Per-NIC link audit: speed, duplex, EEE (802.3az), flow-control, MTU.
//!
//! All checks are unprivileged and OS-specific. The verdict surfaces
//! anything that would degrade Dante/AES67 performance:
//!   * EEE enabled — Dante hates EEE link aggressively pausing the PHY
//!   * half-duplex — fatal for any AVB/PTP-style traffic
//!   * sub-gigabit — Dante's minimum spec is 100 Mb/s but >100 channels
//!     needs gigabit; we warn anything below 1 Gb/s
//!   * flow-control on (per Audinate's official guidance — Dante uses
//!     QoS, not pause frames)
//!
//! Cross-platform implementation:
//!   * macOS — `ifconfig <iface>` (media line); `system_profiler` for MTU.
//!     EEE state isn't queryable on macOS via any public API — left as None.
//!   * Linux — `ethtool <iface>` + `ethtool --show-eee <iface>` +
//!     `ethtool --show-pause <iface>`.
//!   * Windows — `Get-NetAdapter -Name <iface> | Format-List …` for speed/
//!     duplex/MTU; `Get-NetAdapterAdvancedProperty -Name <iface>` greps
//!     for "Energy Efficient Ethernet" + "Flow Control" properties.

use std::process::Command;

use crate::types::LinkAuditResult;

/// Synchronous blocking entrypoint — call from `tokio::task::spawn_blocking`.
pub fn run_blocking(iface: &str) -> LinkAuditResult {
    if iface.is_empty() {
        return LinkAuditResult {
            iface: iface.to_string(),
            link_speed_mbps: None,
            duplex: None,
            eee_enabled: None,
            flow_control_rx: None,
            flow_control_tx: None,
            mtu: None,
            verdict: "error".to_string(),
            issues: Vec::new(),
            error: Some("no interface specified".to_string()),
        };
    }

    let mut result = LinkAuditResult {
        iface: iface.to_string(),
        link_speed_mbps: None,
        duplex: None,
        eee_enabled: None,
        flow_control_rx: None,
        flow_control_tx: None,
        mtu: None,
        verdict: "unknown".to_string(),
        issues: Vec::new(),
        error: None,
    };

    #[cfg(target_os = "macos")]
    populate_macos(iface, &mut result);
    #[cfg(target_os = "linux")]
    populate_linux(iface, &mut result);
    #[cfg(target_os = "windows")]
    populate_windows(iface, &mut result);

    compute_verdict(&mut result);
    result
}

fn compute_verdict(r: &mut LinkAuditResult) {
    let mut issues: Vec<String> = Vec::new();
    if let Some(speed) = r.link_speed_mbps {
        if speed < 1000 {
            issues.push(format!("Sub-gigabit link ({speed} Mb/s)"));
        }
    }
    if let Some(d) = r.duplex.as_deref() {
        if d == "half" {
            issues.push("Half-duplex link".to_string());
        }
    }
    if let Some(true) = r.eee_enabled {
        issues.push("Energy Efficient Ethernet (802.3az) is enabled".to_string());
    }
    if let Some(true) = r.flow_control_rx {
        issues.push("Flow control (RX) is enabled".to_string());
    }
    if let Some(true) = r.flow_control_tx {
        issues.push("Flow control (TX) is enabled".to_string());
    }
    let known_anything = r.link_speed_mbps.is_some()
        || r.duplex.is_some()
        || r.eee_enabled.is_some()
        || r.flow_control_rx.is_some()
        || r.flow_control_tx.is_some()
        || r.mtu.is_some();
    r.verdict = if !known_anything {
        "unknown".to_string()
    } else if issues.is_empty() {
        "ready_for_av".to_string()
    } else {
        "needs_attention".to_string()
    };
    r.issues = issues;
}

#[cfg(target_os = "macos")]
fn populate_macos(iface: &str, r: &mut LinkAuditResult) {
    // ifconfig <iface> — line of interest:
    //   media: autoselect (1000baseT <full-duplex,flow-control,energy-efficient-ethernet>)
    let out = Command::new("ifconfig").arg(iface).output();
    if let Ok(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("media: ") {
                parse_macos_media(rest, r);
            } else if let Some(rest) = l.strip_prefix("mtu ") {
                if let Ok(m) = rest.trim().parse::<u32>() {
                    r.mtu = Some(m);
                }
            } else if l.contains("mtu ") {
                // first ifconfig line, e.g. "en0: flags=8863<UP,...> mtu 1500"
                if let Some(idx) = l.find("mtu ") {
                    let tail = &l[idx + 4..];
                    let num: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(m) = num.parse::<u32>() {
                        r.mtu = Some(m);
                    }
                }
            }
        }
    }
    // EEE is queryable via Apple's private SPI only; we leave it as None.
}

#[cfg(target_os = "macos")]
fn parse_macos_media(media_line: &str, r: &mut LinkAuditResult) {
    // Examples:
    //   autoselect (1000baseT <full-duplex,flow-control,energy-efficient-ethernet>)
    //   autoselect (100baseTX <full-duplex>)
    //   autoselect (none)
    let lower = media_line.to_ascii_lowercase();
    if let Some(speed) = parse_macos_speed(&lower) {
        r.link_speed_mbps = Some(speed);
    }
    if lower.contains("full-duplex") {
        r.duplex = Some("full".to_string());
    } else if lower.contains("half-duplex") {
        r.duplex = Some("half".to_string());
    }
    if lower.contains("energy-efficient-ethernet") {
        r.eee_enabled = Some(true);
    }
    if lower.contains("flow-control") {
        // macOS doesn't split rx/tx in `ifconfig`; report symmetric on.
        r.flow_control_rx = Some(true);
        r.flow_control_tx = Some(true);
    }
}

#[cfg(target_os = "macos")]
fn parse_macos_speed(lower_media: &str) -> Option<u32> {
    // Match patterns like "10gbaseT", "1000baseT", "100baseTX", "10baseT".
    for token in lower_media.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.ends_with("baset") || token.ends_with("basetx") || token.ends_with("baset1") {
            let num: String = token.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num.parse::<u32>() {
                if let Some(rest) = token.strip_prefix(&num) {
                    if rest.starts_with("g") {
                        return Some(n * 1000);
                    }
                }
                return Some(n);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn populate_linux(iface: &str, r: &mut LinkAuditResult) {
    if let Ok(out) = Command::new("ethtool").arg(iface).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("Speed: ") {
                let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = num.parse::<u32>() {
                    r.link_speed_mbps = Some(n);
                }
            } else if let Some(rest) = l.strip_prefix("Duplex: ") {
                let lower = rest.to_ascii_lowercase();
                if lower.contains("full") {
                    r.duplex = Some("full".to_string());
                } else if lower.contains("half") {
                    r.duplex = Some("half".to_string());
                }
            } else if let Some(rest) = l.strip_prefix("MTU: ") {
                if let Ok(m) = rest.trim().parse::<u32>() {
                    r.mtu = Some(m);
                }
            }
        }
    }
    if let Ok(out) = Command::new("ethtool").args(["--show-eee", iface]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("EEE status: ") {
                let lower = rest.to_ascii_lowercase();
                if lower.starts_with("enabled") || lower.starts_with("active") {
                    r.eee_enabled = Some(true);
                } else if lower.starts_with("disabled") || lower.starts_with("not supported") {
                    r.eee_enabled = Some(false);
                }
            }
        }
    }
    if let Ok(out) = Command::new("ethtool")
        .args(["--show-pause", iface])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("RX: ") {
                r.flow_control_rx = Some(rest.trim().eq_ignore_ascii_case("on"));
            } else if let Some(rest) = l.strip_prefix("TX: ") {
                r.flow_control_tx = Some(rest.trim().eq_ignore_ascii_case("on"));
            }
        }
    }
    // MTU fallback via /sys.
    if r.mtu.is_none() {
        if let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu")) {
            if let Ok(m) = s.trim().parse::<u32>() {
                r.mtu = Some(m);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn populate_windows(iface: &str, r: &mut LinkAuditResult) {
    use crate::process_util::NoConsoleExt;
    // Get-NetAdapter is keyed by Name (the friendly name, e.g. "Ethernet 2")
    // OR by InterfaceDescription. The iface picker on Windows supplies the
    // adapter's Name field (matches NetworkInterfaceInfo.name), so use that.
    //
    // We request CSV with explicit columns so the parse is locale-agnostic
    // (Get-NetAdapter | Format-List spelling varies by Windows locale).
    let ps = format!(
        "Get-NetAdapter -Name '{iface}' -ErrorAction SilentlyContinue | \
         Select-Object LinkSpeed,FullDuplex,MtuSize,Status | ConvertTo-Csv -NoTypeInformation"
    );
    if let Ok(out) = Command::new("powershell.exe")
        .no_console()
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut lines = s.lines();
        if let (Some(header), Some(row)) = (lines.next(), lines.next()) {
            let cols: Vec<&str> = header.split(',').map(strip_quotes).collect();
            let vals: Vec<&str> = csv_split(row);
            for (k, v) in cols.iter().zip(vals.iter()) {
                let v = v.trim();
                match k.to_ascii_lowercase().as_str() {
                    "linkspeed" => {
                        // Format: "1 Gbps" / "100 Mbps" / "10 Gbps"
                        if let Some(n) = parse_windows_speed(v) {
                            r.link_speed_mbps = Some(n);
                        }
                    }
                    "fullduplex" => {
                        let lower = v.to_ascii_lowercase();
                        if lower == "true" {
                            r.duplex = Some("full".to_string());
                        } else if lower == "false" {
                            r.duplex = Some("half".to_string());
                        }
                    }
                    "mtusize" => {
                        if let Ok(m) = v.parse::<u32>() {
                            r.mtu = Some(m);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Advanced properties: EEE + flow control. Names vary by driver
    // ("Energy Efficient Ethernet", "Energy-Efficient Ethernet",
    // "Advanced EEE", "*EEE"). Grep both DisplayName and RegistryKeyword.
    let ps = format!(
        "Get-NetAdapterAdvancedProperty -Name '{iface}' -ErrorAction SilentlyContinue | \
         Select-Object DisplayName,RegistryKeyword,DisplayValue,RegistryValue | \
         ConvertTo-Csv -NoTypeInformation"
    );
    if let Ok(out) = Command::new("powershell.exe")
        .no_console()
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut lines = s.lines();
        let _ = lines.next(); // header
        for row in lines {
            let cells: Vec<&str> = csv_split(row);
            if cells.len() < 3 {
                continue;
            }
            let display = cells[0].to_ascii_lowercase();
            let keyword = cells[1].to_ascii_lowercase();
            let value = cells[2].to_ascii_lowercase();
            let on = !(value == "disabled" || value == "off" || value == "0");

            if display.contains("energy") || keyword.contains("eee") {
                r.eee_enabled = Some(on);
            }
            // Many drivers expose a single "Flow Control" toggle (rx+tx together).
            if display.contains("flow control") || keyword.contains("flowcontrol") {
                // Drivers usually expose values like "Rx & Tx Enabled" / "Tx Enabled" / "Rx Enabled" / "Disabled".
                if value.contains("disabled") {
                    r.flow_control_rx = Some(false);
                    r.flow_control_tx = Some(false);
                } else {
                    r.flow_control_rx = Some(value.contains("rx") || value.contains("enabled"));
                    r.flow_control_tx = Some(value.contains("tx") || value.contains("enabled"));
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn parse_windows_speed(s: &str) -> Option<u32> {
    let lower = s.to_ascii_lowercase();
    let num: String = lower.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let n: f64 = num.parse().ok()?;
    if lower.contains("gbps") || lower.contains("gb/s") {
        Some((n * 1000.0) as u32)
    } else if lower.contains("mbps") || lower.contains("mb/s") {
        Some(n as u32)
    } else if lower.contains("kbps") || lower.contains("kb/s") {
        Some((n / 1000.0).max(1.0) as u32)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn strip_quotes(s: &str) -> &str {
    s.trim_matches('"')
}

#[cfg(target_os = "windows")]
fn csv_split(line: &str) -> Vec<&str> {
    // Minimal CSV splitter — PowerShell ConvertTo-Csv quotes every field
    // and double-doubles embedded quotes, which is fine for our use
    // (none of the values we read contain commas).
    let mut out = Vec::new();
    let mut start = 0usize;
    let bytes = line.as_bytes();
    let mut in_quote = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            in_quote = !in_quote;
        } else if c == b',' && !in_quote {
            out.push(line[start..i].trim_matches('"'));
            start = i + 1;
        }
        i += 1;
    }
    out.push(line[start..].trim_matches('"'));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_unknown_when_nothing_known() {
        let mut r = LinkAuditResult {
            iface: "x".into(),
            link_speed_mbps: None,
            duplex: None,
            eee_enabled: None,
            flow_control_rx: None,
            flow_control_tx: None,
            mtu: None,
            verdict: "x".into(),
            issues: vec![],
            error: None,
        };
        compute_verdict(&mut r);
        assert_eq!(r.verdict, "unknown");
        assert!(r.issues.is_empty());
    }

    #[test]
    fn verdict_ready_when_clean() {
        let mut r = LinkAuditResult {
            iface: "en0".into(),
            link_speed_mbps: Some(1000),
            duplex: Some("full".into()),
            eee_enabled: Some(false),
            flow_control_rx: Some(false),
            flow_control_tx: Some(false),
            mtu: Some(1500),
            verdict: "x".into(),
            issues: vec![],
            error: None,
        };
        compute_verdict(&mut r);
        assert_eq!(r.verdict, "ready_for_av");
    }

    #[test]
    fn verdict_attention_when_eee_on() {
        let mut r = LinkAuditResult {
            iface: "en0".into(),
            link_speed_mbps: Some(1000),
            duplex: Some("full".into()),
            eee_enabled: Some(true),
            flow_control_rx: Some(false),
            flow_control_tx: Some(false),
            mtu: Some(1500),
            verdict: "x".into(),
            issues: vec![],
            error: None,
        };
        compute_verdict(&mut r);
        assert_eq!(r.verdict, "needs_attention");
        assert!(r.issues.iter().any(|i| i.contains("Energy")));
    }

    #[test]
    fn verdict_attention_on_subgigabit() {
        let mut r = LinkAuditResult {
            iface: "en0".into(),
            link_speed_mbps: Some(100),
            duplex: Some("full".into()),
            eee_enabled: Some(false),
            flow_control_rx: Some(false),
            flow_control_tx: Some(false),
            mtu: Some(1500),
            verdict: "x".into(),
            issues: vec![],
            error: None,
        };
        compute_verdict(&mut r);
        assert_eq!(r.verdict, "needs_attention");
        assert!(r.issues.iter().any(|i| i.contains("Sub-gigabit")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_media_gigabit_full() {
        let mut r = LinkAuditResult {
            iface: "en0".into(),
            link_speed_mbps: None,
            duplex: None,
            eee_enabled: None,
            flow_control_rx: None,
            flow_control_tx: None,
            mtu: None,
            verdict: "unknown".into(),
            issues: vec![],
            error: None,
        };
        parse_macos_media(
            "autoselect (1000baseT <full-duplex,flow-control,energy-efficient-ethernet>)",
            &mut r,
        );
        assert_eq!(r.link_speed_mbps, Some(1000));
        assert_eq!(r.duplex.as_deref(), Some("full"));
        assert_eq!(r.eee_enabled, Some(true));
        assert_eq!(r.flow_control_rx, Some(true));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parses_windows_speed_strings() {
        assert_eq!(parse_windows_speed("1 Gbps"), Some(1000));
        assert_eq!(parse_windows_speed("100 Mbps"), Some(100));
        assert_eq!(parse_windows_speed("10 Gbps"), Some(10000));
        assert_eq!(parse_windows_speed("foo"), None);
    }
}
