//! Wi-Fi system event subscriber.
//!
//! On macOS, taps `log stream` filtered to wifid/airportd/CoreWLAN to surface
//! roams, scans, association events, deauths, etc. Each event is classified
//! and pushed into a small ring buffer + emitted as a `wifi:event` Tauri
//! event so the frontend can overlay them on the live telemetry chart.
//!
//! On non-macOS platforms the producer task currently no-ops (returns
//! immediately); the ring stays empty and the frontend just renders no
//! markers.
//!
//! Why `log stream` and not a private CoreWLAN binding: zero entitlement
//! requirements, no codesigning headaches, and the same predicate works for
//! every macOS release since 10.12.

use crate::types::WifiEvent;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

pub const RING_CAPACITY: usize = 500;

pub type EventRing = Arc<RwLock<VecDeque<WifiEvent>>>;

pub struct WifiEventsHandle {
    pub running: Arc<AtomicBool>,
    pub ring: EventRing,
}

impl WifiEventsHandle {
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub fn start(app: AppHandle) -> WifiEventsHandle {
    let running = Arc::new(AtomicBool::new(true));
    let ring: EventRing = Arc::new(RwLock::new(VecDeque::with_capacity(RING_CAPACITY)));

    #[cfg(target_os = "macos")]
    spawn_macos_log_stream(app, Arc::clone(&ring), Arc::clone(&running));

    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        tracing::debug!(target: "wifi_events", "wifi event subscriber is macOS-only (no-op on this platform)");
    }

    WifiEventsHandle { running, ring }
}

#[cfg(target_os = "macos")]
fn spawn_macos_log_stream(app: AppHandle, ring: EventRing, running: Arc<AtomicBool>) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;
    use std::process::Stdio;

    tokio::spawn(async move {
        // Filter to the Wi-Fi-relevant subsystems and process images. Predicate
        // is NSPredicate syntax per `man log`; OR-chain keeps it cheap.
        let predicate = "subsystem CONTAINS \"com.apple.wifi\" \
                         OR subsystem CONTAINS \"com.apple.coreWLAN\" \
                         OR subsystem CONTAINS \"com.apple.WiFiVelocity\" \
                         OR processImagePath CONTAINS \"wifid\" \
                         OR processImagePath CONTAINS \"airportd\" \
                         OR processImagePath CONTAINS \"WiFiAgent\"";

        let mut child = match Command::new("log")
            .args([
                "stream",
                "--style", "ndjson",
                "--level", "info",
                "--predicate", predicate,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "wifi_events", error = %e, "could not spawn `log stream` (Wi-Fi event overlay disabled)");
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                tracing::warn!(target: "wifi_events", "no stdout on `log stream` child");
                return;
            }
        };
        tracing::info!(target: "wifi_events", "wifi event subscriber started");

        let mut lines = BufReader::new(stdout).lines();
        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                Ok(None) => {
                    tracing::debug!(target: "wifi_events", "log stream closed; exiting");
                    break;
                }
                Err(e) => {
                    tracing::debug!(target: "wifi_events", error = %e, "log stream read failed; exiting");
                    break;
                }
            };

            if line.is_empty() || line.starts_with('[') {
                // `log stream` prepends a `[` array literal for ndjson; skip it.
                continue;
            }

            let event = match parse_log_line(&line) {
                Some(e) => e,
                None => continue,
            };

            {
                let mut r = ring.write();
                if r.len() == RING_CAPACITY {
                    r.pop_front();
                }
                r.push_back(event.clone());
            }

            if let Err(e) = app.emit("wifi:event", &event) {
                tracing::debug!(target: "wifi_events", error = %e, "emit wifi:event failed");
            }
        }

        let _ = child.kill().await;
        tracing::info!(target: "wifi_events", "wifi event subscriber stopped");
    });
}

#[cfg(target_os = "macos")]
fn parse_log_line(line: &str) -> Option<WifiEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let message = v
        .get("eventMessage")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if message.is_empty() {
        return None;
    }
    let subsystem = v
        .get("subsystem")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let process = v
        .get("processImagePath")
        .and_then(|x| x.as_str())
        .and_then(|p| p.rsplit('/').next())
        .map(|s| s.to_string());

    // Drop super-noisy lines that don't carry diagnostic value.
    let lower = message.to_lowercase();
    if lower.contains("debug") && message.len() < 40 {
        return None;
    }

    let kind = classify(&lower);
    if kind == "ignore" {
        return None;
    }

    let bssid = extract_bssid(&message);
    let ssid = extract_ssid(&message);
    let rssi_dbm = extract_rssi(&message);

    Some(WifiEvent {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        kind: kind.to_string(),
        subsystem,
        process,
        message,
        bssid,
        ssid,
        rssi_dbm,
    })
}

#[cfg(target_os = "macos")]
fn classify(lower: &str) -> &'static str {
    if lower.contains("roam") {
        "roam"
    } else if lower.contains("disassoc") {
        "disassoc"
    } else if lower.contains("deauth") {
        "deauth"
    } else if lower.contains("associat") {
        "assoc"
    } else if lower.contains("auth") && !lower.contains("authentic") {
        "auth"
    } else if lower.contains("scan") {
        "scan"
    } else if lower.contains("power")
        || lower.contains("sleep")
        || lower.contains("wake")
    {
        "power"
    } else if lower.contains("kernel") || lower.contains("driver") {
        "kernel"
    } else if lower.contains("ssid") || lower.contains("bssid") || lower.contains("rssi") {
        "other"
    } else {
        // Most low-signal messages we want to drop entirely.
        "ignore"
    }
}

#[cfg(target_os = "macos")]
fn extract_bssid(message: &str) -> Option<String> {
    // 6-octet MAC, colon- or dash-delimited. The macOS log stream contains
    // multi-byte unicode (e.g. `…`), so we MUST iterate by char_indices and
    // only consider ASCII starting points — slicing &message[i..i+17] with a
    // raw byte index would land inside a multi-byte char and panic.
    let bytes = message.as_bytes();
    let len = bytes.len();
    for (i, ch) in message.char_indices() {
        if !ch.is_ascii() {
            continue;
        }
        if i + 17 > len {
            break;
        }
        // Bytes [i..i+17] are guaranteed ASCII only if every byte in the
        // window is < 0x80. Cheap check first.
        if !bytes[i..i + 17].iter().all(|b| b.is_ascii()) {
            continue;
        }
        let win = &message[i..i + 17];
        let win_bytes = win.as_bytes();
        let mut ok = true;
        for (j, b) in win_bytes.iter().enumerate() {
            let sep = matches!(j, 2 | 5 | 8 | 11 | 14);
            if sep {
                if *b != b':' && *b != b'-' {
                    ok = false;
                    break;
                }
            } else if !b.is_ascii_hexdigit() {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(win.to_string());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn extract_ssid(message: &str) -> Option<String> {
    // Look for patterns like `SSID=foo`, `SSID "foo"`, or `ssid: foo`.
    let lower = message.to_lowercase();
    if let Some(idx) = lower.find("ssid") {
        let rest = &message[idx + 4..];
        // Skip punctuation/whitespace.
        let rest = rest.trim_start_matches([' ', ':', '=', '"', '\'']);
        // Take until next quote or whitespace.
        let end = rest
            .find(|c: char| c == '"' || c == '\'' || c == ',' || c == '\n')
            .unwrap_or(rest.len());
        let candidate = rest[..end].trim();
        if !candidate.is_empty() && candidate.len() <= 64 {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn extract_rssi(message: &str) -> Option<i32> {
    // Pattern: `RSSI=-67` or `rssi: -67` or `-67 dBm`.
    let lower = message.to_lowercase();
    if let Some(idx) = lower.find("rssi") {
        let rest = &message[idx + 4..];
        let rest = rest.trim_start_matches([' ', ':', '=']);
        let token: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        if let Ok(v) = token.parse::<i32>() {
            if (-120..=0).contains(&v) {
                return Some(v);
            }
        }
    }
    // Fallback: look for `-XX dBm`.
    if let Some(idx) = lower.find("dbm") {
        let prefix = &message[..idx];
        let token: String = prefix
            .chars()
            .rev()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        let token: String = token.chars().rev().collect();
        if let Ok(v) = token.parse::<i32>() {
            if (-120..=0).contains(&v) {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    #[test]
    fn classify_roam() {
        assert_eq!(classify("apple80211 roaming from foo to bar"), "roam");
    }

    #[test]
    fn classify_scan() {
        assert_eq!(classify("starting scan request"), "scan");
    }

    #[test]
    fn classify_ignore() {
        assert_eq!(classify("hello world"), "ignore");
    }

    #[test]
    fn parses_bssid_colon() {
        assert_eq!(
            extract_bssid("roamed to AA:BB:CC:11:22:33 (great)"),
            Some("AA:BB:CC:11:22:33".to_string())
        );
    }

    #[test]
    fn parses_bssid_dash() {
        assert_eq!(
            extract_bssid("BSSID=aa-bb-cc-dd-ee-ff"),
            Some("aa-bb-cc-dd-ee-ff".to_string())
        );
    }

    #[test]
    fn parses_rssi() {
        assert_eq!(extract_rssi("connected RSSI=-67 dBm"), Some(-67));
        assert_eq!(extract_rssi("level -82 dBm noise -95"), Some(-82));
        assert_eq!(extract_rssi("rssi: -55"), Some(-55));
    }

    #[test]
    fn parses_ssid_quoted() {
        assert_eq!(
            extract_ssid("joined SSID \"MyNet\" on ch 36"),
            Some("MyNet".to_string())
        );
    }
}
