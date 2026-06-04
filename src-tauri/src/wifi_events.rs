//! Wi-Fi system event subscriber.
//!
//! - **macOS** — taps `log stream` filtered to wifid/airportd/CoreWLAN to
//!   surface roams, scans, association events, deauths, etc.
//! - **Windows** — polls the
//!   `Microsoft-Windows-WLAN-AutoConfig/Operational` event log via
//!   PowerShell `Get-WinEvent`, classifying each event by its numeric
//!   provider ID (8001 = connect success, 8002 = failure, 8003 =
//!   disconnect, 11005/11006 = roam start/complete, 8000 = scan
//!   complete, etc.). One JSON object per line streamed back from a
//!   long-lived `powershell.exe` process; `RecordId`-based dedupe.
//! - **Linux** — no shipping producer (no consistent system event
//!   source); ring stays empty.
//!
//! Each event is classified and pushed into a small ring buffer + emitted
//! as a `wifi:event` Tauri event so the frontend can overlay them on the
//! live telemetry chart.

use crate::types::WifiEvent;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::AppHandle;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use tauri::Emitter;
#[cfg(any(target_os = "macos", target_os = "windows"))]
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
    spawn_macos_log_stream(app.clone(), Arc::clone(&ring), Arc::clone(&running));

    #[cfg(target_os = "windows")]
    spawn_windows_event_log(app.clone(), Arc::clone(&ring), Arc::clone(&running));

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = app;
        tracing::debug!(target: "wifi_events", "no wifi event producer for this platform; ring stays empty");
    }

    WifiEventsHandle { running, ring }
}

#[cfg(target_os = "macos")]
fn spawn_macos_log_stream(app: AppHandle, ring: EventRing, running: Arc<AtomicBool>) {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

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
                "--style",
                "ndjson",
                "--level",
                "info",
                "--predicate",
                predicate,
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

#[allow(dead_code)] // macOS-only event parser; reachable via tests on all platforms.
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
    } else if lower.contains("power") || lower.contains("sleep") || lower.contains("wake") {
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

#[allow(dead_code)] // macOS-only event parser; reachable via tests on all platforms.
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

#[allow(dead_code)] // macOS-only event parser; reachable via tests on all platforms.
fn extract_ssid(message: &str) -> Option<String> {
    // Look for patterns like `SSID=foo`, `SSID "foo"`, or `ssid: foo`.
    let lower = message.to_lowercase();
    if let Some(idx) = lower.find("ssid") {
        let rest = &message[idx + 4..];
        // Skip punctuation/whitespace.
        let rest = rest.trim_start_matches([' ', ':', '=', '"', '\'']);
        // Take until next quote or whitespace.
        let end = rest.find(['"', '\'', ',', '\n']).unwrap_or(rest.len());
        let candidate = rest[..end].trim();
        if !candidate.is_empty() && candidate.len() <= 64 {
            return Some(candidate.to_string());
        }
    }
    None
}

#[allow(dead_code)] // macOS-only event parser; reachable via tests on all platforms.
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

// ---------------------------------------------------------------------------
// Windows producer
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn spawn_windows_event_log(app: AppHandle, ring: EventRing, running: Arc<AtomicBool>) {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    // Long-lived PowerShell loop: tail the WLAN-AutoConfig operational log,
    // emit one JSON object per event, dedupe via RecordId. Sleeps 3s between
    // polls — Get-WinEvent doesn't support tail/follow, so polling is the
    // canonical pattern. NoConsole + NonInteractive keeps the window hidden
    // when launched from the .exe bundle.
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$logName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
# Start at the most recent record so we don't re-emit historical noise on app
# start. RecordId is monotonic per log.
$last = 0
try {
    $seed = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($seed) { $last = [int64]$seed.RecordId }
} catch {}
while ($true) {
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction SilentlyContinue |
                  Where-Object { [int64]$_.RecordId -gt $last } |
                  Sort-Object RecordId
        foreach ($e in $events) {
            $rid = [int64]$e.RecordId
            if ($rid -gt $last) { $last = $rid }
            $obj = [ordered]@{
                Id = $e.Id
                RecordId = $rid
                TimeCreated = $e.TimeCreated.ToString('o')
                ProviderName = $e.ProviderName
                LevelDisplayName = $e.LevelDisplayName
                Message = ($e.Message -replace "`r`n", ' ' -replace "`n", ' ')
            }
            ($obj | ConvertTo-Json -Compress)
        }
    } catch {}
    Start-Sleep -Seconds 3
}
"#;

    tokio::spawn(async move {
        // Detach the powershell console window from the GUI app (no flashing
        // black box on startup). 0x08000000 = CREATE_NO_WINDOW.
        #[cfg(target_os = "windows")]
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;

        let mut cmd = Command::new("powershell.exe");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x0800_0000);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "wifi_events", error = %e, "could not spawn PowerShell (Wi-Fi event overlay disabled)");
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                tracing::warn!(target: "wifi_events", "no stdout on PowerShell child");
                return;
            }
        };
        tracing::info!(target: "wifi_events", "wifi event subscriber started (Windows / Get-WinEvent)");

        let mut lines = BufReader::new(stdout).lines();
        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                Ok(None) => {
                    tracing::debug!(target: "wifi_events", "PowerShell stream closed; exiting");
                    break;
                }
                Err(e) => {
                    tracing::debug!(target: "wifi_events", error = %e, "PowerShell read failed; exiting");
                    break;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.starts_with('{') {
                continue;
            }
            let event = match parse_windows_event_line(trimmed) {
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
        tracing::info!(target: "wifi_events", "wifi event subscriber stopped (Windows)");
    });
}

#[cfg(target_os = "windows")]
fn parse_windows_event_line(line: &str) -> Option<WifiEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let id = v.get("Id").and_then(|x| x.as_i64()).unwrap_or(0);
    let message = v
        .get("Message")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let provider = v
        .get("ProviderName")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let kind = classify_windows_event_id(id).unwrap_or_else(|| {
        let lower = message.to_lowercase();
        let k = classify(&lower);
        if k == "ignore" {
            "other"
        } else {
            k
        }
    });

    // Drop totally empty messages from unclassified IDs.
    if message.is_empty() && kind == "other" {
        return None;
    }

    let bssid = if message.is_empty() {
        None
    } else {
        extract_bssid(&message)
    };
    let ssid = if message.is_empty() {
        None
    } else {
        extract_ssid(&message)
    };
    let rssi_dbm = if message.is_empty() {
        None
    } else {
        extract_rssi(&message)
    };

    Some(WifiEvent {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        kind: kind.to_string(),
        subsystem: provider,
        process: Some("svchost.exe (WlanSvc)".to_string()),
        message,
        bssid,
        ssid,
        rssi_dbm,
    })
}

#[cfg(target_os = "windows")]
fn classify_windows_event_id(id: i64) -> Option<&'static str> {
    // Reference: Microsoft-Windows-WLAN-AutoConfig provider event IDs.
    // Values cross-referenced against Microsoft docs + real-world logs;
    // unknown IDs fall through to message-based classification.
    match id {
        8000..=8002 => Some("assoc"),    // connection start / success / failure
        8003..=8004 => Some("disassoc"), // disconnect / disconnect-reason
        11000..=11010 => Some("roam"),   // roaming start/complete/failure
        12010..=12013 => Some("auth"),   // 802.1X / EAP
        20010..=20020 => Some("auth"),   // wireless security
        4100..=4109 => Some("kernel"),   // native WiFi driver
        6100..=6109 => Some("scan"),     // scan complete/empty
        10000..=10003 => Some("power"),  // radio state change
        _ => None,
    }
}

#[cfg(test)]
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
