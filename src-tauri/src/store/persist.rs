use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::types::{DeviceClass, Finding, ScanResult, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct DeviceEvent {
    pub mac: String,
    pub occurred_at: DateTime<Utc>,
    /// "online" or "offline" (or future: "first_seen", "ip_change", ...).
    pub event_type: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub run_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub findings_count: i64,
    pub devices_online: i64,
    pub devices_total: i64,
    pub worst_severity: Option<Severity>,
}

impl super::Store {
    /// Persist a scan result: insert a run row, upsert each device, record
    /// online↔offline transitions as device_events, store time-series samples
    /// for the headline metrics, and insert findings.
    pub fn record_scan(&self, scan: &ScanResult) -> Result<()> {
        let mut guard = self.conn.lock();
        let tx = guard.transaction()?;

        // ── runs ──
        tx.execute(
            "INSERT OR REPLACE INTO runs (id, started_at, finished_at, summary_json) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                scan.run_id,
                scan.started_at.to_rfc3339(),
                scan.finished_at.to_rfc3339(),
                serde_json::to_string(&run_summary(scan))?,
            ],
        )?;

        // ── samples (link + reachability) ──
        let sampled = scan.finished_at.to_rfc3339();
        let mut insert_sample =
            tx.prepare("INSERT INTO samples (run_id, sampled_at, metric, value, label) VALUES (?1, ?2, ?3, ?4, ?5)")?;
        if let Some(v) = scan.link.rssi_dbm {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "link.rssi_dbm",
                v as f64,
                scan.link.ssid
            ])?;
        }
        if let Some(v) = scan.link.snr_db {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "link.snr_db",
                v as f64,
                scan.link.ssid
            ])?;
        }
        if let Some(v) = scan.link.tx_rate_mbps {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "link.tx_rate_mbps",
                v as f64,
                scan.link.ssid
            ])?;
        }
        if let Some(v) = scan.reachability.gateway_latency_ms {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "reach.gateway_ms",
                v as f64,
                scan.reachability.gateway_ip
            ])?;
        }
        if let Some(v) = scan.reachability.internet_latency_ms {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "reach.internet_ms",
                v as f64,
                None::<String>
            ])?;
        }
        if let Some(v) = scan.reachability.dns_latency_ms {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "reach.dns_ms",
                v as f64,
                None::<String>
            ])?;
        }
        if let Some(v) = scan.reachability.packet_loss_pct {
            insert_sample.execute(params![
                scan.run_id,
                sampled,
                "reach.loss_pct",
                v as f64,
                None::<String>
            ])?;
        }
        let online = scan.devices.iter().filter(|d| d.online).count() as f64;
        let total = scan.devices.len() as f64;
        insert_sample.execute(params![
            scan.run_id,
            sampled,
            "devices.online",
            online,
            None::<String>
        ])?;
        insert_sample.execute(params![
            scan.run_id,
            sampled,
            "devices.total",
            total,
            None::<String>
        ])?;
        drop(insert_sample);

        // ── devices + transition events ──
        let now_iso = scan.finished_at.to_rfc3339();
        for d in &scan.devices {
            // Look up previous state for transition detection.
            let prev_online: Option<i64> = tx
                .query_row(
                    "SELECT last_online FROM devices WHERE mac = ?1",
                    params![d.mac],
                    |r| r.get(0),
                )
                .optional()?;
            let now_online = if d.online { 1_i64 } else { 0 };
            tx.execute(
                "INSERT INTO devices (mac, ip, hostname, vendor, class, first_seen, last_seen, last_online) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT(mac) DO UPDATE SET \
                    ip = COALESCE(excluded.ip, devices.ip), \
                    hostname = COALESCE(excluded.hostname, devices.hostname), \
                    vendor = COALESCE(excluded.vendor, devices.vendor), \
                    class = excluded.class, \
                    last_seen = excluded.last_seen, \
                    last_online = excluded.last_online",
                params![
                    d.mac,
                    d.ip,
                    d.hostname,
                    d.vendor,
                    class_str(&d.class),
                    d.first_seen.to_rfc3339(),
                    d.last_seen.to_rfc3339(),
                    now_online,
                ],
            )?;
            match prev_online {
                None => {
                    // First time we've ever seen this MAC.
                    tx.execute(
                        "INSERT INTO device_events (mac, occurred_at, event_type, details) \
                         VALUES (?1, ?2, 'first_seen', ?3)",
                        params![d.mac, now_iso, d.ip],
                    )?;
                }
                Some(prev) if prev != now_online => {
                    let event = if now_online == 1 { "online" } else { "offline" };
                    tx.execute(
                        "INSERT INTO device_events (mac, occurred_at, event_type, details) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![d.mac, now_iso, event, d.ip],
                    )?;
                }
                _ => {}
            }
        }

        // ── findings ──
        for f in &scan.findings {
            tx.execute(
                "INSERT OR REPLACE INTO findings (id, run_id, rule_id, severity, confidence, observed_at, payload_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    f.id,
                    scan.run_id,
                    f.rule_id,
                    severity_str(&f.severity),
                    f.confidence as f64,
                    f.observed_at.to_rfc3339(),
                    serde_json::to_string(f)?,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Most recent scans (newest first).
    pub fn recent_scans(&self, limit: i64) -> Result<Vec<ScanSummary>> {
        let guard = self.conn.lock();
        let mut stmt = guard.prepare(
            "SELECT id, started_at, finished_at, summary_json \
             FROM runs ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            let id: String = r.get(0)?;
            let started: String = r.get(1)?;
            let finished: Option<String> = r.get(2)?;
            let summary: Option<String> = r.get(3)?;
            Ok((id, started, finished, summary))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, started, finished, summary_json) = row?;
            let parsed: RunSummaryRow = summary_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            out.push(ScanSummary {
                run_id: id,
                started_at: parse_dt(&started),
                finished_at: finished.as_deref().map(parse_dt),
                findings_count: parsed.findings_count,
                devices_online: parsed.devices_online,
                devices_total: parsed.devices_total,
                worst_severity: parsed.worst_severity,
            });
        }
        Ok(out)
    }

    /// Recent online/offline transitions (and first-seen) for a specific MAC.
    pub fn device_events_for(&self, mac: &str, limit: i64) -> Result<Vec<DeviceEvent>> {
        let guard = self.conn.lock();
        let mut stmt = guard.prepare(
            "SELECT mac, occurred_at, event_type, details FROM device_events \
             WHERE mac = ?1 ORDER BY occurred_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![mac, limit], |r| {
            Ok(DeviceEvent {
                mac: r.get(0)?,
                occurred_at: parse_dt(&r.get::<_, String>(1)?),
                event_type: r.get(2)?,
                details: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Network-wide event feed (any device, any type), newest first.
    pub fn recent_device_events(&self, limit: i64) -> Result<Vec<DeviceEvent>> {
        let guard = self.conn.lock();
        let mut stmt = guard.prepare(
            "SELECT mac, occurred_at, event_type, details FROM device_events \
             ORDER BY occurred_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(DeviceEvent {
                mac: r.get(0)?,
                occurred_at: parse_dt(&r.get::<_, String>(1)?),
                event_type: r.get(2)?,
                details: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[derive(Debug, Default, Serialize, serde::Deserialize)]
struct RunSummaryRow {
    findings_count: i64,
    devices_online: i64,
    devices_total: i64,
    #[serde(default)]
    worst_severity: Option<Severity>,
}

fn run_summary(scan: &ScanResult) -> RunSummaryRow {
    let online = scan.devices.iter().filter(|d| d.online).count() as i64;
    RunSummaryRow {
        findings_count: scan.findings.len() as i64,
        devices_online: online,
        devices_total: scan.devices.len() as i64,
        worst_severity: worst_severity(&scan.findings),
    }
}

fn worst_severity(findings: &[Finding]) -> Option<Severity> {
    findings
        .iter()
        .map(|f| f.severity.clone())
        .max_by_key(|s| match s {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        })
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn class_str(c: &DeviceClass) -> &'static str {
    match c {
        DeviceClass::PosTerminal => "pos_terminal",
        DeviceClass::IpCamera => "ip_camera",
        DeviceClass::SmartHome => "smart_home",
        DeviceClass::Printer => "printer",
        DeviceClass::VoiceAssistant => "voice_assistant",
        DeviceClass::Thermostat => "thermostat",
        DeviceClass::Phone => "phone",
        DeviceClass::Laptop => "laptop",
        DeviceClass::TvStreamer => "tv_streamer",
        DeviceClass::GameConsole => "game_console",
        DeviceClass::Nas => "nas",
        DeviceClass::RouterAp => "router_ap",
        DeviceClass::Unknown => "unknown",
    }
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::super::Store;
    use crate::types::{
        DeviceClass, DeviceInfo, Finding, LinkStats, ReachabilityStats, ScanResult, Severity,
    };
    use chrono::Utc;
    use uuid::Uuid;

    fn empty_link() -> LinkStats {
        LinkStats {
            ssid: Some("Home".into()),
            bssid: None,
            band: Some("5".into()),
            channel: Some(36),
            channel_width_mhz: Some(80),
            rssi_dbm: Some(-55),
            noise_dbm: Some(-90),
            snr_db: Some(35),
            tx_rate_mbps: Some(866.0),
            rx_rate_mbps: None,
            security: Some("WPA2".into()),
        }
    }

    fn good_reach() -> ReachabilityStats {
        ReachabilityStats {
            gateway_ip: Some("192.168.1.1".into()),
            gateway_latency_ms: Some(3.0),
            internet_latency_ms: Some(15.0),
            dns_latency_ms: Some(10.0),
            packet_loss_pct: Some(0.0),
        }
    }

    fn dev(mac: &str, online: bool) -> DeviceInfo {
        let now = Utc::now();
        DeviceInfo {
            mac: mac.into(),
            ip: Some("192.168.1.50".into()),
            hostname: Some("test".into()),
            vendor: None,
            class: DeviceClass::Unknown,
            first_seen: now,
            last_seen: now,
            online,
            latency_ms: if online { Some(5.0) } else { None },
        }
    }

    fn scan_with(devices: Vec<DeviceInfo>, findings: Vec<Finding>) -> ScanResult {
        let now = Utc::now();
        ScanResult {
            run_id: Uuid::new_v4().to_string(),
            started_at: now,
            finished_at: now,
            link: empty_link(),
            reachability: good_reach(),
            devices,
            findings,
            recommendations: vec![],
        }
    }

    #[test]
    fn first_scan_emits_first_seen_events() {
        let store = Store::in_memory().unwrap();
        let scan = scan_with(vec![dev("aa:aa:aa:aa:aa:01", true)], vec![]);
        store.record_scan(&scan).unwrap();
        let events = store.device_events_for("aa:aa:aa:aa:aa:01", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "first_seen");
    }

    #[test]
    fn online_to_offline_transition_records_offline_event() {
        let store = Store::in_memory().unwrap();
        store
            .record_scan(&scan_with(vec![dev("aa:aa:aa:aa:aa:02", true)], vec![]))
            .unwrap();
        store
            .record_scan(&scan_with(vec![dev("aa:aa:aa:aa:aa:02", false)], vec![]))
            .unwrap();
        let events = store.device_events_for("aa:aa:aa:aa:aa:02", 10).unwrap();
        // Most-recent first: offline transition, then first_seen.
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "offline");
        assert_eq!(events[1].event_type, "first_seen");
    }

    #[test]
    fn no_event_when_state_unchanged() {
        let store = Store::in_memory().unwrap();
        store
            .record_scan(&scan_with(vec![dev("aa:aa:aa:aa:aa:03", true)], vec![]))
            .unwrap();
        store
            .record_scan(&scan_with(vec![dev("aa:aa:aa:aa:aa:03", true)], vec![]))
            .unwrap();
        let events = store.device_events_for("aa:aa:aa:aa:aa:03", 10).unwrap();
        assert_eq!(events.len(), 1, "only the first_seen event should exist");
    }

    #[test]
    fn recent_scans_summarises_run() {
        let store = Store::in_memory().unwrap();
        let now = Utc::now();
        let finding = Finding {
            id: Uuid::new_v4().to_string(),
            rule_id: "test.rule".into(),
            title: "demo".into(),
            severity: Severity::High,
            confidence: 1.0,
            evidence: vec![],
            affected_devices: vec![],
            recommendation_id: None,
            observed_at: now,
        };
        let scan = scan_with(
            vec![
                dev("aa:aa:aa:aa:aa:04", true),
                dev("aa:aa:aa:aa:aa:05", false),
            ],
            vec![finding],
        );
        store.record_scan(&scan).unwrap();
        let summaries = store.recent_scans(5).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].findings_count, 1);
        assert_eq!(summaries[0].devices_online, 1);
        assert_eq!(summaries[0].devices_total, 2);
        assert_eq!(summaries[0].worst_severity, Some(Severity::High));
    }
}
