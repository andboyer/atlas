use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
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

#[derive(Debug, Clone, Serialize)]
pub struct MetricSample {
    pub metric: String,
    pub value: f64,
    pub sampled_at: DateTime<Utc>,
    pub label: Option<String>,
}

/// A snapshot of network conditions around an incident time. Used to power
/// the "what was happening on the LAN when this device dropped" view, which
/// is the core differentiator for diagnosing POS-terminal random disconnects
/// and IoT dropouts.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentCorrelation {
    pub at: DateTime<Utc>,
    pub window_secs: i64,
    /// Most recent value of each metric inside the window leading up to `at`.
    pub metrics_before: Vec<MetricSample>,
    /// Device events from OTHER devices that occurred inside the window
    /// (i.e. anything that went up or down at roughly the same time).
    pub concurrent_events: Vec<DeviceEvent>,
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

    /// Pull a snapshot of network state around `at`. Returns the most recent
    /// value of each metric within `window_secs` BEFORE `at`, plus any
    /// device transitions (other MACs) within ±window_secs.
    pub fn correlate(
        &self,
        at: DateTime<Utc>,
        window_secs: i64,
        exclude_mac: Option<&str>,
    ) -> Result<IncidentCorrelation> {
        let guard = self.conn.lock();
        let window = Duration::seconds(window_secs);
        let lower = (at - window).to_rfc3339();
        let upper = (at + window).to_rfc3339();
        let at_iso = at.to_rfc3339();

        // Latest sample per metric, before `at`, inside the window.
        let mut metrics_stmt = guard.prepare(
            "SELECT s1.metric, s1.value, s1.sampled_at, s1.label \
             FROM samples s1 \
             JOIN ( \
                 SELECT metric, MAX(sampled_at) AS sampled_at \
                 FROM samples \
                 WHERE sampled_at >= ?1 AND sampled_at <= ?2 \
                 GROUP BY metric \
             ) s2 ON s1.metric = s2.metric AND s1.sampled_at = s2.sampled_at",
        )?;
        let metrics_rows = metrics_stmt.query_map(params![lower, at_iso], |r| {
            Ok(MetricSample {
                metric: r.get(0)?,
                value: r.get(1)?,
                sampled_at: parse_dt(&r.get::<_, String>(2)?),
                label: r.get(3)?,
            })
        })?;
        let metrics_before: Vec<MetricSample> = metrics_rows.collect::<Result<Vec<_>, _>>()?;
        drop(metrics_stmt);

        // Other devices that flipped state inside ±window_secs.
        let mut events_stmt = guard.prepare(
            "SELECT mac, occurred_at, event_type, details FROM device_events \
             WHERE occurred_at >= ?1 AND occurred_at <= ?2 AND mac != COALESCE(?3, '') \
             ORDER BY occurred_at ASC",
        )?;
        let event_rows = events_stmt.query_map(params![lower, upper, exclude_mac], |r| {
            Ok(DeviceEvent {
                mac: r.get(0)?,
                occurred_at: parse_dt(&r.get::<_, String>(1)?),
                event_type: r.get(2)?,
                details: r.get(3)?,
            })
        })?;
        let concurrent_events = event_rows.collect::<Result<Vec<_>, _>>()?;

        Ok(IncidentCorrelation {
            at,
            window_secs,
            metrics_before,
            concurrent_events,
        })
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
            services: vec![],
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
            service_reachability: vec![],
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

    #[test]
    fn correlate_returns_metrics_and_concurrent_events() {
        let store = Store::in_memory().unwrap();
        // Scan 1: POS up, camera up.
        store
            .record_scan(&scan_with(
                vec![
                    dev("aa:aa:aa:aa:aa:06", true),
                    dev("bb:bb:bb:bb:bb:06", true),
                ],
                vec![],
            ))
            .unwrap();
        // Scan 2: both drop at roughly the same time -> incident.
        store
            .record_scan(&scan_with(
                vec![
                    dev("aa:aa:aa:aa:aa:06", false),
                    dev("bb:bb:bb:bb:bb:06", false),
                ],
                vec![],
            ))
            .unwrap();

        // Look up correlation around the POS terminal's drop.
        let pos_events = store.device_events_for("aa:aa:aa:aa:aa:06", 10).unwrap();
        let drop_event = pos_events
            .iter()
            .find(|e| e.event_type == "offline")
            .expect("pos went offline");
        let snap = store
            .correlate(drop_event.occurred_at, 60, Some("aa:aa:aa:aa:aa:06"))
            .unwrap();
        // We should see the gateway latency / link RSSI metrics that we
        // recorded with scan 2.
        assert!(
            snap.metrics_before
                .iter()
                .any(|m| m.metric == "reach.gateway_ms"),
            "expected gateway sample, got {:?}",
            snap.metrics_before
        );
        // The camera's offline event should appear as a concurrent event.
        assert!(
            snap.concurrent_events
                .iter()
                .any(|e| e.mac == "bb:bb:bb:bb:bb:06" && e.event_type == "offline"),
            "expected camera concurrent offline, got {:?}",
            snap.concurrent_events
        );
    }
}
