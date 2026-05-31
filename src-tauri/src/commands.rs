use crate::collectors::default_collector;
use crate::detect::{self, Context};
use crate::store::Store;
use crate::types::{DeviceClass, DeviceInfo, ScanResult};
use chrono::Utc;
use tauri::State;
use uuid::Uuid;

pub struct AppState {
    #[allow(dead_code)]
    pub store: Store,
}

#[tauri::command]
pub async fn run_quick_scan(_state: State<'_, AppState>) -> Result<ScanResult, String> {
    let started_at = Utc::now();
    let collector = default_collector();
    let link = collector.link_stats().await.map_err(|e| e.to_string())?;
    let reach = collector.reachability().await.map_err(|e| e.to_string())?;

    let mut devices = crate::discovery::scan::discover_and_probe().await;
    if devices.is_empty() {
        // Fall back to demo data so the UI is never empty (and so non-macOS
        // platforms can still see what the app does).
        devices = mock_devices();
    }

    let findings = detect::evaluate(&Context {
        link: &link,
        reach: &reach,
        devices: &devices,
    });
    let recommendations = detect::collect_recommendations(&findings);

    Ok(ScanResult {
        run_id: Uuid::new_v4().to_string(),
        started_at,
        finished_at: Utc::now(),
        link,
        reachability: reach,
        devices,
        findings,
        recommendations,
    })
}

fn mock_devices() -> Vec<DeviceInfo> {
    let now = Utc::now();
    vec![
        DeviceInfo {
            mac: "a4:2b:b0:11:22:33".into(),
            ip: Some("192.168.1.1".into()),
            hostname: Some("router".into()),
            vendor: Some("Ubiquiti".into()),
            class: DeviceClass::RouterAp,
            first_seen: now,
            last_seen: now,
            online: true,
            latency_ms: Some(1.8),
        },
        DeviceInfo {
            mac: "00:1a:7d:da:71:11".into(),
            ip: Some("192.168.1.42".into()),
            hostname: Some("Clover-Mini-01".into()),
            vendor: Some("Clover Network".into()),
            class: DeviceClass::PosTerminal,
            first_seen: now,
            last_seen: now,
            online: false,
            latency_ms: None,
        },
        DeviceInfo {
            mac: "b8:27:eb:00:00:aa".into(),
            ip: Some("192.168.1.84".into()),
            hostname: Some("kitchen-printer".into()),
            vendor: Some("Epson".into()),
            class: DeviceClass::Printer,
            first_seen: now,
            last_seen: now,
            online: true,
            latency_ms: Some(6.4),
        },
        DeviceInfo {
            mac: "ec:fa:bc:55:66:77".into(),
            ip: Some("192.168.1.121".into()),
            hostname: Some("front-camera".into()),
            vendor: Some("Reolink".into()),
            class: DeviceClass::IpCamera,
            first_seen: now,
            last_seen: now,
            online: false,
            latency_ms: None,
        },
        DeviceInfo {
            mac: "d8:f1:5b:aa:bb:cc".into(),
            ip: Some("192.168.1.150".into()),
            hostname: Some("smart-bulb-1".into()),
            vendor: Some("TP-Link".into()),
            class: DeviceClass::SmartHome,
            first_seen: now,
            last_seen: now,
            online: true,
            latency_ms: Some(38.1),
        },
    ]
}
