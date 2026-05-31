use super::WifiCollector;
use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;

#[allow(dead_code)]
pub struct MockCollector;

#[async_trait]
impl WifiCollector for MockCollector {
    async fn link_stats(&self) -> Result<LinkStats> {
        Ok(LinkStats {
            ssid: Some("CafeWiFi-5G".into()),
            bssid: Some("a4:2b:b0:11:22:33".into()),
            band: Some("5".into()),
            channel: Some(36),
            channel_width_mhz: Some(80),
            rssi_dbm: Some(-72),
            noise_dbm: Some(-92),
            snr_db: Some(20),
            tx_rate_mbps: Some(173.0),
            rx_rate_mbps: Some(195.0),
            security: Some("WPA2-Personal".into()),
        })
    }

    async fn reachability(&self) -> Result<ReachabilityStats> {
        Ok(ReachabilityStats {
            gateway_ip: Some("192.168.1.1".into()),
            gateway_latency_ms: Some(2.4),
            internet_latency_ms: Some(34.7),
            dns_latency_ms: Some(48.1),
            packet_loss_pct: Some(1.5),
        })
    }
}
