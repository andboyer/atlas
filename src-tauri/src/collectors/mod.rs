use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;

pub mod mock;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[async_trait]
pub trait WifiCollector: Send + Sync {
    async fn link_stats(&self) -> Result<LinkStats>;
    /// Reachability probes are pinned to `iface` when supplied (gateway is
    /// resolved as that NIC's next-hop, every ping is source-bound to it).
    /// `None` is the historical "kernel picks the default route" behaviour.
    async fn reachability(&self, iface: Option<&str>) -> Result<ReachabilityStats>;
}

pub fn default_collector() -> Box<dyn WifiCollector> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::MacOsCollector);
    #[cfg(target_os = "windows")]
    return Box::new(windows::WindowsCollector);
    #[cfg(target_os = "linux")]
    return Box::new(linux::LinuxCollector);
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    Box::new(mock::MockCollector)
}
