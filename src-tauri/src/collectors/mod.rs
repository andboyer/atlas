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
    async fn reachability(&self) -> Result<ReachabilityStats>;
}

pub fn default_collector() -> Box<dyn WifiCollector> {
    // Phase 1: ship the mock collector so the app is demoable everywhere.
    // Phase 2 will swap in the real per-OS implementation.
    Box::new(mock::MockCollector)
}
