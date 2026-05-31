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
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsCollector)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Phase 2 ships real macOS support. Linux/Windows still use mock
        // pending dedicated parsers in Phase 2b.
        Box::new(mock::MockCollector)
    }
}
