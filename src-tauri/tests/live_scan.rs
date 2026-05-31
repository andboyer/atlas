//! Live integration test that exercises real macOS collectors.
//! Run with: `cargo test --test live_scan -- --ignored --nocapture`
//!
//! Excluded from default `cargo test` because it touches the host network.

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn live_macos_full_scan() {
    let c = wifi_troubleshooter_lib::collectors::default_collector();
    let link = c.link_stats().await.expect("link stats");
    println!("\nLINK: {link:#?}");
    let reach = c.reachability().await.expect("reachability");
    println!("\nREACH: {reach:#?}");
    let devices = wifi_troubleshooter_lib::discovery::scan::discover_and_probe().await;
    println!("\nDEVICES: {} found", devices.len());
    for d in devices.iter().take(30) {
        println!(
            "  {:<16} {}  host={:<32?}  vendor={:<22?}  class={:?}  online={}  lat={:?}",
            d.ip.as_deref().unwrap_or("?"),
            d.mac,
            d.hostname.as_deref(),
            d.vendor.as_deref(),
            d.class,
            d.online,
            d.latency_ms
        );
    }
}
