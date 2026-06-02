//! Live integration test that exercises real macOS collectors.
//! Run with: `cargo test --test live_scan -- --ignored --nocapture`
//!
//! Excluded from default `cargo test` because it touches the host network.

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn live_macos_full_scan() {
    let c = atlas_lib::collectors::default_collector();
    let link = c.link_stats().await.expect("link stats");
    println!("\nLINK: {link:#?}");
    let reach = c.reachability().await.expect("reachability");
    println!("\nREACH: {reach:#?}");
    let devices = atlas_lib::discovery::scan::discover_and_probe().await;
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

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn live_macos_findings() {
    use atlas_lib::detect;
    use atlas_lib::detect::{Context, ProfileHints};
    let c = atlas_lib::collectors::default_collector();
    let link = c.link_stats().await.expect("link stats");
    let reach = c.reachability().await.expect("reachability");
    let devices = atlas_lib::discovery::scan::discover_and_probe().await;
    let findings = detect::evaluate(&Context {
        link: &link,
        reach: &reach,
        devices: &devices,
        services: &[],
        profile: ProfileHints::default(),
        anomalies: vec![],
        captive_portal: false,
        dns_leak: false,
        mtu_bytes: None,
        nearby_aps: vec![],
        speed_mbps: None,
    });
    let recs = detect::collect_recommendations(&findings);
    println!("\n=== {} FINDINGS ===", findings.len());
    for f in &findings {
        println!(
            "  [{:?}] {} — {} ({} affected)",
            f.severity,
            f.rule_id,
            f.title,
            f.affected_devices.len()
        );
        for ev in &f.evidence {
            println!("      • {ev}");
        }
    }
    println!("\n=== {} RECOMMENDATIONS ===", recs.len());
    for r in &recs {
        println!("  {} — {}", r.id, r.title);
    }
}
