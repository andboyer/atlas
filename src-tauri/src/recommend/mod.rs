use crate::types::{Recommendation, RecommendationLink};

pub fn lookup(id: &str) -> Option<Recommendation> {
    catalog().into_iter().find(|r| r.id == id)
}

fn rec(
    id: &str,
    title: &str,
    summary: &str,
    steps: &[&str],
    links: &[(&str, &str)],
) -> Recommendation {
    Recommendation {
        id: id.into(),
        title: title.into(),
        summary: summary.into(),
        steps: steps.iter().map(|s| s.to_string()).collect(),
        links: links
            .iter()
            .map(|(label, url)| RecommendationLink {
                label: (*label).into(),
                url: (*url).into(),
            })
            .collect(),
        auto_fix_available: false,
    }
}

pub fn catalog() -> Vec<Recommendation> {
    vec![
        rec(
            "rec.move_closer_or_add_ap",
            "Improve signal at this location",
            "Your WiFi signal here is weak. Move closer to the router or add an access point / mesh node.",
            &[
                "Move within 5–10 meters of the router (line-of-sight if possible).",
                "If you can't move, add a mesh node or wired access point near this location.",
                "For business POS counters, place an AP within line-of-sight of the counter.",
            ],
            &[],
        ),
        rec(
            "rec.change_channel",
            "Change WiFi channel",
            "Your environment is noisy. Switching to a less-used channel often helps.",
            &[
                "Open your router admin UI.",
                "On 2.4 GHz, choose channel 1, 6, or 11 (never anything in between).",
                "On 5 GHz, prefer non-DFS channels (36–48, 149–161) for stability.",
            ],
            &[],
        ),
        rec(
            "rec.switch_dns",
            "Switch DNS resolver",
            "Your default DNS resolver is slow. Try a faster public resolver.",
            &[
                "Set primary DNS to 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9).",
                "Set secondary DNS to 1.0.0.1 or 149.112.112.112.",
                "Apply at the router so every device benefits.",
            ],
            &[("Cloudflare 1.1.1.1", "https://1.1.1.1/")],
        ),
        rec(
            "rec.enable_sqm_qos",
            "Enable SQM / QoS on your router",
            "Packet loss suggests congestion under load. Smart Queue Management (SQM) reduces bufferbloat.",
            &[
                "If your router supports it, enable SQM/QoS (e.g. CAKE on OpenWrt).",
                "Set the rate to ~90% of your measured up/down speed.",
                "Re-test latency under load.",
            ],
            &[],
        ),
        rec(
            "rec.pos_stabilize",
            "Stabilize POS terminals",
            "POS terminals are dropping. They need a dedicated, predictable network path.",
            &[
                "Create a hidden, dedicated SSID just for POS terminals.",
                "Lock the POS SSID to 5 GHz on a fixed non-DFS channel.",
                "Place an AP within line-of-sight of the counter (drywall + appliances kill signal).",
                "Increase DHCP lease time to 7+ days for the POS subnet.",
                "Put POS on its own VLAN; allow only outbound to the payment processor.",
                "If supported, enable LTE/5G failover on the terminal.",
            ],
            &[],
        ),
        rec(
            "rec.iot_dedicated_ssid",
            "Move IoT to a dedicated 2.4 GHz SSID",
            "Cheap IoT chips disassociate when the 2.4 GHz band is congested. A separate SSID with conservative settings fixes most dropouts.",
            &[
                "Create an IoT SSID broadcasting only on 2.4 GHz.",
                "Pin the channel to 1, 6, or 11 (whichever is least used).",
                "Disable band steering for this SSID.",
                "Use WPA2-PSK (some IoT can't handle WPA3 or PMF-required).",
                "Lower DTIM to 1–2 if devices miss wake-ups.",
            ],
            &[],
        ),
    ]
}
