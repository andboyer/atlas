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
            "rec.prefer_5ghz",
            "Move this device to 5 GHz",
            "5 GHz is significantly faster and far less congested than 2.4 GHz. Most laptops, phones, and modern TVs / streamers support it.",
            &[
                "On the router, make sure 5 GHz is enabled and broadcasting.",
                "If you have separate 2.4 GHz and 5 GHz SSIDs, forget the 2.4 GHz one on this device and join the 5 GHz SSID.",
                "If you have a single SSID for both bands, enable band steering on the router (sometimes called 'Smart Connect').",
                "Keep a 2.4 GHz-only SSID just for IoT devices that need it.",
            ],
            &[],
        ),
        rec(
            "rec.check_router_link",
            "Check the router / LAN connection",
            "We couldn't reach the router. Something on the local link is wrong.",
            &[
                "Confirm the router is powered on and its WAN / internet light is solid.",
                "Try reconnecting WiFi (toggle airplane mode) or re-plugging the Ethernet cable.",
                "If using a mesh node, check that its backhaul to the main router is healthy.",
                "Power-cycle the router only as a last step — wait 30 seconds before powering back on.",
            ],
            &[],
        ),
        rec(
            "rec.contact_isp",
            "Internet issue — check or contact your ISP",
            "Your LAN looks healthy, but the path beyond your router is slow or down. This usually points at the ISP, not your equipment.",
            &[
                "Check the ISP's status page or their app for known outages in your area.",
                "Confirm the WAN / internet light on the router is solid (not blinking / off).",
                "Run a wired speed test from a laptop plugged directly into the router to rule out WiFi.",
                "If the issue persists more than a few minutes, contact ISP support with the latency numbers from this app.",
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
            "rec.add_capacity",
            "Add more WiFi capacity",
            "A single access point is being asked to serve a lot of clients. Splitting load across more radios is usually the fix.",
            &[
                "Add a second access point (wired backhaul if possible) in a different part of the space.",
                "Separate SSIDs by band: a 5 GHz SSID for laptops / phones, a 2.4 GHz SSID for IoT.",
                "On business networks, consider an enterprise / 'business-class' AP rated for the client count you actually have.",
                "Avoid placing the new AP right next to the existing one — overlap doesn't add capacity, separation does.",
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
            "rec.pos_printer_path",
            "Fix the POS → printer path",
            "Your POS terminals are up, but a kitchen / receipt printer is unreachable. Orders and receipts will fail until the LAN path is restored.",
            &[
                "Confirm the printer is powered on and connected to the same SSID / VLAN as the POS terminals.",
                "If the POS is on a guest network, disable 'client isolation' for that SSID or move POS + printer to the same VLAN.",
                "Give the printer a DHCP reservation so its IP doesn't change.",
                "If POS configurations reference the printer by IP, switch to mDNS / hostname when possible.",
                "On business networks, give the printer wired Ethernet instead of WiFi — printers handle roaming poorly.",
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
        rec(
            "rec.pos_processor_path",
            "Restore the path to your payment processor",
            "We can't reach one or more of the payment / SaaS endpoints your POS depends on. Card payments will fail until this is restored.",
            &[
                "Run a wired speed test from a laptop plugged directly into the router to confirm the LAN is okay.",
                "From a laptop, try `curl -v https://api.clover.com` (or the affected hostname) — TLS or DNS errors here point at upstream filtering.",
                "Check the ISP status page for outages in your area.",
                "If you have content-filtering, captive portal, or VPN configured, allowlist the payment-processor domains.",
                "Confirm router/firewall isn't blocking outbound 443 to the listed hosts.",
                "Failover to LTE/5G on terminals that support it until the path is restored.",
            ],
            &[],
        ),
        rec(
            "rec.investigate_device",
            "A pinned device dropped",
            "One of your watchlisted devices is offline. Because you flagged it as important, this is treated as a critical event.",
            &[
                "Confirm the device is powered on and not in sleep mode.",
                "Check this app's incident timeline for the moment it dropped — was the LAN simultaneously unhealthy?",
                "If only this device dropped, reboot the device or reconnect it to WiFi.",
                "If many devices dropped together, the issue is the network (AP / channel / DHCP), not the device.",
                "For POS / payment terminals: failover to LTE on devices that support it until WiFi is restored.",
            ],
            &[],
        ),
        rec(
            "rec.anomaly_rssi",
            "Investigate sudden RSSI drop",
            "Your WiFi signal dropped sharply compared to its recent baseline. This often precedes connectivity failures.",
            &[
                "Check whether the AP was rebooted or lost power.",
                "Look for new obstructions (furniture, new appliances) between you and the AP.",
                "If you're on a multi-AP mesh, check whether the system roamed you to a far AP.",
                "Temporarily move closer to the AP to confirm signal recovers.",
                "If the drop is persistent, consider adding an AP or repositioning the existing one.",
            ],
            &[],
        ),
        rec(
            "rec.anomaly_latency",
            "Investigate sudden latency spike to gateway",
            "Gateway latency jumped well above its recent baseline. This indicates local network congestion or router issues.",
            &[
                "Check your router's CPU and memory usage (admin UI > Status).",
                "Look for bandwidth-intensive transfers or a new device saturating the LAN.",
                "If you have QoS/SQM enabled, verify it's configured correctly for your line speed.",
                "Reboot the router if CPU usage looks high — some models accumulate state over long uptimes.",
                "Check for firmware updates for the router.",
            ],
            &[],
        ),
        rec(
            "rec.anomaly_loss",
            "Investigate sudden packet loss spike",
            "Packet loss jumped sharply. Sustained loss above ~2% causes application-level failures.",
            &[
                "Run a continuous ping to your gateway to confirm the loss is real and persistent.",
                "Check for RF interference — microwave ovens, cordless phones, and baby monitors can cause burst loss on 2.4 GHz.",
                "Check the router's WAN interface for CRC errors or input errors (admin UI > WAN stats).",
                "Contact your ISP if loss is present on the WAN side.",
                "On WiFi, try switching channels or bands to rule out interference.",
            ],
            &[],
        ),
        rec(
            "rec.captive_portal",
            "Complete captive portal login",
            "You are connected to a network with a captive portal. Browsing and app traffic will fail until you authenticate.",
            &[
                "Open a browser and navigate to any http:// (not https://) page — the portal login page should appear.",
                "Complete the login, accept terms, or enter your room/ticket code.",
                "If the portal page doesn't open, try navigating to http://neverssl.com.",
                "For recurring portals (hotel, coffee shop): consider using your phone as a hotspot for sensitive work.",
                "For POS / IoT devices: captive portals are incompatible with automated systems — switch to a known-clean network.",
            ],
            &[],
        ),
    ]
}
