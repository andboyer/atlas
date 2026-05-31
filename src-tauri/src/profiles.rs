//! Industry profile presets that tune thresholds and default targets for the
//! detection engine.

/// Default POS / SaaS endpoints to probe when the Retail POS profile is active.
/// These are the common payment-processor and POS-vendor hostnames that, when
/// unreachable, will cause terminal failures during business hours.
pub const RETAIL_POS_TARGETS: &[&str] = &[
    "api.clover.com:443",
    "connect.squareup.com:443",
    "ws-api.toasttab.com:443",
    "api.toasttab.com:443",
    "api.stripe.com:443",
    "secure.paypal.com:443",
    "us.api.poynt.net:443",
];

/// Default targets for the Smart Home profile.  These are common cloud
/// endpoints that smart-home devices depend on; intermittent reachability
/// here often correlates with IoT dropouts.
pub const SMART_HOME_TARGETS: &[&str] = &[
    "alexa.amazon.com:443",
    "home.nest.com:443",
    "iot.us-east-1.amazonaws.com:443",
    "mqtt-api.tuya.com:443",
];

/// Default targets for the Small Office profile.
pub const OFFICE_TARGETS: &[&str] = &[
    "outlook.office365.com:443",
    "teams.microsoft.com:443",
    "slack.com:443",
    "zoom.us:443",
    "github.com:443",
];

/// Return the default `pos_targets` list for a given profile id.
pub fn default_targets_for(profile: &str) -> Vec<String> {
    let list: &[&str] = match profile {
        "retail_pos" => RETAIL_POS_TARGETS,
        "smart_home" => SMART_HOME_TARGETS,
        "office" => OFFICE_TARGETS,
        _ => &[],
    };
    list.iter().map(|s| s.to_string()).collect()
}

/// Maximum acceptable round-trip latency (ms) to a watched SaaS endpoint
/// before we fire `pos.processor_high_latency`. Profile-dependent because POS
/// terminals are more latency-sensitive than e.g. office VPN.
pub fn high_latency_threshold_ms(profile: &str) -> f32 {
    match profile {
        "retail_pos" => 600.0,
        "smart_home" => 1500.0,
        "office" => 800.0,
        _ => 1000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retail_pos_includes_clover_square_toast() {
        let t = default_targets_for("retail_pos");
        assert!(t.iter().any(|s| s.contains("clover")));
        assert!(t.iter().any(|s| s.contains("squareup")));
        assert!(t.iter().any(|s| s.contains("toasttab")));
    }

    #[test]
    fn unknown_profile_returns_empty() {
        assert!(default_targets_for("home").is_empty());
        assert!(default_targets_for("xyz").is_empty());
    }

    #[test]
    fn retail_pos_has_strictest_latency() {
        assert!(high_latency_threshold_ms("retail_pos") < high_latency_threshold_ms("office"));
        assert!(high_latency_threshold_ms("office") < high_latency_threshold_ms("smart_home"));
    }
}
