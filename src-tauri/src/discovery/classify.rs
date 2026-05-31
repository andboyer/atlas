use crate::types::DeviceClass;

/// Classify a device by hints we have: vendor (from OUI) and hostname.
/// Phase 2 will also consume mDNS service strings and HTTP banners.
pub fn classify(vendor: Option<&str>, hostname: Option<&str>) -> DeviceClass {
    let hostname_lc = hostname.map(|s| s.to_ascii_lowercase()).unwrap_or_default();

    if let Some(v) = vendor {
        let vl = v.to_ascii_lowercase();
        if vl.contains("clover")
            || vl.contains("square / block")
            || vl.contains("verifone")
            || vl.contains("ingenico")
            || vl.contains("toast")
        {
            return DeviceClass::PosTerminal;
        }
        if vl.contains("reolink")
            || vl.contains("hikvision")
            || vl.contains("axis")
            || vl.contains("dahua")
            || vl.contains("mobotix")
        {
            return DeviceClass::IpCamera;
        }
        if vl.contains("philips hue")
            || vl.contains("tp-link")
            || vl.contains("tuya")
            || vl.contains("espressif")
        {
            return DeviceClass::SmartHome;
        }
        if vl.contains("epson") || vl.contains("hp") {
            return DeviceClass::Printer;
        }
        if vl.contains("ubiquiti")
            || vl.contains("aruba")
            || vl.contains("meraki")
            || vl.contains("linksys")
        {
            return DeviceClass::RouterAp;
        }
        if vl.contains("roku") {
            return DeviceClass::TvStreamer;
        }
        if vl.contains("amazon") {
            return DeviceClass::VoiceAssistant;
        }
        if vl.contains("google nest") || vl.contains("withings") {
            return DeviceClass::SmartHome;
        }
        if vl.contains("synology") {
            return DeviceClass::Nas;
        }
        if vl.contains("apple") {
            // Could be phone, tablet, or laptop; default to phone unless hostname says otherwise.
            if hostname_lc.contains("macbook") || hostname_lc.contains("imac") {
                return DeviceClass::Laptop;
            }
            return DeviceClass::Phone;
        }
    }

    // Hostname-based hints.
    if !hostname_lc.is_empty() {
        if hostname_lc.contains("clover")
            || hostname_lc.contains("pos")
            || hostname_lc.contains("register")
            || hostname_lc.contains("terminal")
        {
            return DeviceClass::PosTerminal;
        }
        if hostname_lc.contains("camera") || hostname_lc.contains("cam-") {
            return DeviceClass::IpCamera;
        }
        if hostname_lc.contains("printer") || hostname_lc.contains("epson") {
            return DeviceClass::Printer;
        }
        if hostname_lc.contains("router") || hostname_lc.contains("gateway") {
            return DeviceClass::RouterAp;
        }
        if hostname_lc.contains("nas") {
            return DeviceClass::Nas;
        }
        if hostname_lc.contains("bulb") || hostname_lc.contains("plug") {
            return DeviceClass::SmartHome;
        }
        if hostname_lc.contains("echo") || hostname_lc.contains("alexa") {
            return DeviceClass::VoiceAssistant;
        }
        if hostname_lc.contains("roku") || hostname_lc.contains("appletv") {
            return DeviceClass::TvStreamer;
        }
    }

    DeviceClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_clover_by_vendor() {
        assert!(matches!(
            classify(Some("Clover Network"), None),
            DeviceClass::PosTerminal
        ));
    }

    #[test]
    fn classifies_camera_by_hostname() {
        assert!(matches!(
            classify(None, Some("front-camera.local")),
            DeviceClass::IpCamera
        ));
    }

    #[test]
    fn unknown_when_no_hints() {
        assert!(matches!(classify(None, None), DeviceClass::Unknown));
    }
}
