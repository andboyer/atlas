/// Tiny offline OUI lookup. Maps the upper 24 bits of a MAC (in normalized
/// "aa:bb:cc" form) to a vendor string. Curated for POS/IoT/AP vendors
/// most relevant to the troubleshooter's rules. Not exhaustive — full IEEE
/// OUI bundle is ~4 MB and overkill for v1.
pub fn vendor_for_mac(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(0..8)?; // "aa:bb:cc"
                                 // Some vendors use multiple prefixes; list each separately.
    match prefix {
        // POS terminals
        "00:1a:7d" | "c0:c1:c0" | "f0:fe:6b" | "5c:e9:1e" => Some("Clover Network"),
        "44:65:0d" | "f8:d1:11" | "08:dd:b1" => Some("Square / Block"),
        "00:08:74" | "00:1f:81" => Some("Verifone"),
        "00:1c:c0" | "00:1b:67" => Some("Ingenico"),
        "00:0b:fd" => Some("Cisco / Toast hardware"),
        // IP cameras
        "ec:71:db" | "ec:fa:bc" | "9c:8e:cd" => Some("Reolink"),
        "00:0c:43" | "28:57:be" | "44:19:b6" | "c0:51:7e" => Some("Hikvision"),
        "00:40:8c" | "ac:cc:8e" | "b8:a4:4f" => Some("Axis Communications"),
        "00:12:fb" | "00:1b:b4" => Some("Dahua"),
        "00:30:8c" | "00:50:43" => Some("Mobotix"),
        // Voice / smart-home
        "00:0d:4b" | "08:00:71" => Some("Roku"),
        "f0:f6:c1" | "fc:64:ba" => Some("Amazon"),
        "f4:f5:d8" | "f4:f5:e8" | "18:b4:30" => Some("Google Nest"),
        "ec:1a:59" | "50:c7:bf" | "98:da:c4" => Some("TP-Link / Tapo"),
        "70:ee:50" | "00:17:88" => Some("Philips Hue"),
        "5c:cf:7f" | "84:0d:8e" | "a0:20:a6" => Some("Espressif (ESP)"),
        "d4:a6:51" | "70:b3:d5" | "10:52:1c" => Some("Tuya / generic IoT"),
        "00:24:e4" | "a4:cf:12" => Some("Withings / Health"),
        // Printers
        "00:80:77" | "ac:18:26" | "d4:9d:c0" => Some("Epson"),
        "00:21:5a" | "30:cd:a7" | "84:25:3f" => Some("HP"),
        // Routers / APs
        "78:8a:20" | "f0:9f:c2" | "a4:2b:b0" | "fc:ec:da" => Some("Ubiquiti"),
        "00:24:b2" | "00:0d:b9" => Some("Aruba / HPE"),
        "00:1d:7e" | "ec:c8:82" => Some("Cisco / Meraki"),
        "70:bc:10" | "00:24:a5" => Some("Synology"),
        "60:38:e0" | "30:9c:23" => Some("Belkin / Linksys"),
        "98:42:65" | "9c:b6:d0" => Some("Apple"),
        // Phones / laptops (a few common ones; not exhaustive)
        "3c:5a:b4" | "a4:5e:60" | "ec:35:86" => Some("Apple"),
        "fc:f8:ae" => Some("Intel"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_known_clover_prefix() {
        assert_eq!(vendor_for_mac("00:1a:7d:da:71:11"), Some("Clover Network"));
    }

    #[test]
    fn unknown_prefix_returns_none() {
        assert_eq!(vendor_for_mac("ff:ff:ff:00:00:01"), None);
    }
}
