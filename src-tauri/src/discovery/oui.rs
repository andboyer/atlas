/// Tiny offline OUI lookup. Maps the upper 24 bits of a MAC (in normalized
/// "aa:bb:cc" form) to a vendor string. Curated for POS/IoT/AP vendors
/// most relevant to the troubleshooter's rules. Not exhaustive — full IEEE
/// OUI bundle is ~4 MB and overkill for v1.
pub fn vendor_for_mac(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(0..8)?; // "aa:bb:cc"
                                 // Some vendors use multiple prefixes; list each separately.
    match prefix {
        // ── POS terminals ──
        "00:1a:7d" | "c0:c1:c0" | "f0:fe:6b" | "5c:e9:1e" => Some("Clover Network"),
        "44:65:0d" | "f8:d1:11" | "08:dd:b1" => Some("Square / Block"),
        "00:08:74" | "00:1f:81" => Some("Verifone"),
        "00:1c:c0" | "00:1b:67" => Some("Ingenico"),
        "00:0b:fd" => Some("Cisco / Toast hardware"),
        // ── IP cameras ──
        "ec:71:db" | "ec:fa:bc" | "9c:8e:cd" => Some("Reolink"),
        "00:0c:43" | "28:57:be" | "44:19:b6" | "c0:51:7e" => Some("Hikvision"),
        "00:40:8c" | "ac:cc:8e" | "b8:a4:4f" => Some("Axis Communications"),
        "00:12:fb" | "00:1b:b4" => Some("Dahua"),
        "00:30:8c" | "00:50:43" => Some("Mobotix"),
        "2c:aa:8e" | "44:65:0c" | "78:a5:dd" => Some("Wyze"),
        "70:ee:50" | "00:17:88" => Some("Philips Hue"),
        "44:67:55" | "70:1d:5a" => Some("Eufy / Anker"),
        "ec:1b:bd" | "1c:90:ff" | "78:11:dc" => Some("Ring / Amazon"),
        // ── Voice / smart-home / streaming ──
        "00:0d:4b" | "08:00:71" | "ac:3a:7a" | "b8:3e:59" => Some("Roku"),
        "f0:f6:c1" | "fc:64:ba" | "68:54:fd" | "84:d6:d0" | "f0:27:2d" | "0c:47:c9" => {
            Some("Amazon")
        }
        "f4:f5:d8" | "f4:f5:e8" | "18:b4:30" | "20:df:b9" | "30:fd:38" | "6c:ad:f8" => {
            Some("Google / Nest")
        }
        "ec:1a:59" | "50:c7:bf" | "98:da:c4" | "d8:0d:17" | "b0:4e:26" => Some("TP-Link / Tapo"),
        "5c:cf:7f" | "84:0d:8e" | "a0:20:a6" | "e8:db:84" => Some("Espressif (ESP)"),
        "d4:a6:51" | "70:b3:d5" | "10:52:1c" => Some("Tuya / generic IoT"),
        "00:24:e4" | "a4:cf:12" => Some("Withings / Health"),
        "5c:aa:fd" | "94:9f:3e" | "b8:e9:37" | "00:0e:58" => Some("Sonos"),
        "00:17:ab" | "98:b6:e9" | "7c:bb:8a" => Some("Nintendo"),
        "00:1d:0f" | "7c:ed:8d" | "00:13:a9" | "fc:f1:36" | "f8:46:1c" => Some("Sony"),
        "00:21:9b" | "9c:8e:99" | "a0:48:1c" => Some("Microsoft / Xbox"),
        // ── Printers ──
        "00:80:77" | "ac:18:26" | "d4:9d:c0" | "a4:ee:57" | "9c:ae:d3" => Some("Epson"),
        "00:21:5a" | "30:cd:a7" | "84:25:3f" | "94:57:a5" | "e4:e7:49" | "f8:b4:6a" => Some("HP"),
        "00:00:48" | "00:21:b7" | "30:8a:b2" => Some("Lexmark"),
        "00:00:85" | "00:80:92" | "8c:71:f8" => Some("Brother"),
        // ── Routers / APs / network gear ──
        "78:8a:20" | "f0:9f:c2" | "a4:2b:b0" | "fc:ec:da" | "74:ac:b9" | "dc:9f:db"
        | "ac:8b:a9" | "e0:63:da" | "68:d7:9a" | "44:d9:e7" => Some("Ubiquiti"),
        "00:24:b2" | "00:0d:b9" | "94:b4:0f" | "20:4c:03" => Some("Aruba / HPE"),
        "00:1d:7e" | "ec:c8:82" | "88:15:44" | "e0:55:3d" | "00:18:0a" => Some("Cisco / Meraki"),
        "70:bc:10" | "00:24:a5" => Some("Synology"),
        "60:38:e0" | "30:9c:23" => Some("Belkin / Linksys"),
        "c0:56:27" | "fc:34:97" | "e8:cc:18" | "60:32:b1" => Some("Netgear"),
        "00:14:bf" | "1c:b7:2c" | "10:0d:7f" => Some("Asus"),
        "f4:cf:e2" | "1c:6f:65" => Some("Mikrotik"),
        // ── Apple ──
        "98:42:65" | "9c:b6:d0" | "3c:5a:b4" | "a4:5e:60" | "ec:35:86" | "f0:18:98"
        | "78:7e:61" | "b8:e8:56" | "f4:0f:24" | "a8:96:8a" | "70:cd:60" | "ac:bc:32"
        | "5c:f5:da" | "d0:81:7a" | "a8:5b:78" | "f0:db:e2" | "00:23:12" | "00:25:00"
        | "04:0c:ce" | "10:9a:dd" | "14:99:e2" | "20:c9:d0" | "28:cf:e9" | "34:51:c9"
        | "44:fb:42" | "48:43:7c" | "4c:8d:79" | "5c:96:9d" | "6c:70:9f" | "78:31:c1"
        | "80:e6:50" | "88:1f:a1" | "a4:b1:97" | "ac:7f:3e" | "b8:09:8a" | "c8:69:cd"
        | "d4:dc:cd" | "dc:2b:61" | "e0:f8:47" | "f4:5c:89" | "fc:25:3f" => Some("Apple"),
        // ── Samsung ──
        "00:15:b9" | "00:1b:98" | "00:1d:f6" | "00:21:19" | "00:24:54" | "08:08:c2"
        | "1c:62:b8" | "28:39:5e" | "34:23:ba" | "40:0e:85" | "5c:a3:9d" | "84:25:db"
        | "b4:79:a7" | "c8:14:79" | "dc:ee:06" | "e8:50:8b" | "f0:25:b7" => Some("Samsung"),
        // ── Common laptop / phone NIC vendors ──
        "fc:f8:ae" | "04:d4:c4" | "0c:54:15" | "34:13:e8" | "98:fa:9b" | "ac:fd:ce"
        | "c8:f7:50" | "e4:42:a6" => Some("Intel"),
        "8c:dc:d4" | "a4:db:30" => Some("Dell"),
        "00:25:b3" | "08:00:2b" | "3c:d9:2b" => Some("Hewlett-Packard"),
        "00:21:cc" | "00:24:7e" | "44:8a:5b" | "54:bf:64" => Some("Lenovo"),
        "00:1e:c2" | "00:26:08" => Some("Apple Airport"),
        "00:50:f2" => Some("Microsoft"),
        "00:09:5b" => Some("Netgear"),
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
