//! OUI (Organisationally Unique Identifier) → vendor lookup.
//!
//! A small built-in table of the most common WiFi access-point + networking
//! gear vendors. This is **not** a complete IEEE registry — for a full lookup
//! we would need to ship the ~30 MB OUI database, which is overkill for our
//! UX (vendor labelling in nearby AP lists and rogue-AP findings).
//!
//! Prefix matching uses the first 3 octets (24-bit OUI) of the BSSID,
//! lowercased and stripped of separators.

/// Lookup a vendor by BSSID prefix. Returns `None` if not in the built-in
/// table. Input may be in any common BSSID notation (colon, hyphen, dot).
pub fn lookup(bssid: &str) -> Option<&'static str> {
    let cleaned: String = bssid
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.len() != 6 {
        return None;
    }
    OUI_TABLE
        .iter()
        .find(|(prefix, _)| *prefix == cleaned.as_str())
        .map(|(_, name)| *name)
}

/// Static OUI → vendor mapping. Lower-case, no separators. Curated for the
/// vendors most likely to appear on a home / SMB / retail WiFi.
#[rustfmt::skip]
const OUI_TABLE: &[(&str, &str)] = &[
    // Apple
    ("3c0754", "Apple"), ("a4d18c", "Apple"), ("d8d1cb", "Apple"), ("a42bb0", "Apple"),
    ("88665a", "Apple"), ("f0989d", "Apple"), ("c869cd", "Apple"), ("8c8590", "Apple"),
    ("e0acf1", "Apple"),
    // Ubiquiti
    ("002722", "Ubiquiti"), ("0418d6", "Ubiquiti"), ("245a4c", "Ubiquiti"),
    ("44d9e7", "Ubiquiti"), ("687251", "Ubiquiti"), ("74acb9", "Ubiquiti"),
    ("78458c", "Ubiquiti"), ("802aa8", "Ubiquiti"), ("b4fbe4", "Ubiquiti"),
    ("dc9fdb", "Ubiquiti"), ("e063da", "Ubiquiti"), ("f09fc2", "Ubiquiti"),
    // Cisco Meraki
    ("00180a", "Cisco Meraki"), ("88154f", "Cisco Meraki"), ("e0cb4e", "Cisco Meraki"),
    ("ac1741", "Cisco Meraki"), ("e0553d", "Cisco Meraki"), ("3c2c30", "Cisco Meraki"),
    // Cisco (non-Meraki)
    ("001a2f", "Cisco"), ("0026cb", "Cisco"), ("002584", "Cisco"), ("44d3ca", "Cisco"),
    ("70b3d5", "Cisco"), ("e8b748", "Cisco"), ("70df2f", "Cisco"),
    // Aruba / HPE
    ("000b86", "Aruba"), ("24deca", "Aruba"), ("6cf37f", "Aruba"), ("9c1c12", "Aruba"),
    ("ac1614", "Aruba"), ("d8c7c8", "Aruba"),
    // Ruckus
    ("001392", "Ruckus"), ("002482", "Ruckus"), ("8caafd", "Ruckus"),
    // Eero (Amazon)
    ("84d6d0", "Eero"), ("a4a999", "Eero"), ("d4ad20", "Eero"), ("b0fc36", "Eero"),
    // Google / Nest WiFi
    ("18b430", "Google"), ("3c5ab4", "Google"), ("e4f042", "Google"), ("d8c4e9", "Google"),
    // Netgear
    ("000fb5", "Netgear"), ("009005", "Netgear"), ("28c68e", "Netgear"), ("44a56e", "Netgear"),
    ("9c3dcf", "Netgear"), ("a040a0", "Netgear"), ("c40415", "Netgear"),
    // TP-Link
    ("001947", "TP-Link"), ("1431b3", "TP-Link"), ("50bd5f", "TP-Link"), ("984fee", "TP-Link"),
    ("ec086b", "TP-Link"), ("c46e1f", "TP-Link"), ("a842a1", "TP-Link"), ("980ee4", "TP-Link"),
    // ASUS
    ("000c6e", "ASUS"), ("083e8e", "ASUS"), ("305a3a", "ASUS"), ("704d7b", "ASUS"),
    ("9c5c8e", "ASUS"), ("ac9e17", "ASUS"), ("bcee7b", "ASUS"),
    // Linksys / Belkin
    ("001839", "Linksys"), ("002129", "Linksys"), ("c0c1c0", "Linksys"),
    ("94103e", "Belkin"), ("ec1a59", "Belkin"),
    // D-Link
    ("001b11", "D-Link"), ("002191", "D-Link"), ("083e0c", "D-Link"), ("28107b", "D-Link"),
    // Xiaomi / Mi
    ("0c1dc2", "Xiaomi"), ("3480b3", "Xiaomi"), ("64cc2e", "Xiaomi"),
    // Huawei
    ("001882", "Huawei"), ("002568", "Huawei"), ("087a4c", "Huawei"), ("70723c", "Huawei"),
    // Samsung
    ("0008c7", "Samsung"), ("38b54d", "Samsung"), ("78bdbc", "Samsung"),
    // Motorola / Arris (common ISP gear)
    ("0026f3", "Arris"), ("44e137", "Arris"), ("80a062", "Arris"),
    // Technicolor (ATT, Comcast)
    ("001f9e", "Technicolor"), ("d4a928", "Technicolor"), ("c8b373", "Technicolor"),
    // Sagemcom
    ("002628", "Sagemcom"), ("442a60", "Sagemcom"), ("dcf8b9", "Sagemcom"),
    // MikroTik
    ("4c5e0c", "MikroTik"), ("64d154", "MikroTik"), ("c4ad34", "MikroTik"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_apple_oui() {
        assert_eq!(lookup("a4:2b:b0:11:22:33"), Some("Apple"));
        assert_eq!(lookup("A4-2B-B0-AA-BB-CC"), Some("Apple"));
    }

    #[test]
    fn returns_none_for_unknown_oui() {
        assert_eq!(lookup("11:22:33:44:55:66"), None);
    }

    #[test]
    fn handles_malformed_input() {
        assert_eq!(lookup(""), None);
        assert_eq!(lookup("zz:zz:zz"), None);
    }
}
