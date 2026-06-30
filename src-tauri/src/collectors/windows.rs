use super::WifiCollector;
use crate::process_util::NoConsoleExt;
use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;

pub struct WindowsCollector;

#[async_trait]
impl WifiCollector for WindowsCollector {
    async fn link_stats(&self) -> Result<LinkStats> {
        let out = Command::new("netsh")
            .no_console()
            .args(["wlan", "show", "interfaces"])
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut link = parse_netsh_interfaces(&stdout);
        // `netsh` doesn't expose the channel width, so fill it from the
        // native WLAN API (Win11 22H2+). Best-effort — leaves `None` on
        // older Windows or if the adapter is disconnected.
        if link.channel_width_mhz.is_none() {
            link.channel_width_mhz = wlan::channel_width_mhz();
        }
        Ok(link)
    }

    async fn reachability(&self, iface: Option<&str>) -> Result<ReachabilityStats> {
        crate::probes::reachability::collect(iface).await
    }
}

/// Extract the value from a `netsh` line of the form `    KEY    : value`.
/// Uses ` : ` as the separator so MAC addresses (containing `:`) are preserved.
fn field(s: &str, key: &str) -> Option<String> {
    s.lines()
        .find(|l| {
            let t = l.trim_start();
            t.starts_with(key) && t[key.len()..].trim_start().starts_with(':')
        })
        .and_then(|l| l.find(" : ").map(|i| l[i + 3..].trim().to_string()))
        .filter(|v| !v.is_empty())
}

fn parse_netsh_interfaces(s: &str) -> LinkStats {
    let ssid = field(s, "SSID");
    let bssid = field(s, "BSSID");
    let channel: Option<u32> = field(s, "Channel").and_then(|v| v.parse().ok());

    // Windows reports signal as a percentage; approximate dBm: (pct / 2) - 100
    let rssi_dbm = field(s, "Signal")
        .as_deref()
        .and_then(|v| v.trim_end_matches('%').parse::<i32>().ok())
        .map(|p| (p / 2) - 100);

    let tx_rate = field(s, "Transmit rate (Mbps)").and_then(|v| v.parse::<f32>().ok());
    let rx_rate = field(s, "Receive rate (Mbps)").and_then(|v| v.parse::<f32>().ok());
    let security = field(s, "Authentication");

    let band = field(s, "Band").map(|b| match b.as_str() {
        "2.4 GHz" => "2.4".to_string(),
        "5 GHz" => "5".to_string(),
        "6 GHz" => "6".to_string(),
        other => other.to_string(),
    });

    // `Radio type` is netsh's PHY mode column: "802.11ac" / "802.11ax" /
    // "802.11be" / "802.11n" etc. Normalise to a short suffix ("ac", "ax",
    // "be", "n") so it matches the macOS collector's convention.
    let phy_mode = field(s, "Radio type").map(|v| {
        v.trim()
            .strip_prefix("802.11")
            .map(|s| s.to_string())
            .unwrap_or(v)
    });

    let wifi_generation = derive_generation(phy_mode.as_deref(), band.as_deref());
    let vendor = bssid
        .as_deref()
        .and_then(crate::oui::lookup)
        .map(|s| s.to_string());

    LinkStats {
        ssid,
        bssid,
        band,
        channel,
        channel_width_mhz: None, // not in netsh; filled from WLAN API in link_stats()
        rssi_dbm,
        noise_dbm: None,
        snr_db: None,
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: rx_rate,
        security,
        phy_mode,
        wifi_generation,
        vendor,
    }
}

/// Map (PHY mode, band) → marketing Wi-Fi generation. `phy_mode` is the
/// short suffix from `parse_netsh_interfaces` ("ax", "ac", "be", "n", "g",
/// "a"); `band` is "2.4" / "5" / "6".
fn derive_generation(phy_mode: Option<&str>, band: Option<&str>) -> Option<String> {
    let p = phy_mode?.to_lowercase();
    let p = p.trim();
    Some(match (p, band) {
        ("be", _) => "Wi-Fi 7".into(),
        ("ax", Some("6")) => "Wi-Fi 6E".into(),
        ("ax", _) => "Wi-Fi 6".into(),
        ("ac", _) => "Wi-Fi 5".into(),
        ("n", _) => "Wi-Fi 4".into(),
        ("g" | "a", _) => "Wi-Fi 3".into(),
        ("b", _) => "Wi-Fi 1".into(),
        _ => return None,
    })
}

/// Native WLAN API access for data `netsh` doesn't surface.
///
/// Channel width is only reliably available via
/// `WlanQueryInterface(wlan_intf_opcode_realtime_connection_quality)`,
/// which returns a `WLAN_REALTIME_CONNECTION_QUALITY` whose per-link
/// `ulBandwidth` field is the channel width in MHz. That opcode requires
/// Windows 11, version 22H2 or later; on anything older the query fails
/// and we return `None` (callers keep `channel_width_mhz: None`).
///
/// FFI is declared locally and linked against `wlanapi.lib` (ships with
/// the Windows SDK), so this needs no extra crate features. All struct
/// offsets assume the x64 ABI.
mod wlan {
    use std::os::raw::c_void;

    type Handle = isize;
    type Dword = u32;

    /// `wlan_intf_opcode_realtime_connection_quality` (19th autoconf
    /// opcode; not yet a named constant in older `windows-sys`).
    const WLAN_INTF_OPCODE_REALTIME_CONNECTION_QUALITY: i32 = 19;
    /// `wlan_interface_state_connected`.
    const WLAN_INTERFACE_STATE_CONNECTED: i32 = 1;
    /// `WLAN_API_VERSION_2_0`.
    const WLAN_API_VERSION_2_0: Dword = 0x0000_0002;

    #[repr(C)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }

    #[repr(C)]
    struct WlanInterfaceInfo {
        guid: Guid,
        description: [u16; 256],
        state: i32,
    }

    #[repr(C)]
    struct WlanInterfaceInfoList {
        num: Dword,
        index: Dword,
        // ANYSIZE_ARRAY of WlanInterfaceInfo follows contiguously.
        first: WlanInterfaceInfo,
    }

    #[link(name = "wlanapi")]
    extern "system" {
        fn WlanOpenHandle(
            client_version: Dword,
            reserved: *const c_void,
            negotiated_version: *mut Dword,
            client_handle: *mut Handle,
        ) -> Dword;
        fn WlanCloseHandle(client_handle: Handle, reserved: *const c_void) -> Dword;
        fn WlanEnumInterfaces(
            client_handle: Handle,
            reserved: *const c_void,
            interface_list: *mut *mut WlanInterfaceInfoList,
        ) -> Dword;
        fn WlanQueryInterface(
            client_handle: Handle,
            interface_guid: *const Guid,
            opcode: i32,
            reserved: *const c_void,
            data_size: *mut Dword,
            data: *mut *mut c_void,
            opcode_value_type: *mut i32,
        ) -> Dword;
        fn WlanFreeMemory(memory: *const c_void);
    }

    /// Channel width (MHz) of the first connected Wi-Fi adapter, or `None`.
    pub fn channel_width_mhz() -> Option<u32> {
        unsafe {
            let mut handle: Handle = 0;
            let mut negotiated: Dword = 0;
            if WlanOpenHandle(
                WLAN_API_VERSION_2_0,
                std::ptr::null(),
                &mut negotiated,
                &mut handle,
            ) != 0
            {
                return None;
            }
            let width = query_connected(handle);
            WlanCloseHandle(handle, std::ptr::null());
            width
        }
    }

    unsafe fn query_connected(handle: Handle) -> Option<u32> {
        let mut list: *mut WlanInterfaceInfoList = std::ptr::null_mut();
        if WlanEnumInterfaces(handle, std::ptr::null(), &mut list) != 0 || list.is_null() {
            return None;
        }
        let count = (*list).num as usize;
        let base = std::ptr::addr_of!((*list).first);
        let mut result = None;
        for i in 0..count {
            let info = &*base.add(i);
            if info.state != WLAN_INTERFACE_STATE_CONNECTED {
                continue;
            }
            if let Some(bw) = realtime_bandwidth(handle, &info.guid) {
                result = Some(bw);
                break;
            }
        }
        WlanFreeMemory(list as *const c_void);
        result
    }

    unsafe fn realtime_bandwidth(handle: Handle, guid: &Guid) -> Option<u32> {
        let mut size: Dword = 0;
        let mut data: *mut c_void = std::ptr::null_mut();
        let rc = WlanQueryInterface(
            handle,
            guid,
            WLAN_INTF_OPCODE_REALTIME_CONNECTION_QUALITY,
            std::ptr::null(),
            &mut size,
            &mut data,
            std::ptr::null_mut(),
        );
        if rc != 0 || data.is_null() {
            return None;
        }
        // WLAN_REALTIME_CONNECTION_QUALITY (x64 offsets):
        //   0  dwVersion            8  ulLinkQuality   16 ulTxRate
        //   4  dwPhyType           12  ulRxRate        20 bIsMultiLinkAdapter
        //   24 ulNumLinks          28 linksInfo[0]
        // each WLAN_..._LINK_INFO: ulLinkID(+0) lRssi(+4)
        //   ulChannelCenterFrequencyMhz(+8) ulBandwidth(+12)
        // → link[0].ulBandwidth lives at byte offset 40.
        let bw = if size >= 44 {
            let bytes = data as *const u8;
            let num_links = read_u32(bytes, 24);
            if num_links >= 1 {
                let v = read_u32(bytes, 40);
                // Sanity-gate against garbage from a struct-layout mismatch:
                // real 802.11 channel widths are 20–320 MHz.
                if (20..=320).contains(&v) {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        WlanFreeMemory(data);
        bw
    }

    unsafe fn read_u32(base: *const u8, off: usize) -> u32 {
        let mut b = [0u8; 4];
        std::ptr::copy_nonoverlapping(base.add(off), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &str = "\
\r\nThere is 1 interface on the system:\r\n\
\r\n    Name                   : Wi-Fi\r\n\
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz\r\n\
    GUID                   : abcdefab-cdef-abcd-efab-cdefabcdefab\r\n\
    Physical address       : a4:c3:f0:11:22:33\r\n\
    State                  : connected\r\n\
    SSID                   : MyNetwork\r\n\
    BSSID                  : 74:ac:b9:aa:bb:cc\r\n\
    Network type           : Infrastructure\r\n\
    Radio type             : 802.11ac\r\n\
    Authentication         : WPA2-Personal\r\n\
    Cipher                 : CCMP\r\n\
    Connection mode        : Auto Connect\r\n\
    Band                   : 5 GHz\r\n\
    Channel                : 36\r\n\
    Receive rate (Mbps)    : 400.0\r\n\
    Transmit rate (Mbps)   : 400.0\r\n\
    Signal                 : 72%\r\n\
    Profile                : MyNetwork\r\n";

    #[test]
    fn parses_all_fields() {
        let link = parse_netsh_interfaces(SAMPLE);
        assert_eq!(link.ssid.as_deref(), Some("MyNetwork"));
        assert_eq!(link.bssid.as_deref(), Some("74:ac:b9:aa:bb:cc"));
        assert_eq!(link.channel, Some(36));
        assert_eq!(link.band.as_deref(), Some("5"));
        assert_eq!(link.rssi_dbm, Some(-64)); // 72/2 - 100
        assert_eq!(link.tx_rate_mbps, Some(400.0));
        assert_eq!(link.rx_rate_mbps, Some(400.0));
        assert_eq!(link.security.as_deref(), Some("WPA2-Personal"));
    }

    #[test]
    fn ssid_does_not_bleed_into_bssid() {
        // "BSSID" starts_with "SSID" prefix check must not fire
        let link = parse_netsh_interfaces(SAMPLE);
        assert_ne!(link.ssid.as_deref(), Some("74:ac:b9:aa:bb:cc"));
        assert_ne!(link.bssid.as_deref(), Some("MyNetwork"));
    }

    #[test]
    fn derives_wifi5_phy_mode() {
        let link = parse_netsh_interfaces(SAMPLE);
        assert_eq!(link.phy_mode.as_deref(), Some("ac"));
        assert_eq!(link.wifi_generation.as_deref(), Some("Wi-Fi 5"));
    }

    #[test]
    fn derive_generation_table() {
        assert_eq!(
            derive_generation(Some("ax"), Some("6")).as_deref(),
            Some("Wi-Fi 6E")
        );
        assert_eq!(
            derive_generation(Some("ax"), Some("5")).as_deref(),
            Some("Wi-Fi 6")
        );
        assert_eq!(
            derive_generation(Some("be"), Some("6")).as_deref(),
            Some("Wi-Fi 7")
        );
        assert_eq!(
            derive_generation(Some("n"), Some("2.4")).as_deref(),
            Some("Wi-Fi 4")
        );
        assert_eq!(derive_generation(None, Some("5")), None);
    }
}
