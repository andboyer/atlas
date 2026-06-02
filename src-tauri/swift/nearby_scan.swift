// nearby_scan — macOS CoreWLAN sidecar.
//
// Modern macOS (Sonoma+) no longer emits `Signal / Noise:` lines for nearby
// access points in `system_profiler SPAirPortDataType`. Only the connected
// AP retains that field. As a result, every entry in the "Other Local Wi-Fi
// Networks:" block comes back with rssi_dbm=null, which causes the spectrum
// map to render every AP at the chart floor (a flat -100 dBm baseline).
//
// CoreWLAN still exposes real RSSI for nearby networks via
// `CWInterface.scanForNetworks(withSSID:)`. SSIDs may come back as nil
// without Location Services authorization — we tolerate that and emit
// `<hidden>` — but the RSSI / channel / band / width are always present,
// which is all the spectrum chart needs.
//
// Output format: one network per line, TAB-separated:
//   ssid \t bssid \t channel \t band \t width_mhz \t rssi_dbm
//
// (phy_mode and security are intentionally omitted — `CWNetwork` doesn't
//  expose them as scalar properties on modern CoreWLAN. system_profiler
//  is fine for those slow-changing fields; the spectrum chart only needs
//  RSSI / channel / width / band.)
//
// Exit codes:
//   0 — at least one network printed (or zero networks, scan succeeded)
//   1 — no Wi-Fi interface
//   2 — scan call threw

import CoreLocation
import CoreWLAN
import Foundation

// Request Location Services authorization. Without this, macOS will never
// enroll the helper (and by extension the parent .app) in System Settings →
// Privacy & Security → Location Services, and `CWNetwork.ssid` will always
// come back nil ("<hidden>").
//
// CLLocationManager requires:
//   (1) an Info.plist on the calling process that declares
//       NSLocationWhenInUseUsageDescription — for this CLI helper we embed
//       one via `swiftc -sectcreate __TEXT __info_plist .../nearby_scan-Info.plist`
//       (see build.rs). Without the embedded plist the system silently
//       refuses to show the prompt.
//   (2) a live CFRunLoop on the main thread so the system UI can deliver
//       the prompt and the delegate callback. Blocking the main thread with
//       a DispatchSemaphore prevents the prompt from appearing.
//
// We spin the runloop for up to 30 seconds so the user has time to interact
// with the dialog; we exit immediately when the delegate confirms the
// authorization status has settled. After grant, subsequent runs return
// .authorizedAlways/.authorizedWhenInUse immediately without showing UI.
final class LocationGate: NSObject, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    var didSettle = false

    func request() -> CLAuthorizationStatus {
        manager.delegate = self
        let initial = manager.authorizationStatus
        if initial != .notDetermined {
            return initial
        }
        manager.requestWhenInUseAuthorization()

        // Spin the main runloop so the system can present the prompt and
        // deliver the delegate callback. Bail as soon as the delegate fires
        // (didSettle = true) or after the deadline, whichever comes first.
        let deadline = Date().addingTimeInterval(30.0)
        while !didSettle && Date() < deadline {
            RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.25))
        }
        return manager.authorizationStatus
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        if !didSettle {
            didSettle = true
        }
    }
}

let gate = LocationGate()
let finalStatus = gate.request()
FileHandle.standardError.write(
    "nearby_scan: CLLocationManager.authorizationStatus = \(finalStatus.rawValue) (.notDetermined=0 .restricted=1 .denied=2 .authorizedAlways=3 .authorizedWhenInUse=4)\n"
        .data(using: .utf8) ?? Data())

func bandString(_ ch: CWChannel?) -> String {
  guard let band = ch?.channelBand else { return "" }
  switch band {
  case .band2GHz: return "2.4"
  case .band5GHz: return "5"
  case .band6GHz: return "6"
  case .bandUnknown: return ""
  @unknown default: return ""
  }
}

func widthMHz(_ ch: CWChannel?) -> Int {
  guard let w = ch?.channelWidth else { return 0 }
  switch w {
  case .width20MHz: return 20
  case .width40MHz: return 40
  case .width80MHz: return 80
  case .width160MHz: return 160
  case .widthUnknown: return 0
  @unknown default: return 0
  }
}

func sanitize(_ s: String) -> String {
  // Tabs and newlines break our line-oriented protocol; replace with a space.
  return s.replacingOccurrences(of: "\t", with: " ")
    .replacingOccurrences(of: "\n", with: " ")
    .replacingOccurrences(of: "\r", with: " ")
}

let client = CWWiFiClient.shared()
guard let iface = client.interface() else {
  FileHandle.standardError.write("no_interface\n".data(using: .utf8)!)
  exit(1)
}

do {
  let networks = try iface.scanForNetworks(withSSID: nil)
  for n in networks {
    let ssid = sanitize(n.ssid ?? "<hidden>")
    let bssid = sanitize(n.bssid ?? "")
    let ch = n.wlanChannel?.channelNumber ?? 0
    let band = bandString(n.wlanChannel)
    let width = widthMHz(n.wlanChannel)
    let rssi = n.rssiValue
    print("\(ssid)\t\(bssid)\t\(ch)\t\(band)\t\(width)\t\(rssi)")
  }
  exit(0)
} catch {
  FileHandle.standardError.write("scan_error: \(error)\n".data(using: .utf8)!)
  exit(2)
}
