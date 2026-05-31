// macOS WiFi collector — Phase 2 will parse `airport -I`, `wdutil info`,
// `system_profiler SPAirPortDataType`, and `scutil --dns`.
//
// macOS 14+ requires Location Services permission to read SSID/BSSID;
// see https://developer.apple.com/forums/thread/732431.
