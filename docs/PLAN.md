# Atlas — Project Plan

## Goal
A cross-platform desktop app that continuously (or on-demand) collects WiFi
diagnostics, detects complex network issues using a hybrid AI approach, and
gives the user clear, actionable recommendations.

## Key Decisions (confirmed)
- **Platform**: Cross-platform desktop — macOS, Windows, Linux
- **Framework**: Tauri (Rust backend + web frontend)
- **Users**: Consumers, prosumers, and IT pros — selectable mode toggle
- **AI approach**: Hybrid — local rule-based/heuristic engine drives detection;
  optional cloud LLM (user-supplied key) generates plain-language explanations
  and follow-up Q&A

## High-Level Architecture

```
┌─────────────────────────────────────────────┐
│ Frontend (TypeScript + React + Tailwind)    │
│  - Dashboard, live charts, recommendations  │
│  - Mode toggle (Simple / Pro / Admin)       │
└──────────────────┬──────────────────────────┘
                   │ Tauri IPC
┌──────────────────┴──────────────────────────┐
│ Rust Backend (Tauri Core)                    │
│  ┌────────────────────────────────────────┐ │
│  │ Collectors (per-OS adapters)           │ │
│  │  macOS: airport, system_profiler, ping │ │
│  │  Win:   netsh wlan, Get-NetAdapter, … │ │
│  │  Linux: iw, iwconfig, nmcli, ip       │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ Active probes                          │ │
│  │  ping (latency/jitter/loss), DNS time, │ │
│  │  HTTP throughput, traceroute, MTU,     │ │
│  │  speedtest (optional)                  │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ Time-series store (SQLite + WAL)       │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ Detection engine                       │ │
│  │  - Rule engine (deterministic)         │ │
│  │  - Anomaly detection (z-score / EWMA   │ │
│  │    over rolling windows)               │ │
│  │  - Correlation across signals          │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ Recommendation engine                  │ │
│  │  - Rule → fix mapping                  │ │
│  │  - Optional LLM enrichment             │ │
│  └────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

## Signals We'll Collect

### Local device signals (the machine running the app)
- **Link layer**: SSID, BSSID, channel, channel width, band (2.4/5/6 GHz),
  RSSI, noise floor, SNR, PHY rate (Tx/Rx), MCS, security (WPA2/3),
  roaming events, retry rate, association events
- **Neighbor APs**: nearby BSSIDs + channels for co-channel/adjacent-channel
  congestion detection
- **IP/transport**: DHCP lease info, gateway, DNS servers, IPv4/IPv6 status,
  MTU, NAT type
- **Reachability**: ping to gateway / DNS / 1.1.1.1 / 8.8.8.8 — latency,
  jitter, loss
- **DNS**: resolve times for a curated set of hostnames
- **Throughput**: lightweight HTTP range download against a CDN, optional
  full speedtest
- **System**: VPN active?, captive portal?, proxy?, recent OS/driver updates

### Network-wide signals (other devices on the LAN)
- **Device discovery**: ARP sweep of local subnet(s), mDNS/Bonjour
  (`_services._dns-sd._udp`), SSDP/UPnP, NetBIOS, LLDP, DHCP snooping from
  passive sniff where possible.
- **Device fingerprinting**: MAC OUI lookup, mDNS service strings, SSDP
  device descriptors, HTTP banner on common ports, DHCP fingerprint
  (option 55 list). Identify class: POS terminal (Clover/Square/Toast/Aloha),
  IP camera, smart plug/bulb, thermostat, voice assistant, printer, NAS,
  game console, phone, laptop.
- **Per-device reachability**: rolling ICMP/TCP-SYN probe of each known
  device — uptime %, mean latency, loss, response variance.
- **Presence tracking**: track first-seen / last-seen / disconnect events
  per MAC, with timeline.
- **Traffic hints** (best-effort, no deep packet inspection): bytes-in/out
  per device if router SNMP/UPnP-IGD or local pcap is available
  (Admin-mode, opt-in).
- **DHCP health**: pool size vs leases in use (when router API or SNMP
  available), duplicate-IP detection via ARP, lease churn per MAC.
- **Multicast/mDNS load**: rate of mDNS announcements, IGMP groups — high
  rates cause IoT instability.

## Issues the Detection Engine Should Catch

### A. Local-link issues (this device)
1. Weak signal (RSSI < -70 dBm sustained) → move closer / add AP
2. Low SNR despite strong RSSI → noisy environment / interference
3. Channel congestion (≥N strong neighbor BSSIDs on same channel) → change
   channel; suggest specific best channel
4. 2.4 GHz overlap on non-1/6/11 channels
5. Sticky client (stuck on weak AP when stronger BSSID for same SSID is
   visible) → toggle WiFi / enable 802.11k/v on router
6. Repeated disassociation / roaming thrash
7. High retry rate + good RSSI → driver/firmware or interference
8. WPA2 vs WPA3 mismatch / PMF problems

### B. Internet / upstream
9.  Gateway latency low but internet latency high → ISP/upstream issue
10. DNS slow but ping fast → switch DNS, recommend 1.1.1.1 / 9.9.9.9
11. IPv6 misconfig (AAAA resolves but unreachable) → disable IPv6 or fix
    router
12. MTU/PMTUD blackhole (large pings drop, small succeed)
13. Captive portal detected but not completed
14. DHCP lease nearly expired / duplicate IP / 169.254.x.x
15. VPN-induced latency / DNS leak
16. Bufferbloat (latency spikes under load) → recommend SQM/QoS on router
17. Band steering misbehavior (device pinned to 2.4 with 5/6 available)

### C. Network-wide / other devices (IoT, POS, cameras, etc.)
18. **DHCP pool exhaustion** — leases ≥ ~90% of pool, new devices fail to
    join → expand pool / lower lease time.
19. **IP conflicts** — same IP responding from two MACs in ARP → static IP
    collision with DHCP range.
20. **AP client-count overload** — many devices on a single BSSID + rising
    retry/latency → add AP / split SSIDs by band.
21. **2.4 GHz-only device on a 2.4-congested channel** — common for IoT;
    recommend separate 2.4 GHz IoT SSID on a clean channel.
22. **mDNS/Bonjour storm** — high multicast rate correlates with IoT
    dropouts → enable IGMP/mDNS snooping on switch, segment IoT VLAN.
23. **Multicast-to-unicast conversion missing** on AP → streaming/cast
    devices stutter.
24. **Power-save / DTIM mismatch** — IoT devices in deep sleep miss
    beacons; recommend lowering DTIM or disabling aggressive power save
    on AP for IoT SSID.
25. **PMF/802.11w required but device doesn't support it** → IoT can't
    associate; offer compatibility SSID.
26. **Captive portal kicking re-auth** every N hours → POS / IoT lose
    sessions; recommend MAC bypass or removing portal for these devices.
27. **Guest-network isolation** blocking POS↔printer / phone↔Chromecast
    traffic.

### D. POS-specific (Clover, Square, Toast, Aloha, Lightspeed, Verifone)
28. **Terminal random disconnect during business hours** — correlate with:
    - RSSI dip at the counter location (heatmap from neighbor scan).
    - Channel utilization spikes (lots of customer phones at lunch rush).
    - Microwave interference on 2.4 GHz (kitchen adjacency, 2–3 min cycles
      on channels 6–11).
    - DHCP lease churn (short leases + busy network).
    - Captive portal re-auth.
    → Recommend: dedicated POS SSID on 5 GHz, hidden, MAC-allowlist, long
    DHCP lease, separate VLAN, AP positioned within line-of-sight of
    counter, fail-over to cellular dongle for terminals that support it.
29. **Payment processor reachability** — periodic TCP probe to
    `*.clover.com`, `*.squareup.com`, `*.toasttab.com` etc., and to
    common payment gateway endpoints; flag DNS or TLS handshake failures.
30. **Local LAN dependency broken** — POS terminal can't reach kitchen
    printer / KDS / cash drawer hub due to VLAN/isolation/ARP issue.
31. **Time sync drift** — NTP unreachable; payment processors reject
    requests when client clock skew is large.
32. **Firmware/network update window collision** — many POS devices update
    simultaneously and saturate uplink; recommend staggered update window.

### E. IoT-specific (cameras, smart home, voice, sensors)
33. **Camera buffering / dropouts** — sustained upstream saturation or
    high jitter; recommend QoS, wired backhaul for NVR, lower bitrate.
34. **Smart bulb/plug offline cycles** — typically cheap 2.4 GHz chipsets
    that disassociate when channel utilization > ~60%; recommend
    dedicated IoT SSID, fixed channel 1/6/11, disable band steering for
    that SSID.
35. **Voice assistant slow / "having trouble"** — usually DNS or
    region-specific endpoint latency; suggest DNS swap.
36. **Doorbell / camera one-way audio or no notifications** — UPnP/SIP/
    multicast blocked by router or VPN; recommend disabling client
    isolation for that VLAN.
37. **Roaming-unfriendly IoT in multi-AP environments** — IoT pins to
    first AP and won't roam; recommend single AP with extender disabled,
    or matched min-RSSI thresholds.
38. **DNS rebinding protection breaking local IoT control** (Home
    Assistant, Hue) → add allowlist entry on router.

Each rule emits: `severity`, `confidence`, `evidence`, `affected_devices[]`,
`recommendation_id`.

## AI Layer
- **Local (always on)**:
  - Deterministic rule engine evaluates current + rolling-window metrics.
  - Lightweight anomaly detection (EWMA, z-score, simple changepoint) on
    latency/loss/RSSI/throughput to flag "something changed at 7:42pm".
  - Cross-signal correlation (e.g., RSSI drop coincident with loss spike →
    physical/roaming issue, not ISP).
- **Optional cloud LLM (user adds API key)**:
  - Input: structured findings (rules fired + key metrics + recent timeline).
  - Output: plain-language explanation tailored to selected user mode, plus
    a "chat with your network" Q&A pane.
  - Never sends raw packets or PII — only aggregated metrics. Show a
    "preview payload" before sending.

## User Experience
- **Mode toggle**: Simple / Pro / Admin
  - Simple: one big status, top 3 recommendations, "Fix it" buttons where
    possible (e.g., flush DNS, toggle WiFi, switch DNS server).
  - Pro: live charts (RSSI, latency, throughput), event timeline, full
    recommendation list with "why".
  - Admin: raw metrics table, **network map of all detected devices with
    per-device health**, multi-run comparison, export JSON/CSV, schedule
    background monitoring, generate PDF/HTML reports.
- **Industry profiles** (Admin): pick a profile that tunes thresholds and
  enables relevant rule packs:
  - *Retail / Restaurant POS* — emphasizes terminal stability, payment
    processor reachability, kitchen printer reachability.
  - *Smart Home* — emphasizes IoT dropouts, mDNS, multicast.
  - *Small Office* — emphasizes VoIP jitter, VPN, printer reachability.
  - *Home / General* — default.
- **Per-device watchlist**: pin specific MAC addresses (e.g., each Clover
  terminal, each camera) — get an alert the instant one drops.
- **Incident timeline**: when a device disconnects, show synchronized
  view of WiFi metrics, channel utilization, DHCP events, and other
  devices' state at the same moment — this is the core "complex issue"
  story.
- **Notifications**: optional desktop notifications on detected issues.
- **History**: keep last N days of metrics for trend analysis.

## Project Phases & Milestones

### Phase 1 — Foundation (week 1)
- Scaffold Tauri app (`npm create tauri-app`), React + TS + Tailwind frontend.
- Set up Rust workspace: `core`, `collectors`, `detect`, `recommend`, `app`.
- SQLite (via `rusqlite` or `sqlx`) for time-series storage; schema for
  samples, events, runs, findings.
- CI: `cargo fmt`, `cargo clippy`, `cargo test`, `pnpm lint`, `pnpm test`.

### Phase 2 — Collectors (weeks 2–3)
- Per-OS adapters behind a common `WifiCollector` trait:
  - macOS: parse `airport -I`, `airport -s`, `system_profiler SPAirPortDataType`,
    `networksetup`, `scutil --dns`.
  - Windows: `netsh wlan show interfaces`, `netsh wlan show networks mode=bssid`,
    PowerShell `Get-NetAdapter`, `Get-DnsClientServerAddress`.
  - Linux: `iw dev … link/scan`, `nmcli`, `ip`, `resolvectl`.
- Active probes module: ping, DNS, HTTP throughput, traceroute, MTU probe.
- **LAN discovery module** (cross-platform Rust):
  - ARP sweep of local /24 (or learned subnets).
  - mDNS browser (`mdns-sd` crate).
  - SSDP/UPnP discovery.
  - DHCP fingerprint capture via libpcap (opt-in, requires elevation).
  - MAC OUI database (bundled, updatable).
  - Device classifier → label as POS / camera / smart-home / printer /
    phone / laptop / unknown.
- **Per-device probe scheduler** — rolling ICMP/TCP-SYN against discovered
  hosts with per-device history.
- Permission/elevation handling (esp. Windows scan, Linux `iw scan`,
  pcap on all platforms).

### Phase 3 — Detection & Recommendation (weeks 3–4)
- Implement rule engine + initial rule set above.
- Implement anomaly detector + correlation.
- Recommendation catalog as data (YAML/JSON) keyed by `recommendation_id`,
  each with title, steps, links, severity, and optional auto-fix action.

### Phase 4 — UI (weeks 4–5)
- Dashboard with status, charts (Recharts/uPlot), timeline, recommendations.
- Mode toggle + settings (LLM key, scan interval, notifications).
- "Run full diagnostic" button that triggers a 60–120s deep probe.

### Phase 5 — LLM Integration (week 5)
- Provider abstraction (OpenAI / Anthropic / local Ollama).
- Prompt templates fed with structured findings.
- Payload preview + redaction.
- Q&A chat tied to the most recent diagnostic context.

### Phase 6 — Polish & Release (week 6)
- Auto-update via Tauri updater.
- Installers: `.dmg`, `.msi`, `.AppImage` / `.deb`.
- Onboarding tour, crash reporting (opt-in), telemetry (opt-in, aggregated).
- Docs site + sample report.

## Risks / Open Questions
- **Privileges**: Some scans require admin/root or location permission
  (macOS WiFi requires Location Services for SSID/BSSID since Sonoma).
  pcap-based DHCP fingerprinting and ARP sweep need elevation on
  Windows/macOS.
- **Driver variance**: Windows WiFi driver output differs by vendor; parsing
  must be defensive.
- **LAN scanning ethics/policy**: Active scanning is for the user's *own*
  network; need a clear consent dialog and a "do not scan" allowlist
  for guest networks, hotels, coffee shops.
- **Speedtest cost**: bandwidth-heavy; gate behind explicit user action.
- **LLM cost & privacy**: must be opt-in, with clear payload preview. Device
  hostnames and SSIDs may be sensitive — redact by default.
- **Router-side fixes**: We can recommend changes (channel, SQM, IoT SSID,
  DHCP pool) but cannot apply them — out of scope unless we add per-vendor
  router integrations later (UniFi, Mikrotik, OpenWrt, eero, Google WiFi
  are candidate first integrations).
- **POS environment access**: Running the troubleshooter on the same LAN
  as POS terminals is required to probe them; for a SaaS-style monitor,
  we'd need a tiny always-on agent (out of scope for v1).

## Definition of Done (v1)
- Installs cleanly on macOS, Windows, Linux.
- Runs a full diagnostic in <2 min and shows ≥3 prioritized recommendations
  for at least the ~38 issues listed above when reproduced in lab.
- Discovers and classifies LAN devices; per-device watchlist with alerting.
- Industry profile presets (POS, IoT, Office, Home).
- Background monitoring with notifications and incident timeline that
  correlates a device drop with concurrent WiFi/LAN signals.
- Optional LLM explanations behind a user-supplied key.
- Exports a shareable HTML/PDF report.
