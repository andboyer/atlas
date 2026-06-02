# Atlas

> **Atlas — map your network.**

A cross-platform desktop app that uses a hybrid AI approach (deterministic
rule engine + optional LLM explanations) to detect complex Wi-Fi network
issues — including **IoT device dropouts** and **POS terminal random
disconnects** (Clover, Square, Toast, etc.) — and recommend concrete fixes.

> **Status:** Phase 1 scaffold. The app runs end-to-end with a mock
> collector that demonstrates the UI, rule engine, and recommendations.
> Phase 2 will add real per-OS WiFi/LAN collectors.

## Highlights

- **Hybrid AI**: local rule engine for detection + optional cloud LLM for
  plain-language explanations.
- **Network-wide observability**: not just the host machine — discover,
  classify, and monitor every device on the LAN.
- **~38 built-in rules** across 5 buckets: local link, internet/upstream,
  network-wide, POS-specific, IoT-specific.
- **Three user modes**: Simple, Pro, Admin.
- **Industry profiles**: Retail/POS, Smart Home, Small Office, Home.

## Tech stack

- **Tauri 2** (Rust backend, web frontend) — small native binaries
- **React 19 + TypeScript + Tailwind v4** — modern UI
- **SQLite** (via `rusqlite`) — time-series storage for trends and
  incident timelines
- **Zustand** — lightweight React state

## Project structure

```
wifi-troubleshooter/
├── src/                       # React frontend
│   ├── components/            # UI components
│   ├── store.ts               # Zustand store
│   ├── types.ts               # Shared TypeScript types
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css              # Tailwind entry
├── src-tauri/                 # Rust backend
│   └── src/
│       ├── lib.rs             # Tauri entry + setup
│       ├── commands.rs        # Tauri command handlers
│       ├── types.rs           # Shared serializable types
│       ├── store/             # SQLite persistence
│       ├── collectors/        # WiFi/LAN data collectors (per-OS)
│       ├── detect/            # Rule engine + anomaly detection
│       └── recommend/         # Recommendation catalog
└── docs/
    └── PLAN.md                # Full project plan
```

## Development

Prereqs: Rust (stable), Node 20+, pnpm 11+, platform-specific Tauri
[prerequisites](https://tauri.app/start/prerequisites/).

```bash
pnpm install
pnpm tauri dev      # run the desktop app in dev mode
pnpm build          # type-check + build frontend bundle
cargo test --manifest-path src-tauri/Cargo.toml
```

## License

MIT — see `LICENSE`.
