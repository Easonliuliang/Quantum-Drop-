# 🚀 Courier Agent · 智能文件传递体

> Zero-path, verifiable file transit that feels instantaneous.<br />
> Crafted with Tauri · Rust · React and aligned with the AETHER OS ecosystem.

---

## Overview

Courier Agent reimagines file transfer as presence instead of motion. Rather than shuttling bytes through brittle relays, the app folds and manifests data across devices, delivering verified artefacts the moment a transfer begins. The experience is inspired by the AETHER OS philosophy—agents cooperate as thought-forms that materialise when needed and vanish without residue.

Key design intents:

- **Presence-first UX** – metadata and proof land instantly, content converges in the background.
- **Multi-path transport** – QUIC, WebRTC, and TURN routes are orchestrated to keep throughput high.
- **Verifiable outcomes** – every transition yields a portable Proof of Transition (PoT) artefact.

---

## Features

- **Aether-Grade Transport Pipeline** – automatic route selection across LAN QUIC, peer-to-peer WebRTC, relay TURN, and optional caching layers.
- **End-to-End Secrecy** – Noise/XChaCha20-Poly1305 encrypted tunnels with ephemeral identity material; signalling remains blind to payloads.
- **Proof of Transition Ledger** – Merkle-authenticated receipts exportable for offline verification and audit trails.
- **Presence UI** – Vite + React surface emphasises “arrival-first” storytelling, with status cards driven by the Rust runtime.
- **Composable Agents** – the runtime exposes hooks for additional AETHER cognitive agents to subscribe to transfer events and memory graphs.

---

## Folder Structure

```
courier-agent/
├─ README.md
├─ index.html
├─ package.json
├─ tsconfig.json
├─ vitest.config.ts
├─ docs/
│  └─ ARCHITECTURE.md
├─ scripts/
│  ├─ check.sh
│  └─ dev.sh
├─ src/
│  ├─ App.test.tsx
│  ├─ App.tsx
│  ├─ main.tsx
│  ├─ styles.css
│  └─ (future feature modules)
└─ src-tauri/
   ├─ build.rs
   ├─ Cargo.toml
   ├─ src/
   │  └─ main.rs
   └─ tauri.conf.json
```

---

## Quick Start

```bash
# 1. Install toolchains (one time)
rustup target add x86_64-apple-darwin         # macOS example
cargo install tauri-cli                      # optional, npm script bundles it

# 2. Install Node dependencies
npm install

# 3. Launch the React surface + Tauri shell
npm run tauri:dev
# or run the helper script
./scripts/dev.sh

# 4. Quality gate before merging
./scripts/check.sh
# (runs lint, unit tests, rustfmt, and cargo clippy)
```

Additional commands:

- `npm run tauri:build` – produce a distributable desktop bundle.
- `cargo test --manifest-path src-tauri/Cargo.toml` – execute native tests when they are added.
- `npm run preview` – open the compiled React bundle without the Tauri shell.

---

## Troubleshooting

- **`cargo clippy` fails with linker errors** – ensure Xcode Command Line Tools (macOS) or the appropriate Visual Studio Build Tools (Windows) are installed; re-run `rustup target add` for the desired target triple.
- **Tauri dev server cannot reach Vite (`Failed to connect to http://localhost:5173`)** – check that `npm run dev:ui` is running or bump the port in `vite.config.ts` and `src-tauri/tauri.conf.json` to a free slot.
- **`npm run test` exits with missing jsdom** – delete `node_modules`, reinstall dependencies, and verify that the correct Node version (>=18.17) is active via `nvm` or `fnm`.
- **PoT attestation files unsynchronised** – copy the receipt payloads stored by the receiving agent; they remain valid even if the UI process crashes.

---

## AETHER OS Design Notes

Courier Agent is the first data-plane intelligence in the broader AETHER OS constellation:

```
AETHER OS
│
├─ Cognitive Agents (Planner · Researcher · Storyteller ...)
│    ↳ Consume transfer events to seed shared memory graphs
│
└─ ⚛ Courier Agent（数据智能体）
     ├─ Fold: locally encrypts + shards payloads
     ├─ Jump: negotiates multi-path routes with situational policy
     ├─ Manifest: streams previews and metadata to recipients
     ├─ Certify: emits Proof of Transition receipts
     └─ Dissolve: rotates keys and prunes ephemeral caches
```

The agent exposes a Rust command surface (see `src-tauri/src/main.rs`) that other AETHER nodes can embed or invoke. Future integration points include:

- Memory Graph ingestion for cross-agent context.
- Adaptive policy modules to choose between LAN, P2P, or relay topologies.
- Ledger synchronisation with the AETHER “Proof of Thinking” (PoT) standard.

---

## Contributing & Community

We adhere to a Contributor Covenant code of conduct and welcome proposals through issues or discussion threads. See `CONTRIBUTING.md` for workflow details—feature branches, conventional commits, and full check runs (`./scripts/check.sh`) are expected before a pull request is opened.

---

## License

This project is released under the MIT License. A dual-license (MIT + Apache 2.0) can be adopted once upstream dependencies permit.
