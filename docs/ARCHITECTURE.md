# Courier Agent Architecture

Courier Agent is a desktop-first implementation of the AETHER OS data presence layer. It pairs a React/Vite UI with a Rust/Tauri runtime that orchestrates multi-path transport, encryption, and audit trails.

## High-Level View

```
┌────────────────────────┐
│ React Surface           │
│  • Presence UI          │
│  • Transfer Timeline    │
└─────────────┬──────────┘
              │ invoke() commands
              ▼
┌────────────────────────┐
│ Tauri Shell (Rust)     │
│  • Command router       │
│  • State synchroniser   │
│  • Background services  │
└─────────────┬──────────┘
              │ async tasks
              ▼
┌────────────────────────┐
│ Transport Core         │
│  • QUIC engine         │
│  • WebRTC overlay      │
│  • TURN relay          │
│  • PoT attestation     │
└────────────────────────┘
```

## Modules

- **`src-tauri/src/main.rs`** – entrypoint configuring the Tauri window, exposing commands such as `health_check`, and wiring runtime telemetry.
- **Transport subsystem** *(future module)* – will introduce components for path selection, NAT traversal, and congestion control. Planned modules: `transport.rs`, `signaling.rs`, `crypto.rs`, `verifier.rs`.
- **Proof of Transition ledger** – produces verifiable receipts for each transfer using Merkle trees and CID addressing.
- **React UI** – surfaces status, queue management, and attestation browsing. Hooks will subscribe to the command events streaming from the Rust core.

## Data Flow

1. **Fold** – files are encrypted and chunked locally; metadata is staged for immediate manifestation.
2. **Jump** – negotiation logic determines the best route (LAN ➜ P2P ➜ Relay).
3. **Manifest** – the receiving node sees metadata and proof first, followed by payload convergence.
4. **Certify** – PoT receipts are generated for senders and receivers.
5. **Dissolve** – ephemeral keys and caches are shredded once attestations persist.

## Extension Points

- **Agent mesh** – other AETHER cognitive agents subscribe to transfer events for knowledge graph augmentation.
- **Policy plugins** – allow organisations to enforce residency rules, relay choices, or proof retention policies.
- **Observability** – integrate OpenTelemetry exporters for real-time monitoring of throughput, error rates, and trust attestations.

## Technology Stack

- **Rust 1.77+** – systems layer, transport orchestration, encryption, and PoT ledger.
- **Tauri 2.x** – native shell providing window management, command bridge, and bundling.
- **React 18 + Vite 5** – presence-driven interface.
- **Vitest + Testing Library** – unit testing for UI state and command adapters.

## Roadmap Highlights

- Implement QUIC pathway via `quinn` with automatic downgrade to WebRTC (`webrtc-rs`).
- Materialise PoT receipts as signed JSON-LD files.
- Integrate background auto-update pipeline using Tauri updater APIs.
- Deliver cross-platform system service for “always-on” courier presence.
