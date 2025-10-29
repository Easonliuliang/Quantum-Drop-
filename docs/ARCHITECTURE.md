# Courier Agent Architecture

This document tracks the concrete shape of the **S1 · 虫洞最小核** milestone. The complete intent, terminology, and acceptance criteria are recorded in `docs/PROJECT_BLUEPRINT.md`; what follows describes how that blueprint maps onto the code that now exists in the repository.

## Runtime Overview

```
┌───────────────────────────────┐
│ React 18 / Vite UI            │
│  • Tabs: Send / Receive / Log │
│  • Zustand event bridge       │
│  • Proof export / verify UX   │
└──────────────┬────────────────┘
               │ invoke + listen (Tauri)
               ▼
┌───────────────────────────────┐
│ Tauri 2 Runtime (Rust)        │
│  • commands::courier_*        │
│  • transport::Router (lan/p2p/relay)
│  • event emitters (progress)  │
│  • AppState (in-memory)       │
└──────────────┬────────────────┘
               │ async tasks (Tokio)
               ▼
┌───────────────────────────────┐
│ transport::adapters           │
│  • QuicAdapter (quinn loopback│
│    w/ dev TLS)                │
│  • MockLocalAdapter fallback  │
│ attestation::{merkle,pot}     │
│  • SHA-256 Merkle + PoT writer│
└───────────────────────────────┘
```

## Rust Modules

- **`commands`** – primary façade exposed to the UI. Key responsibilities:
  - Manage shared `AppState` (tasks, codes, Proof-of-Transition paths).
  - Implement the S1 command contract `courier_generate_code`, `courier_send`, `courier_receive`, `courier_cancel`, `export_pot`, `verify_pot`, and `list_transfers`.
  - Emit lifecycle, progress, log, and completion events (`transfer_started`, `transfer_progress`, `transfer_completed`, `transfer_failed`, `transfer_log`).
  - Orchestrate the mock transfer via `MockLocalAdapter`, compute Merkle roots, and write `*.pot.json` files.
- **`store`** – light SQLite wrapper (`TransferStore`) responsible for creating the durable schema, upserting terminal transfer records, and serving paged history to the UI command.

- **`transport`** – owns the `TransportAdapter` traits, runtime `Router` (reads preferred routes and enforces the LAN → P2P → relay fallback ladder with 3s/6s/8s timeouts), `QuicAdapter` (quinn-powered loopback with self-signed `localhost` certificates under the `transport-quic` feature), `RelayAdapter` (Tokio TCP loopback guarded by `transport-relay`), `MockLocalAdapter` fallback for headless runs, and a gated `WebRtcAdapter` skeleton.

- **`attestation`** – Merkle helpers hashing chunks/root with SHA-256 (CID salted via Blake3) and a PoT writer that materialises JSON receipts aligned with the blueprint schema.

- **`crypto`** – lightweight helpers for generating share codes and mock session keys (placeholder for upcoming PAKE / Noise integration).

- **`signaling`** – session ticket scaffolding, WebRTC `SessionDescription`/ICE types, and a lightweight Axum `/ws` hub (`signaling-server` feature) that merges `SessionDesc` updates for minimal WebRTC experiments.

## S2 WebRTC DataChannel – Minimal Flow

```
SendPanel "P2P Smoke Test"
        │ invoke courier_p2p_smoke_test
        ▼
┌────────────────────────┐
│ Router::p2p_only       │
│  • WebRtcAdapter       │
│  • Mock fallback       │
└─────────────┬──────────┘
              │ creates paired peers
              ▼
┌─────────────────────────────┐
│ RTCPeerConnection (offerer) │
│  • courier data channel     │
│  • ICE → loopback peer      │
└─────────────┬───────────────┘
              │ echoed frames
┌─────────────────────────────┐
│ RTCPeerConnection (answerer)│
│  • echoes text / binary      │
└─────────────────────────────┘
```

- The Axum `/ws?sessionId=…` signaling server now keeps a shared `SessionDesc` (offer/answer/candidates) so future peers can negotiate across processes.
- `WebRtcAdapter` spins up a loopback answerer, wires ICE candidates, opens the `courier` data channel, and logs connection state changes via `log::info!`.
- `Router` prefers the P2P route when available; transfers surface `route="p2p"` as soon as the WebRTC handshake succeeds.
- The Send panel exposes a “P2P Smoke Test” button that pushes a 64 KiB payload through the data channel and toasts the echoed byte count.

## Feature Flags & Configuration

- `transport-quic` *(enabled by default)* – spins up the quinn-based `QuicAdapter`, wiring the router to emit `route="lan"` when the LAN hop succeeds.
- `transport-webrtc` *(enabled by default in dev builds)* – powers the in-process WebRTC data channel loopback, exchanging frames over a `courier` channel with connection state logs.
- `transport-relay` *(enabled by default in dev builds)* – turns on the Tokio TCP relay loopback adapter and `/relay` registry endpoint for the signaling server.
- `signaling-server` *(opt-in)* – exposes an Axum router with a placeholder `/ws` endpoint for future signaling integration tests.

The router reads its preferred route ordering from `app.yaml` under the app config directory. If the file is absent, the default order (`lan`, `p2p`, `relay`, then mock fallback) is used. Each probe has a dedicated timeout window (3s for LAN, 6s for P2P, 8s for relay) and the first successful hop cancels the rest.

```yaml
# app.yaml
s2:
  transport:
    preferredRoutes:
      - lan
      - p2p
      - relay
    relayEndpoint: tcp://127.0.0.1:6200
    stun:
      - stun:stun.l.google.com:19302
      - turn:turn.relay.example:3478?transport=udp
```

A ready-to-copy sample lives in `docs/app.sample.yaml`.

The QUIC loopback spins up an in-process server/client pair bound to `127.0.0.1`, exchanges a self-signed `localhost` certificate, and echoes frames so tests can assert byte-for-byte delivery.

- **`main.rs`** – wires the modules into Tauri, manages state with `.manage(SharedState::new())`, and registers the expanded command handler list alongside `health_check`.

## Front-end Structure

- **Zustand Store (`src/store/useTransfersStore.ts`)**
  - Centralises command invocation and event subscription (`listen`), ensuring React components receive live transfer updates.
  - Maintains transfer records, progress snapshots, PoT paths, log snippets, and pending codes.
  - Wraps Tauri commands with typed helpers and exposes ergonomic actions (`startSend`, `startReceive`, `updateProgress`, `complete`, `fail`, `listRecent`, etc.).

- **UI Panels**
  - `SendPanel` – file picker (via Tauri dialog), code share banner, active transfer cards with phase/progress/log views, and a P2P smoke test button.
  - `ReceivePanel` – input for courier code + destination directory, mirrored progress cards, plus a DEV-only relay smoke test toggle that exercises the relay adapter directly.
  - `HistoryPanel` – chronological table of transfers with PoT export/verify actions.

- **Event Flow**
  - Store initialises on app mount, listens to the command events, and rehydrates history via `list_transfers`.
  - Components render purely from store state; no direct `invoke` calls live inside UI components.

## Command & Event Contract

Commands accept snake_case parameters and return camelCase objects conforming to the TypeScript definitions in `src/lib/types.ts`:

| Command | Purpose | Notes |
| --- | --- | --- |
| `courier_generate_code(paths, expire_sec?)` | Stage send task, produce code | Scans metadata, inserts task into `AppState` |
| `courier_send(code, paths)` | Start mocked transport | Emits lifecycle + progress events, writes PoT |
| `courier_receive(code, save_dir)` | Simulate incoming transfer | Materialises placeholder payload and proof |
| `courier_cancel(task_id)` | Cancel active task | Emits failure lifecycle + error phase |
| `export_pot(task_id, out_dir)` | Copy PoT to user-selected dir | Returns destination path as string |
| `verify_pot(pot_path)` | Validate PoT JSON schema | Currently checks version + basic sanity |
| `list_transfers(limit?)` | Snapshot recent transfers | Drives UI history bootstrapping |

Events follow the blueprint contract with unchanged names. Payloads are snake_case at the bridge and mapped to camelCase within the store.

## File System Footprint

- Proofs live under the app data directory inside `proofs/` with filenames `{task_id}.pot.json`.
- Runtime logs go through Tauri emitters and are kept in-memory (future work: persist to disk as described in the blueprint).
- Persistent history is stored under `<app_data_dir>/storage/transfers.sqlite3`, created on start if missing.

```
CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY,
  code TEXT,
  direction TEXT NOT NULL,
  status TEXT NOT NULL,
  bytes_total INTEGER,
  bytes_sent INTEGER,
  route TEXT,
  pot_path TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfers_updated_at ON transfers(updated_at);
```

## Tests

- **Rust**
  - `attestation::merkle` tests cover empty-file handling and deterministic hashing for known payloads.
  - `transport::adapter` exercises `MockLocalAdapter` loopback send/recv.
  - `transport::quic` validates the QUIC loopback echo path and self-signed TLS wiring.
  - `transport::router` confirms the LAN preference selects the QUIC adapter when available.

- **Vitest**
  - `App.test.tsx` validates the shell renders and tab navigation swaps panels.
  - `useTransfersStore.test.ts` stubs invoke/listen to exercise store initialisation and send flow mutations.

## Alignment & Next Steps

The implementation mirrors the “Immediate Action” items of `PROJECT_BLUEPRINT.md`: scaffolding for transport/crypto/signaling, command contract, event wiring, PoT generation, and a mocked adapter. The next milestones (S2/S3) will replace the loopback adapter with real QUIC/WebRTC paths, introduce durable history storage, and harden PoT verification—all without changing the front-end event contract established here.
