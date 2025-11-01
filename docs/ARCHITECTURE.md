# Courier Agent Architecture

This document tracks the concrete shape of the **S1 · 虫洞最小核** milestone. The complete intent, terminology, and acceptance criteria are recorded in `docs/PROJECT_BLUEPRINT.md`; what follows describes how that blueprint maps onto the code that now exists in the repository.

## Runtime Overview

```
┌───────────────────────────────┐
│ React 18 / Vite UI            │
│  • Quantum Drop panel         │
│  • 身份/设备面板 + 心跳       │
│  • PoT export / verify UX     │
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
│ Identity / Entitlement store  │
│  • SQLite: identities/devices │
│  • Ed25519 signature验证       │
│ transport::adapters           │
│  • QuicAdapter (quinn loopback│
│    w/ dev TLS)                │
│  • MockLocalAdapter fallback  │
│ attestation::{merkle,pot}     │
│  • SHA-256 Merkle + PoT writer│
└───────────────────────────────┘
```

## Rust Modules

- **`commands`** – primary façade exposed to the UI. Key职责：
  - 管理 `AppState`（任务、PoT 路径）与 `ConfigStore`。
  - 实现 `courier_*` 以及身份相关命令：`auth_register_identity`、`auth_register_device`、`auth_list_devices`、`auth_heartbeat_device`、`auth_load/update_entitlement`。
  - 验证来自 UI 的 Ed25519 签名（`purpose:identity_id:device_id`），拒绝未登记或非 `active` 设备。
  - 透出 `transfer_*` 与 `identity_devices_updated` 事件，驱动前端状态。
- **`store`** –
  - `TransferStore`：与之前一致，持久化传输历史。
  - `IdentityStore`：SQLite `identities` / `devices` / `entitlements`。设备记录包含 `status`、`updated_at`、`last_seen_at`、`capabilities`，提供 `touch_device` 心跳接口并支持事件广播。

- **`transport`** – owns the `TransportAdapter` traits, runtime `Router` (reads preferred routes and enforces the LAN → P2P → relay fallback ladder with 3s/6s/8s timeouts), `QuicAdapter` (quinn-powered loopback with self-signed `localhost` certificates under the `transport-quic` feature), `RelayAdapter` (Tokio TCP loopback guarded by `transport-relay`), `MockLocalAdapter` fallback for headless runs, and a gated `WebRtcAdapter` skeleton.
- **`resume`** – manages transfer chunk catalogs (size, count, bitmap), enforces adaptive sizing policy driven by RTT, persists `{task}-index.json` snapshots under `app_data_dir/cache/`, and exposes helpers for querying missing segments on reconnect.

- **`attestation`** – Merkle helpers hashing chunks/root with SHA-256 (CID salted via Blake3) and a PoT writer that materialises JSON receipts aligned with the blueprint schema.

- **`crypto`** – lightweight helpers for generating share codes 和 mock session keys（后续可换成 Noise/PAKE）。身份签名目前由前端 WebCrypto + `@noble/ed25519` 提供，后端通过 `ed25519-dalek` 校验。

- **`signaling`** – session ticket scaffolding, WebRTC `SessionDescription`/ICE types, and a lightweight Axum `/ws` hub (`signaling-server` feature) that merges `SessionDesc` updates for minimal WebRTC experiments。

## Resumable Chunk Flow

1. When a task starts, `resume::ResumeStore` loads an existing chunk catalog or creates a new one with the policy-selected chunk size (default 4 MiB).
2. Round-trip latency captured during the transport handshake feeds `resume::derive_chunk_size`, bumping chunk payloads to 8 MiB / 16 MiB for high RTT paths and shrinking them to 2 MiB on weak networks or relay hops.
3. Each `transfer_progress` event now includes a `resume` payload so the UI can surface the “可续传” badge, outstanding chunk count, and “继续” action.
4. After every acknowledged chunk the bitmap is persisted to `cache/{task_id}-index.json`; failures leave the snapshot intact so retries only stream missing segments.
5. Successful completion or explicit cancellation removes the cached catalog, keeping the cache directory tidy.

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
  - Maintains transfer records, progress snapshots (including moving-average throughput + ETA), PoT paths, log snippets, and pending codes.
  - Normalises error payloads into `UserFacingError` objects so the shell can surface code-specific CTAs.
  - Wraps Tauri commands with typed helpers and exposes ergonomic actions (`startSend`, `startReceive`, `updateProgress`, `complete`, `fail`, `listRecent`, `verifyPot`, `exportPot`, etc.).

- **UI Panels**
  - `SendPanel` – file picker (via Tauri dialog), drag-and-drop entanglement zone, quantum tunnel cards (with resumable CTA) and a P2P smoke test button.
  - `ReceivePanel` – input for courier code + destination directory, mirrored quantum tunnel visuals, plus a DEV-only relay smoke test toggle that exercises the relay adapter directly.
  - `HistoryPanel` – chronological table of transfers with PoT export/verify toasts, supplemented with a quantum tunnel strip per row when the mode is enabled.
  - `SettingsPanel` – toggles preferred routes, relay enable, code expiry, and the quantum tunnel experience, persisting via `ConfigStore`.
  - See [docs/QUANTUM_UI.md](./QUANTUM_UI.md) for the full quantum tunnel copy and motion spec.

- **Event Flow**
  - Store initialises on app mount, listens到 `transfer_*` 与 `identity_devices_updated` 事件，并通过 `auth_list_devices`/`auth_load_entitlement` 进行复原。
  - `Quantum Drop` 面板直接调用签名命令；核心业务命令都要求携带 `AuthenticatedPayload`。

## Command & Event Contract

Commands accept snake_case parameters and return camelCase objects conforming to the TypeScript definitions in `src/lib/types.ts`:

| Command | Purpose | Notes |
| --- | --- | --- |
| `courier_generate_code(auth)` | 启动发送任务，产生取件码 | 需要附带签名，插入 `AppState` & `code` 映射 |
| `courier_send(auth, code)` | 启动 mock 发送 | 验签后发射事件，写入 PoT |
| `courier_receive(auth)` | 模拟接收 | 验签后生成占位文件与 PoT |
| `courier_cancel(task_id)` | Cancel active task | Emits failure lifecycle + error phase |
| `export_pot(task_id)` | Ensure PoT exists under `proofs/` and return the path | Replays persisted state if required |
| `verify_pot(pot_path)` | Validate PoT JSON schema | Structural checks + actionable error messaging |
| `list_transfers(limit?)` | Snapshot recent transfers | Drives UI history bootstrapping |
| `auth_register_identity(payload)` | 记录身份公钥 | 身份 ID + 公钥十六进制 + 可选 label |
| `auth_register_device(payload)` | 登记设备公钥 | 需有身份签名 (`register:id:device`) |
| `auth_heartbeat_device(auth)` | 心跳/能力上报 | 刷新 `status`、`last_seen_at`、`capabilities`，广播事件 |
| `auth_update_device(auth)` | 编辑终端状态与别名 | 需携带 `update_device` 签名，可同步名称、状态与能力 |
| `auth_list_devices(payload)` | 拉取设备列表 | 返回当前身份所有设备 |
| `auth_load_entitlement(payload)` | 查询权益 | 若无记录返回默认 free |
| `auth_update_entitlement(payload)` | 更新权益占位 | 当前仅本地模拟 |

- 终端状态支持 `active` / `standby` / `inactive` 三种标签。前端点击列表项后可以直接编辑别名、切换状态并调用 `auth_update_device`，同时会带上 `ui:minimal-panel` 能力声明。
- 本地身份使用 `identityVault` 持久化，UI 提供“忘记身份”入口，会调用 `forgetIdentity` + `clearLastIdentityId`，方便在共享设备上快速清除凭据。

### Error Codes

`commands::types::ErrorCode` captures the user-facing failure taxonomy surfaced to the React shell:

| Code | Semantics | CTA |
| --- | --- | --- |
| `E_CODE_EXPIRED` | Session ticket lifetime elapsed. | 重新生成后再试 |
| `E_ROUTE_UNREACH` | Preferred route repeatedly timed out. | 切换到中继重试 |
| `E_DISK_FULL` | File system rejected writes (payloads or proofs). | 清理空间后重试 |
| `E_VERIFY_FAIL` | PoT artifact was structurally invalid. | 重新导出后再次验证 |
| `E_PERM_DENIED` | OS permissions blocked the action. | 前往系统设置授权 |

除了 `transfer_*`、`transfer_log` 等事件外，心跳与权益更新还会触发 `identity_devices_updated`，payload 为 `{ identityId, items }`，供前端同步设备列表/状态。

## File System Footprint

- Proofs live under the app data directory inside `proofs/` with filenames `{task_id}.pot.json`.
- Resume metadata persists next to proofs under `cache/{task_id}-index.json` (deleted automatically once a transfer finalises or is cancelled).
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
  - `resume` module covers bitmap diffing, store round-trips, and an ignored `MockLocalAdapter` retry flow.

- **Vitest**
  - `App.test.tsx` validates the shell renders and tab navigation swaps panels.
  - `useTransfersStore.test.ts` stubs invoke/listen to exercise store initialisation and send flow mutations.

## Alignment & Next Steps

The implementation mirrors the “Immediate Action” items of `PROJECT_BLUEPRINT.md`: scaffolding for transport/crypto/signaling, command contract, event wiring, PoT generation, and a mocked adapter. The next milestones (S2/S3) will replace the loopback adapter with real QUIC/WebRTC paths, introduce durable history storage, and harden PoT verification—all without changing the front-end event contract established here.
