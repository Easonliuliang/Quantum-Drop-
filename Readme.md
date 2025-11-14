# 🚀 Quantum Drop · 量子快传

[![Release Bundles](https://github.com/Easonliuliang/Quantum-Drop-/actions/workflows/release.yml/badge.svg)](https://github.com/Easonliuliang/Quantum-Drop-/actions/workflows/release.yml)
![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)
![Node](https://img.shields.io/badge/node-18.x-026e00?logo=node.js)
![License](https://img.shields.io/badge/license-MIT-blue)

> 消除路径感知、即时完成且可验证的文件传递体验。<br />
> 基于 Tauri · Rust · React 构建，并与 AETHER OS 生态保持一致。

---

## 概览

Quantum Drop · 量子快传 将文件传输重新定义为“存在”，而非“移动”。应用并非让字节穿梭于脆弱的中继链路，而是在设备之间折叠并显化数据，一旦传输启动便产出经过验证的成果。灵感来自 AETHER OS 的理念——智能体以念头协作，需要时显形，用毕即散。

核心设计目标：

- **存在优先的体验**：元数据与证明先行抵达，内容在后台快速收敛。
- **多路径传输调度**：综合 QUIC、WebRTC、TURN 等链路，确保持续吞吐。
- **可验证结果**：每次跃迁都会生成可携带的 Proof of Transition（PoT）文件。

演示（拖拽投递）：

![Demo](demo.gif)

---

## 当前完成度（v0.1.x）

- 前端与交互
  - Quantum Drop 投递区：拖拽 hover/吸入动效（Tauri v2 + Webview 拖拽事件），键盘可达；浏览器模式保留 UI 演示。
  - 标识与文案：应用更名为“Quantum Drop · 量子快传”，全平台图标统一（macOS 圆角风格）。
- 身份与设备
  - 本地生成 Ed25519 身份；登记设备；15s 心跳（状态/能力）。
  - 身份/私钥/last-id 在桌面端落盘持久化（浏览器退化到 localStorage）。
- 传输与事件
  - 传输路由编排器（LAN/QUIC → P2P/WebRTC → Relay/TCP → Mock 兜底），按优先级与超时回退。
  - 局域网直连（阶段一）：发送端在“事件流”中公布监听 IP 与端口，接收端面板输入配对码 + IP:Port + 保存目录后，即可通过 QUIC 真实传输并生成 PoT。
  - 局域网自动发现（阶段二）：发送端通过 mDNS 广播配对码、设备名与端口，接收端支持“配对码自动发现”和“扫描附近发送方”两种模式，一键连接并落地文件。
  - 分片发送与事件流：阶段/进度/速率/路由标签（lan|p2p|relay），完成后导出演示版 PoT 路径。
- 构建与发布
  - Tauri 打包（macOS .app/.dmg 已验证），GitHub Actions 三平台构建与自动发布；仓库体积 ~9MB。

> 说明：LAN/QUIC 已实现真实局域网直连；WebRTC 与 Relay 仍为回环占位，用于保障 UI/事件/路由链路，后续将逐步替换为跨网实现。

## 已知限制与计划

- 真实跨设备传输：LAN 发现/打洞、P2P ICE/STUN/TURN、可部署 Relay 端点（规划中）。
- 断点续传与强校验：块级位图/哈希清单持久化、崩溃恢复、自适应分片（近期优先）。
- 吞吐优化：QUIC 多并发流/拥塞控制调优、I/O 管线化与背压、路由并发竞速与动态切换。
- 端到端加密：会话密钥协商与内容加密落地（设计期）。
- 签名发布：Windows/Linux 代码签名在 CI 预置，待稳定后开启。

## Error Codes

原生运行时会将错误码映射为明确的操作指引，便于快速响应。

| Code | 含义 | 建议操作 |
| --- | --- | --- |
| `E_CODE_EXPIRED` | 配对码尚未连接即已过期。 | 重新生成后再试 |
| `E_ROUTE_UNREACH` | 首选传输路径不可达或持续超时。 | 切换到中继重试 |
| `E_DISK_FULL` | 落地载荷或 PoT 时磁盘空间不足。 | 清理空间后重试 |
| `E_VERIFY_FAIL` | PoT 结构或密码学校验失败。 | 重新导出后再次验证 |
| `E_PERM_DENIED` | 系统权限阻止了操作（存储或网络）。 | 前往系统设置授权 |

---

## 目录结构

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

## 快速开始

```bash
# 1. 安装工具链（首次执行）
# 建议使用项目内 rust-toolchain.toml / .nvmrc 锁定版本
cargo --version && rustc --version            # 确认 Rust 已安装
node -v && npm -v                             # Node 18

# 2. 安装 Node 依赖
npm install

# 3. 启动 Tauri 桌面环境（推荐）
npm run tauri:dev

# 4. 质量校验（Lint/Unit/Clippy）
npm run check
```

常用命令：

- `npm run tauri:build`：生成可发布的桌面安装包。
- `cargo test --manifest-path src-tauri/Cargo.toml`：执行原生单元/集成测试。
- `npm run preview`：在无 Tauri Shell 的情况下预览编译后的前端。

### 多语言（i18n）

桌面端顶部的语言切换器（`LocaleSwitch`）支持在中文与 English 之间即时切换，选择会持久化到本地存储。默认消息定义在 `src/lib/i18n.tsx`，新增语言或文案时只需扩展对应的键值。详见 [docs/i18n.md](docs/i18n.md)。

### 局域网直连（阶段一）操作指引

1. **发送方**
   - 在“量子快传”面板选择文件后点击“启动传输”，应用会生成 6 位配对码并自动监听 QUIC 服务。
   - 打开右侧“事件流”，记录类似 `LAN listener on 0.0.0.0:53214 · share IP: ["192.168.1.23"]` 的日志，将配对码与可用 IP/端口告知接收方。
2. **接收方**
   - 在“接收（同网手动模式）”区输入配对码、发送方 IP、端口，点击“选择”挑选保存目录，再点击“开始接收”。
   - UI 会调用 `courier_receive` 命令，向后端提交以下签名负载：

     ```ts
     await invoke("courier_receive", {
       auth: {
         identityId,
         deviceId,
         signature, // sign(`receive:${identityId}:${deviceId}`)
         payload: {
           code: "QDX9Z3",
           saveDir: "/Users/me/Downloads",
           host: "192.168.1.23",
           port: 53214,
         },
       },
     });
     ```

   - 连接建立后，“事件流”与“传输状态”会实时显示路由（lan）、速率与 PoT 路径。
3. **调试建议**
   - 确保两台设备在同一子网且未被防火墙阻止 UDP 端口；如连接失败，可在 `logs/` 中查看发送端日志。
   - 若需要重复使用端口，可在发送端重新点击“启动传输”或清理旧任务后再次生成。

### 跨网配置（阶段三预览）

编辑 `app.yaml`（位于 `AppData/config/app.yaml`），即可声明信令与 STUN/TURN 服务器，Router 会在 LAN → P2P → Relay 之间并发探测并自动降级：

```yaml
s2:
  transport:
    preferredRoutes:
      - lan
      - p2p
      - relay
    signalingUrl: wss://signaling.quantumdrop.dev/ws
    stun:
      - stun:stun.l.google.com:19302
      - stun:stun1.l.google.com:19302
    turn:
      urls:
        - turn:turn.quantumdrop.dev:3478?transport=udp
      username: quantum
      credential: drop123
    timeouts:
      lan: 3s
      p2p: 10s
      relay: 8s

security:
  enforceSignatureVerification: true
  disconnectOnVerificationFail: true
  enableAuditLog: true
```

> 💡 Tauri 桌面端的“传输统计”面板提供了“刷新权益 / 激活 License / 刷新安全策略”按钮，可直接查看 `enforceSignatureVerification`、`disconnectOnVerificationFail`、`enableAuditLog` 的实时状态并输入 License Key，无需手动编辑文件。开发环境默认放宽验签（`debug` 构建），生产构建或配置/环境变量会自动启用严格模式。

Router 会按 “LAN → P2P → Relay → Mock” 的顺序逐条尝试；某条路由成功即终止后续尝试，其余失败信息会记录在 `transfer_log`，便于排障。如果配置中禁用了某条路径，日志会标记 `adapter unavailable` 以提示原因。

示例日志：

```
12:30:01 route candidates: ["lan","p2p","relay","mock"]
12:30:02 lan success in 42ms
```

```
12:55:10 route candidates: ["lan","p2p","relay","mock"]
12:55:13 lan timed out after 3s
12:55:23 p2p error after 10023ms: signaling handshake failed
12:55:26 relay success in 287ms
```

### 单机 WebRTC 测试

即便只有一台电脑，也可以验证信令签名与 TOFU 流程：

1. 启动两个 Quantum Drop 窗口（`npm run tauri:dev` 启动后，再运行一次启动第二个实例）。  
2. 在窗口 A 选择任意小文件，点击“WebRTC 跨网实验 → 启动 WebRTC 发送”，日志会显示自动生成的 6 位配对码。  
3. 在窗口 B 的“接收（配对码模式）”中输入相同的配对码并选择保存目录，再点击“启动 WebRTC 接收”。  
4. 两端都会收到 `peer_discovered` 事件：若签名验证通过，则直接提示“已签名验证”；否则会弹出指纹核对对话框，确认后加入受信列表。  
5. 受信设备会持久化到 `localStorage["courier.trustedPeers"]`；后续相同指纹会自动信任，可在“已信任设备”面板查看。  

更多安全细节、配置参数与手动测试脚本，见 [`docs/SECURITY.md`](docs/SECURITY.md)。

### License 与权益限制

| License | 限制（默认） | 说明 |
| --- | --- | --- |
| Free | P2P 10 次/月<br>单文件 2 GB<br>最多 3 台设备<br>❌ 断点续传 | 触发限制时 UI 会弹出升级提示；后端也会拒绝超额请求 |
| Pro | 无限 P2P<br>无限文件大小<br>设备无限<br>✅ 断点续传 | 可通过输入 License Key 激活 |
| Enterprise | 自定义 | 支持私有 Relay、审计导出、API 等定制能力 |

#### 限制触发行为

* **设备数量**：注册第 4 台设备时，前端会提示升级；后端 `auth_register_device` 同样会返回 `DEVICE_LIMIT_EXCEEDED`。  
* **文件大小**：拖入超过配额的文件或多选总计超过限制时，会立即弹出升级提示；LAN/WebRTC 命令在后端再次校验，确保无法绕过。  
* **P2P 次数**：WebRTC 发送/接收在提交前检查月度配额；后端 `courier_start_webrtc_*` 也会拒绝超额请求。  
* **断点续传**：免费版不可点击“继续传输”，CLI/Tauri 命令会返回 `RESUME_DISABLED`。  

#### License 激活

1. 在桌面端“传输统计 → 权益信息”面板输入 License Key（示例：`QD-PRO-XXXX-YYYY`），点击“激活 License”。  
2. 激活成功会显示当前套餐、到期日、配额使用情况；失败会提示具体错误（签名错误、身份不匹配等）。  
3. 后端会记录 `license.activated` 审计事件，包含套餐/到期时间，方便统计。  
4. 也可以在终端运行：  

```sh
tauri invoke license_activate --payload '{"identityId":"id_xxx","licenseBlob":"QD-PRO-XXXX-YYYY"}'
```

#### 支付/发行规划

* License 由 Ed25519 签名，Server 端提供支付 Webhook → License 下发 → 邮件通知。  
* 仓库自带 `server/payment-gateway`（Express + TweetNaCl），提供 `/webhook/wechat` / `/webhook/alipay` / `/admin/issue` 等示例端点，可直接在支付平台配置回调进行联调。  
* 计划接入微信/支付宝（国内）与 Stripe/PayPal（全球），支付成功后自动发放 Key。  
* 官网：Next.js + Tailwind，包含 Landing / Pricing / Docs，并提供下载与客服入口。  
* 客户端“升级 Pro”按钮将跳转至定价页面或内嵌 WebView 完成支付。

### PoT 与大文件

- PoT：当前版本在完成后导出演示版 PoT 路径，记录路由与分片确认过程，用于 UI/事件链路验证。
- 大文件策略（规划中）：块级哈希清单 + 断点位图、QUIC 并发流、背压与限速、路由竞速/迁移。

### 示例与样例

- 示例配置：examples/app.sample.yaml
- 示例 PoT 收据：examples/pot.sample.json

---

## 量子身份与终端同频

> 身份/设备能力目前仅在 Tauri 桌面环境生效，浏览器模式会使用内存占位。

1. **创建或导入身份**：在“身份与设备”面板点击“创建主身份”生成 Ed25519 密钥对；如需在其他机器复原，可通过“导出私钥”复制十六进制，并在目标端输入身份 ID + 私钥进行导入。密钥会存放在本地 `AppData/identity` 目录（浏览器回退到 `localStorage`）。
2. **登记设备**：点击“登记新设备”即可生成终端公钥，前端会对 `register:<deviceId>:<devicePublicKey>` 签名，后端写入 SQLite `devices` 表。设备列表会显示状态、最近心跳时间与声明的能力标签。
3. **心跳同步**：面板每 15 秒向 `auth_heartbeat_device` 发送签名心跳，刷新 `status`、`last_seen_at`、`capabilities`，并通过 `identity_devices_updated` 事件广播到所有前端实例，实现“同频”效果。
4. **签名调用**：`courier_generate_code` / `courier_send` / `courier_receive` 均要求携带 `AuthenticatedPayload`，消息体为 `purpose:identity_id:device_id`。未登记或非 `active` 设备会被拒绝，防止越权。

> 传输路径（设计）：优先 LAN(QUIC/UDP) → P2P(WebRTC DataChannel) → Relay(TCP)，失败回退到 Mock。本仓库提供接口与演示适配器，便于后续替换为真实跨设备实现；配置示例见 `docs/app.sample.yaml`。

> 权益（plan/features）当前仍为本地占位，后续需要引入真实付费/令牌逻辑时，可直接扩展 `IdentityStore::set_entitlement` 与相关命令。

---

## 故障排查

- **`cargo clippy` 报链接错误**：请确保已安装 Xcode Command Line Tools（macOS）或相应的 Visual Studio Build Tools（Windows），并为目标平台重新执行 `rustup target add`。
- **Tauri 开发端无法连接 Vite（`Failed to connect to http://localhost:5174`）**：确认 `npm run dev:ui` 已启动，或在 `vite.config.ts` 与 `src-tauri/tauri.conf.json` 中调整为可用端口。
- **`npm run test` 提示缺少 jsdom**：删除 `node_modules` 后重新安装依赖，并确认正在使用符合要求的 Node 版本（>=18.17，可通过 `nvm`/`fnm` 管理）。
- **PoT 证明不同步**：复制接收端持有的 `proofs/<taskId>.pot.json` 文件，即便 UI 进程崩溃，该收据仍然有效。
- **续传状态异常**：手动删除应用数据目录下的 `cache/*.json`，运行时会在下次传输时重建。

---

## AETHER OS 设计注记

Quantum Drop · 量子快传 是 AETHER OS 星群中首个数据平面智能体：

```
AETHER OS
│
├─ Cognitive Agents (Planner · Researcher · Storyteller ...)
│    ↳ Consume transfer events to seed shared memory graphs
│
└─ ⚛ Quantum Drop · 量子快传（数据智能体）
     ├─ Fold: locally encrypts + shards payloads
     ├─ Jump: negotiates multi-path routes with situational policy
     ├─ Manifest: streams previews and metadata to recipients
     ├─ Certify: emits Proof of Transition receipts
     └─ Dissolve: rotates keys and prunes ephemeral caches
```

本智能体通过 Rust 命令面（详见 `src-tauri/src/main.rs`）暴露能力，供其他 AETHER 节点嵌入或调用。后续规划包括：

- 融入 Memory Graph，实现跨智能体共享上下文。
- 自适应策略模块，实现 LAN、P2P、Relay 拓扑的动态选择。
- 与 AETHER “Proof of Thinking”（PoT）标准的账本同步。

---

## 贡献与社区

项目遵循 Contributor Covenant 行为准则，欢迎通过 Issue 或讨论串提交提案。工作流说明见 `CONTRIBUTING.md`——在提交 PR 前请使用 Feature 分支、遵循 Conventional Commits，并完成 `./scripts/check.sh` 全量校验。

---

## 许可证

项目以 MIT License 发布。待上游依赖允许后，可考虑切换为 MIT + Apache 2.0 双许可证模型。

— 如果你喜欢这个项目，欢迎点 Star 支持；后续 Pro 版将解锁“真实 P2P、断点续传、企业 Relay 部署”等能力。

---

## 支持项目

- 扫码支持（占位，后续可替换为你的二维码）：

  <img src="docs/assets/qr.png" width="160" alt="Support QR" />
