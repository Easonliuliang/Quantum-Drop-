# 🚀 Quantum Drop · 量子快传

> 消除路径感知、即时完成且可验证的文件传递体验。<br />
> 基于 Tauri · Rust · React 构建，并与 AETHER OS 生态保持一致。

---

## 概览

Quantum Drop · 量子快传 将文件传输重新定义为“存在”，而非“移动”。应用并非让字节穿梭于脆弱的中继链路，而是在设备之间折叠并显化数据，一旦传输启动便产出经过验证的成果。灵感来自 AETHER OS 的理念——智能体以念头协作，需要时显形，用毕即散。

核心设计目标：

- **存在优先的体验**：元数据与证明先行抵达，内容在后台快速收敛。
- **多路径传输调度**：综合 QUIC、WebRTC、TURN 等链路，确保持续吞吐。
- **可验证结果**：每次跃迁都会生成可携带的 Proof of Transition（PoT）文件。

---

## 功能亮点

- **Aether 级传输管线**：自动在局域网 QUIC、点对点 WebRTC、TURN 中继及可选缓存之间择优切换。
- **可续传分片与自适应大小**：分片目录持久化，仅请求缺失段，并依据 RTT 自动调节分片尺寸。
- **端到端机密性**：使用 Noise/XChaCha20-Poly1305 加密隧道，身份临时生成，信令层对载荷保持盲态。
- **Proof of Transition 账本**：Merkle 校验的收据可导出，便于离线验证和审计。
- **Presence UI**：Vite + React 前端强调“先到感”叙事，状态卡片由 Rust 运行时驱动。
- **量子隧道界面**：参见 [docs/QUANTUM_UI.md](docs/QUANTUM_UI.md)，记录观察者/无时/无界原则、点阵虫洞与复制系统。
- **点阵虫洞（WebGL2）**：点精灵着色器自橙到靛渐变，按路由调整色调，爆发时提升噪声与曝光，并为低动态或不支持 GPU 场景提供自动 2D 备选。
- **沉浸式量子投递区**：零拷贝拖拽界面，带有动态皮肤、强度/速度控制，并支持减缓动效（详见 [Immersive Dropzone](docs/QUANTUM_UI.md#immersive-dropzone-zero-copy-ui)）。
- **可组合智能体**：运行时开放 Hook，供其他 AETHER 认知智能体订阅传输事件与记忆图谱。

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
rustup target add x86_64-apple-darwin         # 以 macOS 为例
cargo install tauri-cli                      # 可选，npm 脚本已自带

# 2. 安装 Node 依赖
npm install

# 3. 启动 React UI 与 Tauri Shell
npm run tauri:dev
# 或执行辅助脚本
./scripts/dev.sh

# 4. 合并前的质量关卡
./scripts/check.sh
# （执行仅构建验证：npm run build、cargo build --release）
```

常用命令：

- `npm run tauri:build`：生成可发布的桌面安装包。
- `cargo test --manifest-path src-tauri/Cargo.toml`：执行原生单元/集成测试。
- `npm run preview`：在无 Tauri Shell 的情况下预览编译后的前端。

### Proof of Transition 工作流

- 每次完成传输都会生成确定性的 `proofs/<taskId>.pot.json` 收据。可在历史面板中通过 **Export PoT** 再次查看存储路径。
- **Verify PoT** 支持加载任意 `.pot.json` 文件，完成结构与签名校验，并在失败时给出可执行提示。
- 传输卡片实时展示字节进度、移动平均速度与预计完成时间，便于与 PoT 导出结果对照。

### 断点续传工作流

- 运行时报告分片状态后，活动卡片会显示“可续传”徽标；中断任务将提供 **继续** 按钮，只补传缺失段。
- 续传元数据存储于 `cache/{taskId}-index.json`，成功完成或手动取消后会自动清理。
- 设置页的“Advanced chunk sizing” 面板可开启自适应分片，并设置最小/最大值（单位 MiB）。

---

## 量子身份与终端同频

> 身份/设备能力目前仅在 Tauri 桌面环境生效，浏览器模式会使用内存占位。

1. **创建或导入身份**：在“身份与设备”面板点击“创建主身份”生成 Ed25519 密钥对；如需在其他机器复原，可通过“导出私钥”复制十六进制，并在目标端输入身份 ID + 私钥进行导入。密钥会存放在本地 `AppData/identity` 目录（浏览器回退到 `localStorage`）。
2. **登记设备**：点击“登记新设备”即可生成终端公钥，前端会对 `register:<deviceId>:<devicePublicKey>` 签名，后端写入 SQLite `devices` 表。设备列表会显示状态、最近心跳时间与声明的能力标签。
3. **心跳同步**：面板每 15 秒向 `auth_heartbeat_device` 发送签名心跳，刷新 `status`、`last_seen_at`、`capabilities`，并通过 `identity_devices_updated` 事件广播到所有前端实例，实现“同频”效果。
4. **签名调用**：`courier_generate_code` / `courier_send` / `courier_receive` 均要求携带 `AuthenticatedPayload`，消息体为 `purpose:identity_id:device_id`。未登记或非 `active` 设备会被拒绝，防止越权。

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
