# Quantum Drop · 安全设计速览

本节记录 S2/S3 阶段已经落地的安全机制，方便在评审、排障或拓展到企业版时查阅。

## 1. 密钥与身份

| 维度 | 存储位置 | 周期 | 说明 |
| --- | --- | --- | --- |
| 身份（Ed25519） | `AppData/identity/<id>.priv` + `.pub` | 永久（可移除） | 由 UI 在“创建主身份”时生成，Tauri 端仅保存到本地磁盘。 |
| 设备公钥 | `identities.sqlite3/devices` | 永久 | 各设备注册时由身份私钥签名，后续命令校验用途。 |
| 会话密钥（X25519→ChaCha20） | 内存 | 单次任务 | `courier_generate_code` / `courier_receive` 创建，`secure_router_stream` 使用后丢弃。 |

> ⚠️ 身份/设备私钥永不送入 Rust；WebRTC 信令签名通过读取 `AppData/identity/<id>.priv`（仅在本机）完成。

## 2. WebRTC 信令签名

1. Router 选择 P2P 路由时会向 `SessionDesc.webrtc` 注入：
   - `identity_id` / `device_id` / `device_name`
   - `signer_public_key`（Ed25519 公钥）
2. WebRTC 适配器在构建信令 URL 时带上 `sessionId`、`deviceId`、`deviceName`、`publicKey`。
3. 适配器从 `AppData/identity/<id>.priv` 读取身份私钥，对 `offer/answer/ICE` 组装规范文本：

```
quantumdrop.signaling.v1
session:<session_id>
device:<device_id>
offer:<sdp_offer>
answer:<sdp_answer>
ice:<json_candidates>
```

4. Signaling Server（Axum）验证：
   - 根据 WebSocket 查询参数登记 `deviceId`+`publicKey`
   - 每次更新校验 Ed25519 签名，失败时根据 `SecurityConfig` 决定仅告警或断开。
   - 成功后在广播快照中附带 `signer_device_id`/`device_name`/`signer_public_key`/`verified`。

## 3. Peer 信任（TOFU）

UI 监听 `peer_discovered` 事件：

```ts
listen<PeerDiscoveredPayload>('peer_discovered', payload => {
  // verified = true 表示服务器已验签
});
```

* 新设备若签名通过 → 自动记录为受信，日志输出 “已签名验证”。
* 未签名设备 → 弹出“发现新设备”对话框，要求用户比对指纹。
* 受信列表以 JSON 形式保存到 `localStorage["courier.trustedPeers"]`（桌面模式同样持久）；下次发现同指纹会自动信任。

> 可在“身份与设备”面板下方查看、清理受信设备。

## 4. 配置与策略

`docs/app.sample.yaml` 中 `security` 字段：

```yaml
security:
  enforceSignatureVerification: true    # 生产建议开启
  disconnectOnVerificationFail: true    # 验签失败立即断开
  enableAuditLog: true                  # 记录日志，便于审计
```

环境变量可覆盖：

| 变量 | 作用 |
| --- | --- |
| `QD_ENFORCE_SIGNATURE` | `true/false` |
| `QD_DISCONNECT_ON_FAIL` | `true/false` |
| `QD_ENABLE_AUDIT_LOG` | `true/false` |

## 5. 路由与降级

* `preferredRoutes`: `[lan, p2p, relay]`（默认为配置中的顺序）。也可在任务级别覆写（WebRTC 测试命令强制 `[p2p]`）。
* Router 一次性并发所有可用适配器，首个成功流即被选用，其余 abort。
* `RouteMetricsRegistry` 按路由存储成功率/延迟/最后错误，UI 可在“路由探测”面板查看。

## 6. 手动测试清单（建议保存在 README 或 release note 中）

1. **LAN + 签名展示**  
   - 终端 A：`courier_generate_code` → `courier_send`  
   - 终端 B：`courier_receive` 输入 IP/端口/公钥  
   - 期望：`peer_discovered` 显示“签名通过”，传输完成生成 PoT。

2. **WebRTC P2P（TOFU）**  
   - 终端 A/B 各运行 `courier_start_webrtc_sender/receiver`。  
   - 首次互信需在 UI 对话框输入指纹；再次连接应自动信任。

3. **签名失败场景**  
   - 将 Signaling Server `security.enforceSignatureVerification` 设为 `true`。  
   - 修改前端传输的签名或公钥，确认服务器日志输出并断开连接。

4. **配置验证**  
   - 修改 `app.yaml` 的 `preferredRoutes`，确认 `transfer_log` 中的 “Route candidates: [...]” 顺序匹配配置。

如需更严格的审计，可把 `trustedPeers` 移出本地存储，挂钩 SQLite 或远程 KV，并在签名事件中记录到 `logs/`。***
