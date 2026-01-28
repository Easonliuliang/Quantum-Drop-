# BLE 近场发现功能实施路线（v2 — 现状对齐版）

## 现状快照

在动手前必须明确当前代码的实际状态，避免路线图脱离项目：

| 模块 | 现状 | 影响 |
|------|------|------|
| **发现层** | 只有 `MdnsRegistry`（`services/mdns.rs`），无抽象接口 | BLE 要接入必须先抽 discovery 层 |
| **接收入口** | `courier_connect_by_code` 直接调 `mdns.discover_sender()` | BLE 发现结果需要注入到同一条调用链 |
| **路由层** | `RouteKind` = Lan / P2p / Relay / MockLocal | BLE **不是**传输路由，不应新增 RouteKind |
| **前端接收 UI** | 无独立 ReceivePage，接收流程散落在 App.tsx | 加 BLE UI 前需先拆出接收组件 |
| **平台 target** | iOS 已有 Xcode 工程（`gen/apple/`），桌面也支持 | BLE 插件需 feature gate，桌面构建时跳过 |

---

## 核心原则

> **BLE 是发现源，不是传输通道。**

BLE 发现的终点是产出一个 `SenderInfo`（和 mDNS 一样），然后交给现有的 LAN/P2P/Relay 路由去建立连接。Router 和 RouteKind 不需要任何改动。

---

## 阶段 1（最高优先级）：抽象统一发现层

**为什么先做这个**：这是唯一不需要 BLE 硬件、不需要原生代码、纯 Rust 重构的阶段，做完后 BLE 可以无痛接入。

### 1.1 新建 `discovery.rs`

```rust
// src-tauri/src/services/discovery.rs

use std::time::Duration;
use super::mdns::{MdnsRegistry, SenderInfo};

#[derive(Debug, Clone, PartialEq)]
pub enum DiscoverySource {
    Mdns,
    Ble,
}

pub struct DiscoveryResult {
    pub source: DiscoverySource,
    pub sender: SenderInfo,
}

pub struct DiscoveryService {
    mdns: MdnsRegistry,
    // 后续: ble: Option<BleScanner>,
}

impl DiscoveryService {
    pub fn new(mdns: MdnsRegistry) -> Self {
        Self { mdns }
    }

    /// 并行竞速发现，谁先返回用谁
    pub async fn discover_by_code(
        &self,
        code: &str,
        timeout: Duration,
    ) -> anyhow::Result<DiscoveryResult> {
        // Phase 1: 只有 mDNS，BLE 接入后加 select! 分支
        let sender = self.mdns.discover_sender(code, timeout).await?;
        Ok(DiscoveryResult {
            source: DiscoverySource::Mdns,
            sender,
        })
    }

    /// 列出所有可见发送方（合并多个发现源）
    pub async fn list_senders(
        &self,
        timeout: Duration,
    ) -> anyhow::Result<Vec<DiscoveryResult>> {
        let mdns_list = self.mdns.list_senders(timeout).await?;
        Ok(mdns_list
            .into_iter()
            .map(|sender| DiscoveryResult {
                source: DiscoverySource::Mdns,
                sender,
            })
            .collect())
    }
}
```

### 1.2 改 `courier_connect_by_code` 调用链

当前（`commands/mod.rs`）：

```rust
// 直接调 mDNS
let sender_info = mdns
    .discover_sender(&auth.payload.code, Duration::from_secs(10))
    .await?;
```

改为：

```rust
// 通过统一发现层
let result = discovery
    .discover_by_code(&auth.payload.code, Duration::from_secs(10))
    .await?;
let sender_info = result.sender;
// result.source 可用于日志/前端展示
```

### 1.3 Tauri State 注册

```rust
// lib.rs
app.manage(DiscoveryService::new(mdns_registry));
```

`courier_connect_by_code` 的参数从 `State<'_, MdnsRegistry>` 改为 `State<'_, DiscoveryService>`。

### 产出

| 操作 | 文件 |
|------|------|
| 新建 | `src-tauri/src/services/discovery.rs` |
| 修改 | `src-tauri/src/services/mod.rs` — 导出 discovery |
| 修改 | `src-tauri/src/commands/mod.rs` — `courier_connect_by_code` 改用 DiscoveryService |
| 修改 | `src-tauri/src/lib.rs` — 注册 DiscoveryService 为 Tauri State |

### 验证标准

- 现有 mDNS 发现流程功能不变
- `courier_connect_by_code` 通过 DiscoveryService 调用 mDNS，行为一致
- 单元测试：mock DiscoveryService 返回 SenderInfo

---

## 阶段 2：BLE 广播数据格式设计

### 约束

BLE 4.x 广播有效载荷最大 **31 字节**。

### 核心问题：IP 地址怎么办？

mDNS 的 `SenderInfo` 包含 `host`（IP 地址），但 BLE 广播 31 字节放不下 IP。解决方案：

| 方案 | 做法 | 适用场景 |
|------|------|----------|
| **A: 扫描端推断** | BLE 只广播 code_hash + port，扫描端用自己的本地网段 + 对方 port 尝试连接 | 同网段，不可靠 |
| **B: GATT 补足** | 广播仅做发现，扫描端连 GATT 读取完整 SenderInfo（IP 列表、pubkey 全文等） | 通用，推荐 |
| **C: Scan Response** | 把 IP 编码进 Scan Response 包（额外 31 字节） | 同网段，较可靠 |

**推荐方案 B**：广播包只做"我在这儿 + 我的 code hash"，扫描端匹配后通过 BLE GATT 连接读取完整的连接信息。这样广播包极简，GATT 没有长度限制。

### 广播包结构（精简版）

```
┌──────────────────────────────────────────────────┐
│  BLE Advertisement Data (≤ 31 bytes)             │
├──────────────────────────────────────────────────┤
│  Flags (AD Type 0x01)                  3 bytes   │
│  Complete 128-bit Service UUID         18 bytes  │  ← QuantumDrop 自定义 UUID
│  Service Data:                         10 bytes  │
│    ├─ Protocol Version                 1 byte    │
│    ├─ Transfer Code Hash (SHA256前6字节) 6 bytes  │  ← SHA256(code)[0..6]
│    ├─ Capability Flags                 1 byte    │  ← bit0:可接收 bit1:QUIC bit2:WebRTC
│    └─ Reserved                         2 bytes   │
│                                        ────────  │
│  Total:                                31 bytes  │
└──────────────────────────────────────────────────┘
```

### GATT Service（扫描匹配后连接读取）

```
Service UUID: QuantumDrop 自定义 128-bit UUID
├── Characteristic: SenderInfo (Read)
│   └─ JSON: { code, device_name, host, port, public_key, cert_fingerprint, addr_list }
└── Characteristic: Session Nonce (Read)
    └─ 防重放随机数
```

扫描端流程：
1. BLE 广播扫描 → 收到 code_hash
2. 本地计算 `SHA256(我要找的 code)[0..6]`，比对
3. 匹配 → BLE GATT 连接 → 读取 SenderInfo Characteristic
4. 拿到完整 `SenderInfo`（含 IP、port、pubkey）
5. 断开 BLE → 走现有 LAN/P2P/Relay 连接

### 产出

| 操作 | 文件 |
|------|------|
| 新建 | `src-tauri/src/services/ble_protocol.rs` — 广播帧编解码 + GATT 数据序列化 |

---

## 阶段 3：Tauri BLE 原生插件

### 技术选型

**方案 A：Tauri 2 Plugin（Swift + Kotlin 原生桥接）** — 唯一可行方案。

`btleplug` 移动端不成熟，Web Bluetooth 不支持 Peripheral 角色。

### 插件结构

```
tauri-plugin-ble/
├── Cargo.toml              ← feature gate: target_os = "ios" / "android"
├── src/
│   └── lib.rs              ← Tauri plugin 注册 + desktop stub (no-op)
├── ios/
│   └── Sources/
│       └── BlePlugin.swift ← CBPeripheralManager + CBCentralManager
└── android/
    └── src/main/kotlin/
        └── BlePlugin.kt   ← BluetoothLeAdvertiser + BluetoothLeScanner
```

### Tauri Commands

```rust
// 广播（发送端使用）
fn ble_start_advertising(service_data: Vec<u8>, sender_info_json: String) -> Result<()>;
fn ble_stop_advertising() -> Result<()>;

// 扫描（接收端使用）
fn ble_start_scanning(target_code_hash: Vec<u8>) -> Result<()>;
fn ble_stop_scanning() -> Result<()>;

// GATT 读取（接收端在匹配后调用）
fn ble_read_sender_info(device_id: String) -> Result<String>;  // 返回 SenderInfo JSON

// 扫描结果通过 Tauri Event 推送
// Event: "ble://device-found" → { device_id, code_hash, rssi, matched: bool }
```

### 桌面平台处理

桌面构建时 BLE 插件编译为 no-op stub：

```rust
// tauri-plugin-ble/src/lib.rs
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    // 所有 command 返回 Err("BLE not available on desktop")
}
```

### 权限配置

**iOS Info.plist**：

```xml
<key>NSBluetoothAlwaysUsageDescription</key>
<string>QuantumDrop uses Bluetooth to discover nearby devices for file transfer</string>
<key>UIBackgroundModes</key>
<array>
    <string>bluetooth-central</string>
    <string>bluetooth-peripheral</string>
</array>
```

**Android AndroidManifest.xml**：

```xml
<uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN"
    android:usesPermissionFlags="neverForLocation" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
```

### 产出

| 操作 | 文件 |
|------|------|
| 新建 | `tauri-plugin-ble/` 整个目录 |
| 修改 | `src-tauri/Cargo.toml` — 添加 `transport-ble` feature + 插件依赖 |
| 修改 | `src-tauri/src/lib.rs` — 注册 BLE 插件（移动端） |
| 修改 | `Info.plist` — 蓝牙权限声明 |

---

## 阶段 4：BLE 接入发现层

将阶段 3 的 BLE 插件接入阶段 1 的 DiscoveryService。

### 修改 DiscoveryService

```rust
impl DiscoveryService {
    pub async fn discover_by_code(
        &self,
        code: &str,
        timeout: Duration,
    ) -> anyhow::Result<DiscoveryResult> {
        tokio::select! {
            // mDNS 路径（同网络）
            result = self.mdns.discover_sender(code, timeout) => {
                Ok(DiscoveryResult {
                    source: DiscoverySource::Mdns,
                    sender: result?,
                })
            }
            // BLE 路径（近场，无需同网）
            result = self.ble_discover(code, timeout) => {
                Ok(DiscoveryResult {
                    source: DiscoverySource::Ble,
                    sender: result?,
                })
            }
        }
    }

    async fn ble_discover(&self, code: &str, timeout: Duration) -> anyhow::Result<SenderInfo> {
        // 1. 计算 code hash
        // 2. 调 BLE 插件开始扫描
        // 3. 等待 "ble://device-found" 事件，matched=true
        // 4. 调 ble_read_sender_info(device_id) 获取完整 SenderInfo
        // 5. 返回 SenderInfo（和 mDNS 返回的结构完全一致）
    }
}
```

### 关键设计：BLE 发现后的连接路径

```
BLE 发现 → GATT 读取 SenderInfo
    │
    ├── SenderInfo.host 可达？（同局域网）
    │   └── YES → Router 走 LAN (QUIC) 直连     ← 最优路径
    │
    ├── 不在同网？
    │   └── Router 走 P2P (WebRTC) 或 Relay     ← 现有路由兜底
    │
    └── Router 决策完全不变，BLE 只负责"找到对方是谁"
```

**BLE 不参与 Router 的任何逻辑。** Router 拿到的仍然是 `SenderInfo`，和 mDNS 来的没区别。

### 发送端同步广播

`courier_send` 目前会调 `mdns.register_sender()`，需要同时触发 BLE 广播：

```rust
// commands/mod.rs — courier_send 内部
mdns.register_sender(code, task_id, port, &addresses, device_name, pubkey, certfp).await?;

// 新增：如果 BLE 可用，同时启动 BLE 广播
#[cfg(feature = "transport-ble")]
if let Some(ble) = app.try_state::<BlePlugin>() {
    let code_hash = sha256(code.as_bytes())[..6].to_vec();
    let sender_info_json = serde_json::to_string(&sender_info)?;
    let _ = ble.start_advertising(code_hash, sender_info_json).await;
}
```

### 产出

| 操作 | 文件 |
|------|------|
| 修改 | `src-tauri/src/services/discovery.rs` — 加 BLE 分支 |
| 修改 | `src-tauri/src/commands/mod.rs` — `courier_send` 加 BLE 广播 |

---

## 阶段 5：前端接收 UI

### 现状分析（阶段 3/4 完成后更新）

原计划假设前端有 Sidebar + 多页面路由架构，**实际不符**：

- 当前唯一界面是 `MinimalUI`（全屏拖拽区 + 右上角齿轮图标）
- `SettingsPanel` 从右侧滑出，承载好友/设备/日志/语言设置
- `Sidebar.tsx`、`SendPage.tsx` 等文件虽存在但**未被渲染**
- `currentPage` 状态声明了但 JSX 未使用
- 无任何接收 UI，`courier_connect_by_code` 后端未被前端调用

### 方案选择：独立接收面板（方案 B）

> "接收"是核心操作，不是"设置"——需要独立入口和专用空间。

**选型理由**：
1. SettingsPanel 滑出面板模式已验证可用，直接复用
2. MinimalUI 只加一个按钮，不破坏发送体验
3. BLE 设备列表 + 配对码输入需要足够空间
4. 移动端交互：接收按钮与齿轮图标对称，点击弹出专用面板

### 实施步骤

#### 5.1 新建 ReceivePanel 组件

```
src/components/ReceivePanel/
├── ReceivePanel.tsx   ← 滑出面板（复用 SettingsPanel 样式）
├── ReceivePanel.css
└── index.ts
```

面板内容分三个区域：

**区域 1：配对码输入**
- 6 位配对码输入框（同 SettingsPanel 中设备码输入的样式）
- 输入后自动调用 `courier_connect_by_code`（走 DiscoveryService 竞速 mDNS + BLE）
- 状态显示：空闲 → 搜索中（动画）→ 已发现 → 连接中 → 传输中

**区域 2：BLE 附近设备列表（仅移动端）**
- 监听 Tauri 事件 `device-found`
- 每个设备条目显示：
  - 设备名 / device_id
  - 发现来源标记：`[BLE]`（信号强度 RSSI dBm）
  - "连接" 按钮 → 调用 `read_sender_info` → 自动开始接收
- 列表顶部显示扫描状态（扫描中 / 已暂停）
- 桌面端此区域隐藏或显示"BLE 仅移动端可用"提示

**区域 3：保存目录选择**
- 默认下载目录
- "更改目录" 按钮（调用 `tauri-plugin-dialog` 文件夹选择）

#### 5.2 MinimalUI 添加接收入口

```tsx
// MinimalUI.tsx — 新增接收按钮（与齿轮图标对称）
<button className="receive-trigger" onClick={onOpenReceive}>
  <svg>...</svg>  {/* 下载图标 */}
</button>
```

位置：左上角或左下角（与右上角齿轮对称）。

#### 5.3 App.tsx 状态与事件

```typescript
// 新增状态
const [receiveOpen, setReceiveOpen] = useState(false);
const [bleDevices, setBleDevices] = useState<BleDevice[]>([]);
const [receiveStatus, setReceiveStatus] = useState<'idle' | 'scanning' | 'found' | 'connecting'>('idle');

// BLE 事件监听（移动端）
useEffect(() => {
  const unlisten = listen<BleDeviceFoundEvent>('device-found', (event) => {
    setBleDevices(prev => {
      const existing = prev.find(d => d.deviceId === event.payload.deviceId);
      if (existing) {
        return prev.map(d => d.deviceId === event.payload.deviceId
          ? { ...d, rssi: event.payload.rssi, matched: event.payload.matched }
          : d
        );
      }
      return [...prev, event.payload];
    });
  });
  return () => { unlisten.then(fn => fn()); };
}, []);

// 配对码接收处理
const handleReceiveByCode = async (code: string, saveDir: string) => {
  setReceiveStatus('scanning');
  await invoke('courier_connect_by_code', {
    auth: { identityId, deviceId, signature, payload: { code, saveDir } },
  });
};
```

#### 5.4 i18n 补充翻译

```typescript
// 中文
"receive.panel.title": "接收文件",
"receive.code.placeholder": "输入 6 位配对码",
"receive.code.searching": "搜索发送方…",
"receive.code.found": "已发现发送方",
"receive.ble.title": "附近设备",
"receive.ble.scanning": "正在扫描…",
"receive.ble.empty": "未发现附近设备",
"receive.ble.connect": "连接",
"receive.ble.desktopHint": "BLE 近场发现仅移动端可用",
"receive.saveDir.label": "保存到",
"receive.saveDir.change": "更改目录",

// English
"receive.panel.title": "Receive Files",
"receive.code.placeholder": "Enter 6-digit code",
"receive.code.searching": "Searching for sender…",
"receive.code.found": "Sender found",
"receive.ble.title": "Nearby Devices",
"receive.ble.scanning": "Scanning…",
"receive.ble.empty": "No nearby devices found",
"receive.ble.connect": "Connect",
"receive.ble.desktopHint": "BLE discovery is only available on mobile",
"receive.saveDir.label": "Save to",
"receive.saveDir.change": "Change folder",
```

### 产出

| 操作 | 文件 | 说明 |
|------|------|------|
| 新建 | `src/components/ReceivePanel/ReceivePanel.tsx` | 滑出式接收面板 |
| 新建 | `src/components/ReceivePanel/ReceivePanel.css` | 面板样式 |
| 新建 | `src/components/ReceivePanel/index.ts` | 导出 |
| 修改 | `src/components/MinimalUI/MinimalUI.tsx` | 添加接收按钮入口 |
| 修改 | `src/components/MinimalUI/MinimalUI.css` | 接收按钮样式 |
| 修改 | `src/App.tsx` | receiveOpen 状态、BLE 事件监听、ReceivePanel 渲染 |
| 修改 | `src/lib/i18n.tsx` | BLE 接收相关翻译 |

### 验证标准

- 点击接收按钮 → 面板滑出
- 输入配对码 → 调用 `courier_connect_by_code` → 显示搜索/发现/连接状态
- 移动端 BLE 扫描 → 设备列表实时更新
- 桌面端 BLE 区域显示"仅移动端"提示
- 面板外点击或 ESC 关闭面板

---

## 阶段 6（暂缓）：完全离线近场传输

> **状态：短期不实施。** 阶段 1–5 覆盖的 LAN + WebSocket 信令 WebRTC + Relay 三条路径已满足绝大多数场景。

### 原方案评估：BLE GATT Signaling（已否决）

原计划用 BLE GATT 代替 WebSocket 交换 WebRTC SDP/ICE，实现零服务器 P2P。经评估**不采用**，原因：

| 问题 | 分析 |
|------|------|
| **场景极窄** | BLE 可达（≤10m）意味着设备在近场。同 WiFi → LAN 直连即可；有网 → 信令服务器可用；无网 → WebRTC ICE 候选全是本地地址，数据通道也建不起来 |
| **复杂度过高** | SDP 2-5KB 需 MTU 分片协议、双平台原生 GATT Server/Client、Rust trait 重构信令核心路径，涉及 13 个文件 |
| **收益不对称** | 本质是为"信令服务器恰好挂了但 STUN/TURN 正常"这一运维问题做架构改造 |

### 替代方向：平台原生 P2P 直连

如果未来确实需要"完全离线近场传输"，更合理的方案是绕开 WebRTC，使用平台原生近场通信：

```
原方案（臃肿）: BLE发现 → BLE GATT信令 → WebRTC → 数据传输
替代方案（精简）: BLE发现 → 平台原生P2P直连 → 数据传输
```

| 平台 | 技术 | 特点 |
|------|------|------|
| iOS | Multipeer Connectivity | Apple 原生框架，WiFi + BLE 自动切换，无需服务器，速度可达百兆级 |
| Android | Wi-Fi Aware / Wi-Fi Direct | 近场高速直连，无需路由器，Android 8.0+ 支持 |
| 跨平台兜底 | BLE 数据通道 | 小文件（<100KB）可直接通过 GATT 传输，无需 WebRTC |

### 如果实施，建议架构

新增 `RouteKind::NearbyDirect`，作为 Router 的一条新路由：

```rust
// transport/router.rs
pub enum RouteKind {
    Lan,        // QUIC 直连
    P2p,        // WebRTC (WebSocket 信令)
    Relay,      // TCP 中继
    Nearby,     // 平台原生近场直连 (Multipeer / WiFi Direct)
    MockLocal,  // 测试
}
```

```
Router 优先级:
  1. LAN (QUIC, 3s)       ← 同网最优
  2. Nearby (原生P2P, 5s) ← 近场、不同网
  3. P2P (WebRTC, 10s)    ← 远程
  4. Relay (TCP, 8s)      ← 兜底
```

### 实施前提

- 阶段 1–5 稳定运行，无明显缺陷
- 有明确的离线传输用户需求
- 双平台真机测试环境就绪

---

## 实施顺序与依赖

```
阶段 1 ──→ 阶段 2 ──→ 阶段 3 ──→ 阶段 4 ──→ 阶段 5    ✅ 已完成
发现层抽象   广播格式   原生插件    接入发现层   前端 UI
(纯Rust)    (纯Rust)  (Swift/Kt) (Rust)     (React)

                                                  ···· 阶段 6（暂缓）
                                                       平台原生 P2P
                                                       (待需求驱动)
```

---

## 核心文件变更清单（阶段 1–5）

| 操作 | 文件 | 阶段 |
|------|------|------|
| **新建** | `src-tauri/src/services/discovery.rs` | 1 |
| **修改** | `src-tauri/src/services/mod.rs` | 1 |
| **修改** | `src-tauri/src/commands/mod.rs` — 改用 DiscoveryService | 1 |
| **修改** | `src-tauri/src/lib.rs` — 注册 DiscoveryService | 1 |
| **新建** | `src-tauri/src/services/ble_protocol.rs` | 2 |
| **新建** | `tauri-plugin-ble/` 整个目录 | 3 |
| **修改** | `src-tauri/Cargo.toml` — feature gate + 依赖 | 3 |
| **修改** | `Info.plist` — 蓝牙权限 | 3 |
| **修改** | `src-tauri/src/services/discovery.rs` — 加 BLE 分支 | 4 |
| **修改** | `src-tauri/src/commands/mod.rs` — courier_send 加 BLE 广播 | 4 |
| **新建** | `src/components/ReceivePanel/ReceivePanel.tsx` | 5 |
| **新建** | `src/components/ReceivePanel/ReceivePanel.css` | 5 |
| **修改** | `src/components/MinimalUI/MinimalUI.tsx` | 5 |
| **修改** | `src/App.tsx` | 5 |
| **修改** | `src/lib/i18n.tsx` | 5 |

## 不变更的文件

| 文件 | 原因 |
|------|------|
| `src-tauri/src/transport/router.rs` | BLE 不是传输路由，Router 无需改动（阶段 6 如实施才会新增 RouteKind） |
| `src-tauri/src/transport/quic.rs` | 传输层不受影响 |
| `src-tauri/src/transport/webrtc.rs` | 传输层不受影响 |
| `src-tauri/src/services/mdns.rs` | 接口不变，被 DiscoveryService 包装 |

---

## 风险点（阶段 1–5）

1. **Tauri 2 移动端 Plugin 桥接**：官方示例少，需参考 `tauri-plugin-nfc` 等社区插件的 Swift/Kotlin 桥接模式
2. **iOS 后台 BLE**：App 进后台后系统截断广播数据至仅 Service UUID，code_hash 会丢失，只能前台使用
3. **Android BLE 碎片化**：不同厂商实现差异大，需要多机型真机测试
4. **GATT 连接稳定性**：BLE GATT 读取 SenderInfo 可能因信号弱或干扰失败，需要重试机制
5. **Feature Gate 复杂度**：`transport-ble` feature 需要确保桌面端编译时完全跳过原生代码，避免构建失败
