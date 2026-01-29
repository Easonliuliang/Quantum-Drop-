# Quantum Drop

[![Release](https://github.com/Easonliuliang/Quantum-Drop-/actions/workflows/release.yml/badge.svg)](https://github.com/Easonliuliang/Quantum-Drop-/actions/workflows/release.yml)
![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)
![Node](https://img.shields.io/badge/node-18.x-026e00?logo=node.js)
![License](https://img.shields.io/badge/license-MIT-blue)

跨平台文件传输工具，基于 Tauri + Rust + React 构建。

![Demo](demo.gif)

## 特性

- **多路由传输** - LAN (QUIC) → P2P (WebRTC) → Relay → BLE，智能路由自动降级
- **量子视觉系统** - WebGL Shader 背景、虫洞隧道、粒子效果，沉浸式传输体验
- **BLE 设备发现** - 蓝牙低功耗近场设备扫描与配对
- **mDNS 自动发现** - 局域网内设备自动发现，无需手动输入 IP
- **朋友系统** - 基于单词组合的配对码，简单易记
- **PoT 传输证明** - 每次传输生成密码学签名的收据
- **Ed25519 身份** - 本地生成密钥对，设备登记与心跳同步
- **国际化** - 中文 / English 即时切换

## 技术栈

| 层级 | 技术 |
|------|------|
| 桌面框架 | Tauri v2 |
| 后端 | Rust |
| 前端 | React 18 + TypeScript |
| 视觉 | Three.js / WebGL Shader |
| 加密 | Ed25519 (@noble/ed25519) |
| 传输 | QUIC / WebRTC / BLE |

## 项目结构

```
├── src/                    # React 前端
│   ├── quantum/            # 量子视觉系统组件
│   │   ├── QuantumField    # WebGL 量子场背景
│   │   ├── EventHorizon    # 事件视界交互层
│   │   ├── WormholePortal  # Three.js 虫洞隧道
│   │   └── CollapseEffect  # 坍缩动画
│   ├── components/         # UI 组件
│   │   ├── MinimalUI       # 极简拖拽界面
│   │   ├── ReceivePanel    # 接收面板
│   │   ├── SettingsPanel   # 设置面板
│   │   └── ColorBends      # 彩虹背景效果
│   └── lib/                # 工具库
├── src-tauri/              # Rust 后端
│   └── src/
│       ├── services/       # 核心服务
│       │   ├── discovery   # 设备发现
│       │   ├── ble_protocol# BLE 协议
│       │   └── mdns        # mDNS 服务
│       ├── transport/      # 传输层
│       ├── crypto/         # 加密模块
│       └── license/        # 授权系统
└── docs/                   # 文档
```

## 快速开始

```bash
# 安装依赖
npm install

# 启动开发环境
npm run tauri:dev

# 构建发布包
npm run tauri:build

# 运行测试
npm run check
```

### 环境要求

- Node.js >= 18.17
- Rust (stable)
- Xcode Command Line Tools (macOS) / Visual Studio Build Tools (Windows)

## 使用

### 发送文件

1. 拖拽文件到窗口，或点击选择文件
2. 自动生成 6 位配对码
3. 等待接收方连接

### 接收文件

1. 点击接收按钮打开面板
2. 输入发送方的配对码
3. 或从 BLE 设备列表选择

### 路由优先级

传输自动按优先级选择最优路由：

1. **LAN** - 局域网 QUIC 直连（最快）
2. **P2P** - WebRTC 点对点
3. **Relay** - 中继服务器
4. **BLE** - 蓝牙近场传输

## 视觉系统

量子视觉系统基于物理隐喻设计：

| 状态 | 视觉效果 |
|------|----------|
| 待机 | 量子场背景缓慢呼吸 |
| 拖拽 | 空间扭曲，引力透镜效果 |
| 传输 | 虫洞隧道，粒子流喷射 |
| 完成 | 坍缩为奇点，收据浮现 |

路由颜色编码：
- 🔵 LAN: `#00f3ff` 青色
- 🟣 P2P: `#bc13fe` 紫色
- 🟠 Relay: `#ff6b35` 橙色

## 开发

```bash
# 前端开发（仅 UI）
npm run dev:ui

# Rust 测试
cargo test --manifest-path src-tauri/Cargo.toml

# 代码检查
npm run lint
cargo clippy --manifest-path src-tauri/Cargo.toml

# 启用 BLE 功能构建
cargo build --manifest-path src-tauri/Cargo.toml --features transport-ble
```

## 开发进度

### 已完成 ✅

| 模块 | 状态 | 说明 |
|------|------|------|
| 身份系统 | ✅ | Ed25519 密钥生成、设备注册、心跳同步 |
| LAN 传输 | ✅ | QUIC 协议直连 |
| P2P 传输 | ✅ | WebRTC 穿透 |
| Relay 传输 | ✅ | 中继服务器备用 |
| mDNS 发现 | ✅ | 局域网设备自动发现 |
| 配对码系统 | ✅ | 6 位字母数字码，3 分钟过期 |
| PoT 证明 | ✅ | 传输收据签名验证 |
| 量子视觉 | ✅ | WebGL 背景、虫洞效果 |
| i18n | ✅ | 中/英文切换 |
| Tauri v2 兼容 | ✅ | 插件权限、API 更新 |

### 进行中 🚧

| 模块 | 状态 | 说明 |
|------|------|------|
| BLE 发现 | 🚧 | 基础层完成，需要启用 feature 测试 |
| BLE 传输 | 📋 | GATT 协议待实现 |

### BLE 功能说明

BLE 功能为可选特性，默认未启用。启用方式：

```toml
# src-tauri/Cargo.toml
[features]
default = ["transport-quic", "transport-webrtc", "transport-relay", "transport-ble"]
```

macOS 需要蓝牙权限，iOS/Android 需要在 Info.plist / AndroidManifest.xml 中声明。

## License

MIT
