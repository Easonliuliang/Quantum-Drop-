# 前端布局优化方案

## 项目背景

项目采用 **Tauri + React + TypeScript + 原生CSS** 技术栈，当前所有内容在单页中垂直堆叠，导致页面过长需要大量滚动。

## 优化目标

- 采用**侧边栏导航 + 主内容区域**的布局架构
- 优化传输状态面板，使用标签页组织多个子面板
- 优化身份与设备面板，使用网格布局展示设备列表
- 减少垂直滚动，提升信息层次感

---

## 📁 文件结构规划

```
src/
├── components/
│   ├── Layout/
│   │   ├── MainLayout.tsx          ← 新建：主布局容器
│   │   ├── Sidebar.tsx             ← 新建：侧边栏导航
│   │   ├── Header.tsx              ← 新建：顶部导航栏
│   │   └── layout.css              ← 新建：布局专用样式
│   ├── Pages/
│   │   ├── SendPage.tsx            ← 新建：发送页面
│   │   ├── ReceivePage.tsx         ← 新建：接收页面
│   │   ├── IdentityPage.tsx        ← 新建：身份管理页面
│   │   ├── TransferStatusPage.tsx  ← 新建：传输状态页面（核心优化）
│   │   ├── WebRTCPage.tsx          ← 新建：WebRTC页面
│   │   └── LogsPage.tsx            ← 新建：日志页面
│   └── ... (保持现有组件)
├── App.tsx                          ← 修改：简化为路由容器
└── styles.css                       ← 修改：添加新样式
```

---

## 📐 整体布局结构

```
┌─────────────────────────────────────────┐
│  [Logo] 时光穿梭机      [语言切换]      │  ← 顶部导航栏
├──────────┬──────────────────────────────┤
│          │                              │
│  侧边栏  │        主内容区域             │
│  导航    │                              │
│          │                              │
│  📤 发送 │    根据左侧选中项动态切换     │
│  📥 接收 │                              │
│  👤 身份 │                              │
│  📊 状态 │                              │
│  📋 日志 │                              │
│          │                              │
└──────────┴──────────────────────────────┘
```

### 侧边栏导航项

1. **📤 发送文件** - 文件投递区 + 已选文件列表
2. **📥 接收文件** - 配对码/扫描/手动三种方式
3. **👤 身份管理** - 身份与设备面板（保持主体设计不变）
4. **📊 传输状态** - 传输进行时的详细信息（条件显示）
5. **🔗 WebRTC** - 跨网实验功能
6. **📋 日志面板** - 事件流日志

---

## 📝 详细代码示例

### 1️⃣ 新建：`src/components/Layout/Sidebar.tsx`

```typescript
import { useI18n } from "../../lib/i18n";

type Page = "send" | "receive" | "identity" | "transfer" | "webrtc" | "logs";

interface SidebarProps {
  currentPage: Page;
  onPageChange: (page: Page) => void;
  hasActiveTransfer: boolean; // 是否有进行中的传输
  hasLogs: boolean; // 是否有日志
}

export function Sidebar({ currentPage, onPageChange, hasActiveTransfer, hasLogs }: SidebarProps) {
  const { t } = useI18n();

  const navItems: Array<{
    id: Page;
    icon: string;
    label: string;
    badge?: boolean; // 是否显示红点提示
    disabled?: boolean;
  }> = [
    { id: "send", icon: "📤", label: t("nav.send", "发送文件") },
    { id: "receive", icon: "📥", label: t("nav.receive", "接收文件") },
    { id: "identity", icon: "👤", label: t("nav.identity", "身份管理") },
    { id: "transfer", icon: "📊", label: t("nav.transfer", "传输状态"), badge: hasActiveTransfer, disabled: !hasActiveTransfer },
    { id: "webrtc", icon: "🔗", label: t("nav.webrtc", "跨网实验") },
    { id: "logs", icon: "📋", label: t("nav.logs", "事件日志"), badge: hasLogs, disabled: !hasLogs },
  ];

  return (
    <aside className="sidebar">
      <nav className="sidebar-nav" role="navigation">
        {navItems.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`nav-item ${currentPage === item.id ? "active" : ""} ${item.disabled ? "disabled" : ""}`}
            onClick={() => !item.disabled && onPageChange(item.id)}
            disabled={item.disabled}
            aria-current={currentPage === item.id ? "page" : undefined}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
            {item.badge && <span className="nav-badge" />}
          </button>
        ))}
      </nav>
    </aside>
  );
}
```

---

### 2️⃣ 新建：`src/components/Layout/Header.tsx`

```typescript
import { LocaleSwitch } from "../LocaleSwitch";

interface HeaderProps {
  title?: string;
}

export function Header({ title = "时光穿梭机" }: HeaderProps) {
  return (
    <header className="app-header">
      <div className="header-left">
        <h1 className="app-title">{title}</h1>
      </div>
      <div className="header-right">
        <LocaleSwitch />
      </div>
    </header>
  );
}
```

---

### 3️⃣ 新建：`src/components/Layout/MainLayout.tsx`

```typescript
import { type ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";

type Page = "send" | "receive" | "identity" | "transfer" | "webrtc" | "logs";

interface MainLayoutProps {
  currentPage: Page;
  onPageChange: (page: Page) => void;
  hasActiveTransfer: boolean;
  hasLogs: boolean;
  children: ReactNode;
}

export function MainLayout({
  currentPage,
  onPageChange,
  hasActiveTransfer,
  hasLogs,
  children,
}: MainLayoutProps) {
  return (
    <div className="app-layout">
      <Header />
      <div className="layout-body">
        <Sidebar
          currentPage={currentPage}
          onPageChange={onPageChange}
          hasActiveTransfer={hasActiveTransfer}
          hasLogs={hasLogs}
        />
        <main className="main-content" role="main">
          {children}
        </main>
      </div>
    </div>
  );
}
```

---

### 4️⃣ 核心优化：`src/components/Pages/TransferStatusPage.tsx`

```typescript
import { useState } from "react";
import { useI18n } from "../../lib/i18n";
import { PanelBoundary } from "../ErrorBoundary/PanelBoundary";

type TabId = "basic" | "monitor" | "stats" | "audit" | "security" | "settings";

interface TransferStatusPageProps {
  // 从 App.tsx 传入的所有传输相关数据
  taskId: string | null;
  taskCode: string | null;
  taskPublicKey: string | null;
  phase: string;
  progress: number | null;
  route: string | null;
  routeAttempts: string[];
  speedBps: number | null;
  bytesSent: number | null;
  bytesTotal: number | null;
  auditLog: any[];
  trustedPeers: any[];
  licenseInfo: any;
}

export function TransferStatusPage(props: TransferStatusPageProps) {
  const { t } = useI18n();
  const [activeTab, setActiveTab] = useState<TabId>("basic");

  const tabs: Array<{ id: TabId; label: string; icon: string }> = [
    { id: "basic", label: t("transfer.tab.basic", "基础信息"), icon: "ℹ️" },
    { id: "monitor", label: t("transfer.tab.monitor", "实时监控"), icon: "📡" },
    { id: "stats", label: t("transfer.tab.stats", "统计数据"), icon: "📊" },
    { id: "audit", label: t("transfer.tab.audit", "审计日志"), icon: "📋" },
    { id: "security", label: t("transfer.tab.security", "安全策略"), icon: "🔒" },
    { id: "settings", label: t("transfer.tab.settings", "高级设置"), icon: "⚙️" },
  ];

  return (
    <div className="transfer-status-page">
      {/* 标签页导航 */}
      <div className="tab-navigation">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`tab-button ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tab-icon">{tab.icon}</span>
            <span className="tab-label">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* 标签页内容 */}
      <div className="tab-content">
        <PanelBoundary>
          {activeTab === "basic" && <BasicInfoTab {...props} />}
          {activeTab === "monitor" && <MonitorTab {...props} />}
          {activeTab === "stats" && <StatsTab {...props} />}
          {activeTab === "audit" && <AuditTab {...props} />}
          {activeTab === "security" && <SecurityTab {...props} />}
          {activeTab === "settings" && <SettingsTab {...props} />}
        </PanelBoundary>
      </div>
    </div>
  );
}

// 基础信息标签页
function BasicInfoTab(props: TransferStatusPageProps) {
  const { taskId, taskCode, taskPublicKey, phase, route } = props;

  return (
    <div className="basic-info-tab">
      <div className="info-grid">
        <div className="info-card">
          <label>取件码</label>
          <div className="info-value">{taskCode || "—"}</div>
        </div>
        <div className="info-card">
          <label>任务ID</label>
          <div className="info-value mono">{taskId || "—"}</div>
        </div>
        <div className="info-card">
          <label>传输阶段</label>
          <div className="info-value">{phase || "—"}</div>
        </div>
        <div className="info-card">
          <label>路由方式</label>
          <div className="info-value">
            {route === "lan" && "🌐 局域网"}
            {route === "p2p" && "🔗 点对点"}
            {route === "relay" && "🌍 中继"}
            {!route && "—"}
          </div>
        </div>
      </div>

      {/* 公钥显示 */}
      {taskPublicKey && (
        <div className="public-key-section">
          <label>公钥</label>
          <div className="mono-value">{taskPublicKey}</div>
        </div>
      )}
    </div>
  );
}

// 实时监控标签页
function MonitorTab(props: TransferStatusPageProps) {
  const { progress, speedBps, bytesSent, bytesTotal, routeAttempts } = props;

  const formatSpeed = (bps: number | null) => {
    if (!bps) return "—";
    if (bps < 1024) return `${bps.toFixed(0)} B/s`;
    if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(2)} KB/s`;
    return `${(bps / 1024 / 1024).toFixed(2)} MB/s`;
  };

  const formatBytes = (bytes: number | null) => {
    if (!bytes) return "—";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
  };

  return (
    <div className="monitor-tab">
      {/* 进度条 */}
      <div className="progress-section">
        <div className="progress-header">
          <span>传输进度</span>
          <span className="progress-percent">{progress !== null ? `${(progress * 100).toFixed(1)}%` : "—"}</span>
        </div>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${(progress || 0) * 100}%` }} />
        </div>
        <div className="progress-details">
          <span>{formatBytes(bytesSent)} / {formatBytes(bytesTotal)}</span>
        </div>
      </div>

      {/* 传输速度 */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-label">当前速度</div>
          <div className="metric-value">{formatSpeed(speedBps)}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">已传输</div>
          <div className="metric-value">{formatBytes(bytesSent)}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">总大小</div>
          <div className="metric-value">{formatBytes(bytesTotal)}</div>
        </div>
      </div>

      {/* 路由尝试 */}
      {routeAttempts && routeAttempts.length > 0 && (
        <div className="route-attempts">
          <h4>路由尝试</h4>
          <ul>
            {routeAttempts.map((attempt, i) => (
              <li key={i}>{attempt}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// 统计数据标签页（复用原 stats-panel 内容）
function StatsTab(props: TransferStatusPageProps) {
  return (
    <div className="stats-tab">
      {/* 从 App.tsx 的 stats-panel 迁移内容 */}
      <p>传输统计、License管理等内容</p>
    </div>
  );
}

// 审计日志标签页（复用原 audit-panel 内容）
function AuditTab(props: TransferStatusPageProps) {
  const { auditLog } = props;

  return (
    <div className="audit-tab">
      <div className="audit-list">
        {auditLog.map((log, i) => (
          <div key={i} className="audit-item">
            <span className="audit-time">{log.timestamp}</span>
            <span className="audit-message">{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// 安全策略标签页（复用原 security-panel + trusted-peers-panel 内容）
function SecurityTab(props: TransferStatusPageProps) {
  const { trustedPeers } = props;

  return (
    <div className="security-tab">
      <div className="trusted-peers-section">
        <h4>已信任设备</h4>
        {/* 信任设备列表 */}
      </div>
      <div className="security-policy-section">
        <h4>安全策略</h4>
        {/* 安全策略配置 */}
      </div>
    </div>
  );
}

// 高级设置标签页（复用原 settings-panel 内容）
function SettingsTab(props: TransferStatusPageProps) {
  return (
    <div className="settings-tab">
      {/* Chunk策略等设置 */}
      <p>Chunk策略、传输参数等设置</p>
    </div>
  );
}
```

---

### 5️⃣ 新建：`src/components/Pages/IdentityPage.tsx`

```typescript
import { useI18n } from "../../lib/i18n";
import { PanelBoundary } from "../ErrorBoundary/PanelBoundary";

interface IdentityPageProps {
  identity: any;
  activeDeviceId: string | null;
  devices: any[];
  selectedDevice: any;
  onCreateIdentity: () => void;
  onForgetIdentity: () => void;
}

export function IdentityPage(props: IdentityPageProps) {
  const { t } = useI18n();
  const { identity, devices, selectedDevice } = props;

  return (
    <div className="identity-page">
      <PanelBoundary>
        <div className="identity-section">
          <h2>{t("identity.heading", "身份与设备")}</h2>

          {/* 身份信息展示 */}
          {identity ? (
            <div className="identity-info">
              <div className="info-grid">
                <div className="info-item">
                  <label>身份标识</label>
                  <div className="value-with-copy">
                    <span className="mono">{identity.identityId}</span>
                    <button type="button" className="copy-btn">复制</button>
                  </div>
                </div>
                <div className="info-item">
                  <label>主公钥</label>
                  <div className="value-with-copy">
                    <span className="mono">{identity.publicKey}</span>
                    <button type="button" className="copy-btn">复制</button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <p className="empty-state">尚未注册身份，点击"创建主身份"即可生成量子身份。</p>
          )}

          {/* 操作按钮组 */}
          <div className="actions-row">
            <button type="button" onClick={props.onCreateIdentity}>创建主身份</button>
            <button type="button" onClick={props.onForgetIdentity}>忘记身份</button>
          </div>

          {/* 设备列表 - 使用网格卡片布局 */}
          {devices.length > 0 && (
            <div className="devices-section">
              <h3>我的设备</h3>
              <div className="device-grid">
                {devices.map((device) => (
                  <div key={device.deviceId} className={`device-card ${device.deviceId === props.activeDeviceId ? "active" : ""}`}>
                    <div className="device-name">{device.name || "未命名设备"}</div>
                    <div className="device-status">{device.status}</div>
                    <div className="device-key">{device.publicKey.slice(0, 16)}...</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 可折叠的身份导入面板 */}
          <details className="collapsible-section">
            <summary>导入现有身份</summary>
            <form className="identity-import-form">
              {/* 导入表单内容 */}
            </form>
          </details>

          {/* 可折叠的权益面板 */}
          <details className="collapsible-section">
            <summary>我的权益</summary>
            <div className="entitlement-content">
              {/* 权益信息 */}
            </div>
          </details>
        </div>
      </PanelBoundary>
    </div>
  );
}
```

---

### 6️⃣ 修改：`src/App.tsx`

将 3936 行的巨大文件简化为路由容器：

```typescript
import { useCallback, useEffect, useState } from "react";
// ... 保留所有现有的 imports ...
import { MainLayout } from "./components/Layout/MainLayout";
import { SendPage } from "./components/Pages/SendPage";
import { ReceivePage } from "./components/Pages/ReceivePage";
import { IdentityPage } from "./components/Pages/IdentityPage";
import { TransferStatusPage } from "./components/Pages/TransferStatusPage";
import { WebRTCPage } from "./components/Pages/WebRTCPage";
import { LogsPage } from "./components/Pages/LogsPage";
import { UpgradePrompt } from "./components/UpgradePrompt";
import { PeerTrustDialog } from "./components/PeerTrustDialog";

type Page = "send" | "receive" | "identity" | "transfer" | "webrtc" | "logs";

export default function App() {
  // ========== 保留所有现有的 state 和 logic ==========
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [taskId, setTaskId] = useState<string | null>(null);
  // ... 所有现有的 state ...

  // ========== 新增：页面路由状态 ==========
  const [currentPage, setCurrentPage] = useState<Page>("send");

  // ========== 保留所有现有的 useEffect 和 handlers ==========
  // ... 所有现有的逻辑 ...

  // ========== 自动切换页面逻辑 ==========
  useEffect(() => {
    // 当开始传输时，自动跳转到传输状态页
    if (taskId && currentPage !== "transfer") {
      setCurrentPage("transfer");
    }
  }, [taskId, currentPage]);

  // ========== 渲染主布局 ==========
  return (
    <MainLayout
      currentPage={currentPage}
      onPageChange={setCurrentPage}
      hasActiveTransfer={Boolean(taskId || taskCode)}
      hasLogs={logs.length > 0}
    >
      {/* 根据当前页面渲染对应组件 */}
      {currentPage === "send" && (
        <SendPage
          files={files}
          onFilesChange={setFiles}
          onStartSend={startSend}
          isSending={isSending}
        />
      )}

      {currentPage === "receive" && (
        <ReceivePage
          receiveMode={receiveMode}
          onReceiveModeChange={setReceiveMode}
          receiveCode={receiveCode}
          onReceiveCodeChange={setReceiveCode}
        />
      )}

      {currentPage === "identity" && (
        <IdentityPage
          identity={identity}
          devices={devices}
          activeDeviceId={activeDeviceId}
          selectedDevice={selectedDevice}
          onCreateIdentity={createMasterIdentity}
          onForgetIdentity={forgetCurrentIdentity}
        />
      )}

      {currentPage === "transfer" && (taskId || taskCode) && (
        <TransferStatusPage
          taskId={taskId}
          taskCode={taskCode}
          taskPublicKey={taskPublicKey}
          phase={phase}
          progress={progress}
          route={route}
          routeAttempts={routeAttempts}
          speedBps={speedBps}
          bytesSent={bytesSent}
          bytesTotal={bytesTotal}
          auditLog={auditLog}
          trustedPeers={trustedPeers}
        />
      )}

      {currentPage === "webrtc" && <WebRTCPage />}

      {currentPage === "logs" && logs.length > 0 && <LogsPage logs={logs} />}

      {/* 全局对话框和提示（不受页面切换影响） */}
      {peerPrompt && (
        <PeerTrustDialog
          peerPrompt={peerPrompt}
          onTrust={trustPeer}
          onReject={rejectPeer}
        />
      )}

      {upgradeReason && <UpgradePrompt reason={upgradeReason} />}
    </MainLayout>
  );
}
```

---

### 7️⃣ 新增：`src/components/Layout/layout.css`

```css
/* ==================== 布局容器 ==================== */
.app-layout {
  width: 100%;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: #020617;
  overflow: hidden;
}

/* ==================== 顶部导航栏 ==================== */
.app-header {
  height: 64px;
  padding: 0 2rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: rgba(15, 23, 42, 0.8);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid rgba(148, 163, 184, 0.15);
  z-index: 100;
}

.app-title {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #e2f3ff;
  background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

/* ==================== 布局主体 ==================== */
.layout-body {
  flex: 1;
  display: flex;
  overflow: hidden;
}

/* ==================== 侧边栏 ==================== */
.sidebar {
  width: 220px;
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(12px);
  border-right: 1px solid rgba(148, 163, 184, 0.15);
  padding: 1.5rem 0.75rem;
  overflow-y: auto;
  flex-shrink: 0;
}

.sidebar-nav {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.875rem 1rem;
  border: none;
  border-radius: 12px;
  background: transparent;
  color: rgba(226, 243, 255, 0.7);
  font-size: 0.9375rem;
  font-weight: 500;
  text-align: left;
  cursor: pointer;
  transition: all 0.2s ease;
  position: relative;
}

.nav-item:hover:not(.disabled) {
  background: rgba(56, 189, 248, 0.1);
  color: #e2f3ff;
}

.nav-item.active {
  background: rgba(56, 189, 248, 0.2);
  color: #38bdf8;
  box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.3);
}

.nav-item.disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.nav-icon {
  font-size: 1.25rem;
  flex-shrink: 0;
}

.nav-label {
  flex: 1;
}

/* 红点提示 */
.nav-badge {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #ef4444;
  flex-shrink: 0;
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

/* ==================== 主内容区 ==================== */
.main-content {
  flex: 1;
  overflow-y: auto;
  padding: 2rem;
  background: radial-gradient(
    circle at 50% 10%,
    rgba(56, 189, 248, 0.08) 0%,
    rgba(2, 6, 23, 0.95) 50%
  );
}

/* ==================== 页面容器通用样式 ==================== */
.identity-page,
.transfer-status-page,
.logs-page {
  max-width: 1200px;
  margin: 0 auto;
}

/* ==================== 传输状态页面 - 标签页导航 ==================== */
.tab-navigation {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  padding: 0.5rem;
  background: rgba(15, 23, 42, 0.4);
  border-radius: 14px;
  border: 1px solid rgba(148, 163, 184, 0.15);
  overflow-x: auto;
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.25rem;
  border: none;
  border-radius: 10px;
  background: transparent;
  color: rgba(226, 243, 255, 0.7);
  font-size: 0.9375rem;
  font-weight: 500;
  white-space: nowrap;
  cursor: pointer;
  transition: all 0.2s ease;
}

.tab-button:hover {
  background: rgba(56, 189, 248, 0.1);
  color: #e2f3ff;
}

.tab-button.active {
  background: rgba(56, 189, 248, 0.25);
  color: #38bdf8;
  box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.4);
}

.tab-icon {
  font-size: 1.125rem;
}

.tab-content {
  padding: 2rem;
  border-radius: 20px;
  background: rgba(15, 23, 42, 0.55);
  border: 1px solid rgba(148, 163, 184, 0.2);
  box-shadow: 0 14px 36px rgba(12, 20, 40, 0.45);
  min-height: 400px;
}

/* ==================== 基础信息标签页 ==================== */
.basic-info-tab .info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.info-card {
  padding: 1rem;
  background: rgba(12, 20, 40, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.1);
}

.info-card label {
  display: block;
  font-size: 0.8125rem;
  color: rgba(226, 243, 255, 0.6);
  margin-bottom: 0.5rem;
}

.info-value {
  font-size: 1rem;
  color: #e2f3ff;
  font-weight: 500;
}

.info-value.mono {
  font-family: "Fira Code", "Consolas", monospace;
  font-size: 0.875rem;
  word-break: break-all;
}

.public-key-section {
  padding: 1rem;
  background: rgba(12, 20, 40, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.1);
}

.mono-value {
  font-family: "Fira Code", "Consolas", monospace;
  font-size: 0.875rem;
  color: #38bdf8;
  word-break: break-all;
  margin-top: 0.5rem;
}

/* ==================== 实时监控标签页 ==================== */
.monitor-tab .progress-section {
  margin-bottom: 2rem;
}

.progress-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.progress-percent {
  font-size: 1.125rem;
  font-weight: 600;
  color: #38bdf8;
}

.progress-bar {
  height: 12px;
  background: rgba(12, 20, 40, 0.6);
  border-radius: 6px;
  overflow: hidden;
  border: 1px solid rgba(148, 163, 184, 0.15);
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #38bdf8 0%, #818cf8 100%);
  border-radius: 6px;
  transition: width 0.3s ease;
  box-shadow: 0 0 12px rgba(56, 189, 248, 0.6);
}

.progress-details {
  margin-top: 0.5rem;
  font-size: 0.875rem;
  color: rgba(226, 243, 255, 0.7);
  text-align: center;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
}

.metric-card {
  padding: 1.25rem;
  background: rgba(12, 20, 40, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.1);
  text-align: center;
}

.metric-label {
  font-size: 0.8125rem;
  color: rgba(226, 243, 255, 0.6);
  margin-bottom: 0.5rem;
}

.metric-value {
  font-size: 1.5rem;
  font-weight: 600;
  color: #38bdf8;
}

/* ==================== 身份页面 - 设备网格 ==================== */
.device-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.device-card {
  padding: 1.25rem;
  background: rgba(12, 20, 40, 0.4);
  border-radius: 14px;
  border: 1px solid rgba(148, 163, 184, 0.15);
  transition: all 0.2s ease;
  cursor: pointer;
}

.device-card:hover {
  border-color: rgba(56, 189, 248, 0.4);
  box-shadow: 0 4px 12px rgba(56, 189, 248, 0.2);
  transform: translateY(-2px);
}

.device-card.active {
  border-color: rgba(56, 189, 248, 0.6);
  background: rgba(56, 189, 248, 0.1);
  box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.3);
}

.device-name {
  font-size: 1rem;
  font-weight: 600;
  color: #e2f3ff;
  margin-bottom: 0.5rem;
}

.device-status {
  font-size: 0.8125rem;
  color: rgba(226, 243, 255, 0.6);
  margin-bottom: 0.75rem;
}

.device-key {
  font-family: "Fira Code", "Consolas", monospace;
  font-size: 0.75rem;
  color: #38bdf8;
  word-break: break-all;
}

/* ==================== 可折叠面板 ==================== */
.collapsible-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: rgba(12, 20, 40, 0.3);
  border-radius: 14px;
  border: 1px solid rgba(148, 163, 184, 0.15);
}

.collapsible-section summary {
  font-weight: 600;
  color: #e2f3ff;
  cursor: pointer;
  user-select: none;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.collapsible-section summary::-webkit-details-marker {
  display: none;
}

.collapsible-section summary::before {
  content: "▶";
  font-size: 0.75rem;
  color: #38bdf8;
  transition: transform 0.2s ease;
}

.collapsible-section[open] summary::before {
  transform: rotate(90deg);
}

.collapsible-section[open] summary {
  margin-bottom: 1rem;
}

/* ==================== 响应式设计 ==================== */
@media (max-width: 1200px) {
  .sidebar {
    width: 180px;
  }

  .nav-label {
    font-size: 0.875rem;
  }
}

@media (max-width: 768px) {
  .layout-body {
    flex-direction: column;
  }

  .sidebar {
    width: 100%;
    border-right: none;
    border-bottom: 1px solid rgba(148, 163, 184, 0.15);
    padding: 1rem;
  }

  .sidebar-nav {
    flex-direction: row;
    overflow-x: auto;
    gap: 0.5rem;
  }

  .nav-item {
    flex-direction: column;
    gap: 0.25rem;
    padding: 0.75rem 0.5rem;
    min-width: 80px;
  }

  .nav-label {
    font-size: 0.75rem;
  }

  .main-content {
    padding: 1rem;
  }

  .tab-navigation {
    overflow-x: scroll;
  }

  .device-grid {
    grid-template-columns: 1fr;
  }
}
```

---

### 8️⃣ 修改：`src/styles.css`

在现有文件末尾添加：

```css
/* ==================== 导入布局样式 ==================== */
@import "./components/Layout/layout.css";

/* ==================== 调整原有 body 样式 ==================== */
body {
  /* 移除原有的 padding 和 center 对齐 */
  padding: 0;
  display: block;
}
```

---

### 9️⃣ 修改：`src/lib/i18n.tsx`

添加导航和传输状态标签页的翻译：

```typescript
const translations = {
  en: {
    // ... 现有翻译 ...
    nav: {
      send: "Send Files",
      receive: "Receive Files",
      identity: "Identity",
      transfer: "Transfer Status",
      webrtc: "WebRTC Lab",
      logs: "Event Logs",
    },
    transfer: {
      tab: {
        basic: "Basic Info",
        monitor: "Monitoring",
        stats: "Statistics",
        audit: "Audit Logs",
        security: "Security",
        settings: "Settings",
      },
    },
  },
  zh: {
    // ... 现有翻译 ...
    nav: {
      send: "发送文件",
      receive: "接收文件",
      identity: "身份管理",
      transfer: "传输状态",
      webrtc: "跨网实验",
      logs: "事件日志",
    },
    transfer: {
      tab: {
        basic: "基础信息",
        monitor: "实时监控",
        stats: "统计数据",
        audit: "审计日志",
        security: "安全策略",
        settings: "高级设置",
      },
    },
  },
};
```

---

## 🎯 实施步骤

### 阶段一：创建新组件结构（1-2小时）
1. 创建 `src/components/Layout/` 目录
2. 创建 `src/components/Pages/` 目录
3. 依次创建布局组件：`Sidebar.tsx`、`Header.tsx`、`MainLayout.tsx`
4. 创建 `layout.css` 样式文件

### 阶段二：拆分页面组件（2-3小时）
5. 从 App.tsx 中提取发送、接收、WebRTC、日志等简单页面
6. **重点**：创建 `TransferStatusPage.tsx`，将多个子面板重构为标签页
7. **重点**：创建 `IdentityPage.tsx`，优化设备列表展示

### 阶段三：重构主 App 组件（1小时）
8. 简化 `App.tsx`，改为路由容器
9. 添加页面切换逻辑
10. 保持所有现有的状态管理和事件监听

### 阶段四：样式调整（1小时）
11. 更新 `styles.css`
12. 测试响应式布局
13. 微调颜色和间距

### 阶段五：测试和优化（1小时）
14. 测试所有页面切换
15. 测试传输流程
16. 测试多语言切换
17. 修复任何布局问题

---

## ✅ 优化效果

### 优化前
- 单页垂直堆叠，需要大量滚动
- 传输状态的多个面板全部展开，占据大量空间
- 身份设备列表垂直排列，占用过多高度

### 优化后
- ✅ 侧边栏导航，一键切换功能模块
- ✅ 传输状态使用 6 个标签页，信息分类清晰
- ✅ 设备列表使用网格卡片，充分利用横向空间
- ✅ 身份导入和权益面板可折叠，默认收起
- ✅ 页面滚动大幅减少，信息层次更清晰
- ✅ 保持原有量子主题风格和动画效果

---

## 📌 注意事项

1. **状态管理**：所有 state 仍然保留在 App.tsx 中，通过 props 传递给页面组件
2. **事件监听**：Tauri 事件监听仍在 App.tsx 的 useEffect 中，不受页面切换影响
3. **全局组件**：对话框和提示组件不受页面切换影响
4. **自动跳转**：开始传输时自动跳转到传输状态页
5. **渐进式重构**：可以先实现基础布局，再逐步拆分页面组件
