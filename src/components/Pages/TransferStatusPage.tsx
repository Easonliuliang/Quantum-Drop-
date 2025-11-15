import { useState, type ReactNode } from "react";
import { useI18n } from "../../lib/i18n";
import { formatBytes } from "../../lib/format";
import { PanelBoundary } from "../ErrorBoundary/PanelBoundary";

type TabId = "basic" | "monitor" | "stats" | "audit" | "security" | "settings";

interface TransferStatusPageProps {
  taskCode: string | null;
  taskId: string | null;
  senderPublicKey: string | null;
  phase: string | null;
  route: string | null;
  routeAttempts: string[] | null;
  progressValue: number | null;
  speedBps: number | null;
  bytesSent: number | null;
  bytesTotal: number | null;
  monitorExtra?: ReactNode;
  statsContent?: ReactNode;
  auditContent?: ReactNode;
  securityContent?: ReactNode;
  settingsContent?: ReactNode;
}

const formatSpeed = (bps: number | null) => {
  if (!bps) {
    return "—";
  }
  if (bps < 1024) {
    return `${bps.toFixed(0)} B/s`;
  }
  if (bps < 1024 * 1024) {
    return `${(bps / 1024).toFixed(2)} KB/s`;
  }
  return `${(bps / 1024 / 1024).toFixed(2)} MB/s`;
};

export function TransferStatusPage({
  taskCode,
  taskId,
  senderPublicKey,
  phase,
  route,
  routeAttempts,
  progressValue,
  speedBps,
  bytesSent,
  bytesTotal,
  monitorExtra,
  statsContent,
  auditContent,
  securityContent,
  settingsContent,
}: TransferStatusPageProps) {
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
      <div className="tab-content">
        <PanelBoundary>
          {activeTab === "basic" && (
            <div className="basic-info-tab">
              <div className="info-grid">
                <div className="info-card">
                  <label>取件码</label>
                  <div className="info-value">{taskCode || "—"}</div>
                </div>
                <div className="info-card">
                  <label>任务 ID</label>
                  <div className="info-value mono">{taskId ?? "—"}</div>
                </div>
                <div className="info-card">
                  <label>传输阶段</label>
                  <div className="info-value">{phase ?? "—"}</div>
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
              {senderPublicKey && (
                <div className="public-key-section">
                  <label>公钥</label>
                  <div className="mono-value">{senderPublicKey}</div>
                </div>
              )}
            </div>
          )}
          {activeTab === "monitor" && (
            <div className="monitor-tab">
              <div className="progress-section">
                <div className="progress-header">
                  <span>传输进度</span>
                  <span className="progress-percent">
                    {typeof progressValue === "number" ? `${(progressValue * 100).toFixed(1)}%` : "—"}
                  </span>
                </div>
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${Math.min(100, Math.max(0, (progressValue ?? 0) * 100))}%` }} />
                </div>
                <div className="progress-details">
                  <span>
                    {bytesSent !== null ? formatBytes(bytesSent ?? 0) : "—"} / {bytesTotal !== null ? formatBytes(bytesTotal ?? 0) : "—"}
                  </span>
                </div>
              </div>
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-label">当前速度</div>
                  <div className="metric-value">{formatSpeed(speedBps ?? null)}</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">已传输</div>
                  <div className="metric-value">{bytesSent !== null ? formatBytes(bytesSent ?? 0) : "—"}</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">总大小</div>
                  <div className="metric-value">{bytesTotal !== null ? formatBytes(bytesTotal ?? 0) : "—"}</div>
                </div>
              </div>
              {routeAttempts && routeAttempts.length > 0 && (
                <div className="route-attempts">
                  <h4>路由尝试</h4>
                  <ul>
                    {routeAttempts.map((attempt, index) => (
                      <li key={`${attempt}-${index}`}>{attempt}</li>
                    ))}
                  </ul>
                </div>
              )}
              {monitorExtra}
            </div>
          )}
          {activeTab === "stats" && <div className="stats-tab">{statsContent}</div>}
          {activeTab === "audit" && <div className="audit-tab">{auditContent}</div>}
          {activeTab === "security" && <div className="security-tab">{securityContent}</div>}
          {activeTab === "settings" && <div className="settings-tab">{settingsContent}</div>}
        </PanelBoundary>
      </div>
    </div>
  );
}
