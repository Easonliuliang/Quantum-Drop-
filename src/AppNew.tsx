import { useState, useCallback, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { downloadDir } from "@tauri-apps/api/path";
import { QuantumBackground } from "./components/QuantumBackground";
import { useI18n } from "./lib/i18n";
import { useAuth } from "./hooks/useAuth";
import "./styles.css";

// 配对码格式验证
const isValidCodeFormat = (code: string): boolean => /^[A-Z0-9]{6}$/i.test(code);

/**
 * Quantum Drop - 乔布斯版
 *
 * 一个界面，看到人，拖文件，完成。
 */

// ============ 类型定义 ============

interface Device {
  id: string;
  name: string;
  type: "phone" | "laptop" | "tablet" | "desktop";
  online: boolean;
  route: "lan" | "p2p" | "ble";
  publicKey?: string;
}

interface TransferProgress {
  taskId: string;
  phase: "preparing" | "pairing" | "connecting" | "transferring" | "finalizing" | "done" | "error";
  progress?: number;
  bytesSent?: number;
  bytesTotal?: number;
  speedBps?: number;
  route?: "lan" | "p2p" | "relay";
  message?: string;
}

interface PeerInfo {
  code: string;
  deviceId?: string;
  deviceName?: string;
  publicKey?: string;
  route?: string;
}

interface GenerateCodeResponse {
  taskId?: string;
  task_id?: string;
  code: string;
  publicKey?: string;
  public_key?: string;
}

// ============ 工具函数 ============

// 根据设备名猜测类型
function guessDeviceType(name: string): Device["type"] {
  const lower = name.toLowerCase();
  if (lower.includes("iphone") || lower.includes("phone") || lower.includes("android")) {
    return "phone";
  }
  if (lower.includes("ipad") || lower.includes("tablet")) {
    return "tablet";
  }
  if (lower.includes("macbook") || lower.includes("laptop") || lower.includes("notebook")) {
    return "laptop";
  }
  return "desktop";
}

// 格式化文件大小
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// 格式化速度
function formatSpeed(bps: number): string {
  if (bps < 1024) return `${bps} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${(bps / 1024 / 1024).toFixed(1)} MB/s`;
}

// ============ 主组件 ============

export default function App() {
  const { t } = useI18n();
  const auth = useAuth();

  // 设备列表
  const [devices, setDevices] = useState<Device[]>([]);
  const [scanning, setScanning] = useState(true);

  // 传输状态
  const [transferring, setTransferring] = useState(false);
  const [transferTarget, setTransferTarget] = useState<string | null>(null);
  const [progress, setProgress] = useState<TransferProgress | null>(null);
  const [transferComplete, setTransferComplete] = useState<string | null>(null);

  // 拖拽状态
  const [isDragging, setIsDragging] = useState(false);
  const [dragOverDevice, setDragOverDevice] = useState<string | null>(null);

  // 弹窗状态
  const [showSettings, setShowSettings] = useState(false);
  const [showManualConnect, setShowManualConnect] = useState(false);

  // 配对码
  const [myCode, setMyCode] = useState<string>("");
  const [codeExpiresAt, setCodeExpiresAt] = useState<number>(0);
  const [remainingTime, setRemainingTime] = useState(0);
  const [inputCode, setInputCode] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  // 待发送的文件
  const pendingFilesRef = useRef<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ============ 设备图标 ============

  const getDeviceIcon = (type: Device["type"]) => {
    switch (type) {
      case "phone":
        return (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="5" y="2" width="14" height="20" rx="2" />
            <line x1="12" y1="18" x2="12.01" y2="18" />
          </svg>
        );
      case "laptop":
        return (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="3" width="20" height="14" rx="2" />
            <line x1="2" y1="20" x2="22" y2="20" />
          </svg>
        );
      case "tablet":
        return (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="4" y="2" width="16" height="20" rx="2" />
            <line x1="12" y1="18" x2="12.01" y2="18" />
          </svg>
        );
      case "desktop":
        return (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="3" width="20" height="14" rx="2" />
            <line x1="8" y1="21" x2="16" y2="21" />
            <line x1="12" y1="17" x2="12" y2="21" />
          </svg>
        );
    }
  };

  // ============ 生成配对码 ============

  const generateMyCode = useCallback(async () => {
    // 生成本地临时码（用于显示，真正的配对码在发送时生成）
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let code = "";
    for (let i = 0; i < 6; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    setMyCode(code);
    setCodeExpiresAt(Date.now() + 180000);
  }, []);

  // ============ 发现设备 ============

  const discoverDevices = useCallback(async () => {
    setScanning(true);
    try {
      const peers = await invoke<PeerInfo[]>("courier_list_senders", {});
      const newDevices: Device[] = peers.map((peer) => ({
        id: peer.deviceId || peer.code,
        name: peer.deviceName || `Device-${peer.code}`,
        type: guessDeviceType(peer.deviceName || ""),
        online: true,
        route: (peer.route as Device["route"]) || "lan",
        publicKey: peer.publicKey,
      }));
      setDevices(newDevices);
    } catch (err) {
      console.error("发现设备失败:", err);
    } finally {
      setScanning(false);
    }
  }, []);

  // ============ 发送文件 ============

  const sendFiles = useCallback(async (deviceId: string, filePaths: string[]) => {
    if (filePaths.length === 0) return;
    if (!auth.ready || !auth.identity || !auth.device) {
      console.error("身份验证未就绪");
      setProgress({
        taskId: "",
        phase: "error",
        message: "身份验证未就绪，请刷新应用重试",
      });
      return;
    }

    setTransferring(true);
    setTransferTarget(deviceId);
    setProgress({ taskId: "", phase: "preparing" });

    try {
      // 1. 生成配对码（需要认证）
      const generateAuth = await auth.createAuthPayload("generate", {
        paths: filePaths,
      });

      const codeResponse = await invoke<GenerateCodeResponse>("courier_generate_code", {
        auth: generateAuth,
      });

      // 验证响应
      if (!codeResponse?.code) {
        throw new Error("生成配对码失败：响应无效");
      }

      setMyCode(codeResponse.code);
      setProgress({ taskId: codeResponse.taskId || codeResponse.task_id || "", phase: "pairing" });

      // 2. 发送文件（需要认证）
      const sendAuth = await auth.createAuthPayload("send", {
        paths: filePaths,
      });

      await invoke("courier_send", {
        auth: sendAuth,
        code: codeResponse.code,
      });
    } catch (err) {
      console.error("发送失败:", err);
      setProgress({
        taskId: "",
        phase: "error",
        message: String(err),
      });
    }
  }, [auth]);

  // ============ 通过配对码连接 ============

  const connectByCode = useCallback(async (code: string) => {
    // 验证配对码格式
    if (!isValidCodeFormat(code)) {
      setConnectError("配对码格式不正确（应为 6 位字母数字）");
      return;
    }
    if (!auth.ready || !auth.identity || !auth.device) {
      setConnectError("身份验证未就绪");
      return;
    }

    setConnecting(true);
    setConnectError(null);

    try {
      // 获取默认保存目录
      let saveDir: string;
      try {
        saveDir = await downloadDir();
      } catch (pathErr) {
        throw new Error(`获取下载目录失败: ${pathErr}`);
      }

      const connectAuth = await auth.createAuthPayload("connect", {
        code: code.toUpperCase(),
        saveDir,
      });

      await invoke("courier_connect_by_code", { auth: connectAuth });
      setShowManualConnect(false);
      setInputCode("");
      // 刷新设备列表
      await discoverDevices();
    } catch (err) {
      console.error("连接失败:", err);
      setConnectError(String(err));
    } finally {
      setConnecting(false);
    }
  }, [auth, discoverDevices]);

  // ============ 拖拽处理 ============

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    if (e.currentTarget === e.target) {
      setIsDragging(false);
      setDragOverDevice(null);
    }
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent, deviceId?: string) => {
      e.preventDefault();
      setIsDragging(false);
      setDragOverDevice(null);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0 && deviceId) {
        // 获取文件路径
        const paths = files.map((f) => (f as File & { path?: string }).path || f.name);
        await sendFiles(deviceId, paths);
      }
    },
    [sendFiles]
  );

  const handleDeviceDragOver = useCallback((e: React.DragEvent, deviceId: string) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverDevice(deviceId);
  }, []);

  const handleDeviceDragLeave = useCallback(() => {
    setDragOverDevice(null);
  }, []);

  // ============ 点击设备 ============

  const handleDeviceClick = useCallback((deviceId: string) => {
    pendingFilesRef.current = [];
    fileInputRef.current?.setAttribute("data-target", deviceId);
    fileInputRef.current?.click();
  }, []);

  const handleFileInput = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = Array.from(e.target.files || []);
      const targetDevice = e.target.getAttribute("data-target");

      if (files.length > 0 && targetDevice) {
        const paths = files.map((f) => (f as File & { path?: string }).path || f.name);
        await sendFiles(targetDevice, paths);
      }

      e.target.value = "";
      e.target.removeAttribute("data-target");
    },
    [sendFiles]
  );

  // ============ 初始化和事件监听 ============

  useEffect(() => {
    // 生成配对码
    generateMyCode();

    // 发现设备
    discoverDevices();

    // 定期刷新设备列表
    const refreshInterval = setInterval(discoverDevices, 10000);

    return () => {
      clearInterval(refreshInterval);
    };
  }, [generateMyCode, discoverDevices]);

  // 监听传输进度
  useEffect(() => {
    let unlisten: (() => void) | null = null;

    listen<TransferProgress>("transfer_progress", (event) => {
      setProgress(event.payload);

      if (event.payload.phase === "done") {
        setTransferComplete(transferTarget);
        setTimeout(() => {
          setTransferring(false);
          setTransferTarget(null);
          setTransferComplete(null);
          setProgress(null);
        }, 2000);
      } else if (event.payload.phase === "error") {
        setTimeout(() => {
          setTransferring(false);
          setTransferTarget(null);
          setProgress(null);
        }, 3000);
      }
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
    };
  }, [transferTarget]);

  // 配对码倒计时
  useEffect(() => {
    if (!showManualConnect) return;

    const timer = setInterval(() => {
      const remaining = Math.max(0, Math.ceil((codeExpiresAt - Date.now()) / 1000));
      setRemainingTime(remaining);

      if (remaining <= 0) {
        generateMyCode();
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [showManualConnect, codeExpiresAt, generateMyCode]);

  // 键盘快捷键
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setShowSettings(false);
        setShowManualConnect(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // ============ 渲染 ============

  return (
    <>
      <QuantumBackground transferState={transferring ? "transferring" : "idle"} />

      <div
        className="quantum-drop"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={(e) => handleDrop(e)}
      >
        {/* 设置按钮 */}
        <button
          className="settings-btn"
          onClick={() => setShowSettings(true)}
          aria-label="Settings"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
        </button>

        {/* 主内容区 */}
        <div className="main-area">
          {/* 设备展示区 */}
          <div className={`devices-area ${isDragging ? "dragging" : ""}`}>
            {devices.length > 0 ? (
              <div className="devices-grid">
                {devices.map((device) => (
                  <div
                    key={device.id}
                    className={`device ${dragOverDevice === device.id ? "drag-over" : ""} ${transferTarget === device.id ? "sending" : ""} ${transferComplete === device.id ? "sent" : ""}`}
                    onClick={() => !transferring && handleDeviceClick(device.id)}
                    onDragOver={(e) => handleDeviceDragOver(e, device.id)}
                    onDragLeave={handleDeviceDragLeave}
                    onDrop={(e) => handleDrop(e, device.id)}
                  >
                    <div className="device-avatar">
                      {getDeviceIcon(device.type)}
                      <span className={`device-status ${device.route}`} />
                    </div>
                    <span className="device-name">{device.name}</span>
                    <span className="device-route">{device.route.toUpperCase()}</span>

                    {/* 传输进度 */}
                    {transferTarget === device.id && progress && (
                      <div className="transfer-overlay">
                        {progress.phase === "transferring" ? (
                          <>
                            <div className="progress-ring">
                              <svg viewBox="0 0 36 36">
                                <circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="3" />
                                <circle
                                  cx="18"
                                  cy="18"
                                  r="16"
                                  fill="none"
                                  stroke="#38bdf8"
                                  strokeWidth="3"
                                  strokeDasharray={`${(progress.progress || 0) * 100} 100`}
                                  strokeLinecap="round"
                                  transform="rotate(-90 18 18)"
                                />
                              </svg>
                              <span className="progress-text">{Math.round((progress.progress || 0) * 100)}%</span>
                            </div>
                            {progress.speedBps && (
                              <span className="transfer-speed">{formatSpeed(progress.speedBps)}</span>
                            )}
                          </>
                        ) : progress.phase === "done" ? (
                          <div className="done-icon">✓</div>
                        ) : progress.phase === "error" ? (
                          <div className="error-icon">✗</div>
                        ) : (
                          <div className="connecting-spinner" />
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-devices">
                <div className="scanning-icon">
                  <div className="radar" />
                </div>
                <p>{scanning ? t("app.scanning", "正在扫描附近设备...") : t("app.noDevices", "未发现设备")}</p>
                {!scanning && (
                  <button className="refresh-btn" onClick={discoverDevices}>
                    {t("app.refresh", "重新扫描")}
                  </button>
                )}
              </div>
            )}
          </div>

          {/* 底部提示 */}
          <div className="bottom-hint">
            {isDragging ? (
              <span className="hint-active">{t("app.dropToDevice", "拖到设备上发送")}</span>
            ) : transferring && progress ? (
              <span className="hint-progress">
                {progress.phase === "connecting" && t("app.connecting", "正在连接...")}
                {progress.phase === "transferring" &&
                  `${formatBytes(progress.bytesSent || 0)} / ${formatBytes(progress.bytesTotal || 0)}`}
                {progress.phase === "done" && t("app.sent", "发送完成")}
                {progress.phase === "error" && (progress.message || t("app.sendFailed", "发送失败"))}
              </span>
            ) : (
              <span>{t("app.dragOrClick", "拖拽文件到设备，或点击设备选择文件")}</span>
            )}
          </div>

          {/* 找不到设备 */}
          <button className="manual-connect-btn" onClick={() => setShowManualConnect(true)}>
            {t("app.cantFind", "找不到设备？")}
          </button>
        </div>

        {/* 隐藏的文件输入 */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: "none" }}
          onChange={handleFileInput}
        />

        {/* 设置面板 */}
        {showSettings && (
          <div className="modal-overlay" onClick={() => setShowSettings(false)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h2>{t("settings.title", "设置")}</h2>
                <button className="modal-close" onClick={() => setShowSettings(false)}>
                  ×
                </button>
              </div>
              <div className="modal-body">
                <div className="setting-row">
                  <div className="setting-label">
                    <span className="setting-icon">📁</span>
                    <div>
                      <div className="setting-title">{t("settings.downloadLocation", "下载位置")}</div>
                      <div className="setting-value">~/Downloads</div>
                    </div>
                  </div>
                  <button className="setting-action">{t("settings.change", "更改")}</button>
                </div>
                <div className="setting-row">
                  <div className="setting-label">
                    <span className="setting-icon">🔔</span>
                    <div>
                      <div className="setting-title">{t("settings.autoReceive", "自动接收")}</div>
                      <div className="setting-desc">
                        {t("settings.autoReceiveDesc", "来自信任设备的文件")}
                      </div>
                    </div>
                  </div>
                  <div className="toggle active" />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 手动连接面板 */}
        {showManualConnect && (
          <div className="modal-overlay" onClick={() => setShowManualConnect(false)}>
            <div className="modal modal-connect" onClick={(e) => e.stopPropagation()}>
              <button className="modal-close-float" onClick={() => setShowManualConnect(false)}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>

              <h3 className="connect-title">{t("manual.title", "手动连接")}</h3>

              {/* 我的配对码 */}
              <div className="my-code-card">
                <div className="my-code-header">
                  <span className="my-code-label">{t("manual.myCode", "我的配对码")}</span>
                  <span className="code-timer">
                    {Math.floor(remainingTime / 60)}:{(remainingTime % 60).toString().padStart(2, "0")}
                  </span>
                </div>
                <div className="my-code-display">
                  {myCode ? `${myCode.slice(0, 3)} ${myCode.slice(3)}` : "------"}
                </div>
                <div className="code-actions">
                  <button
                    className="code-action-btn"
                    onClick={() => navigator.clipboard.writeText(myCode)}
                    title={t("manual.copy", "复制")}
                  >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" />
                      <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                    </svg>
                  </button>
                  <button
                    className="code-action-btn"
                    onClick={generateMyCode}
                    title={t("manual.refresh", "刷新")}
                  >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 4v6h6M23 20v-6h-6" />
                      <path d="M20.49 9A9 9 0 105.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 013.51 15" />
                    </svg>
                  </button>
                </div>
              </div>

              {/* 输入区域 */}
              <div className="enter-code-section">
                <div className="enter-code-label">{t("manual.enterCode", "输入对方配对码")}</div>
                <div className="code-input-row">
                  <input
                    type="text"
                    maxLength={6}
                    placeholder="ABC123"
                    className="code-input-single"
                    value={inputCode}
                    onChange={(e) => setInputCode(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, ""))}
                    onKeyDown={(e) => e.key === "Enter" && connectByCode(inputCode)}
                  />
                  <button
                    className={`go-btn ${connecting ? "loading" : ""} ${inputCode.length === 6 ? "active" : ""}`}
                    onClick={() => connectByCode(inputCode)}
                    disabled={inputCode.length !== 6 || connecting}
                  >
                    {connecting ? <div className="spinner" /> : (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M5 12h14M12 5l7 7-7 7" />
                      </svg>
                    )}
                  </button>
                </div>
                {connectError && <div className="connect-error">{connectError}</div>}
              </div>
            </div>
          </div>
        )}
      </div>

      <style>{`
        .quantum-drop {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          display: flex;
          flex-direction: column;
          z-index: 1;
        }

        .settings-btn {
          position: absolute;
          top: 20px;
          right: 20px;
          width: 40px;
          height: 40px;
          border: none;
          border-radius: 12px;
          background: rgba(255, 255, 255, 0.08);
          color: rgba(255, 255, 255, 0.6);
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
          z-index: 10;
        }

        .settings-btn:hover {
          background: rgba(255, 255, 255, 0.15);
          color: rgba(255, 255, 255, 0.9);
        }

        .settings-btn svg {
          width: 20px;
          height: 20px;
        }

        .main-area {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 60px 40px 40px;
        }

        .devices-area {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          width: 100%;
          max-width: 500px;
          transition: all 0.3s;
        }

        .devices-area.dragging {
          transform: scale(1.02);
        }

        .devices-grid {
          display: flex;
          flex-wrap: wrap;
          justify-content: center;
          gap: 40px;
        }

        .device {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 8px;
          cursor: pointer;
          transition: all 0.2s;
          position: relative;
        }

        .device:hover .device-avatar {
          transform: scale(1.1);
          background: rgba(56, 189, 248, 0.2);
          border-color: rgba(56, 189, 248, 0.5);
        }

        .device.drag-over .device-avatar {
          transform: scale(1.15);
          background: rgba(56, 189, 248, 0.3);
          border-color: rgba(56, 189, 248, 0.8);
          box-shadow: 0 0 30px rgba(56, 189, 248, 0.4);
        }

        .device.sending .device-avatar {
          animation: pulse 1s ease-in-out infinite;
        }

        .device.sent .device-avatar {
          background: rgba(34, 197, 94, 0.2);
          border-color: rgba(34, 197, 94, 0.5);
        }

        .device-avatar {
          width: 80px;
          height: 80px;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.05);
          border: 2px solid rgba(255, 255, 255, 0.1);
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
          position: relative;
        }

        .device-avatar svg {
          width: 32px;
          height: 32px;
          color: rgba(255, 255, 255, 0.7);
        }

        .device-status {
          position: absolute;
          bottom: 4px;
          right: 4px;
          width: 12px;
          height: 12px;
          border-radius: 50%;
          background: #22c55e;
          border: 2px solid #0a0a1a;
        }

        .device-status.p2p {
          background: #f59e0b;
        }

        .device-status.ble {
          background: #3b82f6;
        }

        .device-name {
          font-size: 14px;
          color: rgba(255, 255, 255, 0.8);
          font-weight: 500;
        }

        .device-route {
          font-size: 10px;
          color: rgba(255, 255, 255, 0.4);
          letter-spacing: 1px;
        }

        .transfer-overlay {
          position: absolute;
          top: 0;
          left: 50%;
          transform: translateX(-50%);
          width: 80px;
          height: 80px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          background: rgba(0, 0, 0, 0.7);
          border-radius: 50%;
        }

        .progress-ring {
          position: relative;
          width: 60px;
          height: 60px;
        }

        .progress-ring svg {
          width: 100%;
          height: 100%;
        }

        .progress-text {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          font-size: 12px;
          font-weight: 600;
          color: #fff;
        }

        .transfer-speed {
          font-size: 10px;
          color: rgba(255, 255, 255, 0.6);
          margin-top: 4px;
        }

        .done-icon {
          font-size: 32px;
          color: #22c55e;
        }

        .error-icon {
          font-size: 32px;
          color: #ef4444;
        }

        .connecting-spinner {
          width: 24px;
          height: 24px;
          border: 2px solid rgba(255, 255, 255, 0.2);
          border-top-color: #38bdf8;
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        .no-devices {
          text-align: center;
          color: rgba(255, 255, 255, 0.5);
        }

        .scanning-icon {
          width: 80px;
          height: 80px;
          margin: 0 auto 20px;
          position: relative;
        }

        .radar {
          width: 100%;
          height: 100%;
          border-radius: 50%;
          border: 2px solid rgba(56, 189, 248, 0.3);
          animation: radar 2s ease-out infinite;
        }

        @keyframes radar {
          0% { transform: scale(0.5); opacity: 1; }
          100% { transform: scale(1.5); opacity: 0; }
        }

        .refresh-btn {
          margin-top: 16px;
          padding: 8px 20px;
          background: rgba(255, 255, 255, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.2);
          border-radius: 20px;
          color: rgba(255, 255, 255, 0.7);
          font-size: 13px;
          cursor: pointer;
          transition: all 0.2s;
        }

        .refresh-btn:hover {
          background: rgba(255, 255, 255, 0.2);
          color: #fff;
        }

        .bottom-hint {
          margin-top: 40px;
          font-size: 14px;
          color: rgba(255, 255, 255, 0.4);
          text-align: center;
        }

        .bottom-hint .hint-active {
          color: rgba(56, 189, 248, 0.9);
          font-weight: 500;
        }

        .bottom-hint .hint-progress {
          color: rgba(255, 255, 255, 0.7);
        }

        .manual-connect-btn {
          margin-top: 20px;
          padding: 8px 16px;
          background: transparent;
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 20px;
          color: rgba(255, 255, 255, 0.4);
          font-size: 13px;
          cursor: pointer;
          transition: all 0.2s;
        }

        .manual-connect-btn:hover {
          border-color: rgba(255, 255, 255, 0.3);
          color: rgba(255, 255, 255, 0.7);
        }

        /* Modal */
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.6);
          backdrop-filter: blur(8px);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 100;
        }

        .modal {
          background: rgba(15, 23, 42, 0.95);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 20px;
          width: 90%;
          max-width: 360px;
          overflow: hidden;
        }

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 20px 24px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .modal-header h2 {
          margin: 0;
          font-size: 18px;
          font-weight: 600;
          color: #fff;
        }

        .modal-close {
          width: 32px;
          height: 32px;
          border: none;
          border-radius: 8px;
          background: rgba(255, 255, 255, 0.1);
          color: rgba(255, 255, 255, 0.6);
          font-size: 20px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .modal-body {
          padding: 24px;
        }

        .setting-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px 0;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .setting-row:last-child {
          border-bottom: none;
        }

        .setting-label {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .setting-icon {
          font-size: 20px;
        }

        .setting-title {
          font-size: 15px;
          color: #fff;
          margin-bottom: 2px;
        }

        .setting-value, .setting-desc {
          font-size: 13px;
          color: rgba(255, 255, 255, 0.4);
        }

        .setting-action {
          padding: 8px 16px;
          background: rgba(255, 255, 255, 0.1);
          border: none;
          border-radius: 8px;
          color: rgba(255, 255, 255, 0.8);
          font-size: 13px;
          cursor: pointer;
        }

        .toggle {
          width: 44px;
          height: 24px;
          border-radius: 12px;
          background: rgba(255, 255, 255, 0.2);
          position: relative;
          cursor: pointer;
          transition: all 0.2s;
        }

        .toggle::after {
          content: "";
          position: absolute;
          top: 2px;
          left: 2px;
          width: 20px;
          height: 20px;
          border-radius: 50%;
          background: #fff;
          transition: all 0.2s;
        }

        .toggle.active {
          background: #22c55e;
        }

        .toggle.active::after {
          left: 22px;
        }

        /* 手动连接弹窗 - 毛玻璃风格 */
        .modal-connect {
          padding: 24px;
          max-width: 300px;
          position: relative;
          text-align: center;
          background: rgba(255, 255, 255, 0.08);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid rgba(255, 255, 255, 0.15);
          box-shadow:
            0 8px 32px rgba(0, 0, 0, 0.3),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        }

        .modal-connect .modal-header,
        .modal-connect .modal-body {
          display: none;
        }

        .modal-close-float {
          position: absolute;
          top: 12px;
          right: 12px;
          width: 28px;
          height: 28px;
          border: none;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.1);
          color: rgba(255, 255, 255, 0.5);
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
        }

        .modal-close-float:hover {
          background: rgba(255, 255, 255, 0.2);
          color: rgba(255, 255, 255, 0.9);
        }

        .modal-close-float svg {
          width: 14px;
          height: 14px;
        }

        .connect-title {
          margin: 0 0 20px;
          font-size: 17px;
          font-weight: 600;
          color: rgba(255, 255, 255, 0.9);
        }

        .my-code-card {
          background: rgba(255, 255, 255, 0.06);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 14px;
          padding: 16px;
          margin-bottom: 16px;
        }

        .my-code-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .my-code-label {
          font-size: 11px;
          color: rgba(255, 255, 255, 0.5);
          text-transform: uppercase;
          letter-spacing: 1px;
        }

        .code-timer {
          font-size: 12px;
          font-family: "SF Mono", monospace;
          color: rgba(255, 255, 255, 0.4);
        }

        .my-code-display {
          font-size: 32px;
          font-weight: 700;
          font-family: "SF Mono", "Fira Code", monospace;
          letter-spacing: 3px;
          color: #fff;
          margin-bottom: 12px;
        }

        .code-actions {
          display: flex;
          justify-content: center;
          gap: 8px;
        }

        .code-action-btn {
          width: 36px;
          height: 36px;
          border: none;
          border-radius: 8px;
          background: rgba(255, 255, 255, 0.08);
          color: rgba(255, 255, 255, 0.5);
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
        }

        .code-action-btn:hover {
          background: rgba(255, 255, 255, 0.15);
          color: rgba(255, 255, 255, 0.9);
        }

        .code-action-btn svg {
          width: 16px;
          height: 16px;
        }

        .enter-code-section {
          padding-top: 4px;
        }

        .enter-code-label {
          font-size: 12px;
          color: rgba(255, 255, 255, 0.4);
          margin-bottom: 12px;
        }

        .code-input-row {
          display: flex;
          gap: 8px;
        }

        .code-input-single {
          flex: 1;
          height: 44px;
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 10px;
          background: rgba(255, 255, 255, 0.06);
          color: #fff;
          font-size: 16px;
          font-weight: 600;
          font-family: "SF Mono", "Fira Code", monospace;
          text-align: center;
          text-transform: uppercase;
          letter-spacing: 3px;
          transition: all 0.2s;
        }

        .code-input-single::placeholder {
          color: rgba(255, 255, 255, 0.2);
          letter-spacing: 3px;
        }

        .code-input-single:focus {
          outline: none;
          border-color: rgba(255, 255, 255, 0.25);
          background: rgba(255, 255, 255, 0.1);
        }

        .go-btn {
          width: 44px;
          height: 44px;
          border: none;
          border-radius: 10px;
          background: rgba(255, 255, 255, 0.1);
          color: rgba(255, 255, 255, 0.4);
          cursor: not-allowed;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
          flex-shrink: 0;
        }

        .go-btn.active {
          background: rgba(255, 255, 255, 0.2);
          color: rgba(255, 255, 255, 0.9);
          cursor: pointer;
        }

        .go-btn.active:hover {
          background: rgba(255, 255, 255, 0.3);
        }

        .go-btn svg {
          width: 18px;
          height: 18px;
        }

        .go-btn .spinner {
          width: 18px;
          height: 18px;
          border: 2px solid rgba(255, 255, 255, 0.2);
          border-top-color: rgba(255, 255, 255, 0.8);
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }

        .connect-error {
          margin-top: 12px;
          font-size: 12px;
          color: #ef4444;
        }
      `}</style>
    </>
  );
}
