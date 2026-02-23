import { useState, useCallback, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { downloadDir } from "@tauri-apps/api/path";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { QuantumBackground } from "./components/QuantumBackground";
import { useI18n } from "./lib/i18n";
import { useAuth } from "./hooks/useAuth";
import { Friend, loadFriends, addFriend, isFriend } from "./lib/friendsStore";
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
  host?: string;
  port?: number;
  certFingerprint?: string;
  code?: string;
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

interface TransferLogPayload {
  taskId: string;
  message: string;
}

interface PeerDiscoveredPayload {
  sessionId: string;
  deviceId: string;
  deviceName?: string | null;
  publicKey?: string | null;
  fingerprint?: string | null;
  verified: boolean;
}

interface PeerInfo {
  code: string;
  deviceName?: string;
  deviceId?: string;
  host: string;
  port: number;
  publicKey: string;
  certFingerprint?: string;
  discoveredVia?: string;
  route?: string;
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
  const [transferLogs, setTransferLogs] = useState<{ id: string; message: string }[]>([]);
  const [logFilePath, setLogFilePath] = useState<string | null>(null);

  const sendDirectToReceiver = useCallback(
    async (
      paths: string[],
      target: { host: string; port: number; publicKey: string; certFingerprint?: string },
      targetId: string
    ) => {
      if (!auth.ready || !auth.identity || !auth.device) {
        console.error("身份验证未就绪");
        setProgress({
          taskId: "",
          phase: "error",
          message: "身份验证未就绪，请刷新应用重试",
        });
        return;
      }

      try {
        setTransferring(true);
        setTransferTarget(targetId);
        setProgress({ taskId: "", phase: "connecting", message: "正在连接到接收方..." });

        const sendAuth = await auth.createAuthPayload("send", {
          paths,
          host: target.host,
          port: target.port,
          receiverPublicKey: target.publicKey,
          receiverCertFingerprint: target.certFingerprint || "",
        });

        const response = await invoke<{ taskId: string }>("courier_send_to_receiver", {
          auth: sendAuth,
        });

        console.log("[直连发送] 任务已启动:", response.taskId);
        setProgress({ taskId: response.taskId, phase: "transferring", message: "正在发送文件..." });
      } catch (err) {
        console.error("[直连发送] 失败:", err);
        const errMsg = err instanceof Error ? err.message : typeof err === "object" ? JSON.stringify(err) : String(err);
        setProgress({ taskId: "", phase: "error", message: errMsg });
        setTransferring(false);
        setTransferTarget(null);
      }
    },
    [auth]
  );

  const startSignalingPresence = useCallback(
    async (code: string, durationSec = 30) => {
      if (!auth.ready || !auth.identity || !auth.device) {
        return;
      }
      try {
        const presenceAuth = await auth.createAuthPayload("signal", {
          code: code.trim().toUpperCase(),
          durationSec,
        });
        await invoke("courier_signaling_presence", {
          auth: presenceAuth,
        });
      } catch (err) {
        console.warn("[信令] presence 失败:", err);
      }
    },
    [auth]
  );

  const startWebRtcReceiver = useCallback(
    async (code: string) => {
      if (!auth.ready || !auth.identity || !auth.device) {
        return;
      }
      const normalizedCode = code.trim().toUpperCase();
      if (webrtcReceiverCodeRef.current === normalizedCode) {
        return;
      }
      webrtcReceiverCodeRef.current = normalizedCode;
      try {
        const saveDir = await downloadDir();
        const receiveAuth = await auth.createAuthPayload("webrtc_receive", {
          code: normalizedCode,
          saveDir,
          devicePublicKey: auth.identity.publicKey,
          deviceName: auth.device.name || auth.device.deviceId,
        });
        await invoke("courier_start_webrtc_receiver", { auth: receiveAuth });
      } catch (err) {
        console.warn("[WebRTC] 接收监听失败:", err);
      }
    },
    [auth]
  );

  const sendViaWebRtc = useCallback(
    async (code: string, paths: string[]) => {
      if (!auth.ready || !auth.identity || !auth.device) {
        console.error("身份验证未就绪");
        setProgress({
          taskId: "",
          phase: "error",
          message: "身份验证未就绪，请刷新应用重试",
        });
        return;
      }
      const normalizedCode = code.trim().toUpperCase();
      try {
        setTransferring(true);
        setProgress({ taskId: "", phase: "connecting", message: "正在连接跨网传输..." });
        const sendAuth = await auth.createAuthPayload("webrtc_send", {
          code: normalizedCode,
          filePaths: paths,
          devicePublicKey: auth.identity.publicKey,
          deviceName: auth.device.name || auth.device.deviceId,
        });
        const response = await invoke<{ taskId: string }>("courier_start_webrtc_sender", {
          auth: sendAuth,
        });
        setProgress({ taskId: response.taskId, phase: "transferring", message: "正在发送文件..." });
      } catch (err) {
        console.error("[WebRTC] 发送失败:", err);
        const errMsg = err instanceof Error ? err.message : typeof err === "object" ? JSON.stringify(err) : String(err);
        setProgress({ taskId: "", phase: "error", message: errMsg });
        setTransferring(false);
        setTransferTarget(null);
      }
    },
    [auth]
  );

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
  const [pendingConnectCode, setPendingConnectCode] = useState<string | null>(null);

  // 好友系统
  const [friends, setFriends] = useState<Friend[]>([]);
  const [connectedPeer, setConnectedPeer] = useState<{
    publicKey?: string;
    deviceName: string;
    host?: string;
    port?: number;
    certFingerprint?: string;
    code?: string;
    route?: "lan" | "p2p";
  } | null>(null);
  const [showConnectOptions, setShowConnectOptions] = useState(false);

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

  interface AdvertiseResponse {
    code: string;
    taskId: string;
  }

  const isGeneratingCodeRef = useRef(false);
  const presenceCodeRef = useRef<string | null>(null);
  const webrtcReceiverCodeRef = useRef<string | null>(null);

  const generateMyCode = useCallback(async () => {
    // 防止重复调用
    if (isGeneratingCodeRef.current) return;
    isGeneratingCodeRef.current = true;

    console.log("[配对码] 开始生成, auth.ready=", auth.ready, "identity=", !!auth.identity, "device=", !!auth.device);

    try {
      if (!auth.ready || !auth.identity || !auth.device) {
        // 如果身份未就绪，生成临时显示码
        console.warn("[配对码] 身份未就绪，生成临时显示码（不会广播到 mDNS）");
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let code = "";
        for (let i = 0; i < 6; i++) {
          code += chars[Math.floor(Math.random() * chars.length)];
        }
        setMyCode(code);
        setCodeExpiresAt(Date.now() + 180000);
        return;
      }

      // 获取保存目录
      const saveDir = await downloadDir();
      console.log("[配对码] 保存目录:", saveDir);

      // 调用后端注册配对码到 mDNS
      const advertiseAuth = await auth.createAuthPayload("advertise", {
        saveDir,
      });
      console.log("[配对码] 调用 courier_advertise_receiver...");

      const response = await invoke<AdvertiseResponse>("courier_advertise_receiver", {
        auth: advertiseAuth,
      });

      console.log("[配对码] mDNS 注册成功, code=", response.code, "taskId=", response.taskId);
      setMyCode(response.code);
      setCodeExpiresAt(Date.now() + 180000); // 3分钟过期
    } catch (err) {
      console.error("[配对码] 生成失败:", err);
      // 失败时生成临时显示码
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let code = "";
      for (let i = 0; i < 6; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
      }
      console.warn("[配对码] 使用临时显示码（不会广播到 mDNS）:", code);
      setMyCode(code);
      setCodeExpiresAt(Date.now() + 180000);
    } finally {
      isGeneratingCodeRef.current = false;
    }
  }, [auth.ready, auth.identity, auth.device, auth.createAuthPayload]);

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
        host: peer.host,
        port: peer.port,
        certFingerprint: peer.certFingerprint,
        code: peer.code,
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
    const device = devices.find((d) => d.id === deviceId);

    if (device?.host && device?.port && device?.publicKey) {
      setTransferTarget(deviceId);
      await sendDirectToReceiver(
        filePaths,
        {
          host: device.host,
          port: device.port,
          publicKey: device.publicKey,
          certFingerprint: device.certFingerprint,
        },
        deviceId
      );
      return;
    }

    if (device?.code) {
      setTransferTarget(deviceId);
      await sendViaWebRtc(device.code, filePaths);
      return;
    }

    console.warn("[发送] 缺少接收方信息，无法启动传输", device);
    setProgress({
      taskId: "",
      phase: "error",
      message: "未获取到接收方信息，请刷新设备列表或使用手动连接。",
    });
    setTransferring(false);
    setTransferTarget(null);
  }, [devices, sendDirectToReceiver, sendViaWebRtc]);

  // ============ 通过配对码连接 ============

  const connectByCode = useCallback(async (code: string) => {
    // 验证配对码格式
    if (!isValidCodeFormat(code)) {
      setConnectError("配对码格式不正确（应为 6 位字母数字）");
      return;
    }

    setConnecting(true);
    setConnectError(null);
    setPendingConnectCode(code.toUpperCase());

    try {
      console.log("[连接] 开始通过 mDNS 发现设备...");
      // 通过 mDNS 发现对方设备（超时 5 秒）
      const peers = await invoke<PeerInfo[]>("courier_list_senders", {});
      console.log("[连接] mDNS 发现完成，找到设备数:", peers.length);
      console.log("[连接] 设备列表:", JSON.stringify(peers, null, 2));

      const peer = peers.find(p => p.code?.toUpperCase() === code.toUpperCase());

      if (!peer) {
        const foundCodes = peers.map(p => p.code).join(", ") || "无";
        console.log(`[连接] 未找到配对码 ${code}，已发现的配对码: ${foundCodes}`);
        setConnectError(`未发现局域网设备，尝试跨网连接…`);

        const upper = code.toUpperCase();
        setConnectedPeer({
          deviceName: `设备-${upper}`,
          code: upper,
          route: "p2p",
        });
        setShowConnectOptions(true);
        setShowManualConnect(false);
        setInputCode("");
        void startSignalingPresence(upper, 20);
        return;
      }

      console.log("[连接] 找到匹配设备:", peer.deviceName, "地址:", peer.host, "端口:", peer.port);
      // 保存对方信息，显示选项弹窗
      setConnectedPeer({
        publicKey: peer.publicKey,
        deviceName: peer.deviceName || `设备-${peer.code}`,
        host: peer.host || "",
        port: peer.port || 0,
        certFingerprint: peer.certFingerprint || "",
        code: peer.code,
        route: "lan",
      });
      setPendingConnectCode(null);
      setShowConnectOptions(true);
      setShowManualConnect(false);
      setInputCode("");
    } catch (err) {
      console.error("[连接] 发现设备失败:", err);
      const errMsg = err instanceof Error ? err.message : typeof err === 'string' ? err : JSON.stringify(err);
      setConnectError(`mDNS 发现失败，尝试跨网连接…`);
      const upper = code.toUpperCase();
      setConnectedPeer({
        deviceName: `设备-${upper}`,
        code: upper,
        route: "p2p",
      });
      setShowConnectOptions(true);
      setShowManualConnect(false);
      setInputCode("");
      void startSignalingPresence(upper, 20);
    } finally {
      setConnecting(false);
    }
  }, [startSignalingPresence]);

  // ============ 添加好友 ============

  const handleAddFriend = useCallback(async () => {
    if (!connectedPeer) return;
    if (!connectedPeer.publicKey) {
      setConnectError("尚未获取对方身份，请先建立连接或发送文件。");
      return;
    }

    const friendId = connectedPeer.publicKey.slice(0, 16);
    const newFriend = await addFriend({
      id: friendId,
      publicKey: connectedPeer.publicKey,
      deviceName: connectedPeer.deviceName,
    });

    if (newFriend) {
      setFriends(prev => [...prev, newFriend]);
      setShowConnectOptions(false);
      setConnectedPeer(null);
      setPendingConnectCode(null);
    }
  }, [connectedPeer]);

  // ============ 发送文件给连接的设备 ============

  // 发送文件给已广播的接收方（作为发送方连接到接收方）
  const handleSendToConnected = useCallback(async () => {
    if (!connectedPeer) return;

    try {
      const selected = await openFileDialog({
        multiple: true,
        title: "选择要发送的文件",
      });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      if (paths.length === 0) return;

      console.log("[直连发送] 选中文件:", paths);
      console.log("[直连发送] 目标设备:", connectedPeer.host, connectedPeer.port);

      setShowConnectOptions(false);
      if (connectedPeer.host && connectedPeer.port && connectedPeer.publicKey) {
        await sendDirectToReceiver(
          paths,
          {
            host: connectedPeer.host,
            port: connectedPeer.port,
            publicKey: connectedPeer.publicKey,
            certFingerprint: connectedPeer.certFingerprint,
          },
          connectedPeer.publicKey.slice(0, 16)
        );
      } else if (connectedPeer.code) {
        setTransferTarget(connectedPeer.code);
        await sendViaWebRtc(connectedPeer.code, paths);
      } else {
        setProgress({ taskId: "", phase: "error", message: "缺少目标信息，无法发送。" });
      }

    } catch (err) {
      console.error("[直连发送] 失败:", err);
      const errMsg = err instanceof Error ? err.message : typeof err === 'object' ? JSON.stringify(err) : String(err);
      setProgress({ taskId: "", phase: "error", message: errMsg });
      setTransferring(false);
    }
  }, [connectedPeer, sendDirectToReceiver, sendViaWebRtc]);

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

  const handleDeviceClick = useCallback(async (deviceId: string) => {
    try {
      const selected = await openFileDialog({
        multiple: true,
        title: "选择要发送的文件",
      });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      if (paths.length === 0) return;

      console.log("[文件选择] 选中文件:", paths);
      await sendFiles(deviceId, paths);
    } catch (err) {
      console.error("[点击设备] 发送失败:", err);
      setProgress({ taskId: "", phase: "error", message: `发送失败: ${err}` });
      setTransferring(false);
    }
  }, [sendFiles]);

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
    // 加载好友列表
    loadFriends().then(setFriends);

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

  useEffect(() => {
    let cancelled = false;
    void invoke<string[]>("courier_recent_logs", { limit: 120 })
      .then((lines) => {
        if (cancelled || !Array.isArray(lines) || lines.length === 0) {
          return;
        }
        setTransferLogs(
          lines.map((line, index) => ({
            id: `persist-${index}`,
            message: line,
          })),
        );
      })
      .catch(() => undefined);
    void invoke<string | null>("courier_log_file_path")
      .then((path) => {
        if (!cancelled && path) {
          setLogFilePath(path);
        }
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  // 监听传输进度
  useEffect(() => {
    let unlistenProgress: (() => void) | null = null;
    let unlistenLog: (() => void) | null = null;

    listen<TransferProgress>("transfer_progress", (event) => {
      const payload = event.payload as TransferProgress & {
        task_id?: string;
        bytes_sent?: number;
        bytes_total?: number;
        speed_bps?: number;
      };
      const normalized: TransferProgress = {
        taskId: payload.taskId || payload.task_id || "",
        phase: payload.phase,
        progress: payload.progress,
        bytesSent: payload.bytesSent ?? payload.bytes_sent,
        bytesTotal: payload.bytesTotal ?? payload.bytes_total,
        speedBps: payload.speedBps ?? payload.speed_bps,
        route: payload.route,
        message: payload.message,
      };
      setProgress(normalized);

      if (normalized.phase === "done") {
        setTransferComplete(transferTarget);
        setTimeout(() => {
          setTransferring(false);
          setTransferTarget(null);
          setTransferComplete(null);
          setProgress(null);
        }, 2000);
      } else if (normalized.phase === "error") {
        setTimeout(() => {
          setTransferring(false);
          setTransferTarget(null);
          setProgress(null);
        }, 3000);
      }
    }).then((fn) => {
      unlistenProgress = fn;
    });

    listen<TransferLogPayload>("transfer_log", (event) => {
      const payload = event.payload as TransferLogPayload & { task_id?: string };
      const taskId = payload.taskId || payload.task_id || "";
      const message = payload.message || "";
      console.log("[transfer_log]", taskId, message);
      setTransferLogs((prev) => {
        const next = [
          ...prev,
          {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            message: `[${taskId}] ${message}`,
          },
        ];
        return next.length > 50 ? next.slice(-50) : next;
      });
    }).then((fn) => {
      unlistenLog = fn;
    });

    return () => {
      unlistenProgress?.();
      unlistenLog?.();
    };
  }, [transferTarget]);

  // 监听跨网配对发现
  useEffect(() => {
    let unlistenPeer: (() => void) | null = null;
    listen<PeerDiscoveredPayload>("peer_discovered", (event) => {
      const payload = event.payload;
      if (!pendingConnectCode) return;
      if (payload.sessionId?.toUpperCase() !== pendingConnectCode.toUpperCase()) return;
      if (auth.device?.deviceId && payload.deviceId === auth.device.deviceId) return;

      setConnectedPeer({
        publicKey: payload.publicKey || undefined,
        deviceName: payload.deviceName || `设备-${payload.deviceId}`,
        code: pendingConnectCode,
        route: "p2p",
      });
      setShowConnectOptions(true);
      setShowManualConnect(false);
      setConnecting(false);
      setConnectError(null);
      setPendingConnectCode(null);
    }).then((fn) => {
      unlistenPeer = fn;
    });

    return () => {
      unlistenPeer?.();
    };
  }, [pendingConnectCode, auth.device]);

  // 打开手动连接面板时生成配对码
  useEffect(() => {
    if (showManualConnect) {
      if (!myCode) {
        generateMyCode();
      } else {
        const normalized = myCode.trim().toUpperCase();
        if (presenceCodeRef.current !== normalized) {
          presenceCodeRef.current = normalized;
          void startSignalingPresence(normalized, 180);
        }
        void startWebRtcReceiver(normalized);
      }
    } else {
      presenceCodeRef.current = null;
      webrtcReceiverCodeRef.current = null;
    }
  }, [showManualConnect, myCode, generateMyCode, startSignalingPresence, startWebRtcReceiver]);

  // 配对码倒计时
  useEffect(() => {
    if (!showManualConnect || !codeExpiresAt) return;

    const timer = setInterval(() => {
      const remaining = Math.max(0, Math.ceil((codeExpiresAt - Date.now()) / 1000));
      setRemainingTime(remaining);

      // 只在倒计时归零时重新生成
      if (remaining === 0 && codeExpiresAt > 0) {
        setCodeExpiresAt(0); // 停止计时，等待手动刷新
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
                <div className="setting-log-panel">
                  <div className="setting-title">{t("settings.transferLogs", "传输日志")}</div>
                  <div className="setting-desc">
                    {transferLogs.length > 0
                      ? t("settings.transferLogsDesc", "最近 {count} 条", {
                          count: Math.min(transferLogs.length, 8),
                        })
                      : t("settings.transferLogsEmpty", "暂无传输日志")}
                  </div>
                  {transferLogs.length > 0 && (
                    <div className="setting-log-list">
                      {transferLogs.slice(-8).map((entry) => (
                        <div key={entry.id} className="setting-log-item">
                          <span className="setting-log-message">{entry.message}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {logFilePath && (
                    <div className="setting-desc">
                      {t("settings.transferLogsPath", "日志文件")}: {logFilePath}
                    </div>
                  )}
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

        {/* 连接成功选项弹窗 */}
        {showConnectOptions && connectedPeer && (
          <div className="modal-overlay" onClick={() => { setShowConnectOptions(false); setConnectedPeer(null); setPendingConnectCode(null); }}>
            <div className="modal modal-options" onClick={(e) => e.stopPropagation()}>
              <button className="modal-close-float" onClick={() => { setShowConnectOptions(false); setConnectedPeer(null); setPendingConnectCode(null); }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>

              <div className="connect-success-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>
              </div>

              <h3 className="connect-title">{t("connect.success", "连接成功")}</h3>
              <p className="connect-device-name">{connectedPeer.deviceName}</p>

              <div className="connect-options">
                <button className="option-btn primary" onClick={handleSendToConnected}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="12" y1="18" x2="12" y2="12" />
                    <line x1="9" y1="15" x2="15" y2="15" />
                  </svg>
                  {t("connect.sendFile", "发送文件")}
                </button>
                <button
                  className="option-btn secondary"
                  onClick={handleAddFriend}
                  disabled={!connectedPeer.publicKey}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
                    <circle cx="8.5" cy="7" r="4" />
                    <line x1="20" y1="8" x2="20" y2="14" />
                    <line x1="23" y1="11" x2="17" y2="11" />
                  </svg>
                  {t("connect.addFriend", "添加好友")}
                </button>
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

        .setting-log-panel {
          padding-top: 16px;
        }

        .setting-log-list {
          margin-top: 10px;
          display: flex;
          flex-direction: column;
          gap: 6px;
          max-height: 160px;
          overflow: auto;
          padding-right: 4px;
        }

        .setting-log-item {
          font-size: 12px;
          color: rgba(255, 255, 255, 0.55);
          line-height: 1.4;
        }

        .setting-log-message {
          word-break: break-word;
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

        /* 连接选项弹窗 */
        .modal-options {
          padding: 32px 24px;
          max-width: 280px;
          text-align: center;
          background: rgba(255, 255, 255, 0.08);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid rgba(255, 255, 255, 0.15);
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .connect-success-icon {
          width: 56px;
          height: 56px;
          margin: 0 auto 16px;
          border-radius: 50%;
          background: rgba(34, 197, 94, 0.2);
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .connect-success-icon svg {
          width: 28px;
          height: 28px;
          color: #22c55e;
        }

        .connect-device-name {
          font-size: 14px;
          color: rgba(255, 255, 255, 0.6);
          margin: 0 0 24px;
        }

        .connect-options {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .option-btn {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          padding: 14px 20px;
          border: none;
          border-radius: 12px;
          font-size: 15px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }

        .option-btn svg {
          width: 20px;
          height: 20px;
        }

        .option-btn.primary {
          background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
          color: #fff;
        }

        .option-btn.primary:hover {
          transform: scale(1.02);
          box-shadow: 0 4px 20px rgba(139, 92, 246, 0.4);
        }

        .option-btn.secondary {
          background: rgba(255, 255, 255, 0.1);
          color: rgba(255, 255, 255, 0.9);
          border: 1px solid rgba(255, 255, 255, 0.15);
        }

        .option-btn.secondary:hover {
          background: rgba(255, 255, 255, 0.15);
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
