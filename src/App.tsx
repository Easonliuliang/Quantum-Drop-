import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { getPublicKey, sign as signEd25519, utils as ed25519Utils, etc as ed25519Etc } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { listen as listenTauri } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import {
  loadIdentity,
  loadLastIdentityId,
  rememberIdentity,
  rememberLastIdentityId,
  forgetIdentity,
  clearLastIdentityId,
} from "./lib/identityVault";
import { UpgradePrompt } from "./components/UpgradePrompt";
import { LocaleSwitch } from "./components/LocaleSwitch";
import { PanelBoundary } from "./components/ErrorBoundary/PanelBoundary";
import {
  FRIENDLY_ERROR_MESSAGES,
  LICENSE_REASON_MAP,
  UPGRADE_CONFIG,
  UPGRADE_MESSAGES,
  UPGRADE_URL,
  type UpgradeReason,
} from "./lib/upgrade";
import { useI18n } from "./lib/i18n";

type SelectedFile = {
  name: string;
  size?: number;
  path?: string;
};

type SenderInfo = {
  code: string;
  deviceName: string;
  host: string;
  port: number;
  publicKey: string;
  certFingerprint: string;
};

type TransferProgressPayload = {
  taskId: string;
  phase: "preparing" | "pairing" | "connecting" | "transferring" | "finalizing" | "done" | "error";
  progress?: number;
  bytesSent?: number;
  bytesTotal?: number;
  speedBps?: number;
  route?: "lan" | "p2p" | "relay" | "cache";
  routeAttempts?: string[];
  message?: string;
};

type TransferLogPayload = {
  task_id: string;
  message: string;
};

type TransferLifecyclePayload = {
  taskId: string;
  direction: "send" | "receive";
  code?: string;
  message?: string;
};

type IdentityResponseDto = {
  identityId?: string;
  identity_id?: string;
  publicKey?: string;
  public_key?: string;
  label?: string | null;
  createdAt?: number;
  created_at?: number;
};

type DeviceResponseDto = {
  deviceId?: string;
  device_id?: string;
  identityId?: string;
  identity_id?: string;
  publicKey?: string;
  public_key?: string;
  name?: string | null;
  status?: string;
  createdAt?: number;
  created_at?: number;
  lastSeenAt?: number;
  last_seen_at?: number;
  capabilities?: string[];
};

type DevicesResponseDto = {
  items?: DeviceResponseDto[];
};

type DeviceUpdatePayloadDto = {
  name?: string | null;
  status?: string | null;
  capabilities?: string[] | null;
};

type EntitlementResponseDto = {
  identityId?: string;
  identity_id?: string;
  plan?: string;
  expiresAt?: number | null;
  expires_at?: number | null;
  features?: string[];
  updatedAt?: number;
  updated_at?: number;
};

type IdentityState = {
  identityId: string;
  publicKey: string;
  label?: string | null;
};

type EntitlementState = {
  identityId: string;
  plan: string;
  expiresAt: number | null;
  features: string[];
  updatedAt: number;
};

type DeviceState = {
  deviceId: string;
  identityId: string;
  publicKey: string;
  name?: string | null;
  status: string;
  lastSeenAt: number;
  capabilities: string[];
};

type PeerDiscoveredPayload = {
  sessionId: string;
  deviceId: string;
  deviceName?: string | null;
  fingerprint?: string | null;
  verified: boolean;
};

type NormalizedCommandError = {
  code?: string;
  message: string;
  reason?: string;
};

const extractReasonToken = (message?: string) => {
  if (!message) {
    return undefined;
  }
  const match = message.match(/^([A-Z_]+):/);
  return match ? match[1] : undefined;
};

const DOCS_URL = "https://quantumdrop.com/docs/troubleshooting";
const ONE_MB = 1024 * 1024;

type ErrorActionKey =
  | "copyLogs"
  | "openDocs"
  | "refreshStats"
  | "refreshAudit"
  | "refreshRoutes"
  | "refreshSecurity"
  | "refreshSettings"
  | "refreshLicense"
  | "openPricing";

const ERROR_ACTION_LABELS: Record<ErrorActionKey, string> = {
  copyLogs: "复制最近日志",
  openDocs: "查看排障文档",
  refreshStats: "刷新传输统计",
  refreshAudit: "刷新审计日志",
  refreshRoutes: "刷新路由统计",
  refreshSecurity: "刷新安全策略",
  refreshSettings: "刷新传输设置",
  refreshLicense: "刷新权益信息",
  openPricing: "升级到 Pro",
};

const ERROR_ACTION_SUGGESTIONS: Record<string, ErrorActionKey[]> = {
  E_ROUTE_UNREACH: ["copyLogs", "refreshRoutes", "openDocs"],
  E_CODE_EXPIRED: ["openDocs"],
  E_DISK_FULL: ["openDocs", "copyLogs"],
  P2P_QUOTA_EXCEEDED: ["openPricing"],
  FILE_SIZE_EXCEEDED: ["openPricing"],
  DEVICE_LIMIT_EXCEEDED: ["openPricing"],
  RESUME_DISABLED: ["openPricing"],
  AUDIT_UNAVAILABLE: ["refreshAudit", "copyLogs"],
  STATS_UNAVAILABLE: ["refreshStats", "copyLogs"],
  SECURITY_UNAVAILABLE: ["refreshSecurity", "copyLogs"],
  LICENSE_UNAVAILABLE: ["refreshLicense", "copyLogs"],
  DEFAULT: ["copyLogs", "openDocs"],
};

const DEFAULT_ERROR_ACTIONS = ERROR_ACTION_SUGGESTIONS.DEFAULT;

const deriveErrorActionKeys = (code?: string, reason?: string): ErrorActionKey[] => {
  if (reason && ERROR_ACTION_SUGGESTIONS[reason]) {
    return ERROR_ACTION_SUGGESTIONS[reason];
  }
  if (code && ERROR_ACTION_SUGGESTIONS[code]) {
    return ERROR_ACTION_SUGGESTIONS[code];
  }
  return DEFAULT_ERROR_ACTIONS;
};

type TaskResponseDto = {
  taskId?: string;
  task_id?: string;
};

type RouteMetricsDto = {
  route: string;
  attempts: number;
  successes: number;
  failures: number;
  successRate?: number | null;
  avgLatencyMs?: number | null;
  lastError?: string | null;
};

type TransferStatsDto = {
  totalTransfers: number;
  totalBytes: number;
  successCount: number;
  failureCount: number;
  successRate: number;
  lanPercent: number;
  p2pPercent: number;
  relayPercent: number;
};

type AuditLogEntryDto = {
  id: string;
  timestamp: number;
  eventType: string;
  identityId?: string | null;
  deviceId?: string | null;
  taskId?: string | null;
  details?: Record<string, unknown> | null;
};

type LicenseLimitsDto = {
  p2pMonthlyQuota?: number | null;
  maxFileSizeMb?: number | null;
  maxDevices?: number | null;
  resumeEnabled: boolean;
  historyDays?: number | null;
};

type LicenseStatusDto = {
  identityId: string;
  tier: string;
  licenseKey?: string | null;
  issuedAt: number;
  expiresAt?: number | null;
  limits: LicenseLimitsDto;
  p2pUsed: number;
  p2pQuota?: number | null;
};

type SecurityConfigDto = {
  enforceSignatureVerification: boolean;
  disconnectOnVerificationFail: boolean;
  enableAuditLog: boolean;
};

type ChunkPolicySettings = {
  adaptive: boolean;
  minBytes: number;
  maxBytes: number;
  lanStreams: number;
};

type SettingsPayload = {
  preferredRoutes: string[];
  codeExpireSec: number;
  relayEnabled: boolean;
  chunkPolicy: ChunkPolicySettings;
  quantumMode: boolean;
  minimalQuantumUi: boolean;
  quantumIntensity: number;
  quantumSpeed: number;
  animationsEnabled: boolean;
  audioEnabled: boolean;
  enable3dQuantum: boolean;
  quantum3dQuality: string;
  quantum3dFps: number;
  wormholeMode: boolean;
};

type IdentityDevicesEventPayload = {
  identityId?: string;
  items?: DeviceResponseDto[];
};

const generateRandomHex = (bytes: number) => {
  if (typeof crypto !== "undefined" && "getRandomValues" in crypto) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    return Array.from(array, (value) => value.toString(16).padStart(2, "0")).join("");
  }
  let output = "";
  for (let index = 0; index < bytes; index += 1) {
    output += Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0");
  }
  return output;
};

const PAIRING_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const TRUSTED_PEERS_KEY = "courier.trustedPeers";

const generatePairingCode = (length = 6) => {
  if (length <= 0) {
    return "";
  }
  if (typeof crypto !== "undefined" && "getRandomValues" in crypto) {
    const randomBytes = new Uint8Array(length);
    crypto.getRandomValues(randomBytes);
    return Array.from(randomBytes, (value) => PAIRING_ALPHABET[value % PAIRING_ALPHABET.length]).join("");
  }
  let code = "";
  for (let index = 0; index < length; index += 1) {
    const rand = Math.floor(Math.random() * PAIRING_ALPHABET.length);
    code += PAIRING_ALPHABET[rand];
  }
  return code;
};

const bytesToHex = (bytes: Uint8Array) => Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex: string): Uint8Array => {
  const cleaned = hex.trim().toLowerCase();
  if (cleaned.length % 2 !== 0) {
    throw new Error("十六进制长度必须为偶数");
  }
  const array = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    const byte = cleaned.slice(i, i + 2);
    array[i / 2] = Number.parseInt(byte, 16);
    if (Number.isNaN(array[i / 2])) {
      throw new Error("非法的十六进制字符");
    }
  }
  return array;
};

const normalizeFingerprint = (value: string) =>
  value
    .replace(/[^a-f0-9]/gi, "")
    .toUpperCase();

const formatBytes = (bytes: number) => {
  if (bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
};

const maskLicenseKey = (value?: string | null) => {
  if (!value) {
    return "—";
  }
  if (value.length <= 8) {
    return value;
  }
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
};

const formatAbsoluteTime = (timestamp: number) => {
  if (!Number.isFinite(timestamp)) {
    return "-";
  }
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString();
};

const summarizeAuditDetails = (details: unknown) => {
  if (!details) {
    return "";
  }
  if (typeof details === "string") {
    return details;
  }
  if (Array.isArray(details)) {
    return details
      .slice(0, 3)
      .map((item) => {
        if (item === null) {
          return "null";
        }
        if (typeof item === "object") {
          try {
            return JSON.stringify(item);
          } catch {
            return "[object]";
          }
        }
        return String(item);
      })
      .join(" · ");
  }
  if (typeof details === "object") {
    const entries = Object.entries(details as Record<string, unknown>)
      .filter(([, value]) => value !== null && typeof value !== "object")
      .map(([key, value]) => `${key}: ${String(value)}`)
      .slice(0, 3);
    if (entries.length > 0) {
      return entries.join(" · ");
    }
    try {
      return JSON.stringify(details);
    } catch {
      return "";
    }
  }
  return "";
};

const normalizeLicenseStatus = (raw: unknown, fallbackId: string): LicenseStatusDto => {
  const source = (raw as Record<string, any>) || {};
  const limitsSource = (source.limits as Record<string, any>) || {};
  const limits: LicenseLimitsDto = {
    p2pMonthlyQuota: limitsSource.p2pMonthlyQuota ?? limitsSource.p2p_monthly_quota ?? null,
    maxFileSizeMb: limitsSource.maxFileSizeMb ?? limitsSource.max_file_size_mb ?? null,
    maxDevices: limitsSource.maxDevices ?? limitsSource.max_devices ?? null,
    resumeEnabled: Boolean(limitsSource.resumeEnabled ?? limitsSource.resume_enabled ?? false),
    historyDays: limitsSource.historyDays ?? limitsSource.history_days ?? null,
  };
  return {
    identityId: source.identityId ?? source.identity_id ?? fallbackId,
    tier: source.tier ?? "free",
    licenseKey: source.licenseKey ?? source.license_key ?? null,
    issuedAt: source.issuedAt ?? source.issued_at ?? Date.now(),
    expiresAt: source.expiresAt ?? source.expires_at ?? null,
    limits,
    p2pUsed: source.p2pUsed ?? source.p2p_used ?? 0,
    p2pQuota: source.p2pQuota ?? source.p2p_quota ?? limits.p2pMonthlyQuota ?? null,
  };
};

const formatRelativeTime = (timestamp: number) => {
  const now = Date.now();
  const delta = now - timestamp;
  if (delta < 10_000) {
    return "刚刚";
  }
  const seconds = Math.floor(delta / 1000);
  if (seconds < 60) {
    return `${seconds} 秒前`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} 分钟前`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} 小时前`;
  }
  const days = Math.floor(hours / 24);
  if (days < 30) {
    return `${days} 天前`;
  }
  const months = Math.floor(days / 30);
  if (months < 12) {
    return `${months} 个月前`;
  }
  const years = Math.floor(months / 12);
  return `${years} 年前`;
};

const copyPlainText = async (value: string) => {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
  } else {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }
};

type TauriDialogApi = {
  open: (options: {
    multiple?: boolean;
    directory?: boolean;
    filters?: Array<{ name: string; extensions: string[] }>;
  }) => Promise<string | string[] | null>;
};

type TauriEventApi = {
  listen: <T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>;
};

type TauriInvokeFn = (command: string, args?: Record<string, unknown>) => Promise<unknown>;

type TauriGlobal = {
  dialog?: TauriDialogApi;
  event?: TauriEventApi;
  invoke?: TauriInvokeFn;
  core?: {
    invoke?: TauriInvokeFn;
  };
  tauri?: {
    invoke?: TauriInvokeFn;
  };
};

const getTauri = (): TauriGlobal | undefined => {
  if (typeof window === "undefined") {
    return undefined;
  }
  const source = window as unknown as {
    __TAURI__?: TauriGlobal;
    __TAURI_INTERNALS__?: { invoke?: TauriInvokeFn };
  };
  const existing = source.__TAURI__;
  const internalsInvoke = source.__TAURI_INTERNALS__?.invoke;
  if (!existing && !internalsInvoke) {
    return undefined;
  }
  if (existing) {
    if (internalsInvoke) {
      if (!existing.invoke) {
        existing.invoke = internalsInvoke;
      }
      existing.core = existing.core ?? {};
      existing.tauri = existing.tauri ?? {};
      if (!existing.core.invoke) {
        existing.core.invoke = internalsInvoke;
      }
      if (!existing.tauri.invoke) {
        existing.tauri.invoke = internalsInvoke;
      }
    }
    return existing;
  }
  return {
    invoke: internalsInvoke,
    core: { invoke: internalsInvoke },
    tauri: { invoke: internalsInvoke },
  };
};

const detectTauri = () => {
  if (typeof window === "undefined" || typeof window !== "object") {
    return false;
  }
  const candidate = window as unknown as { __TAURI__?: object; __TAURI_INTERNALS__?: object };
  return Boolean(candidate.__TAURI__ ?? candidate.__TAURI_INTERNALS__);
};

const resolveTauriInvoke = (): TauriInvokeFn => {
  const tauri = getTauri();
  const invoke = tauri?.invoke ?? tauri?.core?.invoke ?? tauri?.tauri?.invoke;
  if (!invoke) {
    throw new Error("Tauri invoke API 不可用");
  }
  return invoke;
};

const formatSize = (bytes: number) => {
  if (bytes === 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value > 9 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
};

export default function App(): JSX.Element {
  const { t } = useI18n();
  const [isTauri, setIsTauri] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [pendingPaths, setPendingPaths] = useState<string[]>([]);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [taskCode, setTaskCode] = useState<string | null>(null);
  const [senderPublicKey, setSenderPublicKey] = useState<string | null>(null);
  const [routeAttempts, setRouteAttempts] = useState<string[] | null>(null);
  const [routeMetrics, setRouteMetrics] = useState<RouteMetricsDto[] | null>(null);
  const [isRouteMetricsLoading, setIsRouteMetricsLoading] = useState(false);
  const [transferStats, setTransferStats] = useState<TransferStatsDto | null>(null);
  const [isStatsLoading, setIsStatsLoading] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntryDto[]>([]);
  const [isAuditLoading, setIsAuditLoading] = useState(false);
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatusDto | null>(null);
  const [isLicenseLoading, setIsLicenseLoading] = useState(false);
  const [licenseInput, setLicenseInput] = useState("");
  const [isActivatingLicense, setIsActivatingLicense] = useState(false);
  const [securityConfig, setSecurityConfig] = useState<SecurityConfigDto | null>(null);
  const [isSecurityLoading, setIsSecurityLoading] = useState(false);
  const [settings, setSettings] = useState<SettingsPayload | null>(null);
  const [isSettingsLoading, setIsSettingsLoading] = useState(false);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [chunkPolicyDraft, setChunkPolicyDraft] = useState<ChunkPolicySettings | null>(null);
  const [peerPrompt, setPeerPrompt] = useState<PeerDiscoveredPayload | null>(null);
  const [peerFingerprintInput, setPeerFingerprintInput] = useState("");
  const [trustedPeers, setTrustedPeers] = useState<Record<string, PeerDiscoveredPayload>>({});
  const [upgradeReason, setUpgradeReason] = useState<UpgradeReason | null>(null);
  const trustedPeersRef = useRef<Record<string, PeerDiscoveredPayload>>({});
  const [progress, setProgress] = useState<TransferProgressPayload | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [identity, setIdentity] = useState<IdentityState | null>(null);
  const [identityPrivateKey, setIdentityPrivateKey] = useState<Uint8Array | null>(null);
  const [devices, setDevices] = useState<DeviceState[]>([]);
  const [entitlement, setEntitlement] = useState<EntitlementState | null>(null);
  const [activeDeviceId, setActiveDeviceId] = useState<string | null>(null);
  const [editDeviceName, setEditDeviceName] = useState("");
  const [editDeviceStatus, setEditDeviceStatus] = useState("active");
  const [isUpdatingDevice, setIsUpdatingDevice] = useState(false);
  const [isForgettingIdentity, setIsForgettingIdentity] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [receiveCode, setReceiveCode] = useState("");
  const [receiveHost, setReceiveHost] = useState("");
  const [receivePort, setReceivePort] = useState("0");
  const [receiveDir, setReceiveDir] = useState("");
  const [isReceiving, setIsReceiving] = useState(false);
  const [receiveMode, setReceiveMode] = useState<"code" | "scan" | "manual">("code");
  const [availableSenders, setAvailableSenders] = useState<SenderInfo[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [receiveSenderKey, setReceiveSenderKey] = useState("");
  const [receiveSenderFingerprint, setReceiveSenderFingerprint] = useState("");
  const [isRegisteringIdentity, setIsRegisteringIdentity] = useState(false);
  const [isRegisteringDevice, setIsRegisteringDevice] = useState(false);
  const [isUpdatingEntitlement, setIsUpdatingEntitlement] = useState(false);
  const [isImportingIdentity, setIsImportingIdentity] = useState(false);
  const [importIdentityId, setImportIdentityId] = useState("");
  const [importPrivateKey, setImportPrivateKey] = useState("");
  const [error, setErrorState] = useState<string | null>(null);
  const [errorActionKeys, setErrorActionKeys] = useState<ErrorActionKey[]>([]);
  const [info, setInfo] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [absorbing, setAbsorbing] = useState(false);
  const beginTransferRef = useRef<(pathsOverride?: string[]) => void>();
  const chunkMinMb = chunkPolicyDraft ? Math.round(chunkPolicyDraft.minBytes / ONE_MB) : 2;
  const chunkMaxMb = chunkPolicyDraft ? Math.round(chunkPolicyDraft.maxBytes / ONE_MB) : 2;
  const lanStreamsDraft = chunkPolicyDraft?.lanStreams ?? 1;
  const chunkSettingsDisabled = !chunkPolicyDraft || isSettingsLoading || isSavingSettings;
  const heartbeatTimerRef = useRef<number | null>(null);
  const heartbeatCapabilities = useMemo(() => ["ui:minimal-panel"], []);
  const deviceStatusOptions = useMemo(() => ["active", "standby", "inactive"], []);
  const selectedDevice = useMemo(() => {
    if (!activeDeviceId) {
      return null;
    }
    return devices.find((device) => device.deviceId === activeDeviceId) ?? null;
  }, [activeDeviceId, devices]);

  const showError = useCallback((message: string, actions: ErrorActionKey[] = DEFAULT_ERROR_ACTIONS) => {
    setErrorState(message);
    setErrorActionKeys(actions);
  }, []);

  const clearError = useCallback(() => {
    setErrorState(null);
    setErrorActionKeys([]);
  }, []);

  const normalizeCommandError = useCallback(
    (error: unknown, fallback: string): NormalizedCommandError => {
      if (error && typeof error === "object") {
        const anyError = error as Record<string, unknown>;
        const code = typeof anyError.code === "string" ? anyError.code : undefined;
        const message = typeof anyError.message === "string" ? anyError.message : fallback;
        const reason = extractReasonToken(message);
        return { code, message, reason };
      }
      const message = typeof error === "string" ? error : fallback;
      return { message, reason: extractReasonToken(message) };
    },
    []
  );

  const handleCommandError = useCallback(
    (error: unknown, fallback: string) => {
      const info = normalizeCommandError(error, fallback);
      const upgrade = info.reason ? LICENSE_REASON_MAP[info.reason] : undefined;
      if (upgrade) {
        setUpgradeReason(upgrade);
        setInfo(null);
        clearError();
        return {
          handled: true,
          message: UPGRADE_MESSAGES[upgrade],
        };
      }
      const friendly = (info.reason && FRIENDLY_ERROR_MESSAGES[info.reason]) || info.message || fallback;
      const actions = deriveErrorActionKeys(info.code, info.reason);
      showError(friendly, actions);
      return { handled: false, message: friendly };
    },
    [normalizeCommandError, showError, clearError, setInfo]
  );

  const captureFiles = useCallback((list: FileList | null) => {
    if (!list) {
      return;
    }
    const next = Array.from(list).map<SelectedFile>((file) => ({
      name: file.name,
      size: file.size,
    }));
    if (next.length > 0) {
      setFiles(next);
    }
  }, []);

  const appendLog = useCallback((entry: string) => {
    setLogs((prev) => {
      const next = [...prev, entry];
      if (next.length > 50) {
        next.shift();
      }
      return next;
    });
  }, []);

  const copyRecentLogs = useCallback(async () => {
    const snapshot = logs.slice(-20).join("\n");
    const text = snapshot.length > 0 ? snapshot : "暂无日志";
    await copyPlainText(text);
    setInfo("最近日志已复制。");
    appendLog("📋 已复制最近日志。");
  }, [logs, appendLog]);

  const openDocs = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open(DOCS_URL, "_blank", "noopener,noreferrer");
    }
      appendLog("📖 打开故障排查文档。");
    }, [appendLog]);

  const removeTrustedPeer = useCallback(
    (deviceId: string) => {
      setTrustedPeers((prev) => {
        if (!prev[deviceId]) {
          return prev;
        }
        const next = { ...prev };
        delete next[deviceId];
        return next;
      });
      appendLog(`🗑️ 已移除信任设备 ${deviceId}`);
    },
    [appendLog]
  );

  const totalSelectedBytes = useMemo(
    () => files.reduce((sum, file) => sum + (file.size ?? 0), 0),
    [files]
  );

  const largestSelectedBytes = useMemo(
    () => files.reduce((max, file) => Math.max(max, file.size ?? 0), 0),
    [files]
  );

  const clearTrustedPeers = useCallback(() => {
    if (Object.keys(trustedPeersRef.current).length === 0) {
      setInfo("当前没有已信任的设备。");
      return;
    }
    setTrustedPeers({});
    appendLog("🧼 已清空所有信任设备。");
  }, [setInfo, appendLog]);

  const copySampleLicense = useCallback(() => {
    void copyPlainText("QD-PRO-XXXX-YYYY-ZZZZ");
    setInfo("示例 License Key 已复制。");
    appendLog("📋 已复制示例 License Key。");
  }, [appendLog]);

  const promptUpgrade = useCallback(
    (reason: UpgradeReason, fallback?: string) => {
      setUpgradeReason(reason);
      if (fallback) {
        showError(fallback, ["openPricing"]);
      }
    },
    [showError]
  );

  const checkDeviceLimit = useCallback(() => {
    if (!licenseStatus?.limits?.maxDevices) {
      return true;
    }
    if (devices.length < licenseStatus.limits.maxDevices) {
      return true;
    }
    promptUpgrade("device_limit", "当前权益设备数量已达上限，请升级以添加更多设备。");
    return false;
  }, [licenseStatus?.limits?.maxDevices, devices.length, promptUpgrade]);

  const incrementP2pUsage = useCallback(() => {
    setLicenseStatus((prev) => {
      if (!prev) {
        return prev;
      }
      return {
        ...prev,
        p2pUsed: prev.p2pUsed + 1,
      };
    });
  }, []);

  const checkP2pQuota = useCallback(() => {
    if (!licenseStatus?.p2pQuota) {
      return true;
    }
    if (licenseStatus.p2pUsed < licenseStatus.p2pQuota) {
      return true;
    }
    promptUpgrade("p2p_quota", "本月跨网配额已用完，请升级到 Pro 版。");
    return false;
  }, [licenseStatus?.p2pQuota, licenseStatus?.p2pUsed, promptUpgrade]);

  const checkFileSizeLimit = useCallback(() => {
    if (!licenseStatus?.limits?.maxFileSizeMb) {
      return true;
    }
    if (largestSelectedBytes === 0) {
      return true;
    }
    const limitBytes = licenseStatus.limits.maxFileSizeMb * 1024 * 1024;
    if (largestSelectedBytes > limitBytes) {
      promptUpgrade(
        "file_size",
        `当前选择的最大文件大小为 ${formatBytes(largestSelectedBytes)}，已超过配额 ${formatBytes(limitBytes)}。`
      );
      return false;
    }
    if (totalSelectedBytes > limitBytes) {
      promptUpgrade(
        "file_size",
        `本次传输总大小为 ${formatBytes(totalSelectedBytes)}，已超过配额 ${formatBytes(limitBytes)}。`
      );
      return false;
    }
    return true;
  }, [licenseStatus?.limits?.maxFileSizeMb, largestSelectedBytes, totalSelectedBytes, promptUpgrade]);

  const handleUpgradeDismiss = useCallback(() => {
    setUpgradeReason(null);
  }, []);

  const handleUpgradeCTA = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open(UPGRADE_URL, "_blank", "noopener,noreferrer");
    }
    appendLog("💎 已打开定价页面了解 Pro 计划。");
    setUpgradeReason(null);
  }, [appendLog]);

  const refreshRouteMetrics = useCallback(async () => {
    if (!detectTauri()) {
      setInfo("路由统计仅在 Tauri 桌面端可用。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      setInfo("Tauri invoke API 不可用，无法获取路由统计。");
      return;
    }
    setIsRouteMetricsLoading(true);
    try {
      const metrics = (await invoke("courier_route_metrics", {})) as RouteMetricsDto[];
      setRouteMetrics(metrics);
      if (!metrics || metrics.length === 0) {
        setInfo("暂无路由统计数据。");
      }
    } catch (err) {
      const result = handleCommandError(err, "路由统计加载失败");
      appendLog(`路由统计加载失败：${result.message}`);
    } finally {
      setIsRouteMetricsLoading(false);
    }
  }, [appendLog, handleCommandError, setInfo]);

  const refreshTransferStats = useCallback(async () => {
    if (!identity) {
      setTransferStats(null);
      return;
    }
    if (!isTauri) {
      setInfo("传输统计仅在 Tauri 桌面端可用。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshTransferStats: invoke unavailable", err);
      setInfo("Tauri invoke API 不可用，无法获取传输统计。");
      return;
    }
    setIsStatsLoading(true);
    try {
      const stats = (await invoke("transfer_stats", {
        payload: { identityId: identity.identityId },
      })) as TransferStatsDto;
      setTransferStats(stats);
    } catch (err) {
      const result = handleCommandError(err, "传输统计加载失败");
      appendLog(`传输统计加载失败：${result.message}`);
    } finally {
      setIsStatsLoading(false);
    }
  }, [identity, isTauri, appendLog, handleCommandError, setInfo]);

  const refreshAuditLogs = useCallback(async () => {
    if (!identity) {
      setAuditLogs([]);
      return;
    }
    if (!isTauri) {
      setInfo("审计日志仅在 Tauri 桌面端可用。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshAuditLogs: invoke unavailable", err);
      setInfo("Tauri invoke API 不可用，无法获取审计日志。");
      return;
    }
    setIsAuditLoading(true);
    try {
      const logs = (await invoke("audit_get_logs", {
        payload: { identityId: identity.identityId },
        limit: 80,
      })) as AuditLogEntryDto[];
      setAuditLogs(logs);
    } catch (err) {
      const result = handleCommandError(err, "审计日志加载失败");
      appendLog(`审计日志加载失败：${result.message}`);
    } finally {
      setIsAuditLoading(false);
    }
  }, [identity, isTauri, appendLog, handleCommandError, setInfo]);

  const refreshLicenseStatus = useCallback(async () => {
    if (!identity) {
      setLicenseStatus(null);
      return;
    }
    if (!isTauri) {
      setInfo("权益信息仅在 Tauri 桌面端可用。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshLicenseStatus: invoke unavailable", err);
      setInfo("Tauri invoke API 不可用，无法获取权益信息。");
      return;
    }
    setIsLicenseLoading(true);
    try {
      const raw = await invoke("license_get_status", {
        payload: { identityId: identity.identityId },
      });
      const status = normalizeLicenseStatus(raw, identity.identityId);
      setLicenseStatus(status);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message, ["refreshLicense", "copyLogs"]);
      appendLog(`⚠️ 获取权益信息失败：${message}`);
    } finally {
      setIsLicenseLoading(false);
    }
  }, [identity, isTauri, appendLog, setInfo, showError]);

  const refreshSecurityConfig = useCallback(async () => {
    if (!isTauri) {
      setInfo("安全策略仅在 Tauri 桌面端可查询。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      showError("Tauri invoke API 不可用，无法读取安全策略。", ["refreshSecurity", "copyLogs"]);
      return;
    }
    setIsSecurityLoading(true);
    try {
      const config = (await invoke("security_get_config", {})) as SecurityConfigDto;
      setSecurityConfig(config);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message, ["refreshSecurity", "copyLogs"]);
      appendLog(`⚠️ 读取安全策略失败：${message}`);
    } finally {
      setIsSecurityLoading(false);
    }
  }, [isTauri, appendLog, showError, setInfo]);

  const refreshSettings = useCallback(async () => {
    if (!isTauri) {
      setInfo("传输设置仅在 Tauri 桌面端可调整。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshSettings: invoke unavailable", err);
      setInfo("Tauri invoke API 不可用，无法获取传输设置。");
      return;
    }
    setIsSettingsLoading(true);
    try {
      const payload = (await invoke("load_settings", {})) as SettingsPayload;
      setSettings(payload);
      setChunkPolicyDraft(payload.chunkPolicy);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message, ["refreshStats", "copyLogs"]);
      appendLog(`⚠️ 读取传输设置失败：${message}`);
    } finally {
      setIsSettingsLoading(false);
    }
  }, [appendLog, isTauri, setInfo, showError]);

  const saveChunkPolicy = useCallback(async () => {
    if (!settings || !chunkPolicyDraft) {
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      showError("Tauri invoke API 不可用，无法保存设置。", ["refreshStats", "copyLogs"]);
      return;
    }
    const minMb = Math.max(2, Math.min(16, Math.round(chunkPolicyDraft.minBytes / ONE_MB)));
    const maxMb = Math.max(minMb, Math.min(16, Math.round(chunkPolicyDraft.maxBytes / ONE_MB)));
    const payload: SettingsPayload = {
      ...settings,
      chunkPolicy: {
        adaptive: chunkPolicyDraft.adaptive,
        minBytes: minMb * ONE_MB,
        maxBytes: maxMb * ONE_MB,
        lanStreams: Math.min(4, Math.max(1, chunkPolicyDraft.lanStreams)),
      },
    };
    setIsSavingSettings(true);
    try {
      const response = (await invoke("update_settings", { payload })) as SettingsPayload;
      setSettings(response);
      setChunkPolicyDraft(response.chunkPolicy);
      setInfo("传输设置已保存。");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message, ["refreshStats", "copyLogs"]);
      appendLog(`⚠️ 保存传输设置失败：${message}`);
    } finally {
      setIsSavingSettings(false);
    }
  }, [chunkPolicyDraft, settings, showError, appendLog, setInfo]);

  const updateChunkPolicyDraft = useCallback((patch: Partial<ChunkPolicySettings>) => {
    setChunkPolicyDraft((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  const handleChunkAdaptiveChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      updateChunkPolicyDraft({ adaptive: event.target.checked });
    },
    [updateChunkPolicyDraft],
  );

  const handleChunkMinChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const value = Number(event.target.value) || 0;
      updateChunkPolicyDraft({ minBytes: Math.max(2, value) * ONE_MB });
    },
    [updateChunkPolicyDraft],
  );

  const handleChunkMaxChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const value = Number(event.target.value) || 0;
      updateChunkPolicyDraft({ maxBytes: Math.max(2, value) * ONE_MB });
    },
    [updateChunkPolicyDraft],
  );

  const handleLanStreamsChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => {
      const value = Number(event.target.value) || 1;
      updateChunkPolicyDraft({ lanStreams: value });
    },
    [updateChunkPolicyDraft],
  );

  const refreshSettingsRef = useRef<() => void>(() => {});
  useEffect(() => {
    refreshSettingsRef.current = () => {
      void refreshSettings();
    };
  }, [refreshSettings]);

  const errorActionHandlers = useMemo<Record<ErrorActionKey, () => void>>(
    () => ({
      copyLogs: copyRecentLogs,
      openDocs,
      refreshStats: () => {
        void refreshTransferStats();
      },
      refreshAudit: () => {
        void refreshAuditLogs();
      },
      refreshRoutes: () => {
        void refreshRouteMetrics();
      },
      refreshSecurity: () => {
        void refreshSecurityConfig();
      },
      refreshSettings: () => {
        void refreshSettings();
      },
      refreshLicense: () => {
        void refreshLicenseStatus();
      },
      openPricing: () => {
        handleUpgradeCTA();
      },
    }),
    [
      copyRecentLogs,
      openDocs,
      refreshTransferStats,
      refreshAuditLogs,
      refreshRouteMetrics,
      refreshSecurityConfig,
      refreshSettings,
      refreshLicenseStatus,
      handleUpgradeCTA,
    ]
  );

  const activateLicense = useCallback(async () => {
    if (!isTauri) {
      setInfo("License 激活需在 Tauri 桌面端运行。");
      return;
    }
    if (!identity) {
      setInfo("请先注册或导入身份，再激活 License。");
      return;
    }
    const trimmed = licenseInput.trim();
    if (!trimmed) {
      showError("请输入 License Key。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      showError("Tauri invoke API 不可用，无法激活 License。");
      return;
    }
    setIsActivatingLicense(true);
    clearError();
    try {
      await invoke("license_activate", {
        payload: {
          identityId: identity.identityId,
          licenseBlob: trimmed,
        },
      });
      setLicenseInput("");
      appendLog("🔏 License 激活成功");
      setInfo("License 激活成功。");
      await refreshLicenseStatus();
    } catch (err) {
      const result = handleCommandError(err, "License 激活失败");
      appendLog(`⚠️ License 激活失败：${result.message}`);
    } finally {
      setIsActivatingLicense(false);
    }
  }, [
    identity,
    isTauri,
    licenseInput,
    appendLog,
    refreshLicenseStatus,
    handleCommandError,
    showError,
    clearError,
    setInfo,
  ]);

  useEffect(() => {
    if (progress?.phase === "done") {
      refreshRouteMetrics().catch((err) => console.warn("refreshRouteMetrics", err));
    }
  }, [progress?.phase, refreshRouteMetrics]);

  useEffect(() => {
    let mounted = true;
    const update = () => {
      if (!mounted) {
        return;
      }
      setIsTauri(detectTauri());
    };
    update();
    const timer = window.setInterval(update, 250);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, []);

  const signPurpose = useCallback(
    async (purpose: string, customDeviceId?: string) => {
      ensureEd25519Hash();
      if (!(identity && identityPrivateKey)) {
        throw new Error("身份密钥不可用");
      }
      const deviceId = customDeviceId ?? activeDeviceId;
      if (!deviceId) {
        throw new Error("缺少设备标识");
      }
      const message = new TextEncoder().encode(
        `${purpose}:${identity.identityId}:${deviceId}`
      );
      const signatureBytes = await signEd25519(message, identityPrivateKey);
      return bytesToHex(signatureBytes);
    },
    [identity, identityPrivateKey, activeDeviceId]
  );

  const sendHeartbeat = useCallback(
    async (status = "active") => {
      if (!detectTauri() || !identity || !identityPrivateKey) {
        return;
      }
      const deviceId = activeDeviceId ?? devices[0]?.deviceId;
      if (!deviceId) {
        return;
      }
      try {
        const invoke = resolveTauriInvoke();
        const signature = await signPurpose("heartbeat", deviceId);
        await invoke("auth_heartbeat_device", {
          auth: {
            identityId: identity.identityId,
            deviceId,
            signature,
            payload: {
              status,
              capabilities: heartbeatCapabilities,
            },
          },
        });
      } catch (err) {
        console.warn("heartbeat failed", err);
      }
    },
    [activeDeviceId, devices, heartbeatCapabilities, identity, identityPrivateKey, signPurpose]
  );

  const refreshDevices = useCallback(
    async (targetIdentityId?: string) => {
      if (!detectTauri()) {
        return;
      }
      const identityId = targetIdentityId ?? identity?.identityId;
      if (!identityId) {
        return;
      }
      try {
        const invoke = resolveTauriInvoke();
    const response = (await invoke("auth_list_devices", {
      payload: { identityId },
    })) as DevicesResponseDto;
    const items = (response.items ?? []).map<DeviceState>((device) => ({
      deviceId: device.deviceId ?? device.device_id ?? `dev_${generateRandomHex(6)}`,
      identityId: device.identityId ?? device.identity_id ?? identityId,
      publicKey: device.publicKey ?? device.public_key ?? "",
      name: device.name ?? null,
      status: device.status ?? "active",
      lastSeenAt: device.lastSeenAt ?? device.last_seen_at ?? Date.now(),
      capabilities: device.capabilities ?? [],
    }));
    setDevices(items);
    setActiveDeviceId((prev) => {
      if (prev && items.some((item) => item.deviceId === prev)) {
        return prev;
      }
      return items[0]?.deviceId ?? prev;
    });
  } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
    showError(message);
    appendLog(`⚠️ 拉取设备失败：${message}`);
  }
},
[appendLog, identity, showError]
);

  const refreshEntitlement = useCallback(
    async (targetIdentityId?: string) => {
      if (!detectTauri()) {
        return;
      }
      const identityId = targetIdentityId ?? identity?.identityId;
      if (!identityId) {
        return;
      }
      try {
        const invoke = resolveTauriInvoke();
        const response = (await invoke("auth_load_entitlement", {
          payload: { identityId },
        })) as EntitlementResponseDto;
        const normalized: EntitlementState = {
          identityId: response.identityId ?? response.identity_id ?? identityId,
          plan: response.plan ?? "free",
          expiresAt: response.expiresAt ?? response.expires_at ?? null,
          features: response.features ?? [],
          updatedAt: response.updatedAt ?? response.updated_at ?? Date.now(),
        };
        setEntitlement(normalized);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        showError(message);
        appendLog(`⚠️ 拉取权益失败：${message}`);
      }
    },
    [appendLog, identity, showError]
  );

  const registerIdentity = useCallback(async () => {
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("registerIdentity: invoke unavailable", err);
      setInfo("身份注册需在 Tauri 桌面环境完成。");
      return;
    }
    setIsRegisteringIdentity(true);
    clearError();
    try {
      ensureEd25519Hash();
      const privateKeyBytes = ed25519Utils.randomPrivateKey();
      const publicKeyBytes = await getPublicKey(privateKeyBytes);
      const publicKeyHex = bytesToHex(publicKeyBytes);
      const privateKeyHex = bytesToHex(privateKeyBytes);

      const identityId = `id_${generateRandomHex(10)}`;
      const response = (await invoke("auth_register_identity", {
        payload: {
          identityId,
          publicKey: publicKeyHex,
          label: t("app.title", "Quantum Drop · 量子快传"),
        },
      })) as IdentityResponseDto;
      const resolvedId = response.identityId ?? response.identity_id ?? identityId;
      const resolvedKey = response.publicKey ?? response.public_key ?? publicKeyHex;
      setIdentity({ identityId: resolvedId, publicKey: resolvedKey, label: response.label ?? null });
      setIdentityPrivateKey(privateKeyBytes);
      setDevices([]);
      setEntitlement(null);
      setInfo(`身份 ${resolvedId} 已注册。`);
      appendLog(`🪐 身份 ${resolvedId} 已注册。`);
      await rememberIdentity({
        identityId: resolvedId,
        publicKeyHex: resolvedKey,
        privateKeyHex,
      });
      await rememberLastIdentityId(resolvedId);
      await refreshEntitlement(resolvedId);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message);
      appendLog(`⚠️ 身份注册失败：${message}`);
    } finally {
      setIsRegisteringIdentity(false);
    }
  }, [appendLog, refreshEntitlement, rememberIdentity, rememberLastIdentityId, clearError, showError, t]);

  const registerDevice = useCallback(async () => {
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("registerDevice: invoke unavailable", err);
      setInfo("设备登记需在 Tauri 桌面环境完成。");
      return;
    }
    if (!identity) {
      setInfo("请先注册身份。");
      return;
    }
    if (!identityPrivateKey) {
      showError("当前会话缺少身份私钥，请重新注册或导入身份。");
      return;
    }
    if (!checkDeviceLimit()) {
      return;
    }
    setIsRegisteringDevice(true);
    clearError();
    try {
      ensureEd25519Hash();
      const deviceId = `dev_${generateRandomHex(10)}`;
      const devicePrivateBytes = ed25519Utils.randomPrivateKey();
      const devicePublicBytes = await getPublicKey(devicePrivateBytes);
      const devicePublicKeyHex = bytesToHex(devicePublicBytes);
      const messageBytes = new TextEncoder().encode(`register:${deviceId}:${devicePublicKeyHex}`);
      const signatureBytes = await signEd25519(messageBytes, identityPrivateKey);
      const signatureHex = bytesToHex(signatureBytes);
      const response = (await invoke("auth_register_device", {
        payload: {
          identityId: identity.identityId,
          deviceId,
          publicKey: devicePublicKeyHex,
          name: `Terminal-${devices.length + 1}`,
          signature: signatureHex,
        },
      })) as DeviceResponseDto;
      const resolvedId = response.deviceId ?? response.device_id ?? deviceId;
      appendLog(`⚡ 设备 ${resolvedId} 已登记。`);
      await refreshDevices(identity.identityId);
      setActiveDeviceId(resolvedId);
      await sendHeartbeat("active");
    } catch (err) {
      const result = handleCommandError(err, "设备登记失败");
      appendLog(`⚠️ 设备登记失败：${result.message}`);
    } finally {
      setIsRegisteringDevice(false);
    }
  }, [appendLog, devices.length, identity, identityPrivateKey, refreshDevices, sendHeartbeat, checkDeviceLimit]);

  const upgradeEntitlement = useCallback(
    async (plan: string) => {
      let invoke: TauriInvokeFn;
      try {
        invoke = resolveTauriInvoke();
      } catch (err) {
        console.warn("upgradeEntitlement: invoke unavailable", err);
        setInfo("权益升级需在 Tauri 桌面环境完成。");
        return;
      }
      if (!identity) {
        setInfo("请先注册身份。");
        return;
      }
      setIsUpdatingEntitlement(true);
      clearError();
      try {
        const response = (await invoke("auth_update_entitlement", {
          payload: {
            identityId: identity.identityId,
            plan,
            features: plan === "pro" ? ["multi-device", "priority-routing"] : [],
          },
        })) as EntitlementResponseDto;
        const normalized: EntitlementState = {
          identityId: response.identityId ?? response.identity_id ?? identity.identityId,
          plan: response.plan ?? plan,
          expiresAt: response.expiresAt ?? response.expires_at ?? null,
          features: response.features ?? [],
          updatedAt: response.updatedAt ?? response.updated_at ?? Date.now(),
        };
        setEntitlement(normalized);
        appendLog(`✨ 权益已更新为 ${normalized.plan}`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        showError(message);
        appendLog(`⚠️ 权益更新失败：${message}`);
      } finally {
        setIsUpdatingEntitlement(false);
      }
    },
    [appendLog, identity, clearError, showError]
  );

  const exportPrivateKey = useCallback(async () => {
    if (!(identity && identityPrivateKey)) {
      setInfo("当前无可导出的身份私钥。");
      return;
    }
    try {
      const hex = bytesToHex(identityPrivateKey);
      await rememberIdentity({
        identityId: identity.identityId,
        publicKeyHex: identity.publicKey,
        privateKeyHex: hex,
      });
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(hex);
        setInfo("已复制私钥到剪贴板，请妥善保管。");
      } else {
        setInfo(hex);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message);
    }
  }, [identity, identityPrivateKey, rememberIdentity, showError]);

  const importIdentity = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const identityId = importIdentityId.trim();
      const privateHex = importPrivateKey.trim();
      if (!identityId) {
        showError("请输入身份标识");
        return;
      }
      if (!privateHex) {
        showError("请输入私钥十六进制");
        return;
      }
    setIsImportingIdentity(true);
    clearError();
    try {
      ensureEd25519Hash();
      const privateBytes = hexToBytes(privateHex);
        if (privateBytes.length !== 32) {
          throw new Error("私钥长度必须为 32 字节");
        }
        const publicKeyBytes = await getPublicKey(privateBytes);
        const publicKeyHex = bytesToHex(publicKeyBytes);
        const invoke = resolveTauriInvoke();
        const response = (await invoke("auth_register_identity", {
          payload: {
            identityId,
            publicKey: publicKeyHex,
            label: null,
          },
        })) as IdentityResponseDto;
        const resolvedId = response.identityId ?? response.identity_id ?? identityId;
        const resolvedKey = response.publicKey ?? response.public_key ?? publicKeyHex;
        setIdentity({ identityId: resolvedId, publicKey: resolvedKey, label: response.label ?? null });
        setIdentityPrivateKey(privateBytes);
        setDevices([]);
        setEntitlement(null);
        await rememberIdentity({
          identityId: resolvedId,
          publicKeyHex: resolvedKey,
          privateKeyHex: privateHex,
        });
        await rememberLastIdentityId(resolvedId);
        setInfo(`身份 ${resolvedId} 导入成功。`);
        appendLog(`🧬 身份 ${resolvedId} 已导入。`);
        setImportIdentityId("");
        setImportPrivateKey("");
        await refreshEntitlement(resolvedId);
        await refreshDevices(resolvedId);
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        showError(message);
        appendLog(`⚠️ 身份导入失败：${message}`);
      } finally {
        setIsImportingIdentity(false);
      }
    },
    [appendLog, importIdentityId, importPrivateKey, refreshDevices, refreshEntitlement, rememberIdentity, rememberLastIdentityId, clearError, showError]
  );

  useEffect(() => {
    let cancelled = false;
    const initialise = async () => {
      try {
        const lastId = await loadLastIdentityId();
        if (!lastId) {
          return;
        }
        const stored = await loadIdentity(lastId);
        if (!stored) {
          return;
        }
        const privateBytes = hexToBytes(stored.privateKeyHex);
        if (privateBytes.length !== 32) {
          return;
        }
        ensureEd25519Hash();
        try {
          const invoke = resolveTauriInvoke();
          await invoke("auth_register_identity", {
            payload: {
              identityId: stored.identityId,
              publicKey: stored.publicKeyHex,
              label: null,
            },
          });
        } catch (err) {
          console.warn("failed to reconcile identity", err);
        }
        if (cancelled) {
          return;
        }
        setIdentity({ identityId: stored.identityId, publicKey: stored.publicKeyHex, label: null });
        setIdentityPrivateKey(privateBytes);
        appendLog(`🔑 已加载身份 ${stored.identityId}`);
        await refreshEntitlement(stored.identityId);
      } catch (err) {
        console.warn("unable to initialise identity", err);
      }
    };
    initialise();
    return () => {
      cancelled = true;
    };
  }, [appendLog, refreshEntitlement]);

  useEffect(() => {
    if (!identity) {
      setDevices([]);
      setEntitlement(null);
      if (heartbeatTimerRef.current) {
        window.clearInterval(heartbeatTimerRef.current);
        heartbeatTimerRef.current = null;
      }
      return;
    }
    if (!isTauri) {
      return;
    }
    refreshDevices(identity.identityId);
    refreshEntitlement(identity.identityId);
  }, [identity, refreshDevices, refreshEntitlement, isTauri]);

  useEffect(() => {
    if (!identity || !isTauri) {
      setTransferStats(null);
      setAuditLogs([]);
      return;
    }
    refreshTransferStats();
    refreshAuditLogs();
    refreshLicenseStatus();
    refreshSecurityConfig();
  }, [identity, isTauri, refreshTransferStats, refreshAuditLogs, refreshLicenseStatus, refreshSecurityConfig]);

  useEffect(() => {
    if (devices.length === 0) {
      setActiveDeviceId(null);
      return;
    }
    if (!activeDeviceId || !devices.some((device) => device.deviceId === activeDeviceId)) {
      setActiveDeviceId(devices[0].deviceId);
    }
  }, [devices, activeDeviceId]);

  useEffect(() => {
    if (!selectedDevice) {
      setEditDeviceName("");
      setEditDeviceStatus("active");
      return;
    }
    setEditDeviceName(selectedDevice.name ?? "");
    setEditDeviceStatus(selectedDevice.status ?? "active");
  }, [selectedDevice]);

  useEffect(() => {
    if (!isTauri || !identity || !identityPrivateKey) {
      return;
    }
    const deviceId = activeDeviceId ?? devices[0]?.deviceId;
    if (!deviceId) {
      return;
    }
    sendHeartbeat("active");
    const timer = window.setInterval(() => {
      sendHeartbeat();
    }, 15000);
    heartbeatTimerRef.current = timer as unknown as number;
    return () => {
      window.clearInterval(timer);
      heartbeatTimerRef.current = null;
    };
  }, [isTauri, identity, identityPrivateKey, activeDeviceId, devices, sendHeartbeat]);

  // 监听 Tauri 系统拖拽（包含绝对路径）——优先 webview.onDragDropEvent，其次事件总线，再退全局注入
  useEffect(() => {
    if (!isTauri) return;
    const unlisteners: Array<() => void | Promise<void>> = [];

    const handler = (evt: { payload: string[] }) => {
      const paths = (evt?.payload ?? []).filter((v) => typeof v === "string");
      if (paths.length === 0) return;
      const displayFiles = paths.map<SelectedFile>((path) => {
        const parts = path.split(/[/\\]/);
        const name = parts[parts.length - 1] ?? path;
        return { name, path };
      });
      setFiles(displayFiles);
      setPendingPaths(paths);
      setTaskId(null);
      setTaskCode(null);
      setSenderPublicKey(null);
      setRouteAttempts(null);
      setRouteMetrics(null);
      setProgress(null);
      setLogs([]);
      setPeerPrompt(null);
      setTrustedPeers({});
      setPeerFingerprintInput("");
      setAbsorbing(true);
      window.setTimeout(() => setAbsorbing(false), 900);
      const canAuto = Boolean(identity && identityPrivateKey && (activeDeviceId || devices[0]));
      if (canAuto && !isSending) {
        window.setTimeout(() => {
          beginTransferRef.current?.(paths);
        }, 220);
      }
    };

    (async () => {
      // 1. webview.onDragDropEvent（提供 drop 类型与绝对路径）
      try {
        const off = await getCurrentWebview().onDragDropEvent((event) => {
          const t = event?.payload?.type;
          if (t === "enter" || t === "over") {
            setHovered(true);
          } else if (t === "leave") {
            setHovered(false);
          } else if (t === "drop") {
            setHovered(false);
            handler({ payload: event.payload.paths ?? [] });
          }
        });
        unlisteners.push(off);
      } catch (err) {
        console.warn("webview.onDragDropEvent failed", err);
      }

      // 2. 事件总线
      try {
        const offEvent = await listenTauri<string[]>("tauri://file-drop", handler);
        unlisteners.push(offEvent);
      } catch (err) {
        console.warn("event.listen fallback failed", err);
      }

      // 3. 全局注入（在 withGlobalTauri=true 时存在）
      const tauri = getTauri();
      const globalListen = tauri?.event?.listen as
        | (<T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>)
        | undefined;
      if (globalListen) {
        try {
          const off = await globalListen<string[]>("tauri://file-drop", handler);
          unlisteners.push(off);
        } catch (err) {
          console.warn("global event listen failed", err);
        }
      }
    })();

    return () => {
      unlisteners.forEach((dispose) => {
        try {
          const result = dispose();
          if (result instanceof Promise) {
            result.catch(() => undefined);
          }
        } catch {
          // ignore
        }
      });
    };
  }, [isTauri, identity, identityPrivateKey, activeDeviceId, devices, isSending]);

  // 保险：在 Tauri 环境里，系统级拖拽可能不触发 DOM onDrop。
  // 用全局 dragenter/dragleave 保证至少出现一次吸入动效，提升反馈感知。
  useEffect(() => {
    if (!detectTauri()) return;
    const onEnter = (e: DragEvent) => {
      // 只在外部拖入时触发，避免内部拖拽干扰
      if (e.dataTransfer && e.dataTransfer.types?.length) {
        setAbsorbing(true);
        window.setTimeout(() => setAbsorbing(false), 600);
      }
    };
    window.addEventListener('dragenter', onEnter);
    return () => window.removeEventListener('dragenter', onEnter);
  }, []);

  useEffect(() => {
    if (!identity) {
      return;
    }
    rememberLastIdentityId(identity.identityId).catch((err) => console.warn("rememberLastIdentityId", err));
  }, [identity]);

  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      // 在 Tauri 环境下，不拦截 DOM drop，让系统级 file-drop 事件拿到绝对路径
      if (detectTauri()) {
        return;
      }
      event.preventDefault();
      setHovered(false);
      captureFiles(event.dataTransfer.files);
      setPendingPaths([]);
      setTaskId(null);
      setTaskCode(null);
      setSenderPublicKey(null);
      setRouteAttempts(null);
      setRouteMetrics(null);
      setProgress(null);
      setLogs([]);
      // 吸入动效（拖拽场景不自动发送）
      setAbsorbing(true);
      window.setTimeout(() => setAbsorbing(false), 900);
    },
    [captureFiles]
  );

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    if (detectTauri()) return;
    event.preventDefault();
    if (!hovered) {
      setHovered(true);
    }
  }, [hovered]);

  const handleDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    if (detectTauri()) return;
    event.preventDefault();
    setHovered(false);
  }, []);

  const handleBrowse = useCallback(async () => {
    clearError();
    setInfo(null);
    if (detectTauri()) {
      try {
        const tauri = getTauri();
        const dialogAny = tauri;
        if (dialogAny?.dialog?.open) {
        const selected = await dialogAny.dialog.open({
          multiple: true,
          filters: [{ name: "All Files", extensions: ["*"] }],
        });
        if (!selected) {
          return;
        }
        const selectedPaths = Array.isArray(selected) ? selected : [selected];
        const normalized = selectedPaths.filter((value): value is string => typeof value === "string");
        if (normalized.length === 0) {
          return;
        }
        const displayFiles = normalized.map<SelectedFile>((path) => {
          const parts = path.split(/[/\\]/);
          const name = parts[parts.length - 1] ?? path;
          return { name, path };
        });
        setFiles(displayFiles);
        setPendingPaths(normalized);
        setTaskId(null);
        setTaskCode(null);
        setSenderPublicKey(null);
        setRouteAttempts(null);
        setRouteMetrics(null);
        setProgress(null);
        setLogs([]);
        // 动效与自动传输
        setAbsorbing(true);
        window.setTimeout(() => setAbsorbing(false), 900);
        const canAuto = Boolean(identity && identityPrivateKey && (activeDeviceId || devices[0]));
        if (canAuto && !isSending) {
          window.setTimeout(() => {
            beginTransferRef.current?.(normalized as unknown as string[]);
          }, 220);
        }
      } else {
        // Tauri dialog 插件不可用时，回退到浏览器文件选择器
        fileInputRef.current?.click();
        setInfo("未检测到 Tauri 对话框插件，已使用系统文件选择器。");
      }
      } catch (err) {
        fileInputRef.current?.click();
        setInfo("文件选择器已回退为浏览器模式。");
      }
    } else {
      fileInputRef.current?.click();
      setInfo("浏览器模式仅展示 UI，传输需在 Tauri 桌面环境运行。");
    }
  }, []);

  const handleFileInput = (event: React.ChangeEvent<HTMLInputElement>) => {
    captureFiles(event.target.files);
    event.target.value = "";
    setPendingPaths([]);
    setTaskId(null);
    setTaskCode(null);
    setSenderPublicKey(null);
    setRouteAttempts(null);
    setRouteMetrics(null);
    setProgress(null);
    setLogs([]);
    // 仅播放吸入动效（input 回退场景无法拿到绝对路径，不自动发送）
    setAbsorbing(true);
    window.setTimeout(() => setAbsorbing(false), 900);
  };

  const humanSpeed = useMemo(() => {
    if (!progress || !progress.speedBps) {
      return null;
    }
    const value = progress.speedBps;
    if (value >= 1024 ** 2) {
      return `${(value / 1024 ** 2).toFixed(1)} MB/s`;
    }
    if (value >= 1024) {
      return `${(value / 1024).toFixed(1)} KB/s`;
    }
    return `${value} B/s`;
  }, [progress]);

  const beginTransfer = useCallback(async (pathsOverride?: string[]) => {
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("beginTransfer: invoke unavailable", err);
      setInfo("需要在 Tauri 桌面环境下运行才能触发模拟传输。");
      return;
    }
    if (!identity || !identityPrivateKey) {
      setInfo("请先创建或导入量子身份。");
      return;
    }
    const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
    if (!activeDevice) {
      setInfo("请至少登记一个终端设备。");
      return;
    }
    const pathsToUse = Array.isArray(pathsOverride) && pathsOverride.length > 0 ? pathsOverride : pendingPaths;
    if (pathsToUse.length === 0) {
      setInfo("请选择至少一个文件。");
      return;
    }
    if (!checkFileSizeLimit()) {
      return;
    }
    setIsSending(true);
    clearError();
    setInfo(null);
    setRouteAttempts(null);
    setRouteMetrics(null);
    try {
      appendLog("准备生成取件码…");
      const signatureGenerate = await signPurpose("generate", activeDevice.deviceId);
      const result = (await invoke("courier_generate_code", {
        auth: {
          identityId: identity.identityId,
          deviceId: activeDevice.deviceId,
          signature: signatureGenerate,
          payload: {
            paths: pathsToUse,
            expireSec: undefined,
          },
        },
      })) as { taskId?: string; task_id?: string; code: string; publicKey?: string; public_key?: string };
      const resolvedTaskId = result.taskId ?? result.task_id ?? null;
      const resolvedPubKey = result.publicKey ?? result.public_key ?? null;
      setTaskId(resolvedTaskId);
      setTaskCode(result.code);
      setSenderPublicKey(resolvedPubKey);
      appendLog(`取件码 ${result.code} 已生成，启动发送…`);
      const signatureSend = await signPurpose("send", activeDevice.deviceId);
      await invoke("courier_send", {
        auth: {
          identityId: identity.identityId,
          deviceId: activeDevice.deviceId,
          signature: signatureSend,
          payload: {
            paths: pathsToUse,
          },
        },
        code: result.code,
      });
      appendLog("传输已启动，等待事件更新…");
      // 最小提示：避免额外文本
    } catch (err) {
      const result = handleCommandError(err, "传输启动失败");
      appendLog(`传输启动失败：${result.message}`);
    } finally {
      setIsSending(false);
    }
  }, [appendLog, pendingPaths, identity, devices, activeDeviceId, signPurpose, handleCommandError, clearError, checkFileSizeLimit]);

  useEffect(() => {
    beginTransferRef.current = beginTransfer;
  }, [beginTransfer]);

  useEffect(() => {
    trustedPeersRef.current = trustedPeers;
  }, [trustedPeers]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    try {
      const raw = window.localStorage.getItem(TRUSTED_PEERS_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Record<string, PeerDiscoveredPayload>;
        setTrustedPeers(parsed);
      }
    } catch (err) {
      console.warn("load trusted peers failed", err);
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    try {
      if (Object.keys(trustedPeers).length === 0) {
        window.localStorage.removeItem(TRUSTED_PEERS_KEY);
      } else {
        window.localStorage.setItem(TRUSTED_PEERS_KEY, JSON.stringify(trustedPeers));
      }
    } catch (err) {
      console.warn("persist trusted peers failed", err);
    }
  }, [trustedPeers]);

  const chooseReceiveDirectory = useCallback(async () => {
    if (!detectTauri()) {
      setInfo("请选择保存目录（仅支持桌面端）");
      return;
    }
    try {
      const tauri = getTauri();
      const dialogAny = tauri as { dialog?: TauriDialogApi };
      if (!dialogAny.dialog?.open) {
        setInfo("未检测到目录选择插件， 请手动输入路径。");
        return;
      }
      const selected = await dialogAny.dialog.open({ directory: true, multiple: false });
      if (typeof selected === "string") {
        setReceiveDir(selected);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message);
    }
  }, [showError]);

const handleManualReceive = useCallback(async () => {
    if (!detectTauri()) {
      setInfo("接收功能需在 Tauri 桌面端运行。");
      return;
    }
    if (!identity || !identityPrivateKey) {
      setInfo("请先创建或导入量子身份。");
      return;
    }
    const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
    if (!activeDevice) {
      setInfo("请至少登记一个终端设备。");
      return;
    }
    const code = receiveCode.trim();
    const host = receiveHost.trim();
    const senderKey = receiveSenderKey.trim();
    const portValue = Number.parseInt(receivePort, 10);
    if (!code) {
      setInfo("请输入 6 位配对码。");
      return;
    }
    if (!host) {
      setInfo("请输入发送方 IP 地址。");
      return;
    }
    if (!Number.isFinite(portValue) || portValue <= 0 || portValue > 65535) {
      setInfo("请输入合法端口（1-65535）。");
      return;
    }
    if (!senderKey) {
      setInfo("请输入发送方公钥。");
      return;
    }
    if (senderKey.length !== 64) {
      setInfo("公钥长度应为 64 位十六进制。");
      return;
    }
    try {
      hexToBytes(senderKey);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setInfo(message);
      return;
    }
    if (!receiveDir.trim()) {
      setInfo("请选择保存目录。");
      return;
    }
    if (!receiveSenderKey.trim()) {
      setInfo("请输入发送方公钥。");
      return;
    }
    if (!receiveSenderFingerprint.trim()) {
      setInfo("请输入发送方证书指纹。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      setInfo("Tauri invoke API 不可用，无法启动接收。");
      return;
    }
    setIsReceiving(true);
    clearError();
    setInfo(null);
    setRouteAttempts(null);
    setRouteMetrics(null);
    try {
      const signature = await signPurpose("receive", activeDevice.deviceId);
      await invoke("courier_receive", {
        auth: {
          identityId: identity.identityId,
          deviceId: activeDevice.deviceId,
          signature,
          payload: {
            code,
            saveDir: receiveDir,
            host,
            port: portValue,
            senderPublicKey: senderKey,
            senderCertFingerprint: receiveSenderFingerprint.trim(),
          },
        },
      });
      setTaskCode(code);
      setSenderPublicKey(null);
      appendLog("接收流程已启动，等待发送端开始传输…");
    } catch (err) {
      const result = handleCommandError(err, "接收启动失败");
      appendLog(`接收启动失败：${result.message}`);
    } finally {
      setIsReceiving(false);
    }
  }, [
    identity,
    identityPrivateKey,
    devices,
    activeDeviceId,
    receiveCode,
    receiveHost,
    receivePort,
    receiveDir,
    receiveSenderKey,
    signPurpose,
    appendLog,
    handleCommandError,
    clearError,
  ]);

  const connectByCode = useCallback(
    async (overrideCode?: string) => {
      if (!detectTauri()) {
        setInfo("自动发现仅在 Tauri 桌面端可用。");
        return;
      }
      if (!identity || !identityPrivateKey) {
        setInfo("请先创建或导入量子身份。");
        return;
      }
      const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
      if (!activeDevice) {
        setInfo("请至少登记一个终端设备。");
        return;
      }
      const codeValue = (overrideCode ?? receiveCode).trim();
      if (!codeValue) {
        setInfo("请输入 6 位配对码。");
        return;
      }
      if (!receiveDir.trim()) {
        setInfo("请选择保存目录。");
        return;
      }
      let invoke: TauriInvokeFn;
      try {
        invoke = resolveTauriInvoke();
      } catch (err) {
        setInfo("Tauri invoke API 不可用，无法启动接收。");
        return;
      }
      setIsReceiving(true);
      clearError();
      setInfo(null);
      setRouteAttempts(null);
      setRouteMetrics(null);
      try {
        const signature = await signPurpose("receive", activeDevice.deviceId);
        await invoke("courier_connect_by_code", {
          auth: {
            identityId: identity.identityId,
            deviceId: activeDevice.deviceId,
            signature,
            payload: {
              code: codeValue,
              saveDir: receiveDir,
            },
          },
        });
        setTaskCode(codeValue);
        setSenderPublicKey(null);
        appendLog("已通过 mDNS 自动发现发送方，等待连接…");
      } catch (err) {
        const result = handleCommandError(err, "接收启动失败");
        appendLog(`接收启动失败：${result.message}`);
      } finally {
        setIsReceiving(false);
      }
    },
    [
      identity,
      identityPrivateKey,
      devices,
      activeDeviceId,
      receiveCode,
      receiveDir,
      signPurpose,
      appendLog,
      handleCommandError,
      clearError,
    ]
  );

  const handleWebRtcSenderTest = useCallback(async () => {
    if (!detectTauri()) {
      setInfo("WebRTC 测试需在 Tauri 桌面端运行。");
      return;
    }
    if (!identity || !identityPrivateKey) {
      setInfo("请先完成身份初始化。");
      return;
    }
    const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
    if (!activeDevice) {
      setInfo("请至少登记一个终端设备。");
      return;
    }
    if (pendingPaths.length === 0) {
      setInfo("请选择至少一个文件再尝试 WebRTC 发送。");
      return;
    }
    if (!checkP2pQuota()) {
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch {
      setInfo("未检测到 Tauri invoke API，无法启动测试。");
      return;
    }
    const codeValue = (taskCode ?? generatePairingCode()).toUpperCase();
    setTaskCode(codeValue);
    setIsSending(true);
    clearError();
    setInfo(null);
    try {
      const signature = await signPurpose("webrtc_send", activeDevice.deviceId);
      const response = (await invoke("courier_start_webrtc_sender", {
        auth: {
          identityId: identity.identityId,
          deviceId: activeDevice.deviceId,
          signature,
          payload: {
            code: codeValue,
            filePaths: pendingPaths,
            devicePublicKey: activeDevice.publicKey,
            deviceName: activeDevice.name,
          },
        },
      })) as TaskResponseDto;
      const resolvedTaskId = response.taskId ?? response.task_id ?? null;
      if (resolvedTaskId) {
        setTaskId(resolvedTaskId);
      }
      setSenderPublicKey(null);
      appendLog(`WebRTC P2P 发送任务已启动（配对码 ${codeValue}）。`);
      setInfo("已启动 WebRTC 发送测试，等待接收方加入。");
      incrementP2pUsage();
    } catch (err) {
      const result = handleCommandError(err, "WebRTC 发送失败");
      appendLog(`WebRTC 发送失败：${result.message}`);
    } finally {
      setIsSending(false);
    }
  }, [
    identity,
    identityPrivateKey,
    devices,
    activeDeviceId,
    pendingPaths,
    taskCode,
    signPurpose,
    appendLog,
    handleCommandError,
    clearError,
    checkP2pQuota,
    incrementP2pUsage,
  ]);

  const handleWebRtcReceiverTest = useCallback(async () => {
    if (!detectTauri()) {
      setInfo("WebRTC 测试需在 Tauri 桌面端运行。");
      return;
    }
    if (!identity || !identityPrivateKey) {
      setInfo("请先完成身份初始化。");
      return;
    }
    const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
    if (!activeDevice) {
      setInfo("请至少登记一个终端设备。");
      return;
    }
    const codeValue = receiveCode.trim().toUpperCase();
    if (!codeValue) {
      setInfo("请输入配对码再启动 WebRTC 接收。");
      return;
    }
    if (!receiveDir.trim()) {
      setInfo("请选择保存目录。");
      return;
    }
    if (!checkP2pQuota()) {
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch {
      setInfo("未检测到 Tauri invoke API，无法启动测试。");
      return;
    }
    setIsReceiving(true);
    clearError();
    setInfo(null);
    try {
      const signature = await signPurpose("webrtc_receive", activeDevice.deviceId);
      const response = (await invoke("courier_start_webrtc_receiver", {
        auth: {
          identityId: identity.identityId,
          deviceId: activeDevice.deviceId,
          signature,
          payload: {
            code: codeValue,
            saveDir: receiveDir,
            devicePublicKey: activeDevice.publicKey,
            deviceName: activeDevice.name,
          },
        },
      })) as TaskResponseDto;
      const resolvedTaskId = response.taskId ?? response.task_id ?? null;
      if (resolvedTaskId) {
        setTaskId(resolvedTaskId);
      }
      setTaskCode(codeValue);
      setSenderPublicKey(null);
      appendLog(`WebRTC P2P 接收任务已启动（配对码 ${codeValue}）。`);
      setInfo("已启动 WebRTC 接收测试，等待发送方。");
      incrementP2pUsage();
    } catch (err) {
      const result = handleCommandError(err, "WebRTC 接收失败");
      appendLog(`WebRTC 接收失败：${result.message}`);
    } finally {
      setIsReceiving(false);
    }
  }, [
    identity,
    identityPrivateKey,
    devices,
    activeDeviceId,
    receiveCode,
    receiveDir,
    signPurpose,
    appendLog,
    handleCommandError,
    clearError,
    checkP2pQuota,
    incrementP2pUsage,
  ]);

  const scanSenders = useCallback(async () => {
    if (!detectTauri()) {
      setInfo("扫描需在 Tauri 桌面端运行。");
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      setInfo("Tauri invoke API 不可用，无法扫描发送方。");
      return;
    }
    setIsScanning(true);
    clearError();
    try {
      const result = (await invoke("courier_list_senders", {})) as SenderInfo[];
      setAvailableSenders(result);
    } catch (err) {
      const result = handleCommandError(err, "发送方扫描失败");
      appendLog(`扫描失败：${result.message}`);
    } finally {
      setIsScanning(false);
    }
  }, [appendLog, handleCommandError, clearError]);

  const handleCopy = useCallback(
    async (field: string, value: string) => {
      try {
        await copyPlainText(value);
        setInfo(`${field} 已复制到剪贴板。`);
        appendLog(`📋 ${field} 已复制。`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        showError(message);
      }
    },
    [appendLog, showError]
  );

  const submitDeviceUpdate = useCallback(
    async (overrideStatus?: string) => {
      let invoke: TauriInvokeFn;
      try {
        invoke = resolveTauriInvoke();
      } catch (err) {
        console.warn("submitDeviceUpdate: invoke unavailable", err);
        setInfo("终端信息更新仅在 Tauri 桌面环境可用。");
        return;
      }
      if (!identity) {
        setInfo("请先注册身份。");
        return;
      }
      if (!identityPrivateKey) {
        showError("当前会话缺少身份私钥，请重新导入或创建身份。");
        return;
      }
      const targetDeviceId = activeDeviceId ?? devices[0]?.deviceId ?? null;
      if (!targetDeviceId) {
        setInfo("请至少登记一个终端设备。");
        return;
      }
      setIsUpdatingDevice(true);
      clearError();
      try {
        const rawStatus = (overrideStatus ?? editDeviceStatus)?.trim();
        const statusValue = rawStatus && rawStatus.length > 0 ? rawStatus : "active";
        const signature = await signPurpose("update_device", targetDeviceId);
        const trimmedName = editDeviceName.trim();
        await invoke("auth_update_device", {
          auth: {
            identityId: identity.identityId,
            deviceId: targetDeviceId,
            signature,
            payload: {
              name: trimmedName.length > 0 ? trimmedName : null,
              status: statusValue,
              capabilities: heartbeatCapabilities,
            },
          },
  });
        await refreshDevices(identity.identityId);
        if (overrideStatus) {
          setEditDeviceStatus(statusValue);
        }
        setInfo("终端信息已更新。");
        appendLog(`🛠️ 终端 ${targetDeviceId} 已更新为 ${statusValue}。`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        showError(message);
        appendLog(`⚠️ 终端更新失败：${message}`);
      } finally {
        setIsUpdatingDevice(false);
      }
    },
    [
      identity,
      identityPrivateKey,
      activeDeviceId,
      devices,
      editDeviceStatus,
      editDeviceName,
      heartbeatCapabilities,
      signPurpose,
      refreshDevices,
      appendLog,
      showError,
      clearError,
    ]
  );

  const markDeviceInactive = useCallback(() => {
    void submitDeviceUpdate("inactive");
  }, [submitDeviceUpdate]);

  const forgetCurrentIdentity = useCallback(async () => {
    if (!identity) {
      setInfo("暂无可移除的身份。");
      return;
    }
    setIsForgettingIdentity(true);
    clearError();
    try {
      await forgetIdentity(identity.identityId);
      await clearLastIdentityId();
      setIdentity(null);
      setIdentityPrivateKey(null);
      setDevices([]);
      setEntitlement(null);
      setActiveDeviceId(null);
      setEditDeviceName("");
      setEditDeviceStatus("active");
      setImportIdentityId("");
      setImportPrivateKey("");
      setTaskId(null);
      setTaskCode(null);
      setSenderPublicKey(null);
      setRouteAttempts(null);
      setProgress(null);
      setLogs([]);
      appendLog(`🧹 已忘记身份 ${identity.identityId}`);
      setInfo("身份已从本机移除，下次启动需重新导入。");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message);
      appendLog(`⚠️ 身份移除失败：${message}`);
    } finally {
      setIsForgettingIdentity(false);
    }
  }, [identity, appendLog, clearError, showError]);

  useEffect(() => {
    if (!isTauri) {
      return;
    }
    let active = true;
    const unlistenRefs: Array<() => void> = [];
    const setup = async () => {
      const tauri = getTauri();
      const listen = tauri?.event?.listen;
      if (!listen) {
        showError("Tauri 事件模块不可用，无法监听传输进度。");
        return;
      }
      const progressListener = await listen<TransferProgressPayload>("transfer_progress", (event) => {
        if (!active) {
          return;
        }
        setProgress(event.payload);
        if (Array.isArray(event.payload.routeAttempts)) {
          setRouteAttempts(event.payload.routeAttempts);
        }
        if (event.payload.message) {
          appendLog(event.payload.message);
        }
      });
      const logListener = await listen<TransferLogPayload>("transfer_log", (event) => {
        if (!active) {
          return;
        }
        appendLog(event.payload.message);
      });
      const devicesListener = await listen<IdentityDevicesEventPayload>(
        "identity_devices_updated",
        (event) => {
          if (!active) {
            return;
          }
          if (!identity) {
            return;
          }
          if (event.payload.identityId && event.payload.identityId !== identity.identityId) {
            return;
          }
          const mapped = (event.payload.items ?? []).map<DeviceState>((device) => ({
            deviceId: device.deviceId ?? device.device_id ?? `dev_${generateRandomHex(6)}`,
            identityId: device.identityId ?? device.identity_id ?? identity.identityId,
            publicKey: device.publicKey ?? device.public_key ?? "",
            name: device.name ?? null,
            status: device.status ?? "active",
            lastSeenAt: device.lastSeenAt ?? device.last_seen_at ?? Date.now(),
            capabilities: device.capabilities ?? [],
          }));
          setDevices(mapped);
          setActiveDeviceId((prev) => {
            if (prev && mapped.some((item) => item.deviceId === prev)) {
              return prev;
            }
            return mapped[0]?.deviceId ?? prev;
          });
        }
      );
      const failedListener = await listen<TransferLifecyclePayload>("transfer_failed", (event) => {
        if (!active) {
          return;
        }
        const message = event.payload.message ?? "传输失败。";
        showError(message);
        appendLog(`✖ 传输失败：${event.payload.message ?? "未知错误"}`);
      });
      const completedListener = await listen<TransferLifecyclePayload>("transfer_completed", (event) => {
        if (!active) {
          return;
        }
        setInfo("传输完成，PoT 证明已生成。");
        appendLog(`✔ 传输完成：${event.payload.message ?? "PoT 已就绪"}`);
      });
      const peerListener = await listen<PeerDiscoveredPayload>("peer_discovered", (event) => {
        if (!active) {
          return;
        }
        const existing = trustedPeersRef.current[event.payload.deviceId];
        const knownFingerprint = existing?.fingerprint
          ? normalizeFingerprint(existing.fingerprint)
          : null;
        const incomingFingerprint = event.payload.fingerprint
          ? normalizeFingerprint(event.payload.fingerprint)
          : null;
        if (
          existing &&
          ((knownFingerprint && incomingFingerprint && knownFingerprint === incomingFingerprint) ||
            !knownFingerprint ||
            !incomingFingerprint)
        ) {
          setTrustedPeers((prev) => ({
            ...prev,
            [event.payload.deviceId]: event.payload,
          }));
          appendLog(
            `🤝 自动信任设备 ${event.payload.deviceName ?? event.payload.deviceId}${
              event.payload.verified ? "（签名通过）" : "（来源于已信任列表）"
            }`
          );
          return;
        }
        setPeerPrompt(event.payload);
        setPeerFingerprintInput("");
        appendLog(
          `🔔 发现新设备 ${event.payload.deviceName ?? event.payload.deviceId}${
            event.payload.verified ? "（已签名验证）" : ""
          }`
        );
      });
      unlistenRefs.push(progressListener, logListener, failedListener, completedListener);
      unlistenRefs.push(devicesListener, peerListener);
    };
    setup();
    return () => {
      active = false;
      unlistenRefs.forEach((unlisten) => {
        try {
          unlisten();
        } catch {
          // ignore
        }
      });
    };
  }, [appendLog, identity, isTauri, showError]);

  useEffect(() => {
    if (progress?.phase === "done") {
      void refreshRouteMetrics();
    }
  }, [progress?.phase, refreshRouteMetrics]);

  useEffect(() => {
    if (!isTauri) {
      return;
    }
    refreshSettingsRef.current();
  }, [isTauri]);

  useEffect(() => {
    if (settings) {
      setChunkPolicyDraft(settings.chunkPolicy);
    }
  }, [settings]);

  return (
    <div className="app-surface">
      <div
        className={`${hovered ? "dropzone is-hovered" : "dropzone"} ${absorbing ? "is-absorbing" : ""}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            handleBrowse();
          }
        }}
        aria-label={t("dropzone.label", "拖拽或选择文件上传")}
      >
        <div className="rings">
          <span className="ring ring-outer" />
          <span className="ring ring-middle" />
          <span className="ring ring-inner" />
          <div className="absorb-particles" aria-hidden="true">
            <span className="p p1" />
            <span className="p p2" />
            <span className="p p3" />
            <span className="p p4" />
            <span className="p p5" />
            <span className="p p6" />
            <span className="p p7" />
            <span className="p p8" />
            <span className="p p9" />
            <span className="p p10" />
            <span className="p p11" />
            <span className="p p12" />
          </div>
        </div>
        <div className="cta">
          <div className="cta-header">
            <h1>{t("app.title", "Quantum Drop · 量子快传")}</h1>
            <LocaleSwitch />
          </div>
          <p>{t("hero.tagline", "轻松拖拽，极速直达。")}</p>
          <button className="browse" onClick={handleBrowse} type="button">
            {t("hero.selectFiles", "选择文件")}
          </button>
        </div>
        <input
          ref={fileInputRef}
          className="file-input"
          type="file"
          multiple
          onChange={handleFileInput}
        />
      </div>
      {files.length > 0 && (
        <div className="file-panel" aria-live="polite">
          <h2>{t("filePanel.title", "已准备传输的文件")}</h2>
          <ul>
            {files.map((file) => (
              <li key={`${file.name}-${file.path ?? file.size ?? 0}`}>
                <span className="file-name">{file.name}</span>
                <span className="file-size">
                  {file.size !== undefined ? formatSize(file.size) : file.path ?? ""}
                </span>
              </li>
            ))}
          </ul>
          {isTauri && !(identity && identityPrivateKey && (activeDeviceId || devices[0])) && (
            <div className="actions-row">
              <button
                className="primary"
                type="button"
                onClick={() => beginTransferRef.current?.()}
                disabled={pendingPaths.length === 0 || isSending}
              >
                {isSending
                  ? t("filePanel.starting", "启动中…")
                  : t("filePanel.start", "启动传输")}
              </button>
            </div>
          )}
        </div>
      )}
      <div className="receive-panel" aria-live="polite">
        <h3>{t("receive.heading", "接收（同网模式）")}</h3>
        <div className="mode-tabs">
          <button
            type="button"
            className={receiveMode === "code" ? "active" : ""}
            onClick={() => setReceiveMode("code")}
          >
            {t("receive.tab.code", "配对码")}
          </button>
          <button
            type="button"
            className={receiveMode === "scan" ? "active" : ""}
            onClick={() => {
              setReceiveMode("scan");
              void scanSenders();
            }}
          >
            {t("receive.tab.scan", "扫描")}
          </button>
          <button
            type="button"
            className={receiveMode === "manual" ? "active" : ""}
            onClick={() => setReceiveMode("manual")}
          >
            {t("receive.tab.manual", "手动")}
          </button>
        </div>

        {receiveMode === "code" && (
          <div className="code-input-mode">
            <p>{t("receive.instructions", "输入 6 位配对码，应用会自动发现发送方。")}</p>
            <div className="receive-grid">
              <label>
                <span>{t("receive.tab.code", "配对码")}</span>
                <input
                  type="text"
                  value={receiveCode}
                  onChange={(event) => setReceiveCode(event.target.value.toUpperCase())}
                  maxLength={6}
                  placeholder="例如：QDX9Z3"
                />
              </label>
              <label className="receive-dir">
                <span>保存目录</span>
                <div className="dir-field">
                  <input
                    type="text"
                    value={receiveDir}
                    onChange={(event) => setReceiveDir(event.target.value)}
                    placeholder="请选择或输入文件夹"
                  />
                  <button type="button" onClick={chooseReceiveDirectory} className="secondary">
                    选择
                  </button>
                </div>
              </label>
            </div>
            <div className="actions-row">
              <button
                type="button"
                className="primary"
                onClick={() => void connectByCode()}
                disabled={isReceiving}
              >
                {isReceiving ? "正在连接…" : "开始接收"}
              </button>
            </div>
          </div>
        )}

        {receiveMode === "scan" && (
          <div className="scan-mode">
            <div className="actions-row">
              <button
                type="button"
                className="secondary"
                onClick={() => void scanSenders()}
                disabled={isScanning}
              >
                {isScanning ? "扫描中…" : "重新扫描"}
              </button>
            </div>
            {availableSenders.length === 0 ? (
              <p>未发现可用的发送方，请确保对方已启动并在同一网络。</p>
            ) : (
              <ul className="sender-list">
                {availableSenders.map((sender) => (
                  <li key={`${sender.code}-${sender.host}`}>
                    <div className="sender-info">
                      <strong>{sender.deviceName}</strong>
                      <span className="code">{sender.code}</span>
                      <span className="addr">
                        {sender.host}:{sender.port}
                      </span>
                      <span className="pubkey">
                        {sender.publicKey.length > 16
                          ? `${sender.publicKey.slice(0, 10)}…${sender.publicKey.slice(-6)}`
                          : sender.publicKey}
                      </span>
                      <span className="fp">
                        {sender.certFingerprint.length > 16
                          ? `${sender.certFingerprint.slice(0, 10)}…${sender.certFingerprint.slice(-6)}`
                          : sender.certFingerprint}
                      </span>
                    </div>
                    <button
                      type="button"
                      className="primary"
                      onClick={() => void connectByCode(sender.code)}
                      disabled={isReceiving}
                    >
                      连接
                    </button>
                    <button
                      type="button"
                      className="plain"
                      onClick={() => handleCopy("发送方公钥", sender.publicKey)}
                    >
                      复制公钥
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {receiveMode === "manual" && (
          <div className="receive-grid manual-mode">
            <p>请向发送方索取 IP、端口与公钥，再选择保存目录即可建立加密 QUIC 连接。</p>
            <label>
              <span>配对码</span>
              <input
                type="text"
                value={receiveCode}
                onChange={(event) => setReceiveCode(event.target.value.toUpperCase())}
                maxLength={6}
                placeholder="例如：QDX9Z3"
              />
            </label>
            <label>
              <span>发送方 IP</span>
              <input
                type="text"
                value={receiveHost}
                onChange={(event) => setReceiveHost(event.target.value)}
                placeholder="192.168.1.10"
              />
            </label>
            <label>
              <span>端口</span>
              <input
                type="number"
                value={receivePort}
                onChange={(event) => setReceivePort(event.target.value)}
                min={1}
                max={65535}
              />
            </label>
            <label>
              <span>发送方公钥</span>
              <input
                type="text"
                value={receiveSenderKey}
                onChange={(event) => setReceiveSenderKey(event.target.value.trim())}
                maxLength={64}
                placeholder="64 位十六进制，例如 E4A1…"
              />
            </label>
            <label>
              <span>证书指纹</span>
              <input
                type="text"
                value={receiveSenderFingerprint}
                onChange={(event) => setReceiveSenderFingerprint(event.target.value.trim())}
                maxLength={64}
                placeholder="64 位十六进制，例如 9AF2…"
              />
            </label>
            <label className="receive-dir">
              <span>保存目录</span>
              <div className="dir-field">
                <input
                  type="text"
                  value={receiveDir}
                  onChange={(event) => setReceiveDir(event.target.value)}
                  placeholder="请选择或输入文件夹"
                />
                <button type="button" onClick={chooseReceiveDirectory} className="secondary">
                  选择
                </button>
              </div>
            </label>
            <div className="actions-row">
              <button
                type="button"
                className="primary"
                onClick={() => void handleManualReceive()}
                disabled={isReceiving}
              >
                {isReceiving ? "正在连接…" : "开始接收"}
              </button>
            </div>
          </div>
        )}
      </div>
      <div className="webrtc-panel" aria-live="polite">
        <h3>WebRTC 跨网实验（阶段三）</h3>
        <p className="hint">
          发送端会在缺少配对码时自动生成 6 位随机码，接收端沿用上方“接收”面板中的配对码与保存目录。该功能目前为实验性质，仅验证 P2P 信令链路。
        </p>
        <div className="actions-row">
          <button
            type="button"
            className="secondary"
            onClick={() => void handleWebRtcSenderTest()}
            disabled={pendingPaths.length === 0 || isSending}
          >
            {isSending ? "WebRTC 发送启动中…" : "启动 WebRTC 发送"}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => void handleWebRtcReceiverTest()}
            disabled={isReceiving}
          >
            {isReceiving ? "WebRTC 接收等待中…" : "启动 WebRTC 接收"}
          </button>
        </div>
      </div>
      <div className="identity-panel" aria-live="polite">
        <h3>身份与设备</h3>
        {identity ? (
          <div className="status-grid">
            <div>
              <span className="status-label">身份标识</span>
              <span className="status-value with-actions">
                <code>{identity.identityId}</code>
                <button
                  type="button"
                  className="copy-button"
                  onClick={() => handleCopy("身份标识", identity.identityId)}
                >
                  复制
                </button>
              </span>
            </div>
            <div>
              <span className="status-label">主公钥</span>
              <span className="status-value with-actions">
                <code>{identity.publicKey}</code>
                <button
                  type="button"
                  className="copy-button"
                  onClick={() => handleCopy("主公钥", identity.publicKey)}
                >
                  复制
                </button>
              </span>
            </div>
          </div>
        ) : (
          <p className="identity-empty">尚未注册身份，点击“创建主身份”即可生成量子身份。</p>
        )}
        {identity && activeDeviceId && (
          <div className="active-device-banner">
            当前终端：
            {devices.find((device) => device.deviceId === activeDeviceId)?.name ?? activeDeviceId}
          </div>
        )}
        {!isTauri && (
          <p className="identity-hint">
            当前运行在浏览器预览模式，身份相关操作会提示如何在桌面端执行。
          </p>
        )}
        <div className="actions-row identity-actions">
          <button
            type="button"
            className="secondary"
            onClick={registerIdentity}
            disabled={isRegisteringIdentity}
          >
            {isRegisteringIdentity ? "创建中…" : "创建主身份"}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={registerDevice}
            disabled={!identity || isRegisteringDevice}
          >
            {isRegisteringDevice ? "登记中…" : "登记新设备"}
          </button>
          <button
            type="button"
            className="plain"
            onClick={exportPrivateKey}
            disabled={!identity || !identityPrivateKey}
          >
            导出私钥
          </button>
          <button
            type="button"
            className="plain"
            onClick={forgetCurrentIdentity}
            disabled={!identity || isForgettingIdentity}
          >
            {isForgettingIdentity ? "移除中…" : "忘记当前身份"}
          </button>
          <button
            type="button"
            className="plain"
            onClick={() => {
              if (!detectTauri()) {
                setInfo("刷新同频需在桌面端运行。");
                return;
              }
              refreshDevices();
              refreshEntitlement();
            }}
            disabled={!identity}
          >
            刷新同频
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => upgradeEntitlement(entitlement?.plan === "pro" ? "free" : "pro")}
            disabled={!identity || isUpdatingEntitlement}
          >
            {isUpdatingEntitlement
              ? "更新中…"
              : entitlement?.plan === "pro"
                ? "降级为 Free"
                : "升级 PRO"}
          </button>
        </div>
        <form className="identity-import" onSubmit={importIdentity}>
          <input
            type="text"
            placeholder="身份标识"
            value={importIdentityId}
            onChange={(event) => setImportIdentityId(event.target.value)}
            autoComplete="off"
          />
          <input
            type="text"
            placeholder="私钥十六进制"
            value={importPrivateKey}
            onChange={(event) => setImportPrivateKey(event.target.value)}
            autoComplete="off"
          />
          <button type="submit" className="secondary" disabled={isImportingIdentity}>
            {isImportingIdentity ? "导入中…" : "导入身份"}
          </button>
        </form>
        <div className="entitlement-panel">
          <span className="status-label">当前权益</span>
          <span className="status-value">
            {entitlement ? entitlement.plan : "free"}
            {entitlement?.features?.length ? ` · ${entitlement.features.join(" · ")}` : ""}
          </span>
        </div>
        <div className="device-list" role="list">
          {identity ? (
            devices.length > 0 ? (
              devices.map((device) => (
                <div
                  key={device.deviceId}
                  className="device-item"
                  role="listitem"
                  data-active={device.deviceId === activeDeviceId}
                  onClick={() => setActiveDeviceId(device.deviceId)}
                >
                  <span className="device-name">{device.name ?? device.deviceId}</span>
                  <span className="device-meta">
                    <span className={`status-badge status-${device.status.toLowerCase()}`}>
                      {device.status}
                    </span>
                    <span className="device-meta-text">
                      {`上次心跳 ${formatRelativeTime(device.lastSeenAt)}`}
                    </span>
                    {device.capabilities.length > 0 && (
                      <span className="device-meta-text">能力 {device.capabilities.join("，")}</span>
                    )}
                    {activeDeviceId === device.deviceId && (
                      <span className="device-active-flag">当前终端</span>
                    )}
                  </span>
                </div>
              ))
            ) : (
              <p className="identity-empty">暂无已登记设备。</p>
            )
          ) : (
            <p className="identity-empty">创建身份后可在此查看设备列表。</p>
          )}
        </div>
        {identity && selectedDevice && (
          <div className="device-editor" role="group" aria-label="终端设置">
            <div className="device-editor-grid">
              <label>
                <span>终端名称</span>
                <input
                  type="text"
                  value={editDeviceName}
                  onChange={(event) => setEditDeviceName(event.target.value)}
                  placeholder="例如：工作站、笔电"
                />
              </label>
              <label>
                <span>终端状态</span>
                <select
                  value={editDeviceStatus}
                  onChange={(event) => setEditDeviceStatus(event.target.value)}
                >
                  {deviceStatusOptions.map((option) => (
                    <option key={option} value={option}>
                      {option === "active"
                        ? "active · 在线"
                        : option === "standby"
                          ? "standby · 待命"
                          : "inactive · 停用"}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="device-editor-actions actions-row">
              <button
                type="button"
                className="secondary"
                onClick={() => void submitDeviceUpdate()}
                disabled={isUpdatingDevice}
              >
                {isUpdatingDevice ? "保存中…" : "保存终端信息"}
              </button>
              <button
                type="button"
                className="plain"
                onClick={() => void submitDeviceUpdate("standby")}
                disabled={isUpdatingDevice || editDeviceStatus === "standby"}
              >
                设为待命
              </button>
              <button
                type="button"
                className="plain"
                onClick={markDeviceInactive}
                disabled={isUpdatingDevice || editDeviceStatus === "inactive"}
              >
                标记为停用
              </button>
            </div>
            <p className="device-editor-hint">
              更新操作会生成签名并通过 `auth_update_device` 提交，保持设备名称统一方便在多设备间切换。
            </p>
          </div>
        )}
      </div>
      {(taskId || taskCode || progress || info || error) && (
        <div className="status-panel" aria-live="polite">
          <h3>传输状态</h3>
          <div className="status-grid">
            {taskCode && (
              <div>
                <span className="status-label">取件码</span>
                <span className="status-value">{taskCode}</span>
              </div>
            )}
            {senderPublicKey && (
              <div>
                <span className="status-label">发送方公钥</span>
                <span className="status-value with-actions">
                  <code>{senderPublicKey}</code>
                  <button
                    type="button"
                    className="copy-button"
                    onClick={() => handleCopy("发送方公钥", senderPublicKey)}
                  >
                    复制
                  </button>
                </span>
              </div>
            )}
            {taskId && (
              <div>
                <span className="status-label">任务 ID</span>
                <span className="status-value">{taskId}</span>
              </div>
            )}
            {progress?.phase && (
              <div>
                <span className="status-label">阶段</span>
                <span className="status-value">{progress.phase}</span>
              </div>
            )}
            {progress?.route && (
              <div>
                <span className="status-label">路由</span>
                <span className="status-value">{progress.route}</span>
              </div>
            )}
            {routeAttempts && routeAttempts.length > 0 && (
              <div>
                <span className="status-label">路由策略</span>
                <span className="status-value route-sequence">
                  {routeAttempts.map((route, index) => (
                    <span key={`${route}-${index}`}>
                      {index > 0 && <span className="route-arrow"> → </span>}
                      {route.toUpperCase()}
                    </span>
                  ))}
                  {progress?.route && (
                    <span className="route-current">
                      {" "}
                      · 当前 {progress.route.toUpperCase()}
                    </span>
                  )}
                </span>
              </div>
            )}
            {typeof progress?.progress === "number" && (
              <div>
                <span className="status-label">进度</span>
                <span className="status-value">{Math.round(progress.progress * 100)}%</span>
              </div>
            )}
            {humanSpeed && (
              <div>
                <span className="status-label">速度</span>
                <span className="status-value">{humanSpeed}</span>
              </div>
            )}
          </div>
          <div className="route-metrics-actions">
            <button
              type="button"
              className="secondary"
              onClick={() => void refreshRouteMetrics()}
              disabled={isRouteMetricsLoading}
            >
              {isRouteMetricsLoading ? "正在获取…" : "查看路由统计"}
            </button>
          </div>
          {routeMetrics && routeMetrics.length > 0 && (
            <div className="route-metrics-panel">
              <table>
                <thead>
                  <tr>
                    <th>路由</th>
                    <th>尝试次数</th>
                    <th>成功次数</th>
                    <th>失败次数</th>
                    <th>成功率</th>
                    <th>平均握手 (ms)</th>
                    <th>最后错误</th>
                  </tr>
                </thead>
                <tbody>
                  {routeMetrics.map((metric) => (
                    <tr key={metric.route}>
                      <td>{metric.route.toUpperCase()}</td>
                      <td>{metric.attempts}</td>
                      <td>{metric.successes}</td>
                      <td>{metric.failures}</td>
                      <td>
                        {typeof metric.successRate === "number"
                          ? `${(metric.successRate * 100).toFixed(1)}%`
                          : "—"}
                      </td>
                      <td>{metric.avgLatencyMs ? metric.avgLatencyMs.toFixed(1) : "—"}</td>
                      <td>{metric.lastError ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {identity && (
            <div className="insights-grid">
              <PanelBoundary
                fallbackKey="panel.statsError"
                fallbackDefault="无法加载传输统计，请刷新重试。"
                onRetry={() => {
                  void refreshTransferStats();
                  void refreshLicenseStatus();
                }}
              >
                <section className="stats-panel" aria-label={t("panel.stats", "传输统计")}>
                <div className="panel-header">
                  <h4>{t("panel.stats", "传输统计")}</h4>
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => void refreshTransferStats()}
                    disabled={isStatsLoading}
                  >
                    {isStatsLoading ? t("actions.refreshing", "更新中…") : t("actions.refresh", "刷新")}
                  </button>
                </div>
                <div className="license-summary">
                  <div className="license-header">
                    <div>
                      <span className="stat-label">{t("license.current", "当前权益")}</span>
                      <strong className="stat-value">
                        {licenseStatus ? licenseStatus.tier.toUpperCase() : "—"}
                      </strong>
                    </div>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => void refreshLicenseStatus()}
                      disabled={isLicenseLoading}
                    >
                      {isLicenseLoading
                        ? t("actions.syncingLicense", "同步权益…")
                        : t("actions.syncLicense", "刷新权益")}
                    </button>
                  </div>
                  {licenseStatus ? (
                    <>
                      {typeof licenseStatus.p2pQuota === "number" && (
                        <div className="quota-section">
                          <span className="stat-label">{t("license.quota", "跨网配额")}</span>
                          <div className="quota-bar">
                            <span
                              className="quota-progress"
                              style={{
                                width: `${Math.min(
                                  100,
                                  (licenseStatus.p2pUsed / Math.max(licenseStatus.p2pQuota, 1)) * 100
                                ).toFixed(0)}%`,
                              }}
                            />
                          </div>
                          <span className="quota-text">
                            {t("license.quotaUsage", "已用 {used} / {quota} 次", {
                              used: licenseStatus.p2pUsed,
                              quota: licenseStatus.p2pQuota ?? 0,
                            })}
                          </span>
                        </div>
                      )}
                      <ul className="license-meta">
                        <li>License Key：{maskLicenseKey(licenseStatus.licenseKey)}</li>
                        <li>签发：{formatAbsoluteTime(licenseStatus.issuedAt)}</li>
                        <li>
                          到期：
                          {licenseStatus.expiresAt ? formatAbsoluteTime(licenseStatus.expiresAt) : "无固定期限"}
                        </li>
                      </ul>
                      <div className="license-limits">
                        <span>
                          {licenseStatus.limits.resumeEnabled ? "✅ 支持断点续传" : "⚠️ 无断点续传"}
                        </span>
                        <span>
                          {licenseStatus.limits.maxFileSizeMb
                            ? `单文件 ≤ ${(licenseStatus.limits.maxFileSizeMb / 1024).toFixed(1)} GB`
                            : "文件大小无限制"}
                        </span>
                        <span>
                          {licenseStatus.limits.maxDevices
                            ? `设备上限 ${licenseStatus.limits.maxDevices}`
                            : "设备数量无限制"}
                        </span>
                      </div>
                    </>
                  ) : (
                    <p className="stats-empty">{t("license.empty", "暂无权益信息，请刷新后重试。")}</p>
                  )}
                  <form
                    className="license-activate"
                    onSubmit={(event) => {
                      event.preventDefault();
                      void activateLicense();
                    }}
                  >
                    <input
                      type="text"
                      placeholder={t("license.placeholder", "输入 License Key，例如 QD-PRO-XXXX-YYYY")}
                      value={licenseInput}
                      onChange={(event) => setLicenseInput(event.target.value)}
                      disabled={isActivatingLicense}
                    />
                    <button
                      type="submit"
                      className="primary"
                      disabled={isActivatingLicense || licenseInput.trim().length === 0}
                    >
                      {isActivatingLicense ? "激活中…" : "激活 License"}
                    </button>
                    <button type="button" className="secondary" onClick={copySampleLicense}>
                      复制示例
                    </button>
                  </form>
                </div>
                {transferStats ? (
                  <>
                    <div className="stat-cards">
                      <div className="stat-card">
                        <span className="stat-label">总传输次数</span>
                        <strong className="stat-value">{transferStats.totalTransfers}</strong>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label">传输总量</span>
                        <strong className="stat-value">{formatSize(transferStats.totalBytes)}</strong>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label">成功率</span>
                        <strong className="stat-value">
                          {(transferStats.successRate * 100).toFixed(1)}%
                        </strong>
                        <span className="stat-subtext">
                          成功 {transferStats.successCount} · 失败 {transferStats.failureCount}
                        </span>
                      </div>
                    </div>
                    <div className="route-distribution">
                      <div className="route-bar" aria-hidden="true">
                        <span
                          className="route-segment route-lan"
                          style={{ width: `${transferStats.lanPercent}%` }}
                        />
                        <span
                          className="route-segment route-p2p"
                          style={{ width: `${transferStats.p2pPercent}%` }}
                        />
                        <span
                          className="route-segment route-relay"
                          style={{ width: `${transferStats.relayPercent}%` }}
                        />
                      </div>
                      <ul className="route-legend">
                        <li>
                          <span className="legend-dot route-lan" />
                          LAN {transferStats.lanPercent.toFixed(0)}%
                        </li>
                        <li>
                          <span className="legend-dot route-p2p" />
                          P2P {transferStats.p2pPercent.toFixed(0)}%
                        </li>
                        <li>
                          <span className="legend-dot route-relay" />
                          Relay {transferStats.relayPercent.toFixed(0)}%
                        </li>
                      </ul>
                    </div>
                  </>
                ) : (
                  <p className="stats-empty">{t("stats.emptyTransfers", "暂无传输记录。")}</p>
                )}
                </section>
              </PanelBoundary>
              <PanelBoundary
                fallbackKey="panel.auditError"
                fallbackDefault="无法加载审计日志，请刷新重试。"
                onRetry={() => void refreshAuditLogs()}
              >
                <section className="audit-panel" aria-label={t("panel.audit", "操作审计")}>
                <div className="panel-header">
                  <h4>{t("panel.audit", "操作审计")}</h4>
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => void refreshAuditLogs()}
                    disabled={isAuditLoading}
                  >
                    {isAuditLoading
                      ? t("actions.syncingAudit", "同步中…")
                      : t("actions.syncAudit", "刷新")}
                  </button>
                </div>
                {auditLogs.length > 0 ? (
                  <ul className="audit-list">
                    {auditLogs.slice(0, 8).map((entry) => {
                      const detailRaw = summarizeAuditDetails(entry.details ?? {});
                      const detailText =
                        detailRaw.length > 160 ? `${detailRaw.slice(0, 157)}…` : detailRaw;
                      return (
                        <li key={entry.id}>
                          <div className="audit-header">
                            <span className="audit-event">{entry.eventType}</span>
                            <span className="audit-time">{formatRelativeTime(entry.timestamp)}</span>
                          </div>
                          <div className="audit-meta">
                            <span>{formatAbsoluteTime(entry.timestamp)}</span>
                            {entry.deviceId && <span>终端 {entry.deviceId}</span>}
                            {entry.taskId && <span>任务 {entry.taskId}</span>}
                          </div>
                          {detailText && <p className="audit-details">{detailText}</p>}
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <p className="stats-empty">{t("audit.empty", "暂无审计记录。")}</p>
                )}
                </section>
              </PanelBoundary>
              <PanelBoundary
                fallbackKey="panel.securityError"
                fallbackDefault="无法加载安全策略，请刷新重试。"
                onRetry={() => void refreshSecurityConfig()}
              >
                <section className="security-panel" aria-label={t("panel.security", "安全策略")}>
                  <div className="panel-header">
                    <h4>{t("panel.security", "安全策略")}</h4>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => void refreshSecurityConfig()}
                      disabled={isSecurityLoading}
                    >
                      {isSecurityLoading ? t("actions.refreshing", "更新中…") : t("actions.refresh", "刷新")}
                    </button>
                  </div>
                  {securityConfig ? (
                    <ul className="security-list">
                      <li data-enabled={securityConfig.enforceSignatureVerification}>
                        <strong>{t("settings.security.signature", "签名校验")}</strong>
                        <span>
                          {securityConfig.enforceSignatureVerification
                            ? t("settings.security.enabledRecommended", "已启用（推荐）")
                            : t("settings.security.disabled", "未启用")}
                        </span>
                      </li>
                      <li data-enabled={securityConfig.disconnectOnVerificationFail}>
                        <strong>{t("settings.security.disconnect", "验签失败断开")}</strong>
                        <span>
                          {securityConfig.disconnectOnVerificationFail
                            ? t("settings.security.disconnect.strict", "失败即断开")
                            : t("settings.security.disconnect.warn", "失败仅警告")}
                        </span>
                      </li>
                      <li data-enabled={securityConfig.enableAuditLog}>
                        <strong>{t("settings.security.audit", "审计日志")}</strong>
                        <span>
                          {securityConfig.enableAuditLog
                            ? t("settings.security.audit.enabled", "记录到本地 SQLite")
                            : t("settings.security.audit.disabled", "未记录")}
                        </span>
                      </li>
                    </ul>
                  ) : (
                    <p className="stats-empty">{t("settings.security.empty", "无法读取安全策略，请刷新或检查配置。")}</p>
                  )}
                </section>
              </PanelBoundary>
              <PanelBoundary
                fallbackKey="panel.settingsError"
                fallbackDefault="无法加载传输设置，请刷新重试。"
                onRetry={() => void refreshSettings()}
              >
                <section className="settings-panel" aria-label={t("panel.settings", "传输设置")}>
                  <div className="panel-header">
                    <h4>{t("panel.settings", "传输设置")}</h4>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => void refreshSettings()}
                      disabled={isSettingsLoading}
                    >
                      {isSettingsLoading ? t("actions.refreshing", "更新中…") : t("actions.refresh", "刷新")}
                    </button>
                  </div>
                  {chunkPolicyDraft ? (
                    <form
                      className="settings-form"
                      onSubmit={(event) => {
                        event.preventDefault();
                        void saveChunkPolicy();
                      }}
                    >
                      <div className="form-grid">
                        <label className="field-group">
                          <span className="field-label">{t("settings.chunk.adaptive", "自适应 Chunk")}</span>
                          <span className="field-hint">{t("settings.chunk.help", "根据网络情况自动调整 Chunk")}</span>
                          <label className="toggle">
                            <input
                              type="checkbox"
                              checked={chunkPolicyDraft.adaptive}
                              onChange={handleChunkAdaptiveChange}
                              disabled={chunkSettingsDisabled}
                            />
                            <span>{chunkPolicyDraft.adaptive ? "已开启" : "已关闭"}</span>
                          </label>
                        </label>
                        <label className="field-group">
                          <span className="field-label">{t("settings.chunk.min", "最小 Chunk (MiB)")}</span>
                          <input
                            type="number"
                            min={2}
                            max={16}
                            value={chunkMinMb}
                            onChange={handleChunkMinChange}
                            disabled={chunkSettingsDisabled}
                          />
                        </label>
                        <label className="field-group">
                          <span className="field-label">{t("settings.chunk.max", "最大 Chunk (MiB)")}</span>
                          <input
                            type="number"
                            min={chunkMinMb}
                            max={16}
                            value={chunkMaxMb}
                            onChange={handleChunkMaxChange}
                            disabled={chunkSettingsDisabled}
                          />
                        </label>
                        <label className="field-group">
                          <span className="field-label">{t("settings.chunk.streams", "LAN 并发流数")}</span>
                          <select
                            value={lanStreamsDraft}
                            onChange={handleLanStreamsChange}
                            disabled={chunkSettingsDisabled}
                          >
                            {[1, 2, 3, 4].map((count) => (
                              <option key={count} value={count}>
                                {count}
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                      <div className="actions-row">
                        <button type="submit" className="primary" disabled={chunkSettingsDisabled || isSavingSettings}>
                          {isSavingSettings ? t("settings.chunk.saving", "保存中…") : t("settings.chunk.save", "保存设置")}
                        </button>
                      </div>
                    </form>
                  ) : (
                    <p className="stats-empty">{t("settings.chunk.empty", "暂无设置，请刷新或稍后重试。")}</p>
                  )}
                </section>
              </PanelBoundary>
            </div>
          )}
          <PanelBoundary
            fallbackKey="panel.trustedError"
            fallbackDefault="无法读取信任列表，请刷新。"
            onRetry={() => void refreshDevices()}
          >
            {Object.keys(trustedPeers).length > 0 && (
              <div className="trusted-peers-panel">
                <div className="panel-header">
                  <h4>{t("panel.trusted", "已信任设备")}</h4>
                  <button type="button" className="secondary" onClick={clearTrustedPeers}>
                    {t("trusted.clear", "清空")}
                  </button>
                </div>
                <ul>
                  {Object.values(trustedPeers).map((peer) => (
                    <li key={`${peer.sessionId}-${peer.deviceId}`}>
                      <strong>{peer.deviceName ?? peer.deviceId}</strong>
                      <span className="peer-fingerprint">
                        {peer.fingerprint ?? t("trusted.unknownFingerprint", "未知指纹")}
                      </span>
                      <span className="peer-status">
                        {peer.verified
                          ? t("trusted.status.verified", "签名通过")
                          : t("trusted.status.manual", "手动信任")}
                      </span>
                      <button
                        type="button"
                        className="plain"
                        onClick={() => removeTrustedPeer(peer.deviceId)}
                      >
                        {t("trusted.remove", "移除")}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </PanelBoundary>
          {info && <div className="toast toast-success">{info}</div>}
          {error && (
            <div className="toast toast-error">
              <div>{error}</div>
              {errorActionKeys.length > 0 && (
                <div className="toast-actions">
                  {errorActionKeys.map((key) => {
                    const handler = errorActionHandlers[key];
                    const label = ERROR_ACTION_LABELS[key];
                    if (!handler || !label) {
                      return null;
                    }
                    return (
                      <button
                        key={`${key}-action`}
                        type="button"
                        onClick={() => {
                          void handler();
                        }}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}
      {peerPrompt && (
        <div className="peer-trust-dialog">
          <h3>发现新设备</h3>
          <p>
            设备: <strong>{peerPrompt.deviceName ?? peerPrompt.deviceId}</strong>
          </p>
          <p>
            指纹: <code>{peerPrompt.fingerprint ?? "未知"}</code>
          </p>
          {peerPrompt.verified ? (
            <p className="peer-status verified">已通过签名验证</p>
          ) : (
            <p className="peer-status warning">未通过签名验证，请与对方核对指纹</p>
          )}
          {!peerPrompt.verified && (
            <label>
              <span>输入对方提供的指纹</span>
              <input
                value={peerFingerprintInput}
                onChange={(event) => setPeerFingerprintInput(event.target.value)}
                placeholder="例如：1A:2B:3C:4D"
              />
            </label>
          )}
          <div className="actions-row">
            <button
              type="button"
              className="primary"
              onClick={() => {
                const reference = peerPrompt.fingerprint
                  ? normalizeFingerprint(peerPrompt.fingerprint)
                  : null;
                const provided = normalizeFingerprint(peerFingerprintInput);
                if (
                  peerPrompt.verified ||
                  (reference && provided.length > 0 && provided === reference)
                ) {
                  setTrustedPeers((prev) => ({
                    ...prev,
                    [peerPrompt.deviceId]: peerPrompt,
                  }));
                  appendLog(
                    `🤝 已信任设备 ${peerPrompt.deviceName ?? peerPrompt.deviceId}${
                      peerPrompt.verified ? "（签名通过）" : ""
                    }`
                  );
                  setPeerPrompt(null);
                  setPeerFingerprintInput("");
                } else {
                  showError("指纹不匹配，无法信任该设备。");
                }
              }}
            >
              信任此设备
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                appendLog(
                  `⛔ 拒绝设备 ${peerPrompt.deviceName ?? peerPrompt.deviceId} 的连接请求`
                );
                setPeerPrompt(null);
                setPeerFingerprintInput("");
              }}
            >
              拒绝
            </button>
          </div>
        </div>
      )}
      {logs.length > 0 && (
        <div className="log-panel" aria-live="polite">
          <h3>事件流</h3>
          <ul>
            {logs.map((entry, index) => (
              <li key={`${entry}-${index}`}>{entry}</li>
            ))}
          </ul>
        </div>
      )}
      {upgradeReason && (
        <UpgradePrompt
          reason={upgradeReason}
          config={UPGRADE_CONFIG[upgradeReason]}
          pricingUrl={UPGRADE_URL}
          onUpgrade={handleUpgradeCTA}
          onClose={handleUpgradeDismiss}
        />
      )}
    </div>
  );
}
const ensureEd25519Hash = () => {
  const hashConcat = (...messages: Uint8Array[]) => {
    let total: Uint8Array;
    try {
      // prefer noble's internal concat if available
      // @ts-expect-error runtime check
      total = (ed25519Etc as any).concatBytes
        ? (ed25519Etc as any).concatBytes(...messages)
        : (() => {
            const len = messages.reduce((acc, m) => acc + m.length, 0);
            const out = new Uint8Array(len);
            let off = 0;
            for (const m of messages) {
              out.set(m, off);
              off += m.length;
            }
            return out;
          })();
    } catch {
      const len = messages.reduce((acc, m) => acc + m.length, 0);
      const out = new Uint8Array(len);
      let off = 0;
      for (const m of messages) {
        out.set(m, off);
        off += m.length;
      }
      total = out;
    }
    return sha512(total);
  };
  if (!ed25519Etc.sha512Sync) {
    ed25519Etc.sha512Sync = (...messages: Uint8Array[]) => hashConcat(...messages);
  }
  if (!ed25519Etc.sha512Async) {
    ed25519Etc.sha512Async = async (...messages: Uint8Array[]) => hashConcat(...messages);
  }
};
ensureEd25519Hash();
