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
import { PanelBoundary } from "./components/ErrorBoundary/PanelBoundary";
import { MainLayout } from "./components/Layout/MainLayout";
import type { Page } from "./components/Layout/types";
import { SendPage } from "./components/Pages/SendPage";
import { IdentityPage } from "./components/Pages/IdentityPage";
import { TransferStatusPage } from "./components/Pages/TransferStatusPage";
import { WebRTCPage } from "./components/Pages/WebRTCPage";
import { LogsPage } from "./components/Pages/LogsPage";
import {
  FRIENDLY_ERROR_MESSAGES,
  LICENSE_REASON_MAP,
  UPGRADE_CONFIG,
  UPGRADE_MESSAGES,
  UPGRADE_URL,
  type UpgradeReason,
} from "./lib/upgrade";
import { useI18n } from "./lib/i18n";
import {
  formatAbsoluteTime,
  formatBytes,
  formatRelativeTime,
  formatSize,
  maskLicenseKey,
  summarizeAuditDetails,
} from "./lib/format";
import { QuantumBackground } from "./components/QuantumBackground";
import { ReceiptView } from "./components/ReceiptView";
import { TransitionReceipt, VerifyPotResponse } from "./lib/types";

type SelectedFile = {
  name: string;
  size?: number;
  path?: string;
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

type P2pConnectionFailedPayload = {
  sessionId: string;
  reason: string;
  suggestion: string;
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
  routeDistribution?: Array<{
    route: string;
    ratio: number;
  }>;
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

type LicenseLimitsRaw = Partial<{
  p2pMonthlyQuota: unknown;
  p2p_monthly_quota: unknown;
  maxFileSizeMb: unknown;
  max_file_size_mb: unknown;
  maxDevices: unknown;
  max_devices: unknown;
  resumeEnabled: unknown;
  resume_enabled: unknown;
  historyDays: unknown;
  history_days: unknown;
}>;

type LicenseStatusRaw = Partial<{
  identityId: unknown;
  identity_id: unknown;
  tier: unknown;
  licenseKey: unknown;
  license_key: unknown;
  issuedAt: unknown;
  issued_at: unknown;
  expiresAt: unknown;
  expires_at: unknown;
  limits: unknown;
  p2pUsed: unknown;
  p2p_used: unknown;
  p2pQuota: unknown;
  p2p_quota: unknown;
}>;

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

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

const readString = (value: unknown): string | null => (typeof value === "string" && value.length > 0 ? value : null);

const readNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  return null;
};

const normalizeLicenseStatus = (raw: unknown, fallbackId: string): LicenseStatusDto => {
  const source: LicenseStatusRaw = isRecord(raw) ? (raw as LicenseStatusRaw) : {};
  const limitsSource: LicenseLimitsRaw = isRecord(source.limits) ? (source.limits as LicenseLimitsRaw) : {};
  const limits: LicenseLimitsDto = {
    p2pMonthlyQuota:
      readNumber(limitsSource.p2pMonthlyQuota) ?? readNumber(limitsSource.p2p_monthly_quota) ?? null,
    maxFileSizeMb: readNumber(limitsSource.maxFileSizeMb) ?? readNumber(limitsSource.max_file_size_mb) ?? null,
    maxDevices: readNumber(limitsSource.maxDevices) ?? readNumber(limitsSource.max_devices) ?? null,
    resumeEnabled: (() => {
      const rawValue = limitsSource.resumeEnabled ?? limitsSource.resume_enabled ?? false;
      return typeof rawValue === "boolean" ? rawValue : Boolean(rawValue);
    })(),
    historyDays: readNumber(limitsSource.historyDays) ?? readNumber(limitsSource.history_days) ?? null,
  };
  return {
    identityId: readString(source.identityId) ?? readString(source.identity_id) ?? fallbackId,
    tier: readString(source.tier) ?? "free",
    licenseKey: readString(source.licenseKey) ?? readString(source.license_key) ?? null,
    issuedAt: readNumber(source.issuedAt) ?? readNumber(source.issued_at) ?? Date.now(),
    expiresAt: readNumber(source.expiresAt) ?? readNumber(source.expires_at) ?? null,
    limits,
    p2pUsed: readNumber(source.p2pUsed) ?? readNumber(source.p2p_used) ?? 0,
    p2pQuota: readNumber(source.p2pQuota) ?? readNumber(source.p2p_quota) ?? limits.p2pMonthlyQuota ?? null,
  };
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

export default function App(): JSX.Element {
  const { t, locale } = useI18n();
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
  type LogEntry = { id: string; message: string; count: number; timestamp: number };
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [receipt, setReceipt] = useState<TransitionReceipt | null>(null);

  const resetLogs = useCallback(() => {
    setLogs([]);
  }, []);
  const [currentPage, setCurrentPage] = useState<Page>("send");
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
  const [isRegisteringIdentity, setIsRegisteringIdentity] = useState(false);
  const [isRegisteringDevice, setIsRegisteringDevice] = useState(false);
  const [isUpdatingEntitlement, setIsUpdatingEntitlement] = useState(false);
  const [isImportingIdentity, setIsImportingIdentity] = useState(false);
  const [importIdentityId, setImportIdentityId] = useState("");
  const [importPrivateKey, setImportPrivateKey] = useState("");
  const [error, setErrorState] = useState<string | null>(null);
  const [errorActionKeys, setErrorActionKeys] = useState<ErrorActionKey[]>([]);
  const [info, setInfo] = useState<string | null>(null);
  const lastErrorRef = useRef<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [absorbing, setAbsorbing] = useState(false);
  const beginTransferRef = useRef<(pathsOverride?: string[]) => Promise<void> | void>();
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

  const showError = useCallback(
    (message: string, actions: ErrorActionKey[] = DEFAULT_ERROR_ACTIONS) => {
      if (lastErrorRef.current === message) {
        return;
      }
      lastErrorRef.current = message;
      setErrorState(message);
      setErrorActionKeys(actions);
    },
    []
  );

  const clearError = useCallback(() => {
    lastErrorRef.current = null;
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
      const normalized = entry.trim().length > 0 ? entry.trim() : entry;
      const last = prev[prev.length - 1];
      if (last && last.message === normalized) {
        const next = [...prev];
        next[next.length - 1] = {
          ...last,
          count: last.count + 1,
          timestamp: Date.now(),
        };
        return next;
      }
      const nextEntry: LogEntry = {
        id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        message: normalized,
        count: 1,
        timestamp: Date.now(),
      };
      return [...prev.slice(-49), nextEntry];
    });
  }, []);

  const copyRecentLogs = useCallback(async () => {
    const snapshot = logs
      .slice(-20)
      .map((entry) => (entry.count > 1 ? `${entry.message} (x${entry.count})` : entry.message))
      .join("\n");
    const text = snapshot.length > 0 ? snapshot : "暂无日志";
    await copyPlainText(text);
    setInfo(t("info.logsCopied", "Recent logs copied."));
    appendLog("📋 已复制最近日志。");
  }, [logs, appendLog, t]);

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
      setInfo(t("info.noTrustedDevices", "No trusted devices yet."));
      return;
    }
    setTrustedPeers({});
    appendLog("🧼 已清空所有信任设备。");
  }, [setInfo, appendLog, t]);

  const copySampleLicense = useCallback(() => {
    void copyPlainText("QD-PRO-XXXX-YYYY-ZZZZ");
    setInfo(t("info.sampleLicenseCopied", "Sample License Key copied."));
    appendLog("📋 已复制示例 License Key。");
  }, [appendLog, t]);

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

  const refreshRouteMetrics = useCallback(async (notify = false) => {
    if (!detectTauri()) {
      setInfo(t("info.routeTauriOnly", "Route metrics are only available in the desktop app."));
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch {
      setInfo(t("info.routeInvokeMissing", "Tauri invoke API unavailable, cannot load route metrics."));
      return;
    }
    setIsRouteMetricsLoading(true);
    try {
      const metrics = (await invoke("courier_route_metrics", {})) as RouteMetricsDto[];
      setRouteMetrics(metrics);
      if (!metrics || metrics.length === 0) {
        setInfo(t("info.routeEmpty", "No route metrics yet."));
      }
    } catch (err) {
      if (notify) {
        handleCommandError(err, "路由统计加载失败");
      } else {
        console.warn("refreshRouteMetrics failed", err);
      }
    } finally {
      setIsRouteMetricsLoading(false);
    }
  }, [handleCommandError, setInfo, t]);

  const refreshTransferStats = useCallback(async (notify = false) => {
    if (!identity) {
      setTransferStats(null);
      return;
    }
    if (!isTauri) {
      setInfo(t("info.statsTauriOnly", "Transfer statistics are only available in the desktop app."));
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshTransferStats: invoke unavailable", err);
      setInfo(t("info.statsInvokeMissing", "Tauri invoke API unavailable, cannot load transfer statistics."));
      return;
    }
    setIsStatsLoading(true);
    try {
      const stats = (await invoke("transfer_stats", {
        payload: { identityId: identity.identityId },
      })) as TransferStatsDto;
      setTransferStats(stats);
    } catch (err) {
      if (notify) {
        handleCommandError(err, "传输统计加载失败");
      } else {
        console.warn("refreshTransferStats failed", err);
      }
    } finally {
      setIsStatsLoading(false);
    }
  }, [identity, isTauri, handleCommandError, setInfo, t]);

  const refreshAuditLogs = useCallback(async (notify = false) => {
    if (!identity) {
      setAuditLogs([]);
      return;
    }
    if (!isTauri) {
      setInfo(t("info.auditTauriOnly", "Audit logs are only available in the desktop app."));
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshAuditLogs: invoke unavailable", err);
      setInfo(t("info.auditInvokeMissing", "Tauri invoke API unavailable, cannot load audit logs."));
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
      if (notify) {
        handleCommandError(err, "审计日志加载失败");
      } else {
        console.warn("refreshAuditLogs failed", err);
      }
    } finally {
      setIsAuditLoading(false);
    }
  }, [identity, isTauri, handleCommandError, setInfo, t]);

  const refreshLicenseStatus = useCallback(async (notify = false) => {
    if (!identity) {
      setLicenseStatus(null);
      return;
    }
    if (!isTauri) {
      setInfo(t("info.licenseTauriOnly", "License info is only available in the desktop app."));
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshLicenseStatus: invoke unavailable", err);
      setInfo(t("info.licenseInvokeMissing", "Tauri invoke API unavailable, cannot load license info."));
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
      if (notify) {
        showError(message, ["refreshLicense", "copyLogs"]);
      } else {
        console.warn("refreshLicenseStatus failed", err);
      }
    } finally {
      setIsLicenseLoading(false);
    }
  }, [identity, isTauri, setInfo, showError, t]);

  const refreshSecurityConfig = useCallback(async (notify = false) => {
    if (!isTauri) {
      setInfo(t("info.securityTauriOnly", "Security policies are only available in the desktop app."));
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (error) {
      console.warn("refreshSecurityConfig: invoke unavailable", error);
      if (notify) {
        showError(t("info.securityInvokeMissing", "Tauri invoke API unavailable, cannot load security policies."), ["refreshSecurity", "copyLogs"]);
      }
      return;
    }
    setIsSecurityLoading(true);
    try {
      const config = (await invoke("security_get_config", {})) as SecurityConfigDto;
      setSecurityConfig(config);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (notify) {
        showError(message, ["refreshSecurity", "copyLogs"]);
      } else {
        console.warn("refreshSecurityConfig failed", err);
      }
    } finally {
      setIsSecurityLoading(false);
    }
  }, [isTauri, showError, setInfo, t]);

  const refreshSettings = useCallback(async (notify = false) => {
    if (!isTauri) {
      setInfo(t("info.settingsTauriOnly", "Transfer settings are only available in the desktop app."));
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("refreshSettings: invoke unavailable", err);
      setInfo(t("info.settingsInvokeMissing", "Tauri invoke API unavailable, cannot load transfer settings."));
      return;
    }
    setIsSettingsLoading(true);
    try {
      const payload = (await invoke("load_settings", {})) as SettingsPayload;
      setSettings(payload);
      setChunkPolicyDraft(payload.chunkPolicy);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (notify) {
        showError(message, ["refreshStats", "copyLogs"]);
      } else {
        console.warn("refreshSettings failed", err);
      }
    } finally {
      setIsSettingsLoading(false);
    }
  }, [isTauri, setInfo, showError, t]);

  const saveChunkPolicy = useCallback(async () => {
    if (!settings || !chunkPolicyDraft) {
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (error) {
      console.warn("saveChunkPolicy: invoke unavailable", error);
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
      setInfo(t("info.settingsSaved", "Transfer settings saved."));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message, ["refreshStats", "copyLogs"]);
      appendLog(`⚠️ 保存传输设置失败：${message}`);
    } finally {
      setIsSavingSettings(false);
    }
  }, [chunkPolicyDraft, settings, showError, appendLog, setInfo, t]);

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

  const refreshSettingsRef = useRef<() => void>(() => { });
  useEffect(() => {
    refreshSettingsRef.current = () => {
      void refreshSettings();
    };
  }, [refreshSettings]);

  const errorActionHandlers = useMemo<Record<ErrorActionKey, () => void>>(
    () => ({
      copyLogs: () => {
        void copyRecentLogs();
      },
      openDocs,
      refreshStats: () => {
        void refreshTransferStats(true);
      },
      refreshAudit: () => {
        void refreshAuditLogs(true);
      },
      refreshRoutes: () => {
        void refreshRouteMetrics(true);
      },
      refreshSecurity: () => {
        void refreshSecurityConfig(true);
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
      setInfo(t("info.activateTauriOnly", "License activation is only available in the desktop app."));
      return;
    }
    if (!identity) {
      setInfo(t("info.activateNeedIdentity", "Register or import an identity before activating a license."));
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
    } catch (error) {
      console.warn("activateLicense: invoke unavailable", error);
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
      setInfo(t("info.licenseActivated", "License activated."));
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
    t,
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
      const signatureBytes = await Promise.resolve(signEd25519(message, identityPrivateKey));
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
      }
    },
    [identity, showError]
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
      }
    },
    [identity, showError]
  );

  const registerIdentity = useCallback(async () => {
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("registerIdentity: invoke unavailable", err);
      setInfo(t("info.identityTauriOnly", "Identity registration is only available in the desktop app."));
      return;
    }
    setIsRegisteringIdentity(true);
    clearError();
    try {
      ensureEd25519Hash();
      const privateKeyBytes = ed25519Utils.randomPrivateKey();
      const publicKeyBytes = getPublicKey(privateKeyBytes);
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
      setInfo(
        t("info.identityRegistered", "Identity {id} registered.", {
          id: resolvedId,
        }),
      );
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
  }, [appendLog, refreshEntitlement, clearError, showError, t]);

  const registerDevice = useCallback(async () => {
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("registerDevice: invoke unavailable", err);
      setInfo(t("info.deviceRegisterTauriOnly", "Device registration is only available in the desktop app."));
      return;
    }
    if (!identity) {
      setInfo(t("info.needIdentity", "Please register an identity first."));
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
      const devicePublicBytes = getPublicKey(devicePrivateBytes);
      const devicePublicKeyHex = bytesToHex(devicePublicBytes);
      const messageBytes = new TextEncoder().encode(`register:${deviceId}:${devicePublicKeyHex}`);
      const signatureBytes = signEd25519(messageBytes, identityPrivateKey);
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
  }, [
    appendLog,
    devices.length,
    identity,
    identityPrivateKey,
    refreshDevices,
    sendHeartbeat,
    checkDeviceLimit,
    clearError,
    handleCommandError,
    showError,
    t,
  ]);

  const upgradeEntitlement = useCallback(
    async (plan: string) => {
      let invoke: TauriInvokeFn;
      try {
        invoke = resolveTauriInvoke();
      } catch (err) {
        console.warn("upgradeEntitlement: invoke unavailable", err);
        setInfo(t("info.entitlementTauriOnly", "Plan upgrades are only available in the desktop app."));
        return;
      }
      if (!identity) {
        setInfo(t("info.needIdentity", "Please register an identity first."));
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
    [appendLog, identity, clearError, showError, t]
  );

  const exportPrivateKey = useCallback(async () => {
    if (!(identity && identityPrivateKey)) {
      setInfo(t("info.noPrivateKey", "No private key available to export."));
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
        setInfo(t("info.privateKeyCopied", "Private key copied to clipboard. Keep it safe."));
      } else {
        setInfo(hex);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message);
    }
  }, [identity, identityPrivateKey, showError, t]);

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
        const publicKeyBytes = getPublicKey(privateBytes);
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
        setInfo(
          t("info.identityImported", "Identity {id} imported successfully.", {
            id: resolvedId,
          }),
        );
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
    [appendLog, importIdentityId, importPrivateKey, refreshDevices, refreshEntitlement, clearError, showError, t]
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
        await refreshEntitlement(stored.identityId);
      } catch (err) {
        console.warn("unable to initialise identity", err);
      }
    };
    void initialise();
    return () => {
      cancelled = true;
    };
  }, [refreshEntitlement]);

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
    void refreshDevices(identity.identityId);
    void refreshEntitlement(identity.identityId);
  }, [identity, refreshDevices, refreshEntitlement, isTauri]);

  useEffect(() => {
    if (!identity || !isTauri) {
      setTransferStats(null);
      setAuditLogs([]);
      return;
    }
    void refreshTransferStats();
    void refreshAuditLogs();
    void refreshLicenseStatus();
    void refreshSecurityConfig();
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
    void sendHeartbeat("active");
    const timer = window.setInterval(() => {
      void sendHeartbeat();
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
      resetLogs();
      setPeerPrompt(null);
      setTrustedPeers({});
      setPeerFingerprintInput("");
      setAbsorbing(true);
      window.setTimeout(() => setAbsorbing(false), 900);
      const canAuto = Boolean(identity && identityPrivateKey && (activeDeviceId || devices[0]));
      if (canAuto && !isSending) {
        window.setTimeout(() => {
          void beginTransferRef.current?.(paths);
        }, 220);
      }
    };

    void (async () => {
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
  }, [isTauri, identity, identityPrivateKey, activeDeviceId, devices, isSending, resetLogs]);

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
      resetLogs();
      // 吸入动效（拖拽场景不自动发送）
      setAbsorbing(true);
      window.setTimeout(() => setAbsorbing(false), 900);
    },
    [captureFiles, resetLogs]
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
          resetLogs();
          // 动效与自动传输
          setAbsorbing(true);
          window.setTimeout(() => setAbsorbing(false), 900);
          const canAuto = Boolean(identity && identityPrivateKey && (activeDeviceId || devices[0]));
          if (canAuto && !isSending) {
            window.setTimeout(() => {
              void beginTransferRef.current?.(normalized as unknown as string[]);
            }, 220);
          }
        } else {
          // Tauri dialog 插件不可用时，回退到浏览器文件选择器
          fileInputRef.current?.click();
          setInfo(t("info.dialogMissing", "Tauri dialog plugin missing. Used system file selector."));
        }
      } catch {
        fileInputRef.current?.click();
        setInfo(t("info.dialogFallback", "File picker fell back to browser mode."));
      }
    } else {
      fileInputRef.current?.click();
      setInfo(t("info.browserPreview", "Browser preview only shows the UI. Please use the desktop app for transfers."));
    }
  }, [activeDeviceId, clearError, devices, identity, identityPrivateKey, isSending, resetLogs, t]);

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
    resetLogs();
    // 仅播放吸入动效（input 回退场景无法拿到绝对路径，不自动发送）
    setAbsorbing(true);
    window.setTimeout(() => setAbsorbing(false), 900);
  };

  const showInlineStartButton = isTauri && !(identity && identityPrivateKey && (activeDeviceId || devices[0]));
  const canStartTransfer = pendingPaths.length > 0;
  const hasActiveTransfer = Boolean(taskId || taskCode || progress);

  const monitorExtra = (
    <>
      <div className="route-metrics-actions">
        <button type="button" className="secondary" onClick={() => void refreshRouteMetrics(true)} disabled={isRouteMetricsLoading}>
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
                  <td>{typeof metric.successRate === "number" ? `${(metric.successRate * 100).toFixed(1)}%` : "—"}</td>
                  <td>{metric.avgLatencyMs ? metric.avgLatencyMs.toFixed(1) : "—"}</td>
                  <td>{metric.lastError ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );

  const statsContent = identity ? (
    <PanelBoundary
      fallbackKey="panel.statsError"
      fallbackDefault="无法加载传输统计，请刷新重试。"
      onRetry={() => {
        void refreshTransferStats(true);
        void refreshLicenseStatus(true);
      }}
    >
      <section className="stats-panel" aria-label={t("panel.stats", "传输统计")}>
        <div className="panel-header">
          <h4>{t("panel.stats", "传输统计")}</h4>
          <button type="button" className="secondary" onClick={() => void refreshTransferStats(true)} disabled={isStatsLoading}>
            {isStatsLoading ? t("actions.refreshing", "更新中…") : t("actions.refresh", "刷新")}
          </button>
        </div>
        <div className="license-summary">
          <div className="license-header">
            <div>
              <span className="stat-label">{t("license.current", "当前权益")}</span>
              <strong className="stat-value">{licenseStatus ? licenseStatus.tier.toUpperCase() : "—"}</strong>
            </div>
            <button type="button" className="secondary" onClick={() => void refreshLicenseStatus(true)} disabled={isLicenseLoading}>
              {isLicenseLoading ? t("actions.syncingLicense", "同步权益…") : t("actions.syncLicense", "刷新权益")}
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
                        width: `${Math.min(100, (licenseStatus.p2pUsed / Math.max(licenseStatus.p2pQuota, 1)) * 100).toFixed(0)}%`,
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
              <ul className="license.meta">
                <li>License Key：{maskLicenseKey(licenseStatus.licenseKey)}</li>
                <li>签发：{formatAbsoluteTime(licenseStatus.issuedAt)}</li>
                <li>到期：{licenseStatus.expiresAt ? formatAbsoluteTime(licenseStatus.expiresAt) : "无固定期限"}</li>
              </ul>
              <div className="license-limits">
                <span>{licenseStatus.limits.resumeEnabled ? "✅ 支持断点续传" : "⚠️ 无断点续传"}</span>
                <span>
                  {licenseStatus.limits.maxFileSizeMb ? `单文件 ≤ ${(licenseStatus.limits.maxFileSizeMb / 1024).toFixed(1)} GB` : "文件大小无限制"}
                </span>
                <span>{licenseStatus.limits.maxDevices ? `设备上限 ${licenseStatus.limits.maxDevices}` : "设备数量无限制"}</span>
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
            <button type="submit" className="primary" disabled={isActivatingLicense || licenseInput.trim().length === 0}>
              {isActivatingLicense ? t("actions.activating", "激活中…") : t("actions.activate", "激活 License")}
            </button>
            <button type="button" className="secondary" onClick={copySampleLicense}>
              {t("actions.copySample", "复制示例")}
            </button>
          </form>
        </div>
        {transferStats ? (
          <>
            <div className="stat-cards">
              <div className="stat-card">
                <span className="stat-label">{t("stats.totalTransfers", "总传输次数")}</span>
                <strong className="stat-value">{transferStats.totalTransfers}</strong>
              </div>
              <div className="stat-card">
                <span className="stat-label">{t("stats.totalBytes", "传输总量")}</span>
                <strong className="stat-value">{formatSize(transferStats.totalBytes)}</strong>
              </div>
              <div className="stat-card">
                <span className="stat-label">{t("stats.successRate", "成功率")}</span>
                <strong className="stat-value">{(transferStats.successRate * 100).toFixed(1)}%</strong>
                <span className="stat-subtext">
                  {t("stats.successFailure", "成功 {succ} · 失败 {fail}", {
                    succ: transferStats.successCount,
                    fail: transferStats.failureCount,
                  })}
                </span>
              </div>
            </div>
            <div className="route-distribution">
              <div className="route-bar" aria-hidden="true">
                {(transferStats.routeDistribution ?? []).map((route) => (
                  <span key={route.route} style={{ width: `${route.ratio * 100}%` }} />
                ))}
              </div>
              <ul>
                {(transferStats.routeDistribution ?? []).map((route) => (
                  <li key={`${route.route}-stat`}>
                    <strong>{route.route.toUpperCase()}</strong>
                    <span>{(route.ratio * 100).toFixed(1)}%</span>
                  </li>
                ))}
              </ul>
            </div>
          </>
        ) : (
          <p className="stats-empty">{t("stats.emptyTransfers", "暂无传输记录。")}</p>
        )}
      </section>
    </PanelBoundary>
  ) : (
    <p className="stats-empty">注册身份后可查看传输统计。</p>
  );

  const auditContent = identity ? (
    <PanelBoundary
      fallbackKey="panel.auditError"
      fallbackDefault="无法加载审计日志，请刷新重试。"
      onRetry={() => void refreshAuditLogs(true)}
    >
      <section className="audit-panel" aria-label={t("panel.audit", "操作审计")}>
        <div className="panel-header">
          <h4>{t("panel.audit", "操作审计")}</h4>
          <button type="button" className="secondary" onClick={() => void refreshAuditLogs(true)} disabled={isAuditLoading}>
            {isAuditLoading ? t("actions.syncingAudit", "同步中…") : t("actions.syncAudit", "刷新")}
          </button>
        </div>
        {auditLogs.length > 0 ? (
          <ul className="audit-list">
            {auditLogs.slice(0, 8).map((entry) => {
              const detailRaw = summarizeAuditDetails(entry.details ?? {});
              const detailText = detailRaw.length > 160 ? `${detailRaw.slice(0, 157)}…` : detailRaw;
              return (
                <li key={entry.id}>
                  <div className="audit-header">
                    <span className="audit-event">{entry.eventType}</span>
                    <span className="audit-time">{formatRelativeTime(entry.timestamp, locale)}</span>
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
  ) : (
    <p className="stats-empty">{t("audit.empty", "暂无审计记录。")}</p>
  );

  const securityContent = identity ? (
    <>
      <PanelBoundary
        fallbackKey="panel.securityError"
        fallbackDefault="无法加载安全策略，请刷新重试。"
        onRetry={() => void refreshSecurityConfig(true)}
      >
        <section className="security-panel" aria-label={t("panel.security", "安全策略")}>
          <div className="panel-header">
            <h4>{t("panel.security", "安全策略")}</h4>
            <button type="button" className="secondary" onClick={() => void refreshSecurityConfig(true)} disabled={isSecurityLoading}>
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
    </>
  ) : null;

  const trustedPeersContent = identity ? (
    <>
      <PanelBoundary fallbackKey="panel.trustedError" fallbackDefault="无法读取信任列表，请刷新。" onRetry={() => void refreshDevices()}>
        {Object.keys(trustedPeers).length > 0 ? (
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
                  <span className="peer-fingerprint">{peer.fingerprint ?? t("trusted.unknownFingerprint", "未知指纹")}</span>
                  <span className="peer-status">
                    {peer.verified ? t("trusted.status.verified", "签名通过") : t("trusted.status.manual", "手动信任")}
                  </span>
                  <button type="button" className="plain" onClick={() => removeTrustedPeer(peer.deviceId)}>
                    {t("trusted.remove", "移除")}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="stats-empty">尚未信任任何设备。</p>
        )}
      </PanelBoundary>
    </>
  ) : (
    <p className="stats-empty">{t("panel.security", "安全策略")}将在注册身份后显示。</p>
  );

  const settingsContent = identity ? (
    <PanelBoundary
      fallbackKey="panel.settingsError"
      fallbackDefault="无法加载传输设置，请刷新重试。"
      onRetry={() => void refreshSettings(true)}
    >
      <section className="settings-panel" aria-label={t("panel.settings", "传输设置")}>
        <div className="panel-header">
          <h4>{t("panel.settings", "传输设置")}</h4>
          <button type="button" className="secondary" onClick={() => void refreshSettings(true)} disabled={isSettingsLoading}>
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
                <select value={lanStreamsDraft} onChange={handleLanStreamsChange} disabled={chunkSettingsDisabled}>
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
  ) : (
    <p className="stats-empty">{t("panel.settings", "传输设置")}仅对已登录身份开放。</p>
  );

  const beginTransfer = useCallback(async (pathsOverride?: string[]) => {
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch (err) {
      console.warn("beginTransfer: invoke unavailable", err);
      setInfo(t("info.transferDesktopOnly", "Simulated transfer requires the desktop app."));
      return;
    }
    if (!identity || !identityPrivateKey) {
      setInfo(t("info.needIdentityDetailed", "Create or import an identity first."));
      return;
    }
    const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
    if (!activeDevice) {
      setInfo(t("info.needDevice", "Please register at least one device."));
      return;
    }
    const pathsToUse = Array.isArray(pathsOverride) && pathsOverride.length > 0 ? pathsOverride : pendingPaths;
    if (pathsToUse.length === 0) {
      setInfo(t("info.needFile", "Please select at least one file."));
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
  }, [
    appendLog,
    pendingPaths,
    identity,
    identityPrivateKey,
    devices,
    activeDeviceId,
    signPurpose,
    handleCommandError,
    clearError,
    checkFileSizeLimit,
    t,
  ]);

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



  const handleWebRtcSenderTest = useCallback(async () => {
    if (!detectTauri()) {
      setInfo(t("info.webrtcTauriOnly", "WebRTC tests require the desktop app."));
      return;
    }
    if (!identity || !identityPrivateKey) {
      setInfo(t("info.needIdentityInitialized", "Complete identity setup first."));
      return;
    }
    const activeDevice = devices.find((device) => device.deviceId === activeDeviceId) ?? devices[0];
    if (!activeDevice) {
      setInfo(t("info.needDevice", "Please register at least one device."));
      return;
    }
    if (pendingPaths.length === 0) {
      setInfo(t("info.needFileForWebrtc", "Select at least one file before starting WebRTC send."));
      return;
    }
    if (!checkP2pQuota()) {
      return;
    }
    let invoke: TauriInvokeFn;
    try {
      invoke = resolveTauriInvoke();
    } catch {
      setInfo(t("info.webrtcInvokeMissing", "Tauri invoke API unavailable, cannot start WebRTC test."));
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
      setInfo(t("info.webrtcSenderStarted", "WebRTC sender started, waiting for receiver."));
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
    t,
  ]);


  const handleCopy = useCallback(
    async (field: string, value: string) => {
      try {
        await copyPlainText(value);
        setInfo(
          t("info.fieldCopied", "{field} copied to clipboard.", {
            field,
          }),
        );
        appendLog(`📋 ${field} 已复制。`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        showError(message);
      }
    },
    [appendLog, showError, t]
  );

  const submitDeviceUpdate = useCallback(
    async (overrideStatus?: string) => {
      let invoke: TauriInvokeFn;
      try {
        invoke = resolveTauriInvoke();
      } catch (err) {
        console.warn("submitDeviceUpdate: invoke unavailable", err);
        setInfo(t("info.deviceUpdateTauriOnly", "Device updates are only available in the desktop app."));
        return;
      }
      if (!identity) {
        setInfo(t("info.needIdentity", "Please register an identity first."));
        return;
      }
      if (!identityPrivateKey) {
        showError("当前会话缺少身份私钥，请重新导入或创建身份。");
        return;
      }
      const targetDeviceId = activeDeviceId ?? devices[0]?.deviceId ?? null;
      if (!targetDeviceId) {
        setInfo(t("info.needDevice", "Please register at least one device."));
        return;
      }
      setIsUpdatingDevice(true);
      clearError();
      try {
        const rawStatus = (overrideStatus ?? editDeviceStatus)?.trim();
        const statusValue = rawStatus && rawStatus.length > 0 ? rawStatus : "active";
        const signature = await signPurpose("update_device", targetDeviceId);
        const trimmedName = editDeviceName.trim();
        const payload: DeviceUpdatePayloadDto = {
          name: trimmedName.length > 0 ? trimmedName : null,
          status: statusValue,
          capabilities: heartbeatCapabilities,
        };
        await invoke("auth_update_device", {
          auth: {
            identityId: identity.identityId,
            deviceId: targetDeviceId,
            signature,
            payload,
          },
        });
        await refreshDevices(identity.identityId);
        if (overrideStatus) {
          setEditDeviceStatus(statusValue);
        }
        setInfo(t("info.deviceUpdated", "Device updated."));
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
      t,
    ]
  );

  const markDeviceInactive = useCallback(() => {
    void submitDeviceUpdate("inactive");
  }, [submitDeviceUpdate]);

  const handleSetDeviceStandby = useCallback(() => {
    void submitDeviceUpdate("standby");
  }, [submitDeviceUpdate]);

  const handleToggleEntitlement = useCallback(() => {
    void upgradeEntitlement(entitlement?.plan === "pro" ? "free" : "pro");
  }, [entitlement?.plan, upgradeEntitlement]);

  const handleSyncIdentity = useCallback(() => {
    if (!detectTauri()) {
      setInfo(t("info.syncTauriOnly", "Resync requires the desktop app."));
      return;
    }
    void refreshDevices();
    void refreshEntitlement();
  }, [refreshDevices, refreshEntitlement, setInfo, t]);

  const forgetCurrentIdentity = useCallback(async () => {
    if (!identity) {
      setInfo(t("info.noIdentityToRemove", "No identity to remove."));
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
      resetLogs();
      appendLog(`🧹 已忘记身份 ${identity.identityId}`);
      setInfo(t("info.identityRemoved", "Identity removed from this device. Import it again next time."));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showError(message);
      appendLog(`⚠️ 身份移除失败：${message}`);
    } finally {
      setIsForgettingIdentity(false);
    }
  }, [identity, appendLog, clearError, showError, resetLogs, t]);

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
        return;
      }
      const progressListener = await listen<TransferProgressPayload>("transfer_progress", async (event) => {
        if (!active) {
          return;
        }
        setProgress(event.payload);
        if (Array.isArray(event.payload.routeAttempts)) {
          setRouteAttempts(event.payload.routeAttempts);
        }

        if (event.payload.phase === "done" && event.payload.message) {
          const potPath = event.payload.message;
          try {
            const invoke = resolveTauriInvoke();
            const response = await invoke("verify_pot", { potPath }) as VerifyPotResponse;

            if (response.receipt && identity?.identityId) {
              const stored = await loadIdentity(identity.identityId);
              if (stored) {
                const myPublicKey = stored.publicKeyHex;
                let isSender = false;
                let needsSigning = false;

                if (response.receipt.sender_identity === myPublicKey && !response.receipt.sender_signature) {
                  isSender = true;
                  needsSigning = true;
                } else if (response.receipt.receiver_identity === myPublicKey && !response.receipt.receiver_signature) {
                  isSender = false;
                  needsSigning = true;
                }

                if (needsSigning) {
                  try {
                    const commitmentHex = await invoke("get_pot_commitment", { potPath, isSender }) as string;
                    const commitment = hexToBytes(commitmentHex);
                    const signatureBytes = await signEd25519(commitment, stored.privateKeyHex);
                    const signature = bytesToHex(signatureBytes);

                    const signedResponse = await invoke("sign_pot", { potPath, signature, isSender }) as VerifyPotResponse;
                    if (signedResponse.receipt) {
                      setReceipt(signedResponse.receipt);
                    } else {
                      setReceipt(response.receipt);
                    }
                  } catch (signErr) {
                    console.error("Failed to sign receipt:", signErr);
                    setReceipt(response.receipt);
                  }
                } else {
                  setReceipt(response.receipt);
                }
              } else {
                setReceipt(response.receipt);
              }
            }
          } catch (err) {
            console.error("Failed to load PoT:", err);
          }
        }
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
      });
      const completedListener = await listen<TransferLifecyclePayload>("transfer_completed", (_event) => {
        if (!active) {
          return;
        }
        setInfo(t("info.transferComplete", "Transfer complete. PoT generated."));
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
          return;
        }
        setPeerPrompt(event.payload);
        setPeerFingerprintInput("");
      });
      const p2pFailedListener = await listen<P2pConnectionFailedPayload>("p2p_connection_failed", (event) => {
        if (!active) {
          return;
        }
        const { reason, suggestion } = event.payload;
        console.warn(`P2P connection failed: ${reason}`);
        setInfo(suggestion || t("info.p2pFailed", "P2P connection failed. Falling back to local transfer."));
      });
      unlistenRefs.push(progressListener, failedListener, completedListener);
      unlistenRefs.push(devicesListener, peerListener, p2pFailedListener);
    };
    void setup();
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
  }, [identity, isTauri, showError, t]);

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

  useEffect(() => {
    if ((taskId || taskCode || progress) && currentPage !== "control") {
      setCurrentPage("control");
    }
  }, [taskId, taskCode, progress, currentPage]);

  // --- Visual Test Mode Logic ---
  const [debugTransferState, setDebugTransferState] = useState<"idle" | "transferring" | "completed">("idle");

  const simulateTransfer = () => {
    // 1. Start Transfer (Warp Speed)
    setDebugTransferState("transferring");

    // 2. Complete Transfer (Collapse & Receipt) after 2 seconds
    setTimeout(() => {
      setDebugTransferState("completed");

      // Delay receipt appearance to let the collapse/explosion animation play out
      setTimeout(() => {
        // Mock Receipt
        setReceipt({
          version: 1,
          transfer_id: "simulated-transfer-id",
          session_id: "simulated-session-id",
          sender_identity: "simulated-sender",
          receiver_identity: "simulated-receiver",
          files: [{ path: "quantum_blueprint_v1.pdf", size: 1024 * 1024 * 45, merkle_root: "mock-hash" }],
          timestamp_start: new Date().toISOString(),
          timestamp_end: new Date().toISOString(),
          route_type: "p2p",
          sender_signature: "mock-sig",
          receiver_signature: "mock-sig",
        } as any);
      }, 2500); // Wait 2.5s after collapse starts before showing receipt
    }, 2000);

    // 3. Reset state is handled by closing the receipt or manual reset
  };

  const transferState = useMemo(() => {
    if (debugTransferState !== "idle") return debugTransferState; // Debug priority
    if (!progress) return "idle";
    switch (progress.phase) {
      case "transferring":
      case "finalizing":
        return "transferring";
      case "done":
        return "completed";
      case "error":
        return "error";
      default:
        return "idle";
    }
  }, [progress, debugTransferState]);

  return (
    <>
      <QuantumBackground transferState={transferState} />

      {/* Debug Button */}
      <button
        onClick={simulateTransfer}
        className="glass-button"
        style={{
          position: 'fixed',
          bottom: '20px',
          right: '20px',
          zIndex: 9999,
          opacity: 0.8
        }}
      >
        🔮 Test UI
      </button>

      <MainLayout
        currentPage={currentPage}
        onPageChange={setCurrentPage}
        hasActiveTransfer={!!taskId}
        hasLogs={logs.length > 0}
      >
        {currentPage === "send" && (
          <SendPage
            files={files}
            hovered={hovered}
            absorbing={absorbing}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onBrowse={() => {
              void handleBrowse();
            }}
            onFileInputChange={handleFileInput}
            fileInputRef={fileInputRef}
            showInlineStartButton={showInlineStartButton}
            canStartTransfer={canStartTransfer}
            isSending={isSending}
            onStartTransfer={() => {
              void beginTransferRef.current?.();
            }}
          />
        )}

        {currentPage === "identity" && (
          <IdentityPage
            identity={identity}
            identityPrivateKeyAvailable={Boolean(identity && identityPrivateKey)}
            activeDeviceId={activeDeviceId}
            devices={devices}
            entitlement={entitlement}
            isTauri={isTauri}
            isRegisteringIdentity={isRegisteringIdentity}
            isRegisteringDevice={isRegisteringDevice}
            isForgettingIdentity={isForgettingIdentity}
            isUpdatingEntitlement={isUpdatingEntitlement}
            importIdentityId={importIdentityId}
            importPrivateKey={importPrivateKey}
            isImportingIdentity={isImportingIdentity}
            selectedDevice={selectedDevice ?? null}
            editDeviceName={editDeviceName}
            editDeviceStatus={editDeviceStatus}
            deviceStatusOptions={deviceStatusOptions}
            isUpdatingDevice={isUpdatingDevice}
            onCopy={(label, value) => {
              void handleCopy(label, value);
            }}
            onRegisterIdentity={() => {
              void registerIdentity();
            }}
            onRegisterDevice={() => {
              void registerDevice();
            }}
            onExportPrivateKey={() => {
              void exportPrivateKey();
            }}
            onForgetIdentity={() => {
              void forgetCurrentIdentity();
            }}
            onSync={handleSyncIdentity}
            onTogglePlan={handleToggleEntitlement}
            onImportIdentityIdChange={setImportIdentityId}
            onImportPrivateKeyChange={setImportPrivateKey}
            onImportIdentity={(event) => {
              void importIdentity(event);
            }}
            onSelectDevice={setActiveDeviceId}
            onEditDeviceNameChange={setEditDeviceName}
            onEditDeviceStatusChange={setEditDeviceStatus}
            onSubmitDeviceUpdate={() => void submitDeviceUpdate()}
            onSetDeviceStandby={handleSetDeviceStandby}
            onMarkDeviceInactive={markDeviceInactive}
          />
        )}

        {currentPage === "webrtc" && (
          <WebRTCPage
            onStartSender={() => void handleWebRtcSenderTest()}
            canStartSender={pendingPaths.length > 0}
            isSending={isSending}
          />
        )}
        {currentPage === "control" && (
          <div className="control-center">
            <section className="control-section">
              <h3>{t("control.transferHeading", "Transfer Status")}</h3>
              {hasActiveTransfer ? (
                <TransferStatusPage
                  taskCode={taskCode}
                  taskId={taskId}
                  senderPublicKey={senderPublicKey}
                  phase={progress?.phase ?? null}
                  route={progress?.route ?? null}
                  routeAttempts={routeAttempts}
                  progressValue={typeof progress?.progress === "number" ? progress.progress : null}
                  speedBps={progress?.speedBps ?? null}
                  bytesSent={progress?.bytesSent ?? null}
                  bytesTotal={progress?.bytesTotal ?? null}
                  monitorExtra={monitorExtra}
                  statsContent={statsContent}
                  auditContent={auditContent}
                  securityContent={securityContent}
                  settingsContent={settingsContent}
                />
              ) : (
                <p className="stats-empty">{t("control.transferEmpty", "No active transfer.")}</p>
              )}
            </section>
            <section className="control-section">
              <h3>{t("control.logsHeading", "Event Logs")}</h3>
              {logs.length > 0 ? <LogsPage logs={logs} /> : <p className="stats-empty">{t("control.logsEmpty", "No logs yet.")}</p>}
            </section>
          </div>
        )}
      </MainLayout>

      {info && <div className="toast toast-success">{info}</div>}
      {error && (
        <div className="toast toast-error">
          <div>{error}</div>
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
            <button
              type="button"
              onClick={() => {
                clearError();
              }}
            >
              知道了
            </button>
          </div>
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
              <input value={peerFingerprintInput} onChange={(event) => setPeerFingerprintInput(event.target.value)} placeholder="例如：1A:2B:3C:4D" />
            </label>
          )}
          <div className="actions-row">
            <button
              type="button"
              className="primary"
              onClick={() => {
                const reference = peerPrompt.fingerprint ? normalizeFingerprint(peerPrompt.fingerprint) : null;
                const provided = normalizeFingerprint(peerFingerprintInput);
                if (peerPrompt.verified || (reference && provided.length > 0 && provided === reference)) {
                  setTrustedPeers((prev) => ({
                    ...prev,
                    [peerPrompt.deviceId]: peerPrompt,
                  }));
                  appendLog(
                    `🤝 已信任设备 ${peerPrompt.deviceName ?? peerPrompt.deviceId}${peerPrompt.verified ? "（签名通过）" : ""
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
                appendLog(`⛔ 拒绝设备 ${peerPrompt.deviceName ?? peerPrompt.deviceId} 的连接请求`);
                setPeerPrompt(null);
                setPeerFingerprintInput("");
              }}
            >
              拒绝
            </button>
          </div>
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
      {receipt && (
        <div className="modal-overlay">
          <div className="modal-content">
            <ReceiptView receipt={receipt} onClose={() => setReceipt(null)} />
          </div>
        </div>
      )}
    </>
  );
}
const concatUint8Arrays = (chunks: Uint8Array[]) => {
  const length = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
};

const ensureEd25519Hash = () => {
  const hashConcat = (...messages: Uint8Array[]) => sha512(concatUint8Arrays(messages));
  if (!ed25519Etc.sha512Sync) {
    ed25519Etc.sha512Sync = (...messages: Uint8Array[]) => hashConcat(...messages);
  }
  if (!ed25519Etc.sha512Async) {
    ed25519Etc.sha512Async = (...messages: Uint8Array[]) => Promise.resolve(hashConcat(...messages));
  }
};
ensureEd25519Hash();
