import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  open: (options: { multiple?: boolean; filters?: Array<{ name: string; extensions: string[] }> }) => Promise<string | string[] | null>;
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
  const [isTauri, setIsTauri] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [pendingPaths, setPendingPaths] = useState<string[]>([]);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [taskCode, setTaskCode] = useState<string | null>(null);
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
  const [isRegisteringIdentity, setIsRegisteringIdentity] = useState(false);
  const [isRegisteringDevice, setIsRegisteringDevice] = useState(false);
  const [isUpdatingEntitlement, setIsUpdatingEntitlement] = useState(false);
  const [isImportingIdentity, setIsImportingIdentity] = useState(false);
  const [importIdentityId, setImportIdentityId] = useState("");
  const [importPrivateKey, setImportPrivateKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [absorbing, setAbsorbing] = useState(false);
  const beginTransferRef = useRef<(pathsOverride?: string[]) => void>();
  const heartbeatTimerRef = useRef<number | null>(null);
  const heartbeatCapabilities = useMemo(() => ["ui:minimal-panel"], []);
  const deviceStatusOptions = useMemo(() => ["active", "standby", "inactive"], []);
  const selectedDevice = useMemo(() => {
    if (!activeDeviceId) {
      return null;
    }
    return devices.find((device) => device.deviceId === activeDeviceId) ?? null;
  }, [activeDeviceId, devices]);

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
        setError((prev) => prev ?? message);
        appendLog(`⚠️ 拉取设备失败：${message}`);
      }
    },
    [appendLog, identity]
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
        setError((prev) => prev ?? message);
        appendLog(`⚠️ 拉取权益失败：${message}`);
      }
    },
    [appendLog, identity]
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
    setError(null);
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
          label: "Quantum Drop · 量子快传",
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
      setError(message);
      appendLog(`⚠️ 身份注册失败：${message}`);
    } finally {
      setIsRegisteringIdentity(false);
    }
  }, [appendLog, refreshEntitlement, rememberIdentity, rememberLastIdentityId]);

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
      setError("当前会话缺少身份私钥，请重新注册或导入身份。");
      return;
    }
    setIsRegisteringDevice(true);
    setError(null);
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
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      appendLog(`⚠️ 设备登记失败：${message}`);
    } finally {
      setIsRegisteringDevice(false);
    }
  }, [appendLog, devices.length, identity, identityPrivateKey, refreshDevices, sendHeartbeat]);

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
      setError(null);
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
        setError(message);
        appendLog(`⚠️ 权益更新失败：${message}`);
      } finally {
        setIsUpdatingEntitlement(false);
      }
    },
    [appendLog, identity]
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
      setError(message);
    }
  }, [identity, identityPrivateKey, rememberIdentity]);

  const importIdentity = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const identityId = importIdentityId.trim();
      const privateHex = importPrivateKey.trim();
      if (!identityId) {
        setError("请输入身份标识");
        return;
      }
      if (!privateHex) {
        setError("请输入私钥十六进制");
        return;
      }
    setIsImportingIdentity(true);
    setError(null);
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
        setError(message);
        appendLog(`⚠️ 身份导入失败：${message}`);
      } finally {
        setIsImportingIdentity(false);
      }
    },
    [appendLog, importIdentityId, importPrivateKey, refreshDevices, refreshEntitlement, rememberIdentity, rememberLastIdentityId]
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
      setProgress(null);
      setLogs([]);
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
    setError(null);
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
    setIsSending(true);
    setError(null);
    setInfo(null);
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
      })) as { taskId?: string; task_id?: string; code: string };
      const resolvedTaskId = result.taskId ?? result.task_id ?? null;
      setTaskId(resolvedTaskId);
      setTaskCode(result.code);
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
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      appendLog(`传输启动失败：${message}`);
    } finally {
      setIsSending(false);
    }
  }, [appendLog, pendingPaths, identity, devices, activeDeviceId, signPurpose]);

  useEffect(() => {
    beginTransferRef.current = beginTransfer;
  }, [beginTransfer]);

  const handleCopy = useCallback(
    async (field: string, value: string) => {
      try {
        await copyPlainText(value);
        setInfo(`${field} 已复制到剪贴板。`);
        appendLog(`📋 ${field} 已复制。`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
      }
    },
    [appendLog]
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
        setError("当前会话缺少身份私钥，请重新导入或创建身份。");
        return;
      }
      const targetDeviceId = activeDeviceId ?? devices[0]?.deviceId ?? null;
      if (!targetDeviceId) {
        setInfo("请至少登记一个终端设备。");
        return;
      }
      setIsUpdatingDevice(true);
      setError(null);
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
        setError(message);
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
    setError(null);
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
      setProgress(null);
      setLogs([]);
      appendLog(`🧹 已忘记身份 ${identity.identityId}`);
      setInfo("身份已从本机移除，下次启动需重新导入。");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      appendLog(`⚠️ 身份移除失败：${message}`);
    } finally {
      setIsForgettingIdentity(false);
    }
  }, [identity, appendLog]);

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
        setError((prev) => prev ?? "Tauri 事件模块不可用，无法监听传输进度。");
        return;
      }
      const progressListener = await listen<TransferProgressPayload>("transfer_progress", (event) => {
        if (!active) {
          return;
        }
        setProgress(event.payload);
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
        setError(event.payload.message ?? "传输失败。");
        appendLog(`✖ 传输失败：${event.payload.message ?? "未知错误"}`);
      });
      const completedListener = await listen<TransferLifecyclePayload>("transfer_completed", (event) => {
        if (!active) {
          return;
        }
        setInfo("传输完成，PoT 证明已生成。");
        appendLog(`✔ 传输完成：${event.payload.message ?? "PoT 已就绪"}`);
      });
      unlistenRefs.push(progressListener, logListener, failedListener, completedListener);
      unlistenRefs.push(devicesListener);
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
  }, [appendLog, identity, isTauri]);

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
        aria-label="拖拽或选择文件上传"
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
          <h1>Quantum Drop · 量子快传</h1>
          <p>拖拽或选择文件，启动 Quantum Drop · 量子快传 的模拟传输流程。</p>
          <button className="browse" onClick={handleBrowse} type="button">
            选择文件
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
          <h2>已准备传输的文件</h2>
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
                {isSending ? "启动中…" : "启动传输"}
              </button>
            </div>
          )}
        </div>
      )}
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
          {info && <div className="toast toast-success">{info}</div>}
          {error && <div className="toast toast-error">{error}</div>}
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
