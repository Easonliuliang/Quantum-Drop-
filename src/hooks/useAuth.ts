/**
 * useAuth hook - 身份验证和签名逻辑
 *
 * 提供身份注册、设备注册、签名等功能
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { getPublicKey, sign as signEd25519, utils as ed25519Utils, etc as ed25519Etc } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { invoke } from "@tauri-apps/api/core";
import {
  loadIdentity,
  loadLastIdentityId,
  rememberIdentity,
  rememberLastIdentityId,
} from "../lib/identityVault";

// 合并 Uint8Array
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

// 确保 ed25519 使用 sha512
const ensureEd25519Hash = () => {
  const hashConcat = (...messages: Uint8Array[]) => sha512(concatUint8Arrays(messages));
  if (!ed25519Etc.sha512Sync) {
    ed25519Etc.sha512Sync = (...messages: Uint8Array[]) => hashConcat(...messages);
  }
  if (!ed25519Etc.sha512Async) {
    ed25519Etc.sha512Async = (...messages: Uint8Array[]) => Promise.resolve(hashConcat(...messages));
  }
};

const bytesToHex = (bytes: Uint8Array) =>
  Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex: string): Uint8Array => {
  const cleaned = hex.trim().toLowerCase();
  if (cleaned.length % 2 !== 0) {
    throw new Error("十六进制长度必须为偶数");
  }
  const result = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    result[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
  }
  return result;
};

const generateRandomHex = (length: number): string => {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
};

export interface Identity {
  identityId: string;
  publicKey: string;
}

export interface Device {
  deviceId: string;
  identityId: string;
  publicKey: string;
  name?: string | null;
  status: string;
  capabilities: string[];
}

interface IdentityResponse {
  identityId?: string;
  identity_id?: string;
  publicKey?: string;
  public_key?: string;
}

interface DeviceResponse {
  deviceId?: string;
  device_id?: string;
  identityId?: string;
  identity_id?: string;
  publicKey?: string;
  public_key?: string;
  name?: string | null;
  status?: string;
  capabilities?: string[];
}

interface DevicesResponse {
  items?: DeviceResponse[];
}

export interface AuthState {
  identity: Identity | null;
  device: Device | null;
  loading: boolean;
  error: string | null;
  ready: boolean;
}

export interface AuthActions {
  signPurpose: (purpose: string) => Promise<string>;
  createAuthPayload: <T>(purpose: string, payload: T) => Promise<{
    identityId: string;
    deviceId: string;
    signature: string;
    payload: T;
  }>;
  refresh: () => Promise<void>;
}

export function useAuth(): AuthState & AuthActions {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [device, setDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const privateKeyRef = useRef<Uint8Array | null>(null);
  const initializedRef = useRef(false);

  // 初始化身份
  const initializeIdentity = useCallback(async () => {
    if (initializedRef.current) return;
    initializedRef.current = true;

    setLoading(true);
    setError(null);

    try {
      ensureEd25519Hash();

      // 1. 尝试加载已保存的身份
      let lastIdentityId = await loadLastIdentityId();
      let storedIdentity = lastIdentityId ? await loadIdentity(lastIdentityId) : null;

      // 2. 如果没有，创建新身份
      if (!storedIdentity) {
        const privateKey = ed25519Utils.randomPrivateKey();
        const publicKey = getPublicKey(privateKey);
        const privateHex = bytesToHex(privateKey);
        const publicHex = bytesToHex(publicKey);
        const newId = `id_${publicHex.slice(0, 20)}`;

        await rememberIdentity({
          identityId: newId,
          publicKeyHex: publicHex,
          privateKeyHex: privateHex,
        });
        await rememberLastIdentityId(newId);

        storedIdentity = {
          identityId: newId,
          publicKeyHex: publicHex,
          privateKeyHex: privateHex,
        };
        lastIdentityId = newId;
      }

      // 3. 保存私钥
      privateKeyRef.current = hexToBytes(storedIdentity.privateKeyHex);

      // 4. 在后端注册身份（如果需要）
      try {
        const response = await invoke<IdentityResponse>("auth_register_identity", {
          payload: {
            identityId: storedIdentity.identityId,
            publicKey: storedIdentity.publicKeyHex,
            label: "QuantumDrop",
          },
        });

        setIdentity({
          identityId: response.identityId || response.identity_id || storedIdentity.identityId,
          publicKey: response.publicKey || response.public_key || storedIdentity.publicKeyHex,
        });
      } catch (err: unknown) {
        // 如果已存在，尝试获取
        const errMsg = err instanceof Error ? err.message : String(err);
        if (errMsg.includes("already exists") || errMsg.includes("CONFLICT")) {
          setIdentity({
            identityId: storedIdentity.identityId,
            publicKey: storedIdentity.publicKeyHex,
          });
        } else {
          throw err;
        }
      }

      // 5. 注册设备
      const deviceId = `dev_${generateRandomHex(10)}`;
      const devicePrivateBytes = ed25519Utils.randomPrivateKey();
      const devicePublicBytes = getPublicKey(devicePrivateBytes);
      const devicePublicKeyHex = bytesToHex(devicePublicBytes);

      // 签名设备注册
      const messageBytes = new TextEncoder().encode(
        `register:${deviceId}:${devicePublicKeyHex}`
      );
      const signatureBytes = signEd25519(messageBytes, privateKeyRef.current);
      const signatureHex = bytesToHex(signatureBytes);

      try {
        const deviceResponse = await invoke<DeviceResponse>("auth_register_device", {
          payload: {
            identityId: storedIdentity.identityId,
            deviceId,
            publicKey: devicePublicKeyHex,
            signature: signatureHex,
            name: "QuantumDrop Device",
            capabilities: ["send", "receive"],
          },
        });

        setDevice({
          deviceId: deviceResponse.deviceId || deviceResponse.device_id || deviceId,
          identityId: deviceResponse.identityId || deviceResponse.identity_id || storedIdentity.identityId,
          publicKey: deviceResponse.publicKey || deviceResponse.public_key || devicePublicKeyHex,
          name: deviceResponse.name,
          status: deviceResponse.status || "active",
          capabilities: deviceResponse.capabilities || ["send", "receive"],
        });
      } catch (err: unknown) {
        // 如果设备已存在，尝试获取设备列表
        const errMsg = err instanceof Error ? err.message : String(err);
        if (errMsg.includes("already exists") || errMsg.includes("CONFLICT")) {
          const devicesResponse = await invoke<DevicesResponse>("auth_list_devices", {
            payload: { identityId: storedIdentity.identityId },
          });

          const existingDevice = devicesResponse.items?.[0];
          if (existingDevice) {
            setDevice({
              deviceId: existingDevice.deviceId || existingDevice.device_id || deviceId,
              identityId: existingDevice.identityId || existingDevice.identity_id || storedIdentity.identityId,
              publicKey: existingDevice.publicKey || existingDevice.public_key || devicePublicKeyHex,
              name: existingDevice.name,
              status: existingDevice.status || "active",
              capabilities: existingDevice.capabilities || ["send", "receive"],
            });
          }
        } else {
          throw err;
        }
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error("初始化身份失败:", errMsg);
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    initializeIdentity();
  }, [initializeIdentity]);

  // 签名函数
  const signPurpose = useCallback(
    async (purpose: string): Promise<string> => {
      ensureEd25519Hash();

      if (!identity || !privateKeyRef.current) {
        throw new Error("身份密钥不可用");
      }
      if (!device) {
        throw new Error("设备未注册");
      }

      const message = new TextEncoder().encode(
        `${purpose}:${identity.identityId}:${device.deviceId}`
      );
      const signatureBytes = await Promise.resolve(
        signEd25519(message, privateKeyRef.current)
      );
      return bytesToHex(signatureBytes);
    },
    [identity, device]
  );

  // 创建认证 payload
  const createAuthPayload = useCallback(
    async <T>(purpose: string, payload: T) => {
      if (!identity || !device) {
        throw new Error("身份或设备未就绪");
      }

      const signature = await signPurpose(purpose);

      return {
        identityId: identity.identityId,
        deviceId: device.deviceId,
        signature,
        payload,
      };
    },
    [identity, device, signPurpose]
  );

  // 刷新身份状态
  const refresh = useCallback(async () => {
    initializedRef.current = false;
    await initializeIdentity();
  }, [initializeIdentity]);

  return {
    identity,
    device,
    loading,
    error,
    ready: !loading && !!identity && !!device,
    signPurpose,
    createAuthPayload,
    refresh,
  };
}
