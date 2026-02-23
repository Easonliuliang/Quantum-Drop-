/**
 * Identity Vault - Tauri v2 兼容版本
 *
 * 使用 @tauri-apps/api 和 @tauri-apps/plugin-fs
 */

import { appDataDir, join } from "@tauri-apps/api/path";
import {
  exists,
  mkdir,
  readTextFile,
  writeTextFile,
  remove,
  BaseDirectory,
} from "@tauri-apps/plugin-fs";

const STORAGE_PREFIX = "courier.identity";
const KEY_PRIVATE = (identityId: string) => `${STORAGE_PREFIX}.${identityId}.private`;
const KEY_PUBLIC = (identityId: string) => `${STORAGE_PREFIX}.${identityId}.public`;
const KEY_DEVICE = (identityId: string) => `${STORAGE_PREFIX}.${identityId}.device`;
const KEY_LAST_ID = `${STORAGE_PREFIX}.last`;

// 检测是否在 Tauri 环境中
const isTauri = (): boolean => {
  if (typeof window === "undefined") return false;
  return "__TAURI_INTERNALS__" in window || "__TAURI__" in window;
};

const writeLocal = (key: string, value: string | null) => {
  try {
    if (value === null) {
      window.localStorage.removeItem(key);
    } else {
      window.localStorage.setItem(key, value);
    }
  } catch {
    // ignore storage errors
  }
};

const readLocal = (key: string): string | null => {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
};

// 确保 identity 目录存在
const ensureIdentityDir = async (): Promise<string> => {
  const base = await appDataDir();
  const target = await join(base, "identity");

  const dirExists = await exists(target);
  if (!dirExists) {
    await mkdir(target, { recursive: true });
  }

  return target;
};

// 获取文件路径
const pathFor = async (filename: string): Promise<string> => {
  const dir = await ensureIdentityDir();
  return await join(dir, filename);
};

export type StoredIdentity = {
  identityId: string;
  publicKeyHex: string;
  privateKeyHex: string;
};

export const rememberIdentity = async (record: StoredIdentity) => {
  if (isTauri()) {
    try {
      const privatePath = await pathFor(`${record.identityId}.priv`);
      const publicPath = await pathFor(`${record.identityId}.pub`);
      const lastPath = await pathFor("last");

      await writeTextFile(privatePath, record.privateKeyHex);
      await writeTextFile(publicPath, record.publicKeyHex);
      await writeTextFile(lastPath, record.identityId);
    } catch (err) {
      console.warn("persist identity to tauri storage failed", err);
      // Fallback to localStorage
      if (typeof window !== "undefined") {
        writeLocal(KEY_PRIVATE(record.identityId), record.privateKeyHex);
        writeLocal(KEY_PUBLIC(record.identityId), record.publicKeyHex);
        writeLocal(KEY_LAST_ID, record.identityId);
      }
    }
  } else if (typeof window !== "undefined") {
    writeLocal(KEY_PRIVATE(record.identityId), record.privateKeyHex);
    writeLocal(KEY_PUBLIC(record.identityId), record.publicKeyHex);
    writeLocal(KEY_LAST_ID, record.identityId);
  }
};

export const loadIdentity = async (identityId: string): Promise<StoredIdentity | null> => {
  if (identityId.trim().length === 0) {
    return null;
  }

  if (isTauri()) {
    try {
      const privatePath = await pathFor(`${identityId}.priv`);
      const publicPath = await pathFor(`${identityId}.pub`);

      const privateExists = await exists(privatePath);
      const publicExists = await exists(publicPath);

      if (!privateExists || !publicExists) {
        return null;
      }

      const privateKeyHex = await readTextFile(privatePath);
      const publicKeyHex = await readTextFile(publicPath);

      if (!privateKeyHex || !publicKeyHex) {
        return null;
      }

      return { identityId, privateKeyHex, publicKeyHex };
    } catch {
      // Fallback to localStorage
      if (typeof window !== "undefined") {
        const privateKeyHex = readLocal(KEY_PRIVATE(identityId));
        const publicKeyHex = readLocal(KEY_PUBLIC(identityId));
        if (privateKeyHex && publicKeyHex) {
          return { identityId, privateKeyHex, publicKeyHex };
        }
      }
      return null;
    }
  }

  if (typeof window === "undefined") {
    return null;
  }

  const privateKeyHex = readLocal(KEY_PRIVATE(identityId));
  const publicKeyHex = readLocal(KEY_PUBLIC(identityId));
  if (!privateKeyHex || !publicKeyHex) {
    return null;
  }
  return { identityId, privateKeyHex, publicKeyHex };
};

export const forgetIdentity = async (identityId: string) => {
  if (isTauri()) {
    try {
      const privatePath = await pathFor(`${identityId}.priv`);
      const publicPath = await pathFor(`${identityId}.pub`);
      const devicePath = await pathFor(`${identityId}.device`);

      const privExists = await exists(privatePath);
      if (privExists) {
        await remove(privatePath);
      }

      const pubExists = await exists(publicPath);
      if (pubExists) {
        await remove(publicPath);
      }

      const deviceExists = await exists(devicePath);
      if (deviceExists) {
        await remove(devicePath);
      }
    } catch (error) {
      console.warn("forgetIdentity: remove files failed", error);
    }
  }

  if (typeof window !== "undefined") {
    writeLocal(KEY_PRIVATE(identityId), null);
    writeLocal(KEY_PUBLIC(identityId), null);
    writeLocal(KEY_DEVICE(identityId), null);
  }
};

export const loadLastIdentityId = async (): Promise<string | null> => {
  if (isTauri()) {
    try {
      const lastPath = await pathFor("last");
      const fileExists = await exists(lastPath);
      if (!fileExists) {
        return null;
      }
      const content = await readTextFile(lastPath);
      return content?.trim() || null;
    } catch {
      // Fallback to localStorage
      if (typeof window !== "undefined") {
        return readLocal(KEY_LAST_ID);
      }
      return null;
    }
  }

  if (typeof window === "undefined") {
    return null;
  }
  return readLocal(KEY_LAST_ID);
};

export const rememberLastIdentityId = async (identityId: string) => {
  if (isTauri()) {
    try {
      const lastPath = await pathFor("last");
      await writeTextFile(lastPath, identityId);
    } catch (err) {
      console.warn("rememberLastIdentityId", err);
      // Fallback to localStorage
      if (typeof window !== "undefined") {
        writeLocal(KEY_LAST_ID, identityId);
      }
    }
  } else if (typeof window !== "undefined") {
    writeLocal(KEY_LAST_ID, identityId);
  }
};

export const rememberDeviceId = async (identityId: string, deviceId: string) => {
  if (identityId.trim().length === 0 || deviceId.trim().length === 0) {
    return;
  }
  if (isTauri()) {
    try {
      const devicePath = await pathFor(`${identityId}.device`);
      await writeTextFile(devicePath, deviceId);
      return;
    } catch (err) {
      console.warn("rememberDeviceId", err);
    }
  }
  if (typeof window !== "undefined") {
    writeLocal(KEY_DEVICE(identityId), deviceId);
  }
};

export const loadDeviceId = async (identityId: string): Promise<string | null> => {
  if (identityId.trim().length === 0) {
    return null;
  }
  if (isTauri()) {
    try {
      const devicePath = await pathFor(`${identityId}.device`);
      const fileExists = await exists(devicePath);
      if (!fileExists) {
        return null;
      }
      const content = await readTextFile(devicePath);
      return content?.trim() || null;
    } catch {
      // Fallback to localStorage
      if (typeof window !== "undefined") {
        return readLocal(KEY_DEVICE(identityId));
      }
      return null;
    }
  }
  if (typeof window === "undefined") {
    return null;
  }
  return readLocal(KEY_DEVICE(identityId));
};

export const clearLastIdentityId = async () => {
  if (isTauri()) {
    try {
      const lastPath = await pathFor("last");
      const fileExists = await exists(lastPath);
      if (fileExists) {
        await remove(lastPath);
      }
    } catch {
      // ignore missing records
    }
  }

  if (typeof window !== "undefined") {
    writeLocal(KEY_LAST_ID, null);
  }
};
