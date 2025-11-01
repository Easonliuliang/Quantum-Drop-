const STORAGE_PREFIX = "courier.identity";
const KEY_PRIVATE = (identityId: string) => `${STORAGE_PREFIX}.${identityId}.private`;
const KEY_PUBLIC = (identityId: string) => `${STORAGE_PREFIX}.${identityId}.public`;
const KEY_LAST_ID = `${STORAGE_PREFIX}.last`;

const isTauri =
  typeof window !== "undefined" && typeof window === "object" && "__TAURI__" in (window as object);

const getTauri = () => {
  if (typeof window === "undefined") {
    return undefined;
  }
  return (window as unknown as { __TAURI__?: Record<string, unknown> }).__TAURI__ as
    | {
        fs?: {
          createDir?: (path: string, options: { recursive: boolean }) => Promise<void>;
          writeTextFile?: (path: string, contents: string) => Promise<void>;
          readTextFile?: (path: string) => Promise<string>;
          removeFile?: (path: string) => Promise<void>;
        };
        path?: {
          appDataDir?: () => Promise<string>;
          join?: (...parts: string[]) => Promise<string>;
        };
      }
    | undefined;
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

const ensureDir = async () => {
  const tauri = getTauri();
  if (!tauri?.fs?.createDir || !tauri?.path?.appDataDir || !tauri?.path?.join) {
    throw new Error("tauri fs/path module unavailable");
  }
  const base = await tauri.path.appDataDir();
  const target = await tauri.path.join(base, "identity");
  try {
    await tauri.fs.createDir(target, { recursive: true });
  } catch {
    // directory may already exist
  }
  return target;
};

const writeFile = async (path: string, contents: string) => {
  const tauri = getTauri();
  if (!tauri?.fs?.writeTextFile) {
    throw new Error("tauri fs module unavailable");
  }
  await tauri.fs.writeTextFile(path, contents);
};

const readFile = async (path: string): Promise<string | null> => {
  const tauri = getTauri();
  if (!tauri?.fs?.readTextFile) {
    throw new Error("tauri fs module unavailable");
  }
  try {
    return await tauri.fs.readTextFile(path);
  } catch {
    return null;
  }
};

const pathFor = async (filename: string) => {
  const tauri = getTauri();
  if (!tauri?.path?.join) {
    throw new Error("tauri path module unavailable");
  }
  const dir = await ensureDir();
  return await tauri.path.join(dir, filename);
};

export type StoredIdentity = {
  identityId: string;
  publicKeyHex: string;
  privateKeyHex: string;
};

export const rememberIdentity = async (record: StoredIdentity) => {
  if (isTauri) {
    try {
      const privatePath = await pathFor(`${record.identityId}.priv`);
      const publicPath = await pathFor(`${record.identityId}.pub`);
      await writeFile(privatePath, record.privateKeyHex);
      await writeFile(publicPath, record.publicKeyHex);
      const lastPath = await pathFor("last");
      await writeFile(lastPath, record.identityId);
    } catch (err) {
      console.warn("persist identity to tauri storage failed", err);
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
  if (isTauri) {
    try {
      const privatePath = await pathFor(`${identityId}.priv`);
      const publicPath = await pathFor(`${identityId}.pub`);
      const privateKeyHex = await readFile(privatePath);
      const publicKeyHex = await readFile(publicPath);
      if (!privateKeyHex || !publicKeyHex) {
        return null;
      }
      return { identityId, privateKeyHex, publicKeyHex };
    } catch {
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
  if (isTauri) {
    const tauri = getTauri();
    if (!tauri?.fs?.removeFile) {
      return;
    }
    try {
      const priv = await pathFor(`${identityId}.priv`);
      await tauri.fs.removeFile(priv);
    } catch {}
    try {
      const pub = await pathFor(`${identityId}.pub`);
      await tauri.fs.removeFile(pub);
    } catch {}
  } else if (typeof window !== "undefined") {
    writeLocal(KEY_PRIVATE(identityId), null);
    writeLocal(KEY_PUBLIC(identityId), null);
  }
};

export const loadLastIdentityId = async (): Promise<string | null> => {
  if (isTauri) {
    try {
      const lastPath = await pathFor("last");
      return await readFile(lastPath);
    } catch {
      return null;
    }
  }
  if (typeof window === "undefined") {
    return null;
  }
  return readLocal(KEY_LAST_ID);
};

export const rememberLastIdentityId = async (identityId: string) => {
  if (isTauri) {
    try {
      const lastPath = await pathFor("last");
      await writeFile(lastPath, identityId);
    } catch (err) {
      console.warn("rememberLastIdentityId", err);
    }
  } else if (typeof window !== "undefined") {
    writeLocal(KEY_LAST_ID, identityId);
  }
};

export const clearLastIdentityId = async () => {
  if (isTauri) {
    try {
      const lastPath = await pathFor("last");
      const tauri = getTauri();
      if (tauri?.fs?.removeFile) {
        await tauri.fs.removeFile(lastPath);
      } else {
        await writeFile(lastPath, "");
      }
    } catch {
      // ignore missing records
    }
  } else if (typeof window !== "undefined") {
    writeLocal(KEY_LAST_ID, null);
  }
};
