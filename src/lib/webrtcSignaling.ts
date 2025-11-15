import { sign as signEd25519 } from "@noble/ed25519";
import { sha256 as sha256Impl } from "@noble/hashes/sha256";

const SIGNATURE_DOMAIN = "quantumdrop.signaling.v1";

export type SignalSessionPayload = {
  sessionId: string;
  offer?: string | null;
  answer?: string | null;
  iceCandidates?: unknown[];
};

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex: string): Uint8Array => {
  const cleaned = hex.trim().replace(/^0x/i, "");
  if (cleaned.length % 2 !== 0) {
    throw new Error("指纹/公钥必须是偶数字符");
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    out[i / 2] = Number.parseInt(cleaned.slice(i, i + 2), 16);
  }
  return out;
};

export const buildSignMessage = (payload: SignalSessionPayload, deviceId: string): string => {
  const offer = payload.offer ?? "";
  const answer = payload.answer ?? "";
  const ice = JSON.stringify(payload.iceCandidates ?? []);
  return [
    SIGNATURE_DOMAIN,
    `session:${payload.sessionId}`,
    `device:${deviceId}`,
    `offer:${offer}`,
    `answer:${answer}`,
    `ice:${ice}`,
  ].join("\n");
};

export const signSessionDesc = (
  payload: SignalSessionPayload,
  deviceId: string,
  privateKey: Uint8Array,
): Promise<string> => {
  const message = new TextEncoder().encode(buildSignMessage(payload, deviceId));
  const signature = signEd25519(message, privateKey);
  return Promise.resolve(bytesToHex(signature));
};

export const fingerprintFromPublicKeyHex = (hex: string): string => {
  const bytes = hexToBytes(hex);
  const hasher = sha256.create();
  hasher.update(bytes);
  const digest: Uint8Array = hasher.digest();
  const limit = Math.min(16, digest.length);
  const segments: string[] = [];
  for (let index = 0; index < limit; index += 1) {
    const value = digest[index];
    const hexValue = value.toString(16).padStart(2, "0").toUpperCase();
    segments.push(hexValue);
  }
  return segments.join(":");
};
type Sha256Hasher = {
  update: (data: Uint8Array) => Sha256Hasher;
  digest: () => Uint8Array;
};

type Sha256Function = {
  (data: Uint8Array | string): Uint8Array;
  create: () => Sha256Hasher;
};

const sha256: Sha256Function = sha256Impl as unknown as Sha256Function;
