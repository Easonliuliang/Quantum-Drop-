import nacl from "tweetnacl";

export type LicenseTier = "FREE" | "PRO" | "ENTERPRISE";

export interface LicenseLimits {
  maxFileSizeMb?: number | null;
  p2pMonthlyQuota?: number | null;
  maxDevices?: number | null;
  resumeEnabled: boolean;
  historyDays?: number | null;
}

export interface LicensePayload {
  key: string;
  tier: LicenseTier;
  identityId: string;
  issuedAt: number;
  expiresAt: number | null;
  limits: LicenseLimits;
  signature?: string;
}

export interface IssueParams {
  identityId: string;
  tier?: LicenseTier;
  validDays?: number;
  limits?: Partial<LicenseLimits>;
}

const DEFAULT_LIMITS: Record<LicenseTier, LicenseLimits> = {
  FREE: {
    maxFileSizeMb: 2048,
    p2pMonthlyQuota: 10,
    maxDevices: 3,
    resumeEnabled: false,
    historyDays: 7,
  },
  PRO: {
    maxFileSizeMb: null,
    p2pMonthlyQuota: null,
    maxDevices: null,
    resumeEnabled: true,
    historyDays: 90,
  },
  ENTERPRISE: {
    maxFileSizeMb: null,
    p2pMonthlyQuota: null,
    maxDevices: null,
    resumeEnabled: true,
    historyDays: 365,
  },
};

const SIGNING_PREFIX = "quantumdrop.license.v1";

export const generateLicenseKey = (tier: LicenseTier) => {
  const random = crypto.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
  return `QD-${tier}-${random.slice(0, 4)}-${random.slice(4, 8)}-${random.slice(8, 12)}`;
};

export const buildSigningPayload = (payload: LicensePayload) => {
  const limitsString = JSON.stringify(payload.limits ?? null);
  return [
    SIGNING_PREFIX,
    payload.key,
    payload.tier,
    payload.identityId,
    payload.issuedAt,
    payload.expiresAt ?? 0,
    limitsString,
  ].join("|");
};

export const signLicense = (payload: LicensePayload, privateKeyHex: string) => {
  if (privateKeyHex.length !== 64) {
    throw new Error("LICENSE_PRIVKEY must be 32-byte hex");
  }
  const seed = Buffer.from(privateKeyHex, "hex");
  const signingKey = nacl.sign.keyPair.fromSeed(seed);
  const signingPayload = buildSigningPayload(payload);
  const signature = nacl.sign.detached(
    new TextEncoder().encode(signingPayload),
    signingKey.secretKey,
  );
  return {
    ...payload,
    signature: Buffer.from(signature).toString("hex"),
  };
};

export const issueLicense = (params: IssueParams, privateKeyHex: string) => {
  const tier = params.tier ?? "PRO";
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = params.validDays
    ? issuedAt + params.validDays * 86400
    : null;
  const limits = {
    ...DEFAULT_LIMITS[tier],
    ...params.limits,
  } as LicenseLimits;
  const payload: LicensePayload = {
    key: generateLicenseKey(tier),
    tier,
    identityId: params.identityId,
    issuedAt,
    expiresAt,
    limits,
  };
  return signLicense(payload, privateKeyHex);
};
