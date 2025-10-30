import type { ErrorCode } from "./types";

export const describeError = (value: unknown): string => {
  if (value instanceof Error) {
    return value.message;
  }
  if (typeof value === "string") {
    return value;
  }
  if (value === undefined) {
    return "undefined";
  }
  if (value === null) {
    return "null";
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value.toString();
  }
  if (typeof value === "symbol") {
    return value.toString();
  }
  try {
    const json = JSON.stringify(value);
    if (typeof json === "string") {
      return json;
    }
  } catch {
    return "[unserialisable error]";
  }
  return "[unserialisable error]";
};

const ERROR_MESSAGES: Record<ErrorCode, { summary: string; cta?: string }> = {
  E_UNKNOWN: {
    summary: "发生未知错误",
  },
  E_INVALID_INPUT: {
    summary: "输入无效，请检查后重试",
  },
  E_NOT_FOUND: {
    summary: "资源未找到",
  },
  E_CODE_EXPIRED: {
    summary: "接入码已过期",
    cta: "重新生成后再试",
  },
  E_ROUTE_UNREACH: {
    summary: "当前路由不可达",
    cta: "切换到中继重试",
  },
  E_DISK_FULL: {
    summary: "磁盘空间不足",
    cta: "清理空间后重试",
  },
  E_VERIFY_FAIL: {
    summary: "PoT 验证失败",
    cta: "重新导出后再次验证",
  },
  E_PERM_DENIED: {
    summary: "缺少系统权限",
    cta: "前往系统设置授权",
  },
};

export type UserFacingError = {
  code?: ErrorCode;
  summary: string;
  detail?: string;
  cta?: string;
  taskId?: string;
};

type CommandErrorShape = {
  code?: string;
  message?: string;
  payload?: {
    code?: string;
    message?: string;
  };
};

const isErrorCode = (value: string): value is ErrorCode =>
  Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, value);

const extractCommandError = (
  value: unknown
): { code?: ErrorCode; message?: string } | null => {
  if (!value || typeof value !== "object") {
    return null;
  }
  const raw = value as CommandErrorShape;
  const payload = raw.payload && typeof raw.payload === "object" ? raw.payload : raw;
  const code =
    typeof payload.code === "string" && isErrorCode(payload.code)
      ? (payload.code as ErrorCode)
      : undefined;
  const message =
    typeof payload.message === "string"
      ? payload.message
      : typeof raw.message === "string"
        ? raw.message
        : undefined;
  if (!code && !message) {
    return null;
  }
  return { code, message };
};

export const resolveUserError = (value: unknown): UserFacingError => {
  const fallback = describeError(value);
  const extracted = extractCommandError(value);
  if (!extracted) {
    return { summary: fallback, detail: fallback };
  }
  if (!extracted.code) {
    return {
      summary: extracted.message ?? fallback,
      detail: fallback,
    };
  }
  const descriptor = ERROR_MESSAGES[extracted.code] ?? ERROR_MESSAGES.E_UNKNOWN;
  return {
    code: extracted.code,
    summary: descriptor.summary,
    detail: extracted.message ?? fallback,
    cta: descriptor.cta,
  };
};
