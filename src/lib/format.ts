const UNITS = ["B", "KB", "MB", "GB", "TB"];

export const formatBytes = (bytes: number) => {
  if (bytes <= 0) {
    return "0 B";
  }
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${UNITS[exponent]}`;
};

export const formatSize = (bytes: number) => {
  if (bytes === 0) {
    return "0 B";
  }
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value > 9 || exponent === 0 ? 0 : 1)} ${UNITS[exponent]}`;
};

export const maskLicenseKey = (value?: string | null) => {
  if (!value) {
    return "—";
  }
  if (value.length <= 8) {
    return value;
  }
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
};

export const formatAbsoluteTime = (timestamp: number) => {
  if (!Number.isFinite(timestamp)) {
    return "-";
  }
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString();
};

export const formatRelativeTime = (timestamp: number, locale = "zh-CN") => {
  if (!Number.isFinite(timestamp)) {
    return "-";
  }
  const diff = timestamp - Date.now();
  const absDiff = Math.abs(diff);
  if (!Number.isFinite(diff)) {
    return "-";
  }
  if (absDiff < 1000) {
    return locale.startsWith("zh") ? "刚刚" : "just now";
  }
  const units: Array<{ limit: number; divisor: number; unit: Intl.RelativeTimeFormatUnit }> = [
    { limit: 60_000, divisor: 1000, unit: "second" },
    { limit: 3_600_000, divisor: 60_000, unit: "minute" },
    { limit: 86_400_000, divisor: 3_600_000, unit: "hour" },
    { limit: 604_800_000, divisor: 86_400_000, unit: "day" },
    { limit: 2_592_000_000, divisor: 604_800_000, unit: "week" },
    { limit: Number.POSITIVE_INFINITY, divisor: 2_592_000_000, unit: "month" },
  ];
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const entry of units) {
    if (absDiff < entry.limit) {
      const value = Math.round(diff / entry.divisor);
      return formatter.format(value, entry.unit);
    }
  }
  return formatter.format(Math.round(diff / 31_536_000_000), "year");
};

const stringifyUnknown = (value: unknown) => {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return String(value);
  }
  if (typeof value === "symbol") {
    return value.description ? `Symbol(${value.description})` : value.toString();
  }
  if (typeof value === "function") {
    return value.name ? `[function ${value.name}]` : "[function]";
  }
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "[object]";
    }
  }
  if (typeof value === "undefined") {
    return "undefined";
  }
  return "";
};

export const summarizeAuditDetails = (details: unknown) => {
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
          return stringifyUnknown(item);
        }
        return String(item);
      })
      .join(" · ");
  }
  if (typeof details === "object") {
    const entries = Object.entries(details as Record<string, unknown>)
      .filter(([, value]) => value !== null && typeof value !== "object")
      .map(([key, value]) => `${key}: ${stringifyUnknown(value)}`)
      .slice(0, 3);
    if (entries.length > 0) {
      return entries.join(" · ");
    }
  }
  return stringifyUnknown(details);
};
