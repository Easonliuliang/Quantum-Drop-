export type UpgradeReason = "p2p_quota" | "file_size" | "device_limit" | "resume_disabled";

export const UPGRADE_URL = "https://quantumdrop.com/pricing";

export const LICENSE_REASON_MAP: Record<string, UpgradeReason> = {
  P2P_QUOTA_EXCEEDED: "p2p_quota",
  FILE_SIZE_EXCEEDED: "file_size",
  DEVICE_LIMIT_EXCEEDED: "device_limit",
  RESUME_DISABLED: "resume_disabled",
};

export const UPGRADE_MESSAGES: Record<UpgradeReason, string> = {
  p2p_quota: "本月跨网传输次数已用完，升级 Pro 享受无限次数。",
  file_size: "免费版单文件限制 2GB，升级 Pro 传输无限大小文件。",
  device_limit: "免费版最多绑定 3 台设备，升级 Pro 解锁无限设备。",
  resume_disabled: "免费版不支持断点续传，升级 Pro 即可随时暂停恢复。",
};

export const UPGRADE_CONFIG: Record<UpgradeReason, { title: string; description: string; cta: string }> = {
  p2p_quota: {
    title: "🚀 本月跨网传输次数已用完",
    description: "免费版每月可使用 10 次 P2P 跨网传输，升级到 Pro 版享受无限次数。",
    cta: "立即升级，享受无限跨网",
  },
  file_size: {
    title: "📦 文件超过 2GB 限制",
    description: "免费版单文件最大 2GB，升级到 Pro 版即可传输任意大小的文件和文件夹。",
    cta: "升级 Pro，传输无限大小",
  },
  device_limit: {
    title: "📱 设备数量已达上限",
    description: "免费版最多绑定 3 台设备，升级到 Pro 版即可管理无限数量的终端。",
    cta: "升级 Pro，解锁无限设备",
  },
  resume_disabled: {
    title: "⏸️ 断点续传需 Pro 版",
    description: "升级后大文件传输可随时暂停恢复，不再担心网络闪断或睡眠。",
    cta: "升级 Pro，开启断点续传",
  },
};

export const FRIENDLY_ERROR_MESSAGES: Record<string, string> = {
  E_CODE_EXPIRED: "配对码已过期，请重新生成。",
  E_ROUTE_UNREACH: "网络连接失败，请检查双方网络或稍后重试。",
  E_DISK_FULL: "磁盘空间不足，请释放空间后再试。",
};
