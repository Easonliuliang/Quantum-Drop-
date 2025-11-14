import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

type Messages = Record<string, string>;
type TranslateParams = Record<string, string | number>;

type I18nContextValue = {
  locale: string;
  setLocale: (next: string) => void;
  t: (key: string, fallback?: string, params?: TranslateParams) => string;
};

const DEFAULT_LOCALE = "zh-CN";
const LOCALE_STORAGE_KEY = "qd_locale";

const DEFAULT_MESSAGES: Record<string, Messages> = {
  "zh-CN": {
    "app.title": "Quantum Drop · 量子快传",
    "hero.tagline": "轻松拖拽，极速直达。",
    "hero.selectFiles": "选择文件",
    "dropzone.label": "拖拽或选择文件上传",
    "filePanel.title": "已准备传输的文件",
    "filePanel.start": "启动传输",
    "filePanel.starting": "启动中…",
    "receive.heading": "接收（同网模式）",
    "receive.tab.code": "配对码",
    "receive.tab.scan": "扫描",
    "receive.tab.manual": "手动",
    "receive.instructions": "输入 6 位配对码，应用会自动发现发送方。",
    "panel.stats": "传输统计",
    "panel.audit": "操作审计",
    "panel.settings": "传输设置",
    "panel.security": "安全策略",
    "panel.trusted": "已信任设备",
    "panel.statsError": "无法加载传输统计，请刷新重试。",
    "panel.auditError": "无法加载审计日志，请刷新重试。",
    "panel.settingsError": "无法加载传输设置，请刷新重试。",
    "panel.securityError": "无法加载安全策略，请刷新重试。",
    "panel.trustedError": "无法加载信任列表，请刷新。",
    "actions.refresh": "刷新",
    "actions.refreshing": "更新中…",
    "actions.syncLicense": "刷新权益",
    "actions.syncingLicense": "同步权益…",
    "actions.syncAudit": "刷新",
    "actions.syncingAudit": "同步中…",
    "license.current": "当前权益",
    "license.quota": "跨网配额",
    "license.quotaUsage": "已用 {used} / {quota} 次",
    "license.empty": "暂无权益信息，请刷新后重试。",
    "license.placeholder": "输入 License Key，例如 QD-PRO-XXXX-YYYY",
    "stats.emptyTransfers": "暂无传输记录。",
    "audit.empty": "暂无审计记录。",
    "settings.security.signature": "签名校验",
    "settings.security.enabledRecommended": "已启用（推荐）",
    "settings.security.disabled": "未启用",
    "settings.security.disconnect": "验签失败断开",
    "settings.security.disconnect.strict": "失败即断开",
    "settings.security.disconnect.warn": "失败仅警告",
    "settings.security.audit": "审计日志",
    "settings.security.audit.enabled": "记录到本地 SQLite",
    "settings.security.audit.disabled": "未记录",
    "settings.security.empty": "无法读取安全策略，请刷新或检查配置。",
    "trusted.clear": "清空",
    "trusted.unknownFingerprint": "未知指纹",
    "trusted.status.verified": "签名通过",
    "trusted.status.manual": "手动信任",
    "trusted.remove": "移除",
    "settings.chunk.adaptive": "自适应 Chunk",
    "settings.chunk.min": "最小 Chunk (MiB)",
    "settings.chunk.max": "最大 Chunk (MiB)",
    "settings.chunk.streams": "LAN 并发流数",
    "settings.chunk.help": "根据网络质量自动调整 Chunk，推荐开启。",
    "settings.chunk.save": "保存设置",
    "settings.chunk.saving": "保存中…",
    "settings.chunk.empty": "暂无设置数据，请刷新或稍后重试。",
    "locale.label": "界面语言",
    "locale.zh": "中文",
    "locale.en": "English",
  },
  en: {
    "app.title": "Quantum Drop",
    "hero.tagline": "Drag & drop files, transfer instantly.",
    "hero.selectFiles": "Select Files",
    "dropzone.label": "Drag or choose files to upload",
    "filePanel.title": "Files queued for transfer",
    "filePanel.start": "Start transfer",
    "filePanel.starting": "Starting…",
    "receive.heading": "Receive (LAN Mode)",
    "receive.tab.code": "Code",
    "receive.tab.scan": "Scan",
    "receive.tab.manual": "Manual",
    "receive.instructions": "Enter the 6-digit code and we will auto-discover the sender.",
    "panel.stats": "Transfer Statistics",
    "panel.audit": "Audit Log",
    "panel.settings": "Transfer Settings",
    "panel.security": "Security Policies",
    "panel.trusted": "Trusted Devices",
    "panel.statsError": "Unable to load transfer stats. Please refresh.",
    "panel.auditError": "Audit log unavailable. Please refresh.",
    "panel.settingsError": "Unable to load transfer settings. Please refresh.",
    "panel.securityError": "Unable to load security policies. Please refresh.",
    "panel.trustedError": "Trusted devices unavailable. Please refresh.",
    "actions.refresh": "Refresh",
    "actions.refreshing": "Refreshing…",
    "actions.syncLicense": "Sync license",
    "actions.syncingLicense": "Syncing…",
    "actions.syncAudit": "Refresh",
    "actions.syncingAudit": "Syncing…",
    "license.current": "Current plan",
    "license.quota": "Cross-network quota",
    "license.quotaUsage": "{used} of {quota} uses consumed",
    "license.empty": "No license data yet. Try refreshing.",
    "license.placeholder": "Enter License Key, e.g. QD-PRO-XXXX-YYYY",
    "stats.emptyTransfers": "No transfers yet.",
    "audit.empty": "No audit entries.",
    "settings.security.signature": "Signature verification",
    "settings.security.enabledRecommended": "Enabled (recommended)",
    "settings.security.disabled": "Disabled",
    "settings.security.disconnect": "Drop on verification failure",
    "settings.security.disconnect.strict": "Fail fast",
    "settings.security.disconnect.warn": "Warn only",
    "settings.security.audit": "Audit log",
    "settings.security.audit.enabled": "Persisted to local SQLite",
    "settings.security.audit.disabled": "Not recorded",
    "settings.security.empty": "Unable to load security policies. Please refresh or check your config.",
    "trusted.clear": "Clear",
    "trusted.unknownFingerprint": "Unknown fingerprint",
    "trusted.status.verified": "Verified",
    "trusted.status.manual": "Manually trusted",
    "trusted.remove": "Remove",
    "settings.chunk.adaptive": "Adaptive chunking",
    "settings.chunk.min": "Min chunk (MiB)",
    "settings.chunk.max": "Max chunk (MiB)",
    "settings.chunk.streams": "LAN parallel streams",
    "settings.chunk.help": "Automatically adjusts chunk size based on network quality.",
    "settings.chunk.save": "Save settings",
    "settings.chunk.saving": "Saving…",
    "settings.chunk.empty": "No settings available yet. Refresh and try again.",
    "locale.label": "Language",
    "locale.zh": "中文",
    "locale.en": "English",
  },
};

type LocaleKey = keyof typeof DEFAULT_MESSAGES;

export const SUPPORTED_LOCALES: Array<{
  value: LocaleKey;
  labelKey: string;
  fallback: string;
}> = [
  { value: "zh-CN", labelKey: "locale.zh", fallback: "中文" },
  { value: "en", labelKey: "locale.en", fallback: "English" },
];

const getInitialLocale = (): LocaleKey => {
  if (typeof window === "undefined") {
    return DEFAULT_LOCALE;
  }
  const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
  if (stored && stored in DEFAULT_MESSAGES) {
    return stored as LocaleKey;
  }
  return DEFAULT_LOCALE;
};

const I18nContext = createContext<I18nContextValue>({
  locale: DEFAULT_LOCALE,
  setLocale: () => undefined,
  t: (_key, fallback) => fallback ?? "",
});

export const I18nProvider = ({ children }: { children: ReactNode }) => {
  const [locale, setLocale] = useState<LocaleKey>(getInitialLocale);
  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    }
  }, [locale]);
  const translate = useCallback(
    (key: string, fallback?: string, params?: TranslateParams) => {
      const template = DEFAULT_MESSAGES[locale]?.[key] ?? fallback ?? key;
      if (!params) {
        return template;
      }
      return Object.entries(params).reduce((acc, [token, value]) => {
        const pattern = new RegExp(`\\{${token}\\}`, "g");
        return acc.replace(pattern, String(value));
      }, template);
    },
    [locale],
  );
  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      setLocale: (next) => {
        if (next in DEFAULT_MESSAGES) {
          setLocale(next as LocaleKey);
        }
      },
      t: translate,
    }),
    [locale, translate],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
};

export const useI18n = () => useContext(I18nContext);
