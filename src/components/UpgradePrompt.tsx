import type { UpgradeReason } from "../lib/upgrade";

type UpgradePromptProps = {
  reason: UpgradeReason;
  config: { title: string; description: string; cta: string };
  pricingUrl: string;
  onUpgrade: () => void;
  onClose: () => void;
};

const FREE_FEATURES = [
  "✅ 局域网无限传输",
  "⚠️ 跨网 10 次/月",
  "⚠️ 单文件 2GB",
  "❌ 无断点续传",
];

const PRO_FEATURES = [
  "✅ 局域网 + 跨网无限次数",
  "✅ 文件大小无限制",
  "✅ 断点续传",
  "✅ 永久历史 & 技术支持",
];

const REASON_LABELS: Record<UpgradeReason, string> = {
  p2p_quota: "跨网次数已用尽",
  file_size: "文件大小受限",
  device_limit: "设备达到上限",
  resume_disabled: "断点续传未启用",
};

export function UpgradePrompt({ reason, config, pricingUrl, onUpgrade, onClose }: UpgradePromptProps) {
  return (
    <div className="upgrade-overlay" role="dialog" aria-modal="true">
      <div className="upgrade-card">
        <button type="button" className="upgrade-close" onClick={onClose} aria-label="关闭升级提示">
          ×
        </button>
        <p className="upgrade-pill">
          {REASON_LABELS[reason]} · 免费版限制
        </p>
        <h2>{config.title}</h2>
        <p className="upgrade-description">{config.description}</p>
        <div className="upgrade-comparison">
          <div className="plan-card plan-free">
            <h3>当前 · 免费版</h3>
            <ul>
              {FREE_FEATURES.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <div className="plan-card plan-pro">
            <div className="plan-badge">Pro · ¥198 / 年</div>
            <h3>升级后</h3>
            <ul>
              {PRO_FEATURES.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
        <div className="upgrade-actions">
          <button type="button" className="primary" onClick={onUpgrade}>
            {config.cta}
          </button>
          <button type="button" className="secondary" onClick={onClose}>
            稍后再说
          </button>
        </div>
        <a
          className="upgrade-link"
          href={pricingUrl}
          target="_blank"
          rel="noreferrer"
          aria-label="打开定价页面（新窗口）"
        >
          查看完整定价与权益 →
        </a>
      </div>
    </div>
  );
}
