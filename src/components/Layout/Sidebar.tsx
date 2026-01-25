import { useI18n } from "../../lib/i18n";
import type { Page } from "./types";

interface SidebarProps {
  currentPage: Page;
  onPageChange: (page: Page) => void;
  hasActiveTransfer: boolean;
  hasLogs: boolean;
}

export function Sidebar({ currentPage, onPageChange, hasActiveTransfer, hasLogs }: SidebarProps) {
  const { t } = useI18n();

  const navItems: Array<{
    id: Page;
    icon: string;
    label: string;
    badge?: boolean;
    disabled?: boolean;
  }> = [
      { id: "send", icon: "📤", label: t("nav.send", "发送文件") },
      { id: "identity", icon: "👤", label: t("nav.identity", "身份管理") },
      { id: "webrtc", icon: "🔗", label: t("nav.webrtc", "跨网实验") },
      {
        id: "control",
        icon: "⚙️",
        label: t("nav.control", "控制面板"),
        badge: hasActiveTransfer || hasLogs,
      },
    ];

  return (
    <aside className="sidebar">
      <nav className="sidebar-nav" role="navigation">
        {navItems.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`nav-item ${currentPage === item.id ? "active" : ""} ${item.disabled ? "disabled" : ""
              }`}
            onClick={() => !item.disabled && onPageChange(item.id)}
            disabled={item.disabled}
            aria-current={currentPage === item.id ? "page" : undefined}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
            {item.badge && <span className="nav-badge" />}
          </button>
        ))}
      </nav>
    </aside>
  );
}
