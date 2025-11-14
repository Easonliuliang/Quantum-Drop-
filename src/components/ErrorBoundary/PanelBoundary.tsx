import type { ReactNode } from "react";

import { useI18n } from "../../lib/i18n";
import { ErrorBoundary } from "./index";

type PanelBoundaryProps = {
  children: ReactNode;
  fallbackKey: string;
  fallbackDefault: string;
  onRetry?: () => void;
};

export const PanelBoundary = ({ children, fallbackKey, fallbackDefault, onRetry }: PanelBoundaryProps) => {
  const { t } = useI18n();
  return (
    <ErrorBoundary
      renderFallback={({ reset, error }) => (
        <div className="panel-error" role="alert">
          <p>{t(fallbackKey, fallbackDefault)}</p>
          {error && <small className="panel-error-detail">{error}</small>}
          <button
            type="button"
            className="secondary"
            onClick={() => {
              reset();
              onRetry?.();
            }}
          >
            {t("actions.refresh", "刷新")}
          </button>
        </div>
      )}
    >
      {children}
    </ErrorBoundary>
  );
};
