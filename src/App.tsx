import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import SendPanel from "./components/SendPanel";
import ReceivePanel from "./components/ReceivePanel";
import HistoryPanel from "./components/HistoryPanel";
import SettingsPanel from "./components/SettingsPanel";
import { useTransfersStore } from "./store/useTransfersStore";
import type { TransferTab, SettingsPayload } from "./lib/types";

type HealthCheck = {
  status: string;
  version: string;
};

const tabs: Array<{ id: TransferTab; label: string }> = [
  { id: "send", label: "Send" },
  { id: "receive", label: "Receive" },
  { id: "history", label: "History" },
  { id: "settings", label: "Settings" },
];

export default function App(): JSX.Element {
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const activeTab = useTransfersStore((state) => state.activeTab);
  const setActiveTab = useTransfersStore((state) => state.setActiveTab);
  const initialize = useTransfersStore((state) => state.initialize);
  const shutdown = useTransfersStore((state) => state.shutdown);
  const lastError = useTransfersStore((state) => state.lastError);
  const resetError = useTransfersStore((state) => state.resetError);
  const resumeTransfer = useTransfersStore((state) => state.resumeTransfer);
  const setQuantumMode = useTransfersStore((state) => state.setQuantumMode);
  const setMinimalQuantumUI = useTransfersStore((state) => state.setMinimalQuantumUI);

  useEffect(() => {
    initialize().catch((error) => {
      console.error("failed to initialise transfer store", error);
    });
    return () => {
      shutdown();
    };
  }, [initialize, shutdown]);

  useEffect(() => {
    invoke<SettingsPayload>("load_settings")
      .then((settings) => {
        setQuantumMode(settings.quantumMode ?? true);
        setMinimalQuantumUI(settings.minimalQuantumUI ?? true);
      })
      .catch((error: unknown) => {
        console.warn("failed to load settings for quantum mode", error);
        setQuantumMode(true);
        setMinimalQuantumUI(true);
      });
  }, [setQuantumMode, setMinimalQuantumUI]);

  useEffect(() => {
    invoke<HealthCheck>("health_check")
      .then(setHealth)
      .catch((err: unknown) => {
        if (err instanceof Error) {
          setHealthError(err.message);
          return;
        }
        setHealthError("Failed to reach the native runtime.");
      });
  }, []);

  const statusLabel = useMemo(() => {
    if (healthError) {
      return `Runtime Offline · ${healthError}`;
    }
    if (!health) {
      return "Contacting native runtime…";
    }
    return `Runtime Healthy · v${health.version}`;
  }, [health, healthError]);

  const handleErrorCta = () => {
    if (!lastError) {
      return;
    }
    if (lastError.taskId) {
      void resumeTransfer(lastError.taskId);
      resetError();
      return;
    }
    switch (lastError.code) {
      case "E_ROUTE_UNREACH":
      case "E_PERM_DENIED":
        setActiveTab("settings");
        break;
      case "E_CODE_EXPIRED":
        setActiveTab("send");
        break;
      default:
        break;
    }
    resetError();
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>Courier Agent</h1>
          <p className="tagline">
            Wormhole core prototype – mocked transport, verifiable trails.
          </p>
        </div>
        <div className="runtime-status" role="status">
          {statusLabel}
        </div>
      </header>

      <nav className="primary-nav" aria-label="Main views">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={
              tab.id === activeTab ? "nav-link is-active" : "nav-link"
            }
            onClick={() => setActiveTab(tab.id)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {lastError && (
        <div className="error-banner" role="alert">
          <div className="error-content">
            <span>{lastError.summary}</span>
            {lastError.detail && lastError.detail !== lastError.summary && (
              <p className="error-detail">{lastError.detail}</p>
            )}
          </div>
          <div className="error-actions">
            {lastError.cta && (
              <button
                className="secondary"
                onClick={handleErrorCta}
                type="button"
              >
                {lastError.cta}
              </button>
            )}
            <button className="plain" onClick={resetError} type="button">
              Dismiss
            </button>
          </div>
        </div>
      )}

      <main className="main-content">
        {activeTab === "send" && <SendPanel />}
        {activeTab === "receive" && <ReceivePanel />}
        {activeTab === "history" && <HistoryPanel />}
        {activeTab === "settings" && <SettingsPanel />}
      </main>
    </div>
  );
}
