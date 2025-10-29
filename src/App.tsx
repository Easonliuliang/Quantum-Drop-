import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import SendPanel from "./components/SendPanel";
import ReceivePanel from "./components/ReceivePanel";
import HistoryPanel from "./components/HistoryPanel";
import { useTransfersStore } from "./store/useTransfersStore";
import type { TransferTab } from "./lib/types";

type HealthCheck = {
  status: string;
  version: string;
};

const tabs: Array<{ id: TransferTab; label: string }> = [
  { id: "send", label: "Send" },
  { id: "receive", label: "Receive" },
  { id: "history", label: "History" }
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

  useEffect(() => {
    initialize().catch((error) => {
      console.error("failed to initialise transfer store", error);
    });
    return () => {
      shutdown();
    };
  }, [initialize, shutdown]);

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
          <span>{lastError}</span>
          <button className="plain" onClick={resetError} type="button">
            Dismiss
          </button>
        </div>
      )}

      <main className="main-content">
        {activeTab === "send" && <SendPanel />}
        {activeTab === "receive" && <ReceivePanel />}
        {activeTab === "history" && <HistoryPanel />}
      </main>
    </div>
  );
}
