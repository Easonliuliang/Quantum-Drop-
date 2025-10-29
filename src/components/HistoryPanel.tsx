import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import { useTransfersStore } from "../store/useTransfersStore";
import type {
  TransferStatus,
  TransferSummary,
  TransferSummaryRaw
} from "../lib/types";
import { describeError } from "../lib/errors";
import { pickDirectory, pickPotFile } from "../lib/dialog";

const statusLabel = (status: TransferStatus) => {
  switch (status) {
    case "pending":
      return "Awaiting";
    case "inprogress":
      return "In Progress";
    case "completed":
      return "Completed";
    case "cancelled":
      return "Cancelled";
    case "failed":
      return "Failed";
    default:
      return status;
  }
};

const shortId = (id: string) => `${id.slice(0, 6)}…${id.slice(-4)}`;
const formatDate = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    hour12: false,
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });

const mapSummary = (raw: TransferSummaryRaw): TransferSummary => ({
  taskId: raw.task_id,
  code: raw.code ?? undefined,
  direction: raw.direction,
  status: raw.status,
  createdAt: raw.created_at,
  updatedAt: raw.updated_at,
  route: raw.route ?? undefined,
  files: raw.files ?? [],
  potPath: raw.pot_path ?? undefined,
});

export default function HistoryPanel(): JSX.Element {
  const [feedback, setFeedback] = useState<string | null>(null);
  const [remoteHistory, setRemoteHistory] = useState<TransferSummary[] | null>(
    null
  );
  const transfersMap = useTransfersStore((state) => state.transfers);
  const listRecent = useTransfersStore((state) => state.listRecent);
  const exportPot = useTransfersStore((state) => state.exportPot);
  const verifyPot = useTransfersStore((state) => state.verifyPot);

  useEffect(() => {
    let cancelled = false;
    const loadHistory = async () => {
      try {
        const response = await invoke<TransferSummaryRaw[]>("list_transfers", {
          limit: 50,
        });
        if (!cancelled) {
          setRemoteHistory(response.map(mapSummary));
        }
      } catch (error) {
        console.error("failed to fetch persisted history", error);
        if (!cancelled) {
          setRemoteHistory(null);
        }
      }
    };
    void loadHistory();
    return () => {
      cancelled = true;
    };
  }, []);

  const fallbackSummaries = useMemo(
    () => listRecent().map((record) => record.summary),
    [listRecent, transfersMap]
  );

  const transfers = useMemo(() => {
    if (!remoteHistory) {
      return fallbackSummaries;
    }
    const merged = new Map<string, TransferSummary>();
    remoteHistory.forEach((summary) => {
      merged.set(summary.taskId, summary);
    });
    fallbackSummaries.forEach((summary) => {
      merged.set(summary.taskId, summary);
    });
    return [...merged.values()].sort(
      (a, b) =>
        new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    );
  }, [remoteHistory, fallbackSummaries]);

  const handleExport = async (taskId: string) => {
    try {
      const directory = await pickDirectory();
      if (!directory) {
        return;
      }
      const path = await exportPot(taskId, directory);
      setFeedback(`PoT exported to ${path}`);
    } catch (caught: unknown) {
      const message = describeError(caught);
      setFeedback(`Failed to export: ${message}`);
    }
  };

  const handleVerify = async (pathHint?: string) => {
    try {
      const selection = await pickPotFile(pathHint);
      if (!selection) {
        return;
      }
      const valid = await verifyPot(selection);
      setFeedback(valid ? "Proof validated successfully" : "Proof invalid");
    } catch (caught: unknown) {
      const message = describeError(caught);
      setFeedback(`Verification failed: ${message}`);
    }
  };

  return (
    <section className="panel-content" aria-label="Transfer history">
      <div className="panel-section">
        <h2>History</h2>
        <p className="panel-subtitle">
          Timeline of the most recent transfers handled by the native runtime.
        </p>
        {feedback && (
          <div className="feedback-banner">
            <span>{feedback}</span>
            <button className="plain" onClick={() => setFeedback(null)}>
              Close
            </button>
          </div>
        )}
        {transfers.length === 0 ? (
          <p className="empty-state">No transfers recorded yet.</p>
        ) : (
          <div className="history-table-wrapper">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Task</th>
                  <th>Direction</th>
                  <th>Status</th>
                  <th>Route</th>
                  <th>Code</th>
                  <th>Updated</th>
                  <th>PoT</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {transfers.map((summary) => (
                  <tr key={summary.taskId}>
                    <td>{shortId(summary.taskId)}</td>
                    <td className="cell-cap">{summary.direction}</td>
                    <td className={`status status-${summary.status}`}>
                      {statusLabel(summary.status)}
                    </td>
                    <td className="cell-cap">
                      {summary.route ? summary.route.toUpperCase() : "—"}
                    </td>
                    <td>{summary.code ?? "—"}</td>
                    <td>{formatDate(summary.updatedAt)}</td>
                    <td>{summary.potPath ? "Yes" : "—"}</td>
                    <td className="table-actions">
                      <button
                        className="plain"
                        onClick={() => {
                          void handleExport(summary.taskId);
                        }}
                      >
                        Export PoT
                      </button>
                      <button
                        className="plain"
                        onClick={() => {
                          void handleVerify(summary.potPath);
                        }}
                        disabled={!summary.potPath}
                        title={
                          summary.potPath
                            ? "Verify proof file"
                            : "Generate PoT first"
                        }
                      >
                        Verify PoT
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
