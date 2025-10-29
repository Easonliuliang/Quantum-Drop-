import { useMemo, useState } from "react";

import { useTransfersStore } from "../store/useTransfersStore";
import type { TransferStatus } from "../lib/types";
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

export default function HistoryPanel(): JSX.Element {
  const [feedback, setFeedback] = useState<string | null>(null);
  const transfersMap = useTransfersStore((state) => state.transfers);
  const exportPot = useTransfersStore((state) => state.exportPot);
  const verifyPot = useTransfersStore((state) => state.verifyPot);

  const transfers = useMemo(
    () =>
      Object.values(transfersMap).sort(
        (a, b) =>
          new Date(b.summary.createdAt).getTime() -
          new Date(a.summary.createdAt).getTime()
      ),
    [transfersMap]
  );

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
                  <th>Code</th>
                  <th>Updated</th>
                  <th>PoT</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {transfers.map(({ summary }) => (
                  <tr key={summary.taskId}>
                    <td>{shortId(summary.taskId)}</td>
                    <td className="cell-cap">{summary.direction}</td>
                    <td className={`status status-${summary.status}`}>
                      {statusLabel(summary.status)}
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
