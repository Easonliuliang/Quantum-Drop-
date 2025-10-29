import { useMemo, useState } from "react";

import { useTransfersStore } from "../store/useTransfersStore";
import type { TransferStatus } from "../lib/types";
import { describeError } from "../lib/errors";
import { pickFiles } from "../lib/dialog";

const formatBytes = (size: number) => {
  if (!size) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(
    Math.floor(Math.log(size) / Math.log(1024)),
    units.length - 1
  );
  const value = size / 1024 ** exponent;
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
};

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

export default function SendPanel(): JSX.Element {
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const isSending = useTransfersStore((state) => state.isSending);
  const pendingCode = useTransfersStore((state) => state.pendingCode);
  const clearPending = useTransfersStore((state) => state.clearPending);
  const startSend = useTransfersStore((state) => state.startSend);
  const transfersMap = useTransfersStore((state) => state.transfers);

  const sendTransfers = useMemo(
    () =>
      Object.values(transfersMap)
        .filter((record) => record.summary.direction === "send")
        .sort(
          (a, b) =>
            new Date(b.summary.createdAt).getTime() -
            new Date(a.summary.createdAt).getTime()
        ),
    [transfersMap]
  );

  const handleSelectFiles = async () => {
    try {
      const files = await pickFiles();
      setSelectedFiles(files);
    } catch (caught: unknown) {
      const message = describeError(caught);
      console.error("file selection failed", message);
    }
  };

  const handleSend = async () => {
    if (!selectedFiles.length) {
      return;
    }
    try {
      await startSend(selectedFiles);
    } catch (caught: unknown) {
      const message = describeError(caught);
      console.error("failed to initiate send", message);
    }
  };

  const handleCopyCode = async (code: string) => {
    try {
      await navigator.clipboard.writeText(code);
    } catch (caught: unknown) {
      const message = describeError(caught);
      console.error("clipboard copy failed", message);
    }
  };

  return (
    <section className="panel-content" aria-label="Send files">
      <div className="panel-section">
        <h2>Send</h2>
        <p className="panel-subtitle">
          Generate a courier code and stream your files over the mock transport.
        </p>
        <div className="form-row">
          <button
            className="primary"
            onClick={() => {
              void handleSelectFiles();
            }}
          >
            Select files
          </button>
          <button
            className="secondary"
            onClick={() => {
              void handleSend();
            }}
            disabled={!selectedFiles.length || isSending}
          >
            {isSending ? "Starting…" : "Start send"}
          </button>
        </div>
        {selectedFiles.length > 0 && (
          <ul className="file-list">
            {selectedFiles.map((file) => (
              <li key={file}>{file}</li>
            ))}
          </ul>
        )}
        {pendingCode && (
          <div className="code-banner">
            <div>
              <strong>Courier code:</strong> {pendingCode.code}
            </div>
            <div className="code-actions">
              <button
                className="secondary"
                onClick={() => {
                  void handleCopyCode(pendingCode.code);
                }}
              >
                Copy
              </button>
              <button className="plain" onClick={clearPending}>
                Dismiss
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="panel-section">
        <h3>Active Transfers</h3>
        {sendTransfers.length === 0 ? (
          <p className="empty-state">No send tasks yet.</p>
        ) : (
          <div className="transfers-grid">
            {sendTransfers.map((record) => {
              const { summary, progress, logs } = record;
              const percent = progress?.progress
                ? Math.round(progress.progress * 100)
                : undefined;
              return (
                <article className="transfer-card" key={summary.taskId}>
                  <header className="transfer-header">
                    <span className="task-id">{shortId(summary.taskId)}</span>
                    <span className={`status status-${summary.status}`}>
                      {statusLabel(summary.status)}
                    </span>
                  </header>
                  <div className="transfer-body">
                    <div className="progress-line">
                      <span className="label">Phase</span>
                      <span className="value">
                        {progress?.phase ?? "waiting"}
                        {percent !== undefined ? ` · ${percent}%` : ""}
                      </span>
                    </div>
                    {percent !== undefined && (
                      <div
                        className="progress-bar"
                        role="progressbar"
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-valuenow={percent}
                      >
                        <div
                          className="progress-bar-fill"
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                    )}
                    {progress?.route && (
                      <div className="route-line">
                        <span className="label">Route</span>
                        <span className={`route-chip route-${progress.route}`}>
                          {progress.route.toUpperCase()}
                        </span>
                      </div>
                    )}
                    {progress?.message && (
                      <div className="progress-message">{progress.message}</div>
                    )}
                    {summary.files.length > 0 && (
                      <ul className="transfer-files">
                        {summary.files.map((file) => (
                          <li key={file.name}>
                            <span>{file.name}</span>
                            <span>{formatBytes(file.size)}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                  {logs.length > 0 && (
                    <div className="transfer-logs">
                      <span className="label">Recent log</span>
                      <span className="value">{logs[logs.length - 1].message}</span>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
