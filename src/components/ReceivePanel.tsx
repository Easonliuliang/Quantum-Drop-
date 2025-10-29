import { useMemo, useState } from "react";

import { useTransfersStore } from "../store/useTransfersStore";
import type { TransferStatus } from "../lib/types";
import { describeError } from "../lib/errors";
import { pickDirectory } from "../lib/dialog";

const statusLabel = (status: TransferStatus) => {
  switch (status) {
    case "pending":
      return "Awaiting";
    case "inprogress":
      return "Receiving";
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

export default function ReceivePanel(): JSX.Element {
  const [code, setCode] = useState("");
  const [saveDir, setSaveDir] = useState("");
  const isReceiving = useTransfersStore((state) => state.isReceiving);
  const startReceive = useTransfersStore((state) => state.startReceive);
  const transfersMap = useTransfersStore((state) => state.transfers);

  const receiveTransfers = useMemo(
    () =>
      Object.values(transfersMap)
        .filter((record) => record.summary.direction === "receive")
        .sort(
          (a, b) =>
            new Date(b.summary.createdAt).getTime() -
            new Date(a.summary.createdAt).getTime()
        ),
    [transfersMap]
  );

  const handleChooseDir = async () => {
    try {
      const directory = await pickDirectory();
      if (!directory) {
        return;
      }
      setSaveDir(directory);
    } catch (caught: unknown) {
      const message = describeError(caught);
      console.error("directory selection failed", message);
    }
  };

  const handleReceive = async () => {
    if (!code || !saveDir) {
      return;
    }
    try {
      await startReceive(code.trim(), saveDir);
    } catch (caught: unknown) {
      const message = describeError(caught);
      console.error("receive start failed", message);
    }
  };

  return (
    <section className="panel-content" aria-label="Receive files">
      <div className="panel-section">
        <h2>Receive</h2>
        <p className="panel-subtitle">
          Enter a courier code and pick a destination directory.
        </p>
        <div className="form-group">
          <label htmlFor="receive-code">Courier code</label>
          <input
            id="receive-code"
            type="text"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder="e.g. 4F7H2K"
          />
        </div>
        <div className="form-group">
          <label htmlFor="receive-dir">Save location</label>
          <div className="input-row">
            <input
              id="receive-dir"
              type="text"
              value={saveDir}
              onChange={(event) => setSaveDir(event.target.value)}
              placeholder="Select a directory"
            />
            <button
              className="secondary"
              onClick={() => {
                void handleChooseDir();
              }}
            >
              Browse
            </button>
          </div>
        </div>
        <button
          className="primary"
          onClick={() => {
            void handleReceive();
          }}
          disabled={!code || !saveDir || isReceiving}
        >
          {isReceiving ? "Preparing…" : "Start receive"}
        </button>
      </div>

      <div className="panel-section">
        <h3>Incoming Transfers</h3>
        {receiveTransfers.length === 0 ? (
          <p className="empty-state">No receive tasks yet.</p>
        ) : (
          <div className="transfers-grid">
            {receiveTransfers.map((record) => {
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
                    {progress?.message && (
                      <div className="progress-message">{progress.message}</div>
                    )}
                  </div>
                  {logs.length > 0 && (
                    <div className="transfer-logs">
                      <span className="label">Recent log</span>
                      <span className="value">
                        {logs[logs.length - 1].message}
                      </span>
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
