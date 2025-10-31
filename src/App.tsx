import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type SelectedFile = {
  name: string;
  size?: number;
  path?: string;
};

type TransferProgressPayload = {
  taskId: string;
  phase: "preparing" | "pairing" | "connecting" | "transferring" | "finalizing" | "done" | "error";
  progress?: number;
  bytesSent?: number;
  bytesTotal?: number;
  speedBps?: number;
  route?: "lan" | "p2p" | "relay" | "cache";
  message?: string;
};

type TransferLogPayload = {
  task_id: string;
  message: string;
};

type TransferLifecyclePayload = {
  taskId: string;
  direction: "send" | "receive";
  code?: string;
  message?: string;
};

type TauriDialogApi = {
  open: (options: { multiple?: boolean; filters?: Array<{ name: string; extensions: string[] }> }) => Promise<string | string[] | null>;
};

type TauriEventApi = {
  listen: <T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>;
};

type TauriInvokeFn = (command: string, args?: Record<string, unknown>) => Promise<unknown>;

type TauriGlobal = {
  dialog?: TauriDialogApi;
  event?: TauriEventApi;
  invoke?: TauriInvokeFn;
  tauri?: {
    invoke?: TauriInvokeFn;
  };
};

const isTauri =
  typeof window !== "undefined" && typeof window === "object" && "__TAURI__" in (window as object);

const getTauri = (): TauriGlobal | undefined => {
  if (!isTauri) {
    return undefined;
  }
  return (window as unknown as { __TAURI__?: TauriGlobal }).__TAURI__;
};

const formatSize = (bytes: number) => {
  if (bytes === 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value > 9 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
};

export default function App(): JSX.Element {
  const [hovered, setHovered] = useState(false);
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [pendingPaths, setPendingPaths] = useState<string[]>([]);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [taskCode, setTaskCode] = useState<string | null>(null);
  const [progress, setProgress] = useState<TransferProgressPayload | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const captureFiles = useCallback((list: FileList | null) => {
    if (!list) {
      return;
    }
    const next = Array.from(list).map<SelectedFile>((file) => ({
      name: file.name,
      size: file.size,
    }));
    if (next.length > 0) {
      setFiles(next);
    }
  }, []);

  const appendLog = useCallback((entry: string) => {
    setLogs((prev) => {
      const next = [...prev, entry];
      if (next.length > 50) {
        next.shift();
      }
      return next;
    });
  }, []);

  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setHovered(false);
      captureFiles(event.dataTransfer.files);
      setPendingPaths([]);
      setTaskId(null);
      setTaskCode(null);
      setProgress(null);
      setLogs([]);
      setInfo(isTauri ? "拖拽文件后请点击“选择文件”以使用 Tauri 文件对话框再试。" : null);
    },
    [captureFiles]
  );

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (!hovered) {
      setHovered(true);
    }
  }, [hovered]);

  const handleDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setHovered(false);
  }, []);

  const handleBrowse = useCallback(async () => {
    setError(null);
    setInfo(null);
    if (isTauri) {
      try {
        const tauri = getTauri();
        const dialog = tauri?.dialog;
        if (!dialog?.open) {
          setError("当前 Tauri 对话框 API 不可用，请确认插件已启用。");
          return;
        }
        const selected = await dialog.open({
          multiple: true,
          filters: [{ name: "All Files", extensions: ["*"] }],
        });
        if (!selected) {
          return;
        }
        const selectedPaths = Array.isArray(selected) ? selected : [selected];
        const normalized = selectedPaths.filter((value): value is string => typeof value === "string");
        if (normalized.length === 0) {
          setInfo("未选择任何文件。");
          return;
        }
        const displayFiles = normalized.map<SelectedFile>((path) => {
          const parts = path.split(/[/\\]/);
          const name = parts[parts.length - 1] ?? path;
          return { name, path };
        });
        setFiles(displayFiles);
        setPendingPaths(normalized);
        setTaskId(null);
        setTaskCode(null);
        setProgress(null);
        setLogs([]);
        setInfo("文件已准备，点击“启动传输”开始模拟发送。");
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } else {
      fileInputRef.current?.click();
      setInfo("浏览器模式仅展示 UI，传输需在 Tauri 桌面环境运行。");
    }
  }, []);

  const handleFileInput = (event: React.ChangeEvent<HTMLInputElement>) => {
    captureFiles(event.target.files);
    event.target.value = "";
    setPendingPaths([]);
    setTaskId(null);
    setTaskCode(null);
    setProgress(null);
    setLogs([]);
    setInfo("浏览器模式仅展示 UI，传输需在 Tauri 桌面环境运行。");
  };

  const humanSpeed = useMemo(() => {
    if (!progress || !progress.speedBps) {
      return null;
    }
    const value = progress.speedBps;
    if (value >= 1024 ** 2) {
      return `${(value / 1024 ** 2).toFixed(1)} MB/s`;
    }
    if (value >= 1024) {
      return `${(value / 1024).toFixed(1)} KB/s`;
    }
    return `${value} B/s`;
  }, [progress]);

  const beginTransfer = useCallback(async () => {
    if (!isTauri) {
      setInfo("需要在 Tauri 桌面环境下运行才能触发模拟传输。");
      return;
    }
    if (pendingPaths.length === 0) {
      setInfo("请选择至少一个文件。");
      return;
    }
    setIsSending(true);
    setError(null);
    setInfo(null);
    try {
      appendLog("准备生成取件码…");
      const tauri = getTauri();
      const invoke = tauri?.invoke ?? tauri?.tauri?.invoke;
      if (!invoke) {
        throw new Error("当前 Tauri invoke API 不可用。");
      }
      const result = (await invoke("courier_generate_code", {
        paths: pendingPaths,
      })) as { taskId?: string; task_id?: string; code: string };
      const resolvedTaskId = result.taskId ?? result.task_id ?? null;
      setTaskId(resolvedTaskId);
      setTaskCode(result.code);
      appendLog(`取件码 ${result.code} 已生成，启动发送…`);
      await invoke("courier_send", {
        code: result.code,
        paths: pendingPaths,
      });
      appendLog("传输已启动，等待事件更新…");
      setInfo("模拟传输进行中，如在另一设备运行可输入相同取件码触发接收过程。");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      appendLog(`传输启动失败：${message}`);
    } finally {
      setIsSending(false);
    }
  }, [appendLog, pendingPaths]);

  useEffect(() => {
    if (!isTauri) {
      return;
    }
    let active = true;
    const unlistenRefs: Array<() => void> = [];
    const setup = async () => {
      const tauri = getTauri();
      const listen = tauri?.event?.listen;
      if (!listen) {
        setError((prev) => prev ?? "Tauri 事件模块不可用，无法监听传输进度。");
        return;
      }
      const progressListener = await listen<TransferProgressPayload>("transfer_progress", (event) => {
        if (!active) {
          return;
        }
        setProgress(event.payload);
        if (event.payload.message) {
          appendLog(event.payload.message);
        }
      });
      const logListener = await listen<TransferLogPayload>("transfer_log", (event) => {
        if (!active) {
          return;
        }
        appendLog(event.payload.message);
      });
      const failedListener = await listen<TransferLifecyclePayload>("transfer_failed", (event) => {
        if (!active) {
          return;
        }
        setError(event.payload.message ?? "传输失败。");
        appendLog(`✖ 传输失败：${event.payload.message ?? "未知错误"}`);
      });
      const completedListener = await listen<TransferLifecyclePayload>("transfer_completed", (event) => {
        if (!active) {
          return;
        }
        setInfo("传输完成，PoT 证明已生成。");
        appendLog(`✔ 传输完成：${event.payload.message ?? "PoT 已就绪"}`);
      });
      unlistenRefs.push(progressListener, logListener, failedListener, completedListener);
    };
    setup();
    return () => {
      active = false;
      unlistenRefs.forEach((unlisten) => {
        try {
          unlisten();
        } catch {
          // ignore
        }
      });
    };
  }, [appendLog]);

  return (
    <div className="app-surface">
      <div
        className={hovered ? "dropzone is-hovered" : "dropzone"}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            handleBrowse();
          }
        }}
        aria-label="拖拽或选择文件上传"
      >
        <div className="rings">
          <span className="ring ring-outer" />
          <span className="ring ring-middle" />
          <span className="ring ring-inner" />
        </div>
        <div className="cta">
          <h1>Quantum Drop</h1>
          <p>拖拽或选择文件，启动 Courier Agent 的模拟传输流程。</p>
          <button className="browse" onClick={handleBrowse} type="button">
            选择文件
          </button>
        </div>
        <input
          ref={fileInputRef}
          className="file-input"
          type="file"
          multiple
          onChange={handleFileInput}
        />
      </div>
      {files.length > 0 && (
        <div className="file-panel" aria-live="polite">
          <h2>已准备传输的文件</h2>
          <ul>
            {files.map((file) => (
              <li key={`${file.name}-${file.path ?? file.size ?? 0}`}>
                <span className="file-name">{file.name}</span>
                <span className="file-size">
                  {file.size !== undefined ? formatSize(file.size) : file.path ?? ""}
                </span>
              </li>
            ))}
          </ul>
          {isTauri && (
            <div className="actions-row">
              <button
                className="primary"
                type="button"
                onClick={beginTransfer}
                disabled={pendingPaths.length === 0 || isSending}
              >
                {isSending ? "启动中…" : "启动传输"}
              </button>
            </div>
          )}
        </div>
      )}
      {(taskId || taskCode || progress || info || error) && (
        <div className="status-panel" aria-live="polite">
          <h3>传输状态</h3>
          <div className="status-grid">
            {taskCode && (
              <div>
                <span className="status-label">取件码</span>
                <span className="status-value">{taskCode}</span>
              </div>
            )}
            {taskId && (
              <div>
                <span className="status-label">任务 ID</span>
                <span className="status-value">{taskId}</span>
              </div>
            )}
            {progress?.phase && (
              <div>
                <span className="status-label">阶段</span>
                <span className="status-value">{progress.phase}</span>
              </div>
            )}
            {progress?.route && (
              <div>
                <span className="status-label">路由</span>
                <span className="status-value">{progress.route}</span>
              </div>
            )}
            {typeof progress?.progress === "number" && (
              <div>
                <span className="status-label">进度</span>
                <span className="status-value">{Math.round(progress.progress * 100)}%</span>
              </div>
            )}
            {humanSpeed && (
              <div>
                <span className="status-label">速度</span>
                <span className="status-value">{humanSpeed}</span>
              </div>
            )}
          </div>
          {info && <div className="toast toast-success">{info}</div>}
          {error && <div className="toast toast-error">{error}</div>}
        </div>
      )}
      {logs.length > 0 && (
        <div className="log-panel" aria-live="polite">
          <h3>事件流</h3>
          <ul>
            {logs.map((entry, index) => (
              <li key={`${entry}-${index}`}>{entry}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
