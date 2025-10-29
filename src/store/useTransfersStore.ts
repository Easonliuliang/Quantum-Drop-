import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type {
  ExportPotResponse,
  GenerateCodeResponse,
  TaskResponse,
  TransferLifecycleEvent,
  TransferLifecycleEventPayload,
  TransferLogEvent,
  TransferLogEventPayload,
  TransferProgress,
  TransferProgressPayload,
  TransferSummary,
  TransferSummaryRaw,
  TransferTab,
  TransferDirection,
  VerifyPotResponse,
} from "../lib/types";
import { resolveUserError, type UserFacingError } from "../lib/errors";

type TransferMetrics = {
  averageSpeed?: number;
  etaSeconds?: number;
};

type TransferRecord = {
  summary: TransferSummary;
  progress?: TransferProgress;
  logs: TransferLogEvent[];
  speedHistory: number[];
  metrics?: TransferMetrics;
};

type TransfersState = {
  activeTab: TransferTab;
  transfers: Record<string, TransferRecord>;
  pendingCode?: { taskId: string; code: string } | null;
  ready: boolean;
  isSending: boolean;
  isReceiving: boolean;
  lastError?: UserFacingError | null;
  teardown?: () => void;
  initialize: () => Promise<void>;
  shutdown: () => void;
  setActiveTab: (tab: TransferTab) => void;
  startSend: (
    paths: string[],
    expireSeconds?: number
  ) => Promise<{ taskId: string; code: string }>;
  startReceive: (code: string, saveDir: string) => Promise<string>;
  cancelTransfer: (taskId: string) => Promise<void>;
  exportPot: (taskId: string) => Promise<string>;
  verifyPot: (potPath: string) => Promise<VerifyPotResponse>;
  updateProgress: (progress: TransferProgress) => void;
  complete: (event: TransferLifecycleEvent) => void;
  fail: (event: TransferLifecycleEvent) => void;
  listRecent: () => TransferRecord[];
  resetError: () => void;
  clearPending: () => void;
};

const nowIso = () => new Date().toISOString();

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

const mapLifecycle = (
  payload: TransferLifecycleEventPayload
): TransferLifecycleEvent => ({
  taskId: payload.task_id,
  direction: payload.direction,
  code: payload.code ?? undefined,
  message: payload.message ?? undefined,
});

const mapProgress = (payload: TransferProgressPayload): TransferProgress => ({
  taskId: payload.task_id,
  phase: payload.phase,
  progress: payload.progress ?? undefined,
  bytesSent: payload.bytes_sent ?? undefined,
  bytesTotal: payload.bytes_total ?? undefined,
  speedBps: payload.speed_bps ?? undefined,
  route: payload.route ?? undefined,
  message: payload.message ?? undefined,
});

const mapLog = (payload: TransferLogEventPayload): TransferLogEvent => ({
  taskId: payload.task_id,
  message: payload.message,
  timestamp: nowIso(),
});

const createPlaceholderSummary = (
  taskId: string,
  direction: TransferDirection
): TransferSummary => ({
  taskId,
  direction,
  status: "pending",
  createdAt: nowIso(),
  updatedAt: nowIso(),
  route: undefined,
  files: [],
});

const ensureRecord = (
  transfers: Record<string, TransferRecord>,
  summary: TransferSummary
): TransferRecord => {
  const existing = transfers[summary.taskId];
  if (existing) {
    return {
      summary,
      progress: existing.progress,
      logs: existing.logs,
      speedHistory: existing.speedHistory,
      metrics: existing.metrics,
    };
  }
  return { summary, logs: [], speedHistory: [] };
};

const appendLog = (
  transfers: Record<string, TransferRecord>,
  log: TransferLogEvent,
  fallbackDirection: TransferDirection
) => {
  const existing = transfers[log.taskId];
  if (!existing) {
    transfers[log.taskId] = {
      summary: createPlaceholderSummary(log.taskId, fallbackDirection),
      logs: [log],
      speedHistory: [],
    };
    return;
  }
  transfers[log.taskId] = {
    ...existing,
    logs: [...existing.logs, log],
  };
};

const sortTransfers = (records: TransferRecord[]) =>
  records.sort(
    (a, b) =>
      new Date(b.summary.createdAt).getTime() -
      new Date(a.summary.createdAt).getTime()
  );

const extractName = (filePath: string) => {
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] || filePath;
};

export const useTransfersStore = create<TransfersState>((set, get) => ({
  activeTab: "send",
  transfers: {},
  pendingCode: null,
  ready: false,
  isSending: false,
  isReceiving: false,
  lastError: null,

  initialize: async () => {
    if (get().ready) {
      return;
    }

    const unlistenFns: UnlistenFn[] = [];

    const register = async <T>(
      event: string,
      handler: (payload: T) => void
    ) => {
      const unlisten = await listen<T>(event, ({ payload }) => handler(payload));
      unlistenFns.push(unlisten);
    };

    await register<TransferLifecycleEventPayload>("transfer_started", (payload) => {
      const lifecycle = mapLifecycle(payload);
      set((state) => {
        const transfers = { ...state.transfers };
        const existing =
          transfers[lifecycle.taskId]?.summary ??
          createPlaceholderSummary(lifecycle.taskId, lifecycle.direction);
        const summary: TransferSummary = {
          ...existing,
          direction: lifecycle.direction,
          status: "inprogress",
          code: lifecycle.code ?? existing.code,
          updatedAt: nowIso(),
        };
        transfers[lifecycle.taskId] = ensureRecord(transfers, summary);
        return { transfers };
      });
    });

    await register<TransferProgressPayload>(
      "transfer_progress",
      (payload) => {
        const progress = mapProgress(payload);
        get().updateProgress(progress);
      }
    );

    await register<TransferLifecycleEventPayload>(
      "transfer_completed",
      (payload) => {
        const lifecycle = mapLifecycle(payload);
        get().complete(lifecycle);
      }
    );

    await register<TransferLifecycleEventPayload>("transfer_failed", (payload) => {
      const lifecycle = mapLifecycle(payload);
      get().fail(lifecycle);
    });

    await register<TransferLogEventPayload>("transfer_log", (payload) => {
      const log = mapLog(payload);
      set((state) => {
        const transfers = { ...state.transfers };
        appendLog(transfers, log, "send");
        return { transfers };
      });
    });

    set({
      ready: true,
      teardown: () => {
        unlistenFns.forEach((unlisten) => unlisten());
      },
    });

    try {
      const history = await invoke<TransferSummaryRaw[]>("list_transfers", {
        limit: 50,
      });
      set((state) => {
        const transfers = { ...state.transfers };
        history
          .map(mapSummary)
          .forEach((summary) => {
            transfers[summary.taskId] = ensureRecord(transfers, summary);
          });
        return { transfers };
      });
    } catch (error) {
      console.error("failed to load transfer history", error);
    }
  },

  shutdown: () => {
    const teardown = get().teardown;
    if (teardown) {
      teardown();
    }
    set({ ready: false, teardown: undefined });
  },

  setActiveTab: (tab) => set({ activeTab: tab }),

  startSend: async (paths, expireSeconds) => {
    if (!paths.length) {
      throw new Error("No files selected");
    }
    set({ isSending: true, lastError: null });
    try {
      const response = await invoke<GenerateCodeResponse>(
        "courier_generate_code",
        {
          paths,
          expire_sec: expireSeconds,
        }
      );

      const now = nowIso();
      const placeholder: TransferSummary = {
        taskId: response.taskId,
        code: response.code,
        direction: "send",
        status: "pending",
        createdAt: now,
        updatedAt: now,
        files: paths.map((path) => ({ name: extractName(path), size: 0 })),
        potPath: undefined,
      };

      set((state) => {
        const transfers = { ...state.transfers };
        transfers[placeholder.taskId] = ensureRecord(transfers, placeholder);
        return { transfers, pendingCode: { taskId: response.taskId, code: response.code } };
      });

      await invoke<TaskResponse>("courier_send", {
        code: response.code,
        paths,
      });

      return { taskId: response.taskId, code: response.code };
    } catch (error) {
      set({ lastError: resolveUserError(error) });
      throw error;
    } finally {
      set({ isSending: false });
    }
  },

  startReceive: async (code, saveDir) => {
    set({ isReceiving: true, lastError: null });
    try {
      const response = await invoke<TaskResponse>("courier_receive", {
        code,
        save_dir: saveDir,
      });

      const now = nowIso();
      const summary: TransferSummary = {
        taskId: response.taskId,
        code,
        direction: "receive",
        status: "pending",
        createdAt: now,
        updatedAt: now,
        files: [],
        potPath: undefined,
      };

      set((state) => {
        const transfers = { ...state.transfers };
        transfers[summary.taskId] = ensureRecord(transfers, summary);
        return { transfers };
      });

      return response.taskId;
    } catch (error) {
      set({ lastError: resolveUserError(error) });
      throw error;
    } finally {
      set({ isReceiving: false });
    }
  },

  cancelTransfer: async (taskId) => {
    await invoke("courier_cancel", { task_id: taskId });
  },

  exportPot: async (taskId) => {
    const response = await invoke<ExportPotResponse>("export_pot", {
      task_id: taskId,
    });
    set((state) => {
      const transfers = { ...state.transfers };
      const existing = transfers[taskId];
      if (existing) {
        transfers[taskId] = {
          ...existing,
          summary: { ...existing.summary, potPath: response.potPath },
        };
      }
      return { transfers };
    });
    return response.potPath;
  },

  verifyPot: async (potPath) => {
    const response = await invoke<VerifyPotResponse>("verify_pot", {
      pot_path: potPath,
    });
    if (!response.valid) {
      set({
        lastError: resolveUserError({
          payload: {
            code: "E_VERIFY_FAIL",
            message: response.reason ?? "Proof verification failed",
          },
        }),
      });
    } else {
      set((state) =>
        state.lastError?.code === "E_VERIFY_FAIL" ? { lastError: null } : {}
      );
    }
    return response;
  },

  updateProgress: (progress) =>
    set((state) => {
      const transfers = { ...state.transfers };
      const existing = transfers[progress.taskId];
      let summary: TransferSummary;
      if (!existing) {
        summary = createPlaceholderSummary(progress.taskId, "send");
        if (progress.route) {
          summary.route = progress.route;
        }
      } else {
        summary = progress.route
          ? { ...existing.summary, route: progress.route }
          : existing.summary;
      }

      let speedHistory = existing?.speedHistory ?? [];
      let metrics = existing?.metrics;
      if (typeof progress.speedBps === "number") {
        speedHistory = [...speedHistory, progress.speedBps].slice(-5);
        if (speedHistory.length > 0) {
          const averageSpeed =
            speedHistory.reduce((sum, value) => sum + value, 0) /
            speedHistory.length;
          let etaSeconds: number | undefined;
          if (
            typeof progress.bytesTotal === "number" &&
            typeof progress.bytesSent === "number"
          ) {
            const remaining = Math.max(0, progress.bytesTotal - progress.bytesSent);
            etaSeconds = averageSpeed > 0 ? Math.ceil(remaining / averageSpeed) : undefined;
          }
          metrics = {
            averageSpeed,
            etaSeconds: etaSeconds ?? metrics?.etaSeconds,
          };
        }
      } else if (progress.phase === "done") {
        metrics = {
          averageSpeed: metrics?.averageSpeed,
          etaSeconds: 0,
        };
      }

      transfers[progress.taskId] = {
        summary,
        progress,
        logs: existing ? existing.logs : [],
        speedHistory,
        metrics,
      };
      return { transfers };
    }),

  complete: (event) =>
    set((state) => {
      const transfers = { ...state.transfers };
      const existing =
        transfers[event.taskId]?.summary ??
        createPlaceholderSummary(event.taskId, event.direction);
      const summary: TransferSummary = {
        ...existing,
        status: "completed",
        code: event.code ?? existing.code,
        updatedAt: nowIso(),
        potPath: event.message ?? existing.potPath,
      };
      const record = ensureRecord(transfers, summary);
      transfers[event.taskId] = record.metrics
        ? {
            ...record,
            metrics: { ...record.metrics, etaSeconds: 0 },
          }
        : record;
      return { transfers };
    }),

  fail: (event) =>
    set((state) => {
      const transfers = { ...state.transfers };
      const existing =
        transfers[event.taskId]?.summary ??
        createPlaceholderSummary(event.taskId, event.direction);
      const summary: TransferSummary = {
        ...existing,
        status: "failed",
        code: event.code ?? existing.code,
        updatedAt: nowIso(),
      };
      const record = ensureRecord(transfers, summary);
      transfers[event.taskId] = record;
      return {
        transfers,
        lastError: event.message
          ? resolveUserError({ message: event.message })
          : state.lastError,
      };
    }),

  listRecent: () => {
    const { transfers } = get();
    return sortTransfers(Object.values(transfers));
  },

  resetError: () => set({ lastError: null }),
  clearPending: () => set({ pendingCode: null }),
}));
