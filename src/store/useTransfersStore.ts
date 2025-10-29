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

type TransferRecord = {
  summary: TransferSummary;
  progress?: TransferProgress;
  logs: TransferLogEvent[];
};

type TransfersState = {
  activeTab: TransferTab;
  transfers: Record<string, TransferRecord>;
  pendingCode?: { taskId: string; code: string } | null;
  ready: boolean;
  isSending: boolean;
  isReceiving: boolean;
  lastError?: string | null;
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
  exportPot: (taskId: string, outDir: string) => Promise<string>;
  verifyPot: (potPath: string) => Promise<boolean>;
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
    };
  }
  return { summary, logs: [] };
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
      const message = error instanceof Error ? error.message : String(error);
      set({ lastError: message });
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
      const message = error instanceof Error ? error.message : String(error);
      set({ lastError: message });
      throw error;
    } finally {
      set({ isReceiving: false });
    }
  },

  cancelTransfer: async (taskId) => {
    await invoke("courier_cancel", { task_id: taskId });
  },

  exportPot: async (taskId, outDir) => {
    const response = await invoke<ExportPotResponse>("export_pot", {
      task_id: taskId,
      out_dir: outDir,
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
      set({ lastError: response.reason ?? "Proof verification failed" });
    }
    return response.valid;
  },

  updateProgress: (progress) =>
    set((state) => {
      const transfers = { ...state.transfers };
      const existing = transfers[progress.taskId];
      if (!existing) {
        transfers[progress.taskId] = {
          summary: createPlaceholderSummary(progress.taskId, "send"),
          progress,
          logs: [],
        };
      } else {
        transfers[progress.taskId] = { ...existing, progress };
      }
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
      transfers[event.taskId] = ensureRecord(transfers, summary);
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
      transfers[event.taskId] = ensureRecord(transfers, summary);
      return {
        transfers,
        lastError: event.message ?? state.lastError,
      };
    }),

  listRecent: () => {
    const { transfers } = get();
    return sortTransfers(Object.values(transfers));
  },

  resetError: () => set({ lastError: null }),
  clearPending: () => set({ pendingCode: null }),
}));
