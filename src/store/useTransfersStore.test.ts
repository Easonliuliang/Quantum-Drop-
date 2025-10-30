import { beforeEach, describe, expect, it, vi } from "vitest";

import { useTransfersStore } from "./useTransfersStore";

const invokeMock = vi.fn<(command: string, payload?: unknown) => Promise<unknown>>();
const listenMock = vi.fn<(event: string, handler: unknown) => Promise<() => void>>(
  () => Promise.resolve(() => {})
);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (command: string, payload?: unknown) => invokeMock(command, payload)
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: unknown) => listenMock(event, handler)
}));

const resetStore = () => {
  useTransfersStore.setState({
    activeTab: "send",
    transfers: {},
    pendingCode: null,
    ready: false,
    isSending: false,
    isReceiving: false,
    lastError: null,
    teardown: undefined,
  });
};

describe("useTransfersStore", () => {
  beforeEach(() => {
    resetStore();
    invokeMock.mockReset();
    listenMock.mockReset();
    listenMock.mockResolvedValue(() => {});
  });

  it("initialises and loads history", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "list_transfers") {
        return Promise.resolve([
          {
            task_id: "tsk_123",
            code: "ABC123",
            direction: "send",
            status: "completed",
            created_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T01:00:00Z",
            files: [{ name: "report.pdf", size: 1024 }],
            pot_path: "/tmp/tsk_123.pot.json",
          },
        ]);
      }
      return Promise.resolve({});
    });

    await useTransfersStore.getState().initialize();

    expect(listenMock).toHaveBeenCalled();
    const state = useTransfersStore.getState();
    expect(state.ready).toBe(true);
    expect(Object.keys(state.transfers)).toContain("tsk_123");
    const summary = state.transfers["tsk_123"].summary;
    expect(summary.status).toBe("completed");
    expect(summary.potPath).toBe("/tmp/tsk_123.pot.json");
  });

  it("creates a pending send task and stores code", async () => {
    invokeMock.mockImplementation((command: string, _payload: unknown) => {
      switch (command) {
        case "list_transfers":
          return Promise.resolve([]);
        case "courier_generate_code":
          return Promise.resolve({ taskId: "tsk_send", code: "ZXCV12" });
        case "courier_send":
          return Promise.resolve({ taskId: "tsk_send" });
        default:
          return Promise.resolve({});
      }
    });

    const result = await useTransfersStore
      .getState()
      .startSend(["/Users/demo/file.txt"]);

    const state = useTransfersStore.getState();
    expect(result.code).toBe("ZXCV12");
    expect(state.pendingCode?.code).toBe("ZXCV12");
    expect(state.transfers["tsk_send"].summary.direction).toBe("send");
  });

  it("updates progress via dedicated reducer", () => {
    useTransfersStore.setState((state) => ({
      ...state,
      transfers: {
        tsk_prog: {
          summary: {
            taskId: "tsk_prog",
            code: "CODE42",
            direction: "send",
            status: "pending",
            createdAt: "2024-01-01T00:00:00Z",
            updatedAt: "2024-01-01T00:00:00Z",
            files: [],
            potPath: undefined,
          },
          logs: [],
          progress: undefined,
          speedHistory: [],
        },
      },
    }));

    useTransfersStore.getState().updateProgress({
      taskId: "tsk_prog",
      phase: "transferring",
      progress: 0.42,
      bytesSent: 4200,
      bytesTotal: 10000,
      speedBps: 2048,
      route: "lan",
      message: "Streaming payload",
    });

    const record = useTransfersStore.getState().transfers["tsk_prog"];
    expect(record.progress?.phase).toBe("transferring");
    expect(record.progress?.route).toBe("lan");
    expect(record.progress?.progress).toBeCloseTo(0.42);
    expect(record.summary.route).toBe("lan");
    expect(record.metrics?.averageSpeed).toBeCloseTo(2048, 4);
    expect(record.metrics?.etaSeconds).toBe(3);
  });

  it("surfaces verify_pot failures with a user-facing error", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "verify_pot") {
        return Promise.resolve({ valid: false, reason: "checksum mismatch" });
      }
      return Promise.resolve({});
    });

    const response = await useTransfersStore.getState().verifyPot("/tmp/proof.pot.json");
    expect(response.valid).toBe(false);
    const state = useTransfersStore.getState();
    expect(state.lastError?.code).toBe("E_VERIFY_FAIL");
    expect(state.lastError?.detail).toBe("checksum mismatch");
  });

  it("updates summary pot path after export", async () => {
    useTransfersStore.setState((state) => ({
      ...state,
      transfers: {
        task_export: {
          summary: {
            taskId: "task_export",
            direction: "send",
            status: "completed",
            code: "EXPORT1",
            createdAt: "2024-01-01T00:00:00Z",
            updatedAt: "2024-01-01T00:00:00Z",
            files: [],
            potPath: undefined,
          },
          logs: [],
          progress: undefined,
          speedHistory: [],
        },
      },
    }));

    invokeMock.mockImplementation((command: string) => {
      if (command === "export_pot") {
        return Promise.resolve({ potPath: "/proofs/task_export.pot.json" });
      }
      return Promise.resolve({});
    });

    const path = await useTransfersStore.getState().exportPot("task_export");
    expect(path).toBe("/proofs/task_export.pot.json");
    const state = useTransfersStore.getState();
    expect(state.transfers["task_export"].summary.potPath).toBe(path);
  });

  it("preserves resume metadata across progress frames", () => {
    useTransfersStore.getState().updateProgress({
      taskId: "tsk_resume",
      phase: "transferring",
      progress: 0.25,
      bytesSent: 1024,
      bytesTotal: 4096,
      route: "lan",
      resume: {
        chunkSize: 4096,
        totalChunks: 4,
        receivedChunks: [true, false, false, false],
      },
    });
    let record = useTransfersStore.getState().transfers["tsk_resume"];
    expect(record.resume?.totalChunks).toBe(4);
    expect(record.resume?.receivedChunks[0]).toBe(true);

    useTransfersStore.getState().updateProgress({
      taskId: "tsk_resume",
      phase: "transferring",
      progress: 0.5,
      bytesSent: 2048,
      bytesTotal: 4096,
      route: "lan",
      message: "continuing",
    });

    record = useTransfersStore.getState().transfers["tsk_resume"];
    expect(record.resume?.totalChunks).toBe(4);
    expect(record.resume?.receivedChunks[0]).toBe(true);
    expect(record.progress?.resume?.receivedChunks[0]).toBe(true);
  });

  it("issues resume command and resets failure badge", async () => {
    invokeMock.mockImplementation((command: string, payload?: unknown) => {
      if (command === "courier_resume") {
        expect(payload).toEqual({ task_id: "tsk_resume" });
        return Promise.resolve({ taskId: "tsk_resume" });
      }
      if (command === "list_transfers") {
        return Promise.resolve([]);
      }
      return Promise.resolve({});
    });

    useTransfersStore.setState((state) => ({
      ...state,
      transfers: {
        tsk_resume: {
          summary: {
            taskId: "tsk_resume",
            code: "RST123",
            direction: "send",
            status: "failed",
            createdAt: "2024-01-01T00:00:00Z",
            updatedAt: "2024-01-01T00:00:00Z",
            files: [],
          },
          logs: [],
          progress: undefined,
          speedHistory: [],
          resume: {
            chunkSize: 4096,
            totalChunks: 2,
            receivedChunks: [true, false],
          },
        },
      },
      lastError: {
        summary: "transfer failed",
        cta: "继续传输",
        taskId: "tsk_resume",
      },
    }));

    await useTransfersStore.getState().resumeTransfer("tsk_resume");

    expect(invokeMock).toHaveBeenCalledWith("courier_resume", { task_id: "tsk_resume" });
    const record = useTransfersStore.getState().transfers["tsk_resume"];
    expect(record.summary.status).toBe("pending");
    expect(useTransfersStore.getState().lastError).toBeNull();
  });

  it("adds resume CTA when transfer fails", () => {
    useTransfersStore.setState((state) => ({
      ...state,
      transfers: {
        tsk_fail: {
          summary: {
            taskId: "tsk_fail",
            direction: "receive",
            status: "inprogress",
            createdAt: "2024-01-01T00:00:00Z",
            updatedAt: "2024-01-01T00:00:00Z",
            files: [],
          },
          logs: [],
          speedHistory: [],
          progress: undefined,
          resume: {
            chunkSize: 4096,
            totalChunks: 3,
            receivedChunks: [true, false, false],
          },
        },
      },
    }));

    useTransfersStore.getState().fail({
      taskId: "tsk_fail",
      direction: "receive",
      message: "network timeout",
    });

    const state = useTransfersStore.getState();
    expect(state.lastError?.cta).toBe("继续传输");
    expect(state.lastError?.taskId).toBe("tsk_fail");
    expect(state.transfers["tsk_fail"].summary.status).toBe("failed");
  });
});
