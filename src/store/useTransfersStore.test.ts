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
      .initiateSend(["/Users/demo/file.txt"]);

    const state = useTransfersStore.getState();
    expect(result.code).toBe("ZXCV12");
    expect(state.pendingCode?.code).toBe("ZXCV12");
    expect(state.transfers["tsk_send"].summary.direction).toBe("send");
  });
});
