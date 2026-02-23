import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  invokeMock,
  listenMock,
  openDialogMock,
  downloadDirMock,
  createAuthPayloadMock,
  authState,
} = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  listenMock: vi.fn(),
  openDialogMock: vi.fn(),
  downloadDirMock: vi.fn(),
  createAuthPayloadMock: vi.fn(),
  authState: {
    value: {
      ready: true,
      identity: {
        identityId: "id_test",
        publicKey: "a".repeat(64),
      },
      device: {
        deviceId: "dev_test",
        identityId: "id_test",
        publicKey: "b".repeat(64),
        name: "QuantumDrop Device",
        status: "active",
        capabilities: ["send", "receive"],
      },
      loading: false,
      error: null,
      signPurpose: vi.fn(async () => "sig"),
      createAuthPayload: vi.fn(),
      refresh: vi.fn(async () => undefined),
    },
  },
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => listenMock(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  downloadDir: (...args: unknown[]) => downloadDirMock(...args),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => openDialogMock(...args),
}));

vi.mock("./components/QuantumBackground", () => ({
  QuantumBackground: () => <div data-testid="quantum-bg" />,
}));

vi.mock("./hooks/useAuth", () => ({
  useAuth: () => authState.value,
}));

import AppNew from "./AppNew";

describe("AppNew", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    listenMock.mockReset();
    openDialogMock.mockReset();
    downloadDirMock.mockReset();
    createAuthPayloadMock.mockReset();

    listenMock.mockResolvedValue(() => undefined);
    downloadDirMock.mockResolvedValue("/Users/test/Downloads");

    createAuthPayloadMock.mockImplementation(async (purpose: string, payload: unknown) => ({
      identityId: "id_test",
      deviceId: "dev_test",
      signature: `${purpose}_sig`,
      payload,
    }));

    authState.value = {
      ...authState.value,
      ready: true,
      loading: false,
      error: null,
      createAuthPayload: createAuthPayloadMock,
    };

    invokeMock.mockImplementation(async (command: string) => {
      if (command === "courier_advertise_receiver") {
        return { code: "ABC123", taskId: "adv-1" };
      }
      if (command === "courier_list_senders") {
        return [];
      }
      if (command === "courier_recent_logs") {
        return [];
      }
      if (command === "courier_log_file_path") {
        return "/tmp/runtime.log";
      }
      if (command === "courier_send_to_receiver") {
        return { taskId: "send-1" };
      }
      return {};
    });
  });

  it("启动时会调用广播接收命令", async () => {
    render(<AppNew />);

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith(
        "courier_advertise_receiver",
        expect.objectContaining({
          auth: expect.objectContaining({
            payload: expect.objectContaining({ saveDir: "/Users/test/Downloads" }),
          }),
        }),
      );
    });
  });

  it("点击已发现设备会走直连发送命令", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "courier_advertise_receiver") {
        return { code: "ABC123", taskId: "adv-1" };
      }
      if (command === "courier_list_senders") {
        return [
          {
            code: "PEER01",
            deviceName: "Receiver Device",
            host: "192.168.31.195",
            port: 59228,
            publicKey: "c".repeat(64),
            certFingerprint: "d".repeat(64),
            discoveredVia: "mdns",
          },
        ];
      }
      if (command === "courier_recent_logs") {
        return [];
      }
      if (command === "courier_log_file_path") {
        return "/tmp/runtime.log";
      }
      if (command === "courier_send_to_receiver") {
        return { taskId: "send-1" };
      }
      return {};
    });

    openDialogMock.mockResolvedValue(["/tmp/demo.txt"]);

    render(<AppNew />);

    const device = await screen.findByText("Receiver Device");
    fireEvent.click(device);

    await waitFor(() => {
      expect(openDialogMock).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith(
        "courier_send_to_receiver",
        expect.objectContaining({
          auth: expect.objectContaining({
            payload: expect.objectContaining({
              host: "192.168.31.195",
              port: 59228,
            }),
          }),
        }),
      );
    });

    expect(createAuthPayloadMock).toHaveBeenCalledWith(
      "send",
      expect.objectContaining({
        host: "192.168.31.195",
        port: 59228,
      }),
    );
  });
});
