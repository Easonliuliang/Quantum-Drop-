import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import HistoryPanel from "./HistoryPanel";
import { useTransfersStore } from "../store/useTransfersStore";

const invokeMock = vi.hoisted(() =>
  vi.fn((_command: string, _payload?: unknown) => Promise.resolve([]))
);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (command: string, payload?: unknown) => invokeMock(command, payload),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

describe("HistoryPanel", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue([
      {
        task_id: "task_abcdef0123",
        code: "HIST42",
        direction: "send",
        status: "completed",
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T01:00:00Z",
        files: [],
        pot_path: "/tmp/task_abcdef0123.pot.json",
      },
    ]);
    useTransfersStore.setState({ transfers: {} });
  });

  it("renders persisted history rows from the native bridge", async () => {
    render(<HistoryPanel />);

    expect(await screen.findByText("HIST42")).toBeVisible();
    expect(screen.getByText("Completed")).toBeVisible();
    expect(screen.getByText("Yes")).toBeVisible();
  });
});
