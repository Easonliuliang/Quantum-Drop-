import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import SendPanel from "./SendPanel";
import { useTransfersStore } from "../store/useTransfersStore";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("../lib/dialog", () => ({
  pickFiles: vi.fn(),
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
    quantumMode: true,
    minimalQuantumUI: true,
    teardown: undefined,
  });
};

describe("SendPanel", () => {
  beforeEach(() => {
    resetStore();
  });

  it("renders the immersive dropzone when minimalQuantumUI is enabled", () => {
    useTransfersStore.setState({ minimalQuantumUI: true });
    render(<SendPanel />);

    expect(
      screen.getByRole("button", { name: /drag files to start quantum transfer/i })
    ).toBeInTheDocument();
    expect(screen.queryByText("Select files")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run P2P smoke test" })
    ).toBeInTheDocument();
  });

  it("falls back to the legacy UI when minimalQuantumUI is disabled", () => {
    useTransfersStore.setState({ minimalQuantumUI: false });
    render(<SendPanel />);

    expect(screen.getByText("Select files")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /drag files to start quantum transfer/i })
    ).not.toBeInTheDocument();
    expect(screen.getByText("P2P Smoke Test")).toBeInTheDocument();
  });
});
