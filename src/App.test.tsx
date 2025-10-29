import { fireEvent, render, screen, within } from "@testing-library/react";
import { vi } from "vitest";
import App from "./App";

const invokeMock = vi.hoisted(() =>
  vi.fn((cmd: string) => {
    switch (cmd) {
      case "health_check":
        return Promise.resolve({ status: "ok", version: "0.1.0" });
      case "list_transfers":
        return Promise.resolve([]);
      default:
        return Promise.resolve({});
    }
  })
);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {})
}));

vi.mock(
  "@tauri-apps/plugin-dialog",
  () => ({
    open: vi.fn().mockResolvedValue(null)
  }),
  { virtual: true }
);

describe("App", () => {
  beforeEach(() => {
    invokeMock.mockClear();
  });

  it("renders shell and switches tabs", async () => {
    render(<App />);
    expect(
      await screen.findByRole("heading", { name: /Courier Agent/i })
    ).toBeVisible();
    const navigation = screen.getByRole("navigation", { name: /Main views/i });
    const sendTab = within(navigation).getByRole("button", { name: /Send/i });
    expect(sendTab).toHaveClass("is-active");

    fireEvent.click(screen.getByRole("button", { name: /Receive/i }));
    expect(await screen.findByLabelText(/Receive files/i)).toBeVisible();
  });
});
