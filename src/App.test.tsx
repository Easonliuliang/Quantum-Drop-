import { render, screen } from "@testing-library/react";
import { vi } from "vitest";
import App from "./App";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockResolvedValue({
    status: "ok",
    version: "0.1.0"
  })
}));

describe("App", () => {
  it("renders hero title and tagline", async () => {
    render(<App />);
    expect(
      await screen.findByRole("heading", { name: /Courier Agent/i })
    ).toBeVisible();
    expect(
      await screen.findByText(/Zero-path, verifiable file transit/i)
    ).toBeVisible();
  });
});
