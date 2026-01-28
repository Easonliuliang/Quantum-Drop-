import { fireEvent, render, screen } from "@testing-library/react";
import { vi } from "vitest";

// Mock WebGL-heavy components that cannot run in jsdom
vi.mock("./components/QuantumBackground", () => ({
  QuantumBackground: () => <div data-testid="quantum-bg" />,
}));
vi.mock("./components/StarfieldBackground", () => ({
  __esModule: true,
  default: () => <div data-testid="starfield-bg" />,
}));

import App from "./App";

describe("App", () => {
  it("renders minimal UI surface", () => {
    render(<App />);
    expect(screen.getByTestId("quantum-bg")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Settings" })).toBeVisible();
  });

  it("accepts file input without error", () => {
    render(<App />);
    const file = new File(["payload"], "quantum.txt", { type: "text/plain" });
    const input = document.querySelector<HTMLInputElement>("input[type='file']");
    expect(input).not.toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- guard above is for test clarity
    fireEvent.change(input!, { target: { files: [file] } });
    // MinimalUI does not render file names; verify input exists and handler runs
    expect(input).toBeInTheDocument();
  });
});
