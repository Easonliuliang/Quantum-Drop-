import { fireEvent, render, screen } from "@testing-library/react";

import App from "./App";

describe("App", () => {
  it("renders quantum drop surface", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Quantum Drop" })).toBeVisible();
    expect(screen.getByRole("button", { name: "选择文件" })).toBeVisible();
    expect(screen.getByLabelText("拖拽或选择文件上传")).toBeVisible();
  });

  it("captures selected files", () => {
    render(<App />);
    const file = new File(["payload"], "quantum.txt", { type: "text/plain" });
    const input = screen.getByLabelText("拖拽或选择文件上传").querySelector<HTMLInputElement>(
      ".file-input"
    );
    expect(input).not.toBeNull();
    if (!input) {
      throw new Error("missing file input");
    }
    fireEvent.change(input, { target: { files: [file] } });
    expect(screen.getByText("quantum.txt")).toBeInTheDocument();
  });
});
