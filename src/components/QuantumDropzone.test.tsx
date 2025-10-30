import { describe, expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";

import QuantumDropzone from "./QuantumDropzone";

describe("QuantumDropzone", () => {
  it("calls onFiles when files are dropped", () => {
    const handleFiles = vi.fn();
    const { getByRole } = render(
      <QuantumDropzone onFiles={handleFiles} phase="preparing" route="lan" />
    );
    const dropzone = getByRole("button");
    const file = new File(["payload"], "drop.txt", { type: "text/plain" });

    fireEvent.dragOver(dropzone, {
      dataTransfer: { files: [file] },
    });
    fireEvent.drop(dropzone, {
      dataTransfer: { files: [file] },
    });

    expect(handleFiles).toHaveBeenCalledTimes(1);
    expect(handleFiles).toHaveBeenCalledWith([file]);
  });

  it("invokes callback when files are selected via the picker", () => {
    const handleFiles = vi.fn();
    const { container } = render(
      <QuantumDropzone onFiles={handleFiles} phase="connecting" route="p2p" />
    );
    const dropzone = container.querySelector(".qdz");
    const input = container.querySelector(".qdz-input") as HTMLInputElement;
    const file = new File(["payload"], "select.txt", { type: "text/plain" });

    expect(dropzone).not.toBeNull();
    fireEvent.click(dropzone as Element);
    fireEvent.change(input, { target: { files: [file] } });

    expect(handleFiles).toHaveBeenCalled();
    expect(handleFiles).toHaveBeenLastCalledWith([file]);
  });

  it("applies the correct route skin class", () => {
    const noop = vi.fn();
    const { container, rerender } = render(
      <QuantumDropzone onFiles={noop} phase="preparing" route="lan" />
    );
    const root = container.querySelector(".qdz");
    expect(root).toHaveClass("qdz--lan");

    rerender(<QuantumDropzone onFiles={noop} phase="preparing" route="p2p" />);
    expect(root).toHaveClass("qdz--p2p");

    rerender(<QuantumDropzone onFiles={noop} phase="preparing" route="relay" />);
    expect(root).toHaveClass("qdz--relay");
  });
});
