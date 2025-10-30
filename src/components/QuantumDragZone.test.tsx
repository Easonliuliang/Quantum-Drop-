import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import QuantumDragZone from "./QuantumDragZone";

describe("QuantumDragZone", () => {
  it("invokes callback with dropped files", () => {
    const handleDrop = vi.fn();
    render(<QuantumDragZone onDropFiles={handleDrop} />);

    const zone = screen.getByText("将文件拖入量子场");
    const file = new File(["demo"], "sample.txt", { type: "text/plain" });

    fireEvent.drop(zone, {
      dataTransfer: {
        files: [file],
      },
      preventDefault: vi.fn(),
    });

    expect(handleDrop).toHaveBeenCalledTimes(1);
    expect(handleDrop).toHaveBeenCalledWith([file]);
  });
});
