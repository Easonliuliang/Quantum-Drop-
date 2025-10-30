import { useCallback, useState } from "react";
import type { DragEvent, ReactNode } from "react";

type QuantumDragZoneProps = {
  onDropFiles: (files: File[]) => void;
  disabled?: boolean;
  children?: ReactNode;
  hint?: string;
};

const isChildNode = (parent: EventTarget | null, child: EventTarget | null) => {
  if (!(parent instanceof HTMLElement) || !(child instanceof HTMLElement)) {
    return false;
  }
  return parent.contains(child);
};

export default function QuantumDragZone({
  onDropFiles,
  disabled = false,
  children,
  hint,
}: QuantumDragZoneProps): JSX.Element {
  const [isActive, setIsActive] = useState(false);

  const handleDragOver = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      if (disabled) {
        return;
      }
      event.preventDefault();
      setIsActive(true);
    },
    [disabled]
  );

  const handleDragLeave = useCallback((event: DragEvent<HTMLDivElement>) => {
    if (disabled) {
      return;
    }
    if (!isChildNode(event.currentTarget, event.relatedTarget)) {
      setIsActive(false);
    }
  }, [disabled]);

  const handleDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setIsActive(false);
      if (disabled) {
        return;
      }
      const files = Array.from(event.dataTransfer?.files ?? []);
      if (files.length > 0) {
        onDropFiles(files);
      }
    },
    [onDropFiles, disabled]
  );

  return (
    <div
      className={`quantum-drag-zone${isActive ? " is-active" : ""}${
        disabled ? " is-disabled" : ""
      }`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      aria-disabled={disabled}
    >
      <div className="quantum-drag-veil" aria-hidden="true" />
      <div className="quantum-drag-content">
        {children ?? (
          <>
            <p className="quantum-drag-title">将文件拖入量子场</p>
            <p className="quantum-drag-hint">
              {hint ?? "释放即可建立纠缠连接"}
            </p>
          </>
        )}
      </div>
    </div>
  );
}
