import {
  useCallback,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type KeyboardEvent,
  type MouseEvent,
  type CSSProperties,
} from "react";

export type QuantumDropzonePhase =
  | "preparing"
  | "pairing"
  | "connecting"
  | "transferring"
  | "finalizing"
  | "done"
  | "error";

type QuantumDropzoneRoute = "lan" | "p2p" | "relay";

type QuantumDropzoneProps = {
  onFiles: (files: File[]) => void;
  phase: QuantumDropzonePhase;
  route?: QuantumDropzoneRoute;
  disabled?: boolean;
};

const PHASE_STATE: Record<QuantumDropzonePhase, "cloud" | "tunnel" | "collapse" | "decohere"> = {
  preparing: "cloud",
  pairing: "cloud",
  connecting: "cloud",
  transferring: "tunnel",
  finalizing: "collapse",
  done: "collapse",
  error: "decohere",
};

const ELECTRON_COUNT = 3;
const PARTICLE_COUNT = 24;

const isLeavingNode = (current: EventTarget | null, related: EventTarget | null) => {
  if (!(current instanceof HTMLElement)) {
    return true;
  }
  if (!(related instanceof HTMLElement)) {
    return true;
  }
  return !current.contains(related);
};

export default function QuantumDropzone({
  onFiles,
  phase,
  route = "p2p",
  disabled = false,
}: QuantumDropzoneProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const handleOpenDialog = useCallback(
    (event?: MouseEvent<HTMLDivElement> | KeyboardEvent<HTMLDivElement>) => {
      if (disabled) {
        return;
      }
      event?.preventDefault();
      inputRef.current?.click();
    },
    [disabled]
  );

  const resetInput = useCallback(() => {
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }, []);

  const handleFiles = useCallback(
    (files: File[]) => {
      if (!files.length) {
        return;
      }
      onFiles(files);
    },
    [onFiles]
  );

  const handleInputChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      if (disabled) {
        resetInput();
        return;
      }
      const list = event.target.files;
      const files = list ? Array.from(list) : [];
      handleFiles(files);
      resetInput();
    },
    [disabled, handleFiles, resetInput]
  );

  const handleDragEnter = useCallback((event: DragEvent<HTMLDivElement>) => {
    if (disabled) {
      return;
    }
    event.preventDefault();
    setDragActive(true);
  }, [disabled]);

  const handleDragOver = useCallback((event: DragEvent<HTMLDivElement>) => {
    if (disabled) {
      return;
    }
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "copy";
    }
    if (!dragActive) {
      setDragActive(true);
    }
  }, [disabled, dragActive]);

  const handleDragLeave = useCallback((event: DragEvent<HTMLDivElement>) => {
    if (disabled) {
      return;
    }
    if (isLeavingNode(event.currentTarget, event.relatedTarget)) {
      setDragActive(false);
    }
  }, [disabled]);

  const handleDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragActive(false);
      if (disabled) {
        return;
      }
      const list = event.dataTransfer?.files;
      const files = list ? Array.from(list) : [];
      handleFiles(files);
    },
    [disabled, handleFiles]
  );

  const handleKeyDown = useCallback((event: KeyboardEvent<HTMLDivElement>) => {
    if (disabled) {
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      handleOpenDialog(event);
    }
  }, [disabled, handleOpenDialog]);

  const phaseState = PHASE_STATE[phase] ?? "cloud";
  const classes = useMemo(() => {
    const base = ["qdz", `qdz-${phaseState}`, `qdz--${route}`];
    if (dragActive) {
      base.push("qdz-drag-active");
    }
    if (disabled) {
      base.push("is-disabled");
    }
    return base.join(" ");
  }, [phaseState, route, dragActive, disabled]);

  const particles = useMemo(() => {
    return Array.from({ length: PARTICLE_COUNT }, (_, index) => {
      const angle = (index / PARTICLE_COUNT) * Math.PI * 2;
      const orbit = 48 + (index % 6) * 12;
      const depth = 0.4 + ((index % 5) * 0.1);
      const delay = (index % 10) * -0.4;
      const style: CSSProperties = {
        "--tx": `${Math.cos(angle) * orbit}px`,
        "--ty": `${Math.sin(angle) * orbit}px`,
        "--delay": `${delay}s`,
        "--depth": depth,
      } as CSSProperties;
      return {
        id: index,
        style,
      };
    });
  }, []);

  const electrons = useMemo(() => {
    return Array.from({ length: ELECTRON_COUNT }, (_, index) => {
      const style: CSSProperties = {
        "--offset": `${index * 120}deg`,
        "--delay": `${index * -0.6}s`,
      } as CSSProperties;
      return {
        id: index,
        style,
      };
    });
  }, []);

  return (
    <div
      className={classes}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      onClick={() => {
        handleOpenDialog();
      }}
      onKeyDown={handleKeyDown}
      onDragEnter={handleDragEnter}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      data-phase={phase}
      data-route={route}
    >
      <input
        ref={inputRef}
        className="qdz-input"
        type="file"
        multiple
        tabIndex={-1}
        aria-hidden="true"
        onChange={handleInputChange}
      />
      <span className="sr-only">drag files to start quantum transfer</span>
      <div className="qdz-surface" aria-hidden="true">
        <div className="qdz-singularity" />
        <div className="qdz-wave-function">
          <div className="probability-cloud" />
          <div className="interference-pattern" />
        </div>
        <div className="qdz-quantum-rings">
          <span className="ring ring-1" />
          <span className="ring ring-2" />
          <span className="ring ring-3" />
        </div>
        <div className="qdz-quantum-particles">
          {particles.map((particle) => (
            <span
              key={particle.id}
              className="particle"
              style={particle.style}
            />
          ))}
        </div>
        <div className="qdz-drag-sensor">
          <span className="drag-orbit" />
          <div className="electrons">
            {electrons.map((electron) => (
              <span
                key={electron.id}
                className={`electron electron-${electron.id + 1}`}
                style={electron.style}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
