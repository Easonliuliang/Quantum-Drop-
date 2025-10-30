import { useEffect, useMemo, useRef } from "react";

import type { TransferPhase, TransferRoute } from "../lib/types";
import QuantumStatusIndicator from "./QuantumStatusIndicator";
import { playQuantumPing } from "../lib/quantumSound";

type QuantumTunnelProps = {
  phase: TransferPhase;
  route?: TransferRoute;
  canResume?: boolean;
  onResume?: () => void;
  hint?: string | null;
};

type TunnelStage = "cloud" | "tunnel" | "collapse" | "error";

const phaseToStage = (phase: TransferPhase): TunnelStage => {
  switch (phase) {
    case "preparing":
    case "pairing":
    case "connecting":
      return "cloud";
    case "transferring":
      return "tunnel";
    case "finalizing":
    case "done":
      return "collapse";
    case "error":
    default:
      return "error";
  }
};

const stageTone: Partial<Record<TunnelStage, "pair" | "tunnel" | "collapse">> =
  {
    cloud: "pair",
    tunnel: "tunnel",
    collapse: "collapse",
  };

const routeFriendlyLabel = (route?: TransferRoute) => {
  if (!route) {
    return null;
  }
  switch (route) {
    case "lan":
      return "LAN";
    case "p2p":
      return "P2P";
    case "relay":
      return "RELAY";
    case "cache":
      return "CACHE";
    default:
      return route.toUpperCase();
  }
};

export default function QuantumTunnel({
  phase,
  route,
  canResume = false,
  onResume,
  hint,
}: QuantumTunnelProps): JSX.Element {
  const stage = useMemo(() => phaseToStage(phase), [phase]);
  const previousStage = useRef<TunnelStage>(stage);

  useEffect(() => {
    if (previousStage.current !== stage) {
      const tone = stageTone[stage];
      if (tone) {
        void playQuantumPing(tone);
      }
      previousStage.current = stage;
    }
  }, [stage]);

  const routeLabel = routeFriendlyLabel(route);

  return (
    <div className={`qt-container stage-${stage}`}>
      <div className="quantum-tunnel-bg" aria-hidden="true" />
      <div className="qt-core">
        <div className="qt-field" aria-hidden="true">
          <div className="qt-photon-stream" />
          <div className="qt-starlight" />
        </div>
        <QuantumStatusIndicator phase={phase} hint={hint} />
        <div className="qt-footer">
          {routeLabel && (
            <span className={`quantum-route route-${route}`}>
              {routeLabel}
            </span>
          )}
          {canResume && onResume && (
            <button
              type="button"
              className="quantum-button"
              onClick={() => {
                onResume();
              }}
            >
              继续跃迁
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
