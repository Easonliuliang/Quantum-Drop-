import type { TransferPhase } from "../lib/types";
import { QUANTUM_PHASE_COPY } from "../lib/quantumPhases";

type QuantumStatusIndicatorProps = {
  phase: TransferPhase;
  hint?: string | null;
};

export default function QuantumStatusIndicator({
  phase,
  hint,
}: QuantumStatusIndicatorProps): JSX.Element {
  const copy = QUANTUM_PHASE_COPY[phase];
  return (
    <div
      className={`quantum-status quantum-phase-${phase}`}
      role="status"
      aria-live="polite"
    >
      <span className="quantum-status-label">{copy.title}</span>
      <span className="quantum-status-description">
        {hint ?? copy.description}
      </span>
    </div>
  );
}
