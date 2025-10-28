import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type HealthCheck = {
  status: string;
  version: string;
};

const features: Array<{ title: string; description: string }> = [
  {
    title: "Zero-Hop Presence",
    description:
      "Files materialise instantly across devices and converge in the background."
  },
  {
    title: "Multipath Transport",
    description:
      "Courier Agent orchestrates QUIC, WebRTC, and TURN relays to maintain throughput."
  },
  {
    title: "Proof of Transition",
    description:
      "Every transfer emits a portable attestation that can be verified offline."
  }
];

export default function App(): JSX.Element {
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<HealthCheck>("health_check")
      .then(setHealth)
      .catch((err: unknown) => {
        if (err instanceof Error) {
          setError(err.message);
          return;
        }
        setError("Failed to reach the native runtime.");
      });
  }, []);

  const statusLabel = useMemo(() => {
    if (error) {
      return `Runtime Offline · ${error}`;
    }
    if (!health) {
      return "Contacting native runtime…";
    }
    return `Runtime Healthy · v${health.version}`;
  }, [health, error]);

  return (
    <main className="container">
      <header className="hero">
        <h1>Courier Agent</h1>
        <p className="tagline">
          Zero-path, verifiable file transit. Powered by Tauri&nbsp;+&nbsp;Rust.
        </p>
        <div className="status">{statusLabel}</div>
      </header>

      <section className="panel">
        <h2>Key Capabilities</h2>
        <ul>
          {features.map((feature) => (
            <li key={feature.title}>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel">
        <h2>Design Mantra</h2>
        <p>
          Courier Agent reframes transfer as spatial presence: files fold, jump,
          manifest, certify, and dissolve. Every device participates in the
          lattice; the network is an emergent property rather than a staging
          area.
        </p>
      </section>
    </main>
  );
}
