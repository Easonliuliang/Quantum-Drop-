import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import type { SettingsPayload } from "../lib/types";
import { describeError } from "../lib/errors";
import { useTransfersStore } from "../store/useTransfersStore";

type RouteOption = {
  id: string;
  label: string;
  description: string;
};

const ROUTE_ORDER = ["lan", "p2p", "relay"] as const;
const ROUTES: RouteOption[] = [
  {
    id: "lan",
    label: "LAN",
    description: "Prefer local QUIC paths when peers share the same network.",
  },
  {
    id: "p2p",
    label: "P2P",
    description: "Use direct WebRTC channels when traversal is possible.",
  },
  {
    id: "relay",
    label: "Relay",
    description: "Fallback TURN relay for difficult network topologies.",
  },
];

const normaliseRoutes = (routes: string[]): string[] => {
  const set = new Set(routes);
  return ROUTE_ORDER.filter((route) => set.has(route));
};

const cloneSettings = (settings: SettingsPayload | null): SettingsPayload | null =>
  settings
    ? {
        ...settings,
        preferredRoutes: [...settings.preferredRoutes],
        chunkPolicy: { ...settings.chunkPolicy },
      }
    : null;

const withDefaults = (settings: SettingsPayload): SettingsPayload => ({
  ...settings,
  quantumMode: settings.quantumMode ?? true,
});

export default function SettingsPanel(): JSX.Element {
  const [settings, setSettings] = useState<SettingsPayload | null>(null);
  const [initial, setInitial] = useState<SettingsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const setQuantumMode = useTransfersStore((state) => state.setQuantumMode);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const payload = await invoke<SettingsPayload>("load_settings");
        if (!cancelled) {
          const hydrated = withDefaults(payload);
          setSettings(hydrated);
          setInitial(cloneSettings(hydrated));
          setQuantumMode(hydrated.quantumMode);
        }
      } catch (caught: unknown) {
        if (!cancelled) {
          setError(describeError(caught));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [setQuantumMode]);

  const isDirty = useMemo(() => {
    if (!settings || !initial) {
      return false;
    }
    const serialised = JSON.stringify(settings);
    const baseline = JSON.stringify(initial);
    return serialised !== baseline;
  }, [settings, initial]);

  const toggleRoute = (routeId: string) => {
    setSettings((current) => {
      if (!current) {
        return current;
      }
      const selected = new Set(current.preferredRoutes);
      if (selected.has(routeId)) {
        if (selected.size === 1) {
          return current; // keep at least one route selected
        }
        selected.delete(routeId);
      } else {
        selected.add(routeId);
      }
      const preferredRoutes = normaliseRoutes(Array.from(selected));
      return {
        ...current,
        preferredRoutes,
      };
    });
  };

  const toggleRelay = (enabled: boolean) => {
    setSettings((current) => {
      if (!current) {
        return current;
      }
      let preferredRoutes = [...current.preferredRoutes];
      if (!enabled) {
        preferredRoutes = preferredRoutes.filter((route) => route !== "relay");
      } else if (!preferredRoutes.includes("relay")) {
        preferredRoutes = normaliseRoutes([...preferredRoutes, "relay"]);
      }
      return {
        ...current,
        relayEnabled: enabled,
        preferredRoutes,
      };
    });
  };

  const toggleAdaptiveChunks = (enabled: boolean) => {
    setSettings((current) =>
      current
        ? {
            ...current,
            chunkPolicy: { ...current.chunkPolicy, adaptive: enabled },
          }
        : current
    );
  };

  const toggleQuantumUi = (enabled: boolean) => {
    setSettings((current) =>
      current
        ? {
            ...current,
            quantumMode: enabled,
          }
        : current
    );
    setQuantumMode(enabled);
  };

  const handleChunkBoundChange = (field: "minBytes" | "maxBytes", value: number) => {
    setSettings((current) => {
      if (!current) {
        return current;
      }
      const clampMiB = (input: number, fallbackBytes: number) => {
        if (Number.isNaN(input)) {
          return Math.round(fallbackBytes / (1024 * 1024));
        }
        const rounded = Math.round(input);
        return Math.min(16, Math.max(2, rounded));
      };
      const targetMiB = clampMiB(value, current.chunkPolicy[field]);
      const nextBytes = targetMiB * 1024 * 1024;
      const policy = { ...current.chunkPolicy, [field]: nextBytes };
      if (field === "minBytes" && policy.minBytes > policy.maxBytes) {
        policy.maxBytes = policy.minBytes;
      }
      if (field === "maxBytes" && policy.maxBytes < policy.minBytes) {
        policy.minBytes = policy.maxBytes;
      }
      return {
        ...current,
        chunkPolicy: policy,
      };
    });
  };

  const handleTtlChange = (value: number) => {
    setSettings((current) =>
      current
        ? {
            ...current,
            codeExpireSec: Number.isNaN(value) ? current.codeExpireSec : Math.max(60, Math.round(value)),
          }
        : current
    );
  };

  const handleSave = async () => {
    if (!settings || saving || !isDirty) {
      return;
    }
    setSaving(true);
    setFeedback(null);
    setError(null);
    try {
      const payload = await invoke<SettingsPayload>("update_settings", {
        payload: settings,
      });
      const hydrated = withDefaults(payload);
      setSettings(hydrated);
      setInitial(cloneSettings(hydrated));
      setQuantumMode(hydrated.quantumMode);
      setFeedback("Settings saved successfully");
    } catch (caught: unknown) {
      setError(describeError(caught));
    } finally {
      setSaving(false);
    }
  };

  if (loading || !settings) {
    return (
      <section className="panel-content" aria-label="Runtime settings">
        <div className="panel-section">
          <h2>Settings</h2>
          <p className="panel-subtitle">Loading runtime configuration…</p>
        </div>
      </section>
    );
  }

  const minChunkMiB = Math.round(settings.chunkPolicy.minBytes / (1024 * 1024));
  const maxChunkMiB = Math.round(settings.chunkPolicy.maxBytes / (1024 * 1024));

  return (
    <section className="panel-content" aria-label="Runtime settings">
      <div className="panel-section">
        <h2>Settings</h2>
        <p className="panel-subtitle">
          Adjust the native runtime routing preferences and code expiry policy.
        </p>
        {feedback && <div className="toast toast-success">{feedback}</div>}
        {error && <div className="error-inline">{error}</div>}

        <fieldset className="form-group">
          <legend>Preferred Routes</legend>
          <p className="form-hint">
            Courier will attempt routes in the order below. At least one route must remain enabled.
          </p>
          <div className="route-options">
            {ROUTES.map((route) => {
              const checked = settings.preferredRoutes.includes(route.id);
              const disabled = route.id === "relay" && !settings.relayEnabled;
              return (
                <label key={route.id} className={disabled ? "checkbox disabled" : "checkbox"}>
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={disabled}
                    onChange={() => toggleRoute(route.id)}
                  />
                  <span className="checkbox-label">{route.label}</span>
                  <span className="checkbox-description">{route.description}</span>
                </label>
              );
            })}
          </div>
        </fieldset>

        <div className="form-group">
          <label htmlFor="relay-toggle">Relay transport</label>
          <div className="input-row">
            <input
              id="relay-toggle"
              type="checkbox"
              checked={settings.relayEnabled}
              onChange={(event) => toggleRelay(event.target.checked)}
            />
            <span className="checkbox-description">
              Enable TURN relay fallback. Required for the relay route toggle above.
            </span>
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="code-ttl">Code expiry (seconds)</label>
          <input
            id="code-ttl"
            type="number"
            min={60}
            step={30}
            value={settings.codeExpireSec}
            onChange={(event) => handleTtlChange(Number(event.target.value))}
          />
          <p className="form-hint">
            Defines the default lifetime for generated courier codes (minimum 60 seconds).
          </p>
        </div>

        <div className="form-group">
          <label htmlFor="quantum-ui-toggle">Quantum tunnel interface</label>
          <div className="input-row">
            <input
              id="quantum-ui-toggle"
              type="checkbox"
              checked={settings.quantumMode}
              onChange={(event) => toggleQuantumUi(event.target.checked)}
            />
            <span className="checkbox-description">
              Replace legacy progress bars with the quantum tunnel visuals.
            </span>
          </div>
        </div>

        <details className="form-group advanced">
          <summary>Advanced chunk sizing</summary>
          <p className="form-hint">
            Adaptive sizing raises chunk payloads when latency is high and shrinks them on weak links. Values are stored in MiB.
          </p>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={settings.chunkPolicy.adaptive}
              onChange={(event) => toggleAdaptiveChunks(event.target.checked)}
            />
            <span className="checkbox-label">Enable adaptive chunk policy</span>
            <span className="checkbox-description">
              RTT &gt; 80ms expands up to the max size, unreliable routes fall back to the minimum.
            </span>
          </label>
          <div className="input-row chunk-range">
            <label htmlFor="chunk-min">Min chunk (MiB)</label>
            <input
              id="chunk-min"
              type="number"
              min={2}
              max={maxChunkMiB}
              value={minChunkMiB}
              disabled={!settings.chunkPolicy.adaptive}
              onChange={(event) =>
                handleChunkBoundChange("minBytes", Number(event.target.value))
              }
            />
            <label htmlFor="chunk-max">Max chunk (MiB)</label>
            <input
              id="chunk-max"
              type="number"
              min={minChunkMiB}
              max={16}
              value={maxChunkMiB}
              disabled={!settings.chunkPolicy.adaptive}
              onChange={(event) =>
                handleChunkBoundChange("maxBytes", Number(event.target.value))
              }
            />
          </div>
        </details>

        <div className="form-actions">
          <button
            className="primary"
            onClick={() => {
              void handleSave();
            }}
            disabled={!isDirty || saving}
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>
    </section>
  );
}
