use std::{
    fs,
    path::{Path, PathBuf},
    sync::RwLock,
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const ROUTE_ORDER: &[&str] = &["lan", "p2p", "relay"];
const MIN_CODE_TTL: i64 = 60;
const DEFAULT_CODE_TTL: i64 = 900;
const MIN_CHUNK_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

fn default_true() -> bool {
    true
}

fn default_intensity() -> u8 {
    2
}

fn default_speed() -> f32 {
    1.0
}

fn default_quality() -> String {
    "medium".to_string()
}

fn default_fps() -> u16 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdaptiveChunkPolicy {
    pub enabled: bool,
    pub min_bytes: u64,
    pub max_bytes: u64,
}

impl Default for AdaptiveChunkPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_bytes: MIN_CHUNK_BYTES,
            max_bytes: MAX_CHUNK_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSettings {
    pub preferred_routes: Vec<String>,
    pub code_expire_sec: i64,
    pub relay_enabled: bool,
    #[serde(default = "default_true")]
    pub quantum_mode: bool,
    #[serde(default = "default_true")]
    pub minimal_quantum_ui: bool,
    #[serde(default = "default_intensity")]
    pub quantum_intensity: u8,
    #[serde(default = "default_speed")]
    pub quantum_speed: f32,
    #[serde(default = "default_true")]
    pub animations_enabled: bool,
    #[serde(default = "default_true")]
    pub audio_enabled: bool,
    #[serde(default = "default_true", rename = "enable3DQuantum")]
    pub enable_3d_quantum: bool,
    #[serde(default = "default_quality", rename = "quantum3DQuality")]
    pub quantum_3d_quality: String,
    #[serde(default = "default_fps", rename = "quantum3DFps")]
    pub quantum_3d_fps: u16,
    #[serde(default = "default_true")]
    pub wormhole_mode: bool,
    #[serde(default)]
    pub chunk_policy: AdaptiveChunkPolicy,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            preferred_routes: ROUTE_ORDER.iter().map(|value| value.to_string()).collect(),
            code_expire_sec: DEFAULT_CODE_TTL,
            relay_enabled: true,
            quantum_mode: true,
            minimal_quantum_ui: true,
            quantum_intensity: default_intensity(),
            quantum_speed: default_speed(),
            animations_enabled: true,
            audio_enabled: true,
            enable_3d_quantum: true,
            quantum_3d_quality: default_quality(),
            quantum_3d_fps: default_fps(),
            wormhole_mode: true,
            chunk_policy: AdaptiveChunkPolicy::default(),
        }
    }
}

impl RuntimeSettings {
    fn normalised(mut self) -> Self {
        let mut filtered = Vec::new();
        for route in &self.preferred_routes {
            let lower = route.trim().to_ascii_lowercase();
            if lower.is_empty() {
                continue;
            }
            if lower == "relay" && !self.relay_enabled {
                continue;
            }
            if ROUTE_ORDER.iter().any(|candidate| candidate == &lower)
                && filtered.iter().all(|existing: &String| existing != &lower)
            {
                filtered.push(lower);
            }
        }

        if filtered.is_empty() {
            filtered = ROUTE_ORDER
                .iter()
                .filter(|value| **value != "relay" || self.relay_enabled)
                .map(|value| value.to_string())
                .collect();
        } else {
            filtered.sort_by_key(|value| {
                ROUTE_ORDER
                    .iter()
                    .position(|candidate| candidate == &value.as_str())
                    .unwrap_or(usize::MAX)
            });
        }
        self.preferred_routes = filtered;
        if self.code_expire_sec < MIN_CODE_TTL {
            self.code_expire_sec = MIN_CODE_TTL;
        }
        if !(1..=3).contains(&self.quantum_intensity) {
            self.quantum_intensity = default_intensity();
        }
        if !self.quantum_speed.is_finite() {
            self.quantum_speed = default_speed();
        }
        self.quantum_speed = self.quantum_speed.clamp(0.6, 1.6);
        let lowered = self.quantum_3d_quality.trim().to_ascii_lowercase();
        if !matches!(lowered.as_str(), "low" | "medium" | "high") {
            self.quantum_3d_quality = default_quality();
        } else {
            self.quantum_3d_quality = lowered;
        }
        if self.quantum_3d_fps == 0 {
            self.quantum_3d_fps = default_fps();
        }
        self.quantum_3d_fps = self.quantum_3d_fps.clamp(30, 60);
        let min_bytes = Self::clamp_chunk_bytes(self.chunk_policy.min_bytes);
        let mut max_bytes = Self::clamp_chunk_bytes(self.chunk_policy.max_bytes);
        if max_bytes < min_bytes {
            max_bytes = min_bytes;
        }
        self.chunk_policy.min_bytes = min_bytes;
        self.chunk_policy.max_bytes = max_bytes;
        self
    }

    fn clamp_chunk_bytes(value: u64) -> u64 {
        let clamped = value.clamp(MIN_CHUNK_BYTES, MAX_CHUNK_BYTES);
        let unit = 1024 * 1024;
        let multiples = (clamped + unit - 1) / unit;
        (multiples * unit).clamp(MIN_CHUNK_BYTES, MAX_CHUNK_BYTES)
    }
}

#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    settings: RwLock<RuntimeSettings>,
}

impl ConfigStore {
    pub fn initialise(app: &AppHandle) -> Result<Self> {
        let mut base = app
            .path()
            .app_data_dir()
            .context("failed to resolve app data dir for config store")?;
        base.push("config");
        fs::create_dir_all(&base).context("failed to prepare config directory")?;
        let path = base.join("settings.json");
        let initial = if path.exists() {
            Self::read_settings(&path).unwrap_or_default()
        } else {
            RuntimeSettings::default()
        };
        Ok(Self {
            path,
            settings: RwLock::new(initial.normalised()),
        })
    }

    pub fn get(&self) -> RuntimeSettings {
        self.settings
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn update(&self, next: RuntimeSettings) -> Result<RuntimeSettings> {
        let mut guard = self
            .settings
            .write()
            .map_err(|_| anyhow!("config store poisoned"))?;
        let normalised = next.normalised();
        let json =
            serde_json::to_vec_pretty(&normalised).context("failed to serialise settings json")?;
        fs::write(&self.path, json)
            .with_context(|| format!("failed to persist settings to {}", self.path.display()))?;
        *guard = normalised.clone();
        Ok(normalised)
    }

    fn read_settings(path: &Path) -> Result<RuntimeSettings> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read settings from {}", path.display()))?;
        let parsed: RuntimeSettings =
            serde_json::from_str(&contents).context("invalid settings payload")?;
        Ok(parsed)
    }
}
