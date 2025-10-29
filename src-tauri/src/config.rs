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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSettings {
    pub preferred_routes: Vec<String>,
    pub code_expire_sec: i64,
    pub relay_enabled: bool,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            preferred_routes: ROUTE_ORDER.iter().map(|value| value.to_string()).collect(),
            code_expire_sec: DEFAULT_CODE_TTL,
            relay_enabled: true,
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
        self
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
        fs::write(&self.path, json).with_context(|| {
            format!(
                "failed to persist settings to {}",
                self.path.display()
            )
        })?;
        *guard = normalised.clone();
        Ok(normalised)
    }

    fn read_settings(path: &Path) -> Result<RuntimeSettings> {
        let contents = fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read settings from {}",
                path.display()
            )
        })?;
        let parsed: RuntimeSettings =
            serde_json::from_str(&contents).context("invalid settings payload")?;
        Ok(parsed)
    }
}
