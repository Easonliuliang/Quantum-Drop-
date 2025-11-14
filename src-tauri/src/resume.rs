use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::{config::AdaptiveChunkPolicy, transport::RouteKind};

const MIN_CHUNK_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkCatalog {
    pub chunk_size: u64,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub received_chunks: Vec<bool>,
}

impl ChunkCatalog {
    pub fn new(total_bytes: u64, chunk_size: u64) -> Self {
        let adjusted_size = chunk_size.max(MIN_CHUNK_BYTES).min(MAX_CHUNK_BYTES);
        let effective_total = if total_bytes == 0 {
            adjusted_size
        } else {
            total_bytes
        };
        let total_chunks = if effective_total == 0 {
            1
        } else {
            ((effective_total + adjusted_size - 1) / adjusted_size).max(1)
        };
        Self {
            chunk_size: adjusted_size,
            total_chunks,
            total_bytes: effective_total,
            received_chunks: vec![false; total_chunks as usize],
        }
    }

    pub fn mark_received(&mut self, index: u64) -> bool {
        if let Some(slot) = self.received_chunks.get_mut(index as usize) {
            let was_set = *slot;
            *slot = true;
            return !was_set;
        }
        false
    }

    pub fn reconcile_total_bytes(&mut self, total_bytes: u64) {
        let effective_total = if total_bytes == 0 {
            self.chunk_size
        } else {
            total_bytes
        };
        let required_chunks = ((effective_total + self.chunk_size - 1) / self.chunk_size).max(1);
        self.total_bytes = effective_total;
        if required_chunks as usize != self.received_chunks.len() {
            self.received_chunks.resize(required_chunks as usize, false);
        }
        self.total_chunks = required_chunks;
    }

    pub fn missing_indices(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|idx| {
                let index = *idx as usize;
                self.received_chunks
                    .get(index)
                    .map(|flag| !*flag)
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.received_chunks
            .iter()
            .take(self.total_chunks as usize)
            .all(|flag| *flag)
    }

    pub fn chunk_length(&self, index: u64) -> u64 {
        if index + 1 >= self.total_chunks {
            let consumed = index.saturating_mul(self.chunk_size);
            let remaining = self.total_bytes.saturating_sub(consumed);
            if remaining == 0 {
                self.chunk_size
            } else {
                remaining.min(self.chunk_size)
            }
        } else {
            self.chunk_size.min(self.total_bytes)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResumeStore {
    base_dir: PathBuf,
}

impl ResumeStore {
    pub fn from_app(app: &AppHandle) -> Result<Self> {
        let mut path = app
            .path()
            .app_data_dir()
            .context("failed to resolve app data dir for resume store")?;
        path.push("cache");
        Self::with_base_dir(path)
    }

    pub fn with_base_dir(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)
            .with_context(|| format!("failed to prepare resume cache at {}", base_dir.display()))?;
        Ok(Self { base_dir })
    }

    pub fn load(&self, task_id: &str) -> Result<Option<ChunkCatalog>> {
        let path = self.path_for(task_id);
        if !path.exists() {
            return Ok(None);
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read resume catalog {}", path.display()))?;
        let catalog: ChunkCatalog = serde_json::from_str(&contents)
            .with_context(|| format!("invalid resume catalog {}", path.display()))?;
        Ok(Some(catalog))
    }

    pub fn store(&self, task_id: &str, catalog: &ChunkCatalog) -> Result<()> {
        let path = self.path_for(task_id);
        let payload =
            serde_json::to_vec_pretty(catalog).context("failed to serialise chunk catalog")?;
        fs::write(&path, payload)
            .with_context(|| format!("failed to persist resume catalog {}", path.display()))?;
        Ok(())
    }

    pub fn remove(&self, task_id: &str) -> Result<()> {
        let path = self.path_for(task_id);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove resume catalog {}", path.display()))?;
        }
        Ok(())
    }

    fn path_for(&self, task_id: &str) -> PathBuf {
        self.base_dir.join(format!("{task_id}-index.json"))
    }
}

pub fn derive_chunk_size(
    policy: &AdaptiveChunkPolicy,
    route: &RouteKind,
    observed_rtt: Duration,
    weak_network: bool,
    historical_success: Option<f32>,
) -> u64 {
    if !policy.enabled {
        return DEFAULT_CHUNK_BYTES;
    }
    let mut require_conservative = weak_network || matches!(route, RouteKind::Relay);
    if let Some(rate) = historical_success {
        if rate < 0.5 {
            require_conservative = true;
        }
    }
    if require_conservative {
        return align(policy.min_bytes.max(MIN_CHUNK_BYTES));
    }

    let rtt_ms = observed_rtt.as_millis() as u64;
    let mut suggestion = if rtt_ms > 150 {
        16 * 1024 * 1024
    } else if rtt_ms > 80 {
        8 * 1024 * 1024
    } else {
        DEFAULT_CHUNK_BYTES
    };
    if let Some(rate) = historical_success {
        if rate < 0.8 {
            suggestion = suggestion.min(8 * 1024 * 1024);
        }
    }
    suggestion = suggestion.clamp(policy.min_bytes, policy.max_bytes);
    align(suggestion)
}

fn align(value: u64) -> u64 {
    let unit = 1024 * 1024;
    let multiples = (value + unit - 1) / unit;
    (multiples * unit).clamp(MIN_CHUNK_BYTES, MAX_CHUNK_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_lan_streams;
    use crate::transport::{
        adapter::{MockLocalAdapter, TransportAdapter},
        Frame, SessionDesc,
    };

    #[test]
    fn bitmap_diff_only_returns_missing_indices() {
        let mut catalog = ChunkCatalog::new(32 * 1024 * 1024, 4 * 1024 * 1024);
        catalog.mark_received(0);
        catalog.mark_received(2);
        let missing = catalog.missing_indices();
        assert_eq!(missing, vec![1, 3, 4, 5, 6, 7]);
        let received = catalog.received_chunks.iter().filter(|flag| **flag).count();
        assert_eq!(received, 2);
    }

    #[test]
    fn chunk_size_respects_policy_bounds() {
        let policy = AdaptiveChunkPolicy {
            enabled: true,
            min_bytes: 2 * 1024 * 1024,
            max_bytes: 16 * 1024 * 1024,
            lan_streams: default_lan_streams(),
        };
        let size_fast = derive_chunk_size(
            &policy,
            &RouteKind::Lan,
            Duration::from_millis(20),
            false,
            Some(0.95),
        );
        assert_eq!(size_fast, 4 * 1024 * 1024);
        let size_medium = derive_chunk_size(
            &policy,
            &RouteKind::Lan,
            Duration::from_millis(120),
            false,
            Some(0.7),
        );
        assert_eq!(size_medium, 8 * 1024 * 1024);
        let size_slow = derive_chunk_size(
            &policy,
            &RouteKind::Lan,
            Duration::from_millis(220),
            false,
            Some(0.9),
        );
        assert_eq!(size_slow, 16 * 1024 * 1024);
        let weak = derive_chunk_size(
            &policy,
            &RouteKind::Relay,
            Duration::from_millis(90),
            true,
            None,
        );
        assert_eq!(weak, 2 * 1024 * 1024);
    }

    #[test]
    fn resume_store_roundtrip() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = ResumeStore::with_base_dir(temp.path().to_path_buf()).expect("store");
        let mut catalog = ChunkCatalog::new(10 * 1024 * 1024, 4 * 1024 * 1024);
        catalog.mark_received(1);
        store.store("task", &catalog).expect("store catalog");
        let loaded = store.load("task").expect("load").expect("catalog");
        assert_eq!(loaded.chunk_size, catalog.chunk_size);
        assert_eq!(loaded.total_bytes, catalog.total_bytes);
        assert_eq!(loaded.received_chunks, catalog.received_chunks);
        store.remove("task").expect("remove");
        assert!(store.load("task").expect("load after remove").is_none());
    }

    #[test]
    fn chunk_size_reduces_when_success_rate_low() {
        let policy = AdaptiveChunkPolicy {
            enabled: true,
            min_bytes: 2 * 1024 * 1024,
            max_bytes: 16 * 1024 * 1024,
            lan_streams: default_lan_streams(),
        };
        let value = derive_chunk_size(
            &policy,
            &RouteKind::Lan,
            Duration::from_millis(40),
            false,
            Some(0.4),
        );
        assert_eq!(value, 2 * 1024 * 1024);
    }

    #[tokio::test]
    #[ignore]
    async fn mock_adapter_resume_flow() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = ResumeStore::with_base_dir(temp.path().to_path_buf()).expect("store");
        let mut catalog = ChunkCatalog::new(8 * 1024 * 1024, 4 * 1024 * 1024);
        catalog.mark_received(0);
        store.store("task", &catalog).expect("store");

        let adapter = MockLocalAdapter::new();
        let session = SessionDesc::new("resume-test");
        let mut stream = adapter
            .connect(&session)
            .await
            .expect("connect mock adapter");

        let chunk_len = catalog.chunk_length(1);
        let payload = vec![0xAB; chunk_len as usize];
        stream.send(Frame::Data(payload)).await.expect("send chunk");
        catalog.mark_received(1);
        store
            .store("task", &catalog)
            .expect("persist updated catalog");
        let missing = catalog.missing_indices();
        assert!(missing.is_empty());
        stream.close().await.expect("close stream");
    }
}
