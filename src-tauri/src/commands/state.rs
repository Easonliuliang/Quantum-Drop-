use std::{collections::HashMap, path::PathBuf, sync::Arc};

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::types::{TransferDirection, TransferFileSummary, TransferStatus, TransferSummary};

#[derive(Debug, Clone)]
pub struct TrackedFile {
    pub name: String,
    pub size: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TransferTask {
    pub task_id: String,
    pub code: Option<String>,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub files: Vec<TrackedFile>,
    pub pot_path: Option<PathBuf>,
    pub session_key: String,
}

impl TransferTask {
    pub fn new(
        direction: TransferDirection,
        code: Option<String>,
        files: Vec<TrackedFile>,
        session_key: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            task_id: Uuid::new_v4().to_string(),
            code,
            direction,
            status: TransferStatus::Pending,
            created_at: now,
            updated_at: now,
            files,
            pot_path: None,
            session_key,
        }
    }

    pub fn to_summary(&self) -> TransferSummary {
        TransferSummary {
            task_id: self.task_id.clone(),
            code: self.code.clone(),
            direction: self.direction.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            route: None,
            files: self
                .files
                .iter()
                .map(|file| TransferFileSummary {
                    name: file.name.clone(),
                    size: file.size,
                })
                .collect(),
            pot_path: self.pot_path.as_ref().map(|p| p.display().to_string()),
        }
    }
}

#[derive(Debug)]
struct AppStateInner {
    transfers: RwLock<HashMap<String, TransferTask>>,
    code_lookup: RwLock<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                transfers: RwLock::new(HashMap::new()),
                code_lookup: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub async fn insert_task(&self, task: TransferTask) -> TransferTask {
        let mut transfers = self.inner.transfers.write().await;
        let mut code_lookup = self.inner.code_lookup.write().await;
        if let Some(code) = &task.code {
            code_lookup.insert(code.clone(), task.task_id.clone());
        }
        let task_id = task.task_id.clone();
        transfers.insert(task_id.clone(), task.clone());
        task
    }

    pub async fn update_task<F>(&self, task_id: &str, updater: F) -> Option<TransferTask>
    where
        F: FnOnce(&mut TransferTask),
    {
        let mut transfers = self.inner.transfers.write().await;
        let task = transfers.get_mut(task_id)?;
        updater(task);
        task.updated_at = Utc::now();
        Some(task.clone())
    }

    pub async fn set_status(&self, task_id: &str, status: TransferStatus) -> Option<TransferTask> {
        self.update_task(task_id, |task| {
            task.status = status.clone();
        })
        .await
    }

    pub async fn set_pot_path(&self, task_id: &str, pot_path: PathBuf) -> Option<TransferTask> {
        self.update_task(task_id, |task| {
            task.pot_path = Some(pot_path);
        })
        .await
    }

    pub async fn get_task(&self, task_id: &str) -> Option<TransferTask> {
        let transfers = self.inner.transfers.read().await;
        transfers.get(task_id).cloned()
    }

    pub async fn find_by_code(&self, code: &str) -> Option<TransferTask> {
        let code_lookup = self.inner.code_lookup.read().await;
        let task_id = code_lookup.get(code)?.clone();
        drop(code_lookup);
        self.get_task(&task_id).await
    }

    pub async fn list_transfers(&self, limit: Option<usize>) -> Vec<TransferSummary> {
        let transfers = self.inner.transfers.read().await;
        let mut items: Vec<_> = transfers.values().cloned().collect();
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        if let Some(limit) = limit {
            items.truncate(limit);
        }
        items.into_iter().map(|task| task.to_summary()).collect()
    }

    pub async fn track_code(&self, code: &str, task_id: &str) {
        let mut code_lookup = self.inner.code_lookup.write().await;
        code_lookup.insert(code.to_string(), task_id.to_string());
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
