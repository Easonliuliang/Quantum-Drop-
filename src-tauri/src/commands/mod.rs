mod state;
pub mod types;

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use tauri::{AppHandle, Emitter, EventTarget, Manager, State};
use tokio::time::sleep;

use crate::{
    attestation::{compute_file_attestation, write_proof_of_transition, FileAttestation},
    crypto,
    signaling::SessionTicket,
    store::{TransferRecord, TransferStore},
    transport::{Frame, Router, SelectedRoute, SessionDesc},
};

use state::{TrackedFile, TransferTask};
use types::{
    CommandError, ExportPotResponse, GenerateCodeResponse, TaskResponse, TransferDirection,
    TransferLifecycleEvent, TransferPhase, TransferProgressEvent, TransferRoute, TransferStatus,
    TransferSummary, VerifyPotResponse,
};

const DEFAULT_CODE_TTL_SECONDS: i64 = 900;
const MOCK_RECEIVE_FILE_SIZE: u64 = 2 * 1024 * 1024;

pub use state::AppState as SharedState;

#[tauri::command]
pub async fn courier_generate_code(
    state: State<'_, SharedState>,
    paths: Vec<String>,
    expire_sec: Option<i64>,
) -> Result<GenerateCodeResponse, String> {
    if paths.is_empty() {
        return Err(CommandError::invalid("At least one file is required").to_string());
    }
    let files = collect_files(&paths).map_err(|err| err.to_string())?;
    let code = crypto::generate_task_code(6);
    let session_key = crypto::derive_mock_session_key();
    let task = TransferTask::new(
        TransferDirection::Send,
        Some(code.clone()),
        files,
        session_key,
    );
    let task = state.insert_task(task).await;

    let ttl = expire_sec.unwrap_or(DEFAULT_CODE_TTL_SECONDS);
    let ticket = SessionTicket::new(code.clone(), ttl);
    state.track_code(&code, &task.task_id).await;

    let response = GenerateCodeResponse {
        task_id: task.task_id,
        code: ticket.code,
        qr_data_url: None,
    };
    Ok(response)
}

#[tauri::command]
pub async fn courier_send(
    app: AppHandle,
    state: State<'_, SharedState>,
    code: String,
    paths: Vec<String>,
) -> Result<TaskResponse, String> {
    if paths.is_empty() {
        return Err(CommandError::invalid("At least one file is required").to_string());
    }
    let files = collect_files(&paths).map_err(|err| err.to_string())?;
    let session_key = crypto::derive_mock_session_key();
    let maybe_task = state.find_by_code(&code).await;

    let task = if let Some(existing) = maybe_task {
        state
            .update_task(&existing.task_id, |task| {
                task.files = files.clone();
                task.status = TransferStatus::InProgress;
            })
            .await
            .unwrap_or(existing)
    } else {
        let task = TransferTask::new(
            TransferDirection::Send,
            Some(code.clone()),
            files,
            session_key,
        );
        let task = state.insert_task(task).await;
        state.track_code(&code, &task.task_id).await;
        task
    };

    spawn_transfer_runner(&app, state.inner().clone(), task.task_id.clone());

    Ok(TaskResponse {
        task_id: task.task_id,
    })
}

#[tauri::command]
pub async fn courier_receive(
    app: AppHandle,
    state: State<'_, SharedState>,
    code: String,
    save_dir: String,
) -> Result<TaskResponse, String> {
    let save_dir_path = Path::new(&save_dir);
    if !save_dir_path.exists() {
        fs::create_dir_all(save_dir_path)
            .map_err(|err| format!("failed to prepare save directory: {err}"))?;
    }
    if !save_dir_path.is_dir() {
        return Err(CommandError::invalid("save_dir must be a directory").to_string());
    }

    let mock_file_path = save_dir_path.join(format!("courier-receive-{code}.bin"));
    let tracked_file = TrackedFile {
        name: mock_file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("incoming.bin")
            .to_string(),
        size: 0,
        path: mock_file_path.clone(),
    };

    let session_key = crypto::derive_mock_session_key();
    let task = TransferTask::new(
        TransferDirection::Receive,
        Some(code.clone()),
        vec![tracked_file],
        session_key,
    );
    let task = state.insert_task(task).await;
    state.track_code(&code, &task.task_id).await;

    spawn_transfer_runner(&app, state.inner().clone(), task.task_id.clone());

    Ok(TaskResponse {
        task_id: task.task_id,
    })
}

#[tauri::command]
pub async fn courier_cancel(
    app: AppHandle,
    state: State<'_, SharedState>,
    task_id: String,
) -> Result<(), String> {
    let updated = state
        .set_status(&task_id, TransferStatus::Cancelled)
        .await
        .ok_or_else(|| CommandError::NotFound.to_string())?;

    let direction = updated.direction.clone();
    let code = updated.code.clone();
    persist_transfer_snapshot(&app, &updated, None, None, None);

    emit_event(
        &app,
        "transfer_failed",
        &TransferLifecycleEvent {
            task_id: task_id.clone(),
            direction,
            code,
            message: Some("Transfer cancelled by user".into()),
        },
    );
    Ok(())
}

#[tauri::command]
pub async fn export_pot(
    state: State<'_, SharedState>,
    task_id: String,
    out_dir: String,
) -> Result<ExportPotResponse, String> {
    let task = state
        .get_task(&task_id)
        .await
        .ok_or_else(|| CommandError::NotFound.to_string())?;

    let pot_path = task.pot_path.ok_or_else(|| {
        CommandError::invalid("Proof of Transition not yet available").to_string()
    })?;

    let out_dir_path = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir_path)
        .map_err(|err| format!("failed to create export directory: {err}"))?;

    let file_name = pot_path
        .file_name()
        .ok_or_else(|| CommandError::invalid("invalid pot path").to_string())?;
    let destination = out_dir_path.join(file_name);
    fs::copy(&pot_path, &destination).map_err(|err| format!("failed to export PoT file: {err}"))?;

    Ok(ExportPotResponse {
        pot_path: destination.display().to_string(),
    })
}

#[tauri::command]
pub async fn verify_pot(pot_path: String) -> Result<VerifyPotResponse, String> {
    let path = PathBuf::from(&pot_path);
    if !path.exists() {
        return Err(CommandError::invalid("PoT file not found").to_string());
    }

    let file = fs::File::open(&path).map_err(|err| format!("failed to open PoT file: {err}"))?;
    let proof: FileProof =
        serde_json::from_reader(file).map_err(|err| format!("invalid PoT JSON: {err}"))?;

    let valid = proof.version == "1" && !proof.files.is_empty();
    Ok(VerifyPotResponse {
        valid,
        reason: if valid {
            None
        } else {
            Some("Unsupported PoT version or empty file list".into())
        },
    })
}

#[tauri::command]
pub async fn list_transfers(
    state: State<'_, SharedState>,
    store: State<'_, TransferStore>,
    limit: Option<usize>,
) -> Result<Vec<TransferSummary>, String> {
    let mut persisted: Vec<TransferSummary> = store
        .list_transfers(limit, None)
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|record| TransferStore::to_summary(&record))
        .collect();

    let mut current = state.list_transfers(None).await;
    let known_ids: HashSet<String> = persisted
        .iter()
        .map(|summary| summary.task_id.clone())
        .collect();
    current.retain(|summary| !known_ids.contains(&summary.task_id));
    persisted.extend(current.into_iter());
    persisted.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    if let Some(limit) = limit {
        persisted.truncate(limit);
    }
    Ok(persisted)
}

#[derive(serde::Deserialize)]
struct FileProof {
    version: String,
    files: Vec<FileAttestation>,
}

fn spawn_transfer_runner(app: &AppHandle, state: SharedState, task_id: String) {
    let app_handle = app.clone();
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();

    tauri::async_runtime::spawn(async move {
        if let Err(err) = simulate_transfer(
            app_handle.clone(),
            state_clone.clone(),
            task_id_clone.clone(),
        )
        .await
        {
            let error_message = err.to_string();
            let updated = state_clone
                .set_status(&task_id_clone, TransferStatus::Failed)
                .await;
            let direction = if let Some(task_snapshot) = updated.clone() {
                persist_transfer_snapshot(&app_handle, &task_snapshot, None, None, None);
                task_snapshot.direction.clone()
            } else {
                state_clone
                    .get_task(&task_id_clone)
                    .await
                    .map(|task| task.direction)
                    .unwrap_or(TransferDirection::Send)
            };
            emit_progress(
                &app_handle,
                TransferProgressEvent {
                    task_id: task_id_clone.clone(),
                    phase: TransferPhase::Error,
                    progress: None,
                    bytes_sent: None,
                    bytes_total: None,
                    speed_bps: None,
                    route: None,
                    message: Some(error_message.clone()),
                },
            );
            emit_event(
                &app_handle,
                "transfer_failed",
                &TransferLifecycleEvent {
                    task_id: task_id_clone,
                    direction,
                    code: None,
                    message: Some(error_message),
                },
            );
        }
    });
}

async fn simulate_transfer(app: AppHandle, state: SharedState, task_id: String) -> Result<()> {
    let task = state
        .get_task(&task_id)
        .await
        .ok_or_else(|| anyhow!("transfer task not found"))?;

    emit_log(
        &app,
        &task_id,
        format!("Transfer session key {}", task.session_key),
    );

    let router = Router::from_app(&app);
    let candidate_labels: Vec<String> = router
        .preferred_routes()
        .iter()
        .map(|route| route.label().to_string())
        .collect();
    emit_log(
        &app,
        &task_id,
        format!("Route candidates: {:?}", candidate_labels),
    );

    emit_event(
        &app,
        "transfer_started",
        &TransferLifecycleEvent {
            task_id: task_id.clone(),
            direction: task.direction.clone(),
            code: task.code.clone(),
            message: None,
        },
    );
    state.set_status(&task_id, TransferStatus::InProgress).await;

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Preparing,
            progress: Some(0.05),
            bytes_sent: None,
            bytes_total: None,
            speed_bps: None,
            route: None,
            message: Some("Preparing transfer context".into()),
        },
    );
    sleep(Duration::from_millis(200)).await;

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Pairing,
            progress: Some(0.15),
            bytes_sent: None,
            bytes_total: None,
            speed_bps: None,
            route: None,
            message: Some("Exchanging pairing code".into()),
        },
    );
    sleep(Duration::from_millis(200)).await;

    let session = SessionDesc {
        session_id: task_id.clone(),
    };
    let SelectedRoute {
        route: selected_route,
        mut stream,
    } = router
        .connect(&session)
        .await
        .map_err(|err| anyhow!("transport selection failed: {err}"))?;
    emit_log(
        &app,
        &task_id,
        format!("Selected transport route {}", selected_route.label()),
    );
    let route = TransferRoute::from(selected_route.clone());

    stream
        .send(Frame::Control("handshake".into()))
        .await
        .map_err(|err| anyhow!("transport handshake failed: {err}"))?;
    if let Ok(frame) = stream.recv().await {
        emit_log(&app, &task_id, format!("Control frame echo: {:?}", frame));
    }

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Connecting,
            progress: Some(0.25),
            bytes_sent: None,
            bytes_total: None,
            speed_bps: None,
            route: Some(route.clone()),
            message: Some(format!(
                "{} route established",
                route_label(&route).to_uppercase()
            )),
        },
    );

    let mut tracked_files = task.files.clone();

    let total_bytes: u64 = tracked_files.iter().map(|f| f.size).sum();
    let total_bytes = if total_bytes == 0 {
        MOCK_RECEIVE_FILE_SIZE
    } else {
        total_bytes
    };

    let steps = 4;
    for idx in 1..=steps {
        sleep(Duration::from_millis(350)).await;
        let sent_fraction = idx as f32 / steps as f32;
        let sent_bytes = (total_bytes as f32 * sent_fraction) as u64;
        stream
            .send(Frame::Data(vec![idx as u8; 256]))
            .await
            .map_err(|err| anyhow!("transport failed: {err}"))?;
        emit_progress(
            &app,
            TransferProgressEvent {
                task_id: task_id.clone(),
                phase: TransferPhase::Transferring,
                progress: Some(0.25 + sent_fraction * 0.5),
                bytes_sent: Some(sent_bytes),
                bytes_total: Some(total_bytes),
                speed_bps: Some(8 * 1024 * 1024),
                route: Some(route.clone()),
                message: Some("Streaming payload".into()),
            },
        );
    }

    stream.close().await.ok();

    if matches!(task.direction, TransferDirection::Receive) {
        tracked_files = materialise_mock_payload(&tracked_files).await?;
        let updated_files = tracked_files.clone();
        state
            .update_task(&task_id, |task| {
                task.files = updated_files;
            })
            .await;
    }

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Finalizing,
            progress: Some(0.85),
            bytes_sent: Some(total_bytes),
            bytes_total: Some(total_bytes),
            speed_bps: Some(4 * 1024 * 1024),
            route: Some(route.clone()),
            message: Some("Finalising transfer & generating proof".into()),
        },
    );

    let mut attestations = Vec::new();
    for tracked in &tracked_files {
        let attestation = compute_file_attestation(&tracked.path)
            .with_context(|| format!("unable to attest file {}", tracked.path.display()))?;
        attestations.push(attestation);
    }

    let proofs_dir = default_proofs_dir(&app)?;
    let route_label_str = route_label(&route).to_string();
    let pot_path =
        write_proof_of_transition(&task_id, &attestations, &route_label_str, &proofs_dir)?;
    state.set_pot_path(&task_id, pot_path.clone()).await;
    if let Some(task_snapshot) = state.set_status(&task_id, TransferStatus::Completed).await {
        persist_transfer_snapshot(
            &app,
            &task_snapshot,
            Some(total_bytes),
            Some(total_bytes),
            Some(route_label_str.clone()),
        );
    }

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Done,
            progress: Some(1.0),
            bytes_sent: Some(total_bytes),
            bytes_total: Some(total_bytes),
            speed_bps: None,
            route: Some(route.clone()),
            message: Some("Transfer completed".into()),
        },
    );

    emit_event(
        &app,
        "transfer_completed",
        &TransferLifecycleEvent {
            task_id: task_id.clone(),
            direction: task.direction.clone(),
            code: task.code.clone(),
            message: Some(pot_path.display().to_string()),
        },
    );

    emit_log(
        &app,
        &task_id,
        format!("Proof of Transition stored at {}", pot_path.display()),
    );

    Ok(())
}

fn emit_event<T>(app: &AppHandle, event: &str, payload: &T)
where
    T: serde::Serialize + Clone,
{
    if let Err(err) = app.emit_to(EventTarget::app(), event, payload.clone()) {
        eprintln!("failed to emit event {event}: {err}");
    }
}

fn persist_transfer_snapshot(
    app: &AppHandle,
    task: &TransferTask,
    bytes_sent: Option<u64>,
    bytes_total: Option<u64>,
    route: Option<String>,
) {
    let store = app.state::<TransferStore>();
    let computed_total: u64 = task.files.iter().map(|file| file.size).sum();
    let total = bytes_total.or_else(|| (computed_total > 0).then_some(computed_total));
    let sent = bytes_sent.or(total);
    let record = TransferRecord {
        id: task.task_id.clone(),
        code: task.code.clone(),
        direction: task.direction.clone(),
        status: task.status.clone(),
        bytes_total: total,
        bytes_sent: sent,
        route,
        pot_path: task
            .pot_path
            .as_ref()
            .map(|path| path.display().to_string()),
        created_at: task.created_at.timestamp_millis(),
        updated_at: task.updated_at.timestamp_millis(),
    };
    if let Err(err) = store.insert_or_update(&record) {
        eprintln!("failed to persist transfer {}: {err}", task.task_id);
    }
}

fn emit_progress(app: &AppHandle, payload: TransferProgressEvent) {
    emit_event(app, "transfer_progress", &payload);
}

fn emit_log(app: &AppHandle, task_id: &str, message: String) {
    emit_event(
        app,
        "transfer_log",
        &LogPayload {
            task_id: task_id.to_string(),
            message,
        },
    );
}

#[derive(Clone, serde::Serialize)]
struct LogPayload {
    task_id: String,
    message: String,
}

fn collect_files(paths: &[String]) -> Result<Vec<TrackedFile>> {
    let mut files = Vec::new();
    for path in paths {
        let path_obj = PathBuf::from(path);
        if !path_obj.exists() {
            return Err(anyhow!("File not found: {}", path_obj.display()));
        }
        let metadata = path_obj
            .metadata()
            .context("failed to read file metadata")?;
        if metadata.is_dir() {
            return Err(anyhow!(
                "Directories are not yet supported: {}",
                path_obj.display()
            ));
        }
        files.push(TrackedFile {
            name: path_obj
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string(),
            size: metadata.len(),
            path: path_obj,
        });
    }
    Ok(files)
}

fn default_proofs_dir(app: &AppHandle) -> Result<PathBuf> {
    let mut dir = app
        .path()
        .app_data_dir()
        .map_err(|err| anyhow!("failed to resolve app data dir: {err}"))?;
    dir.push("proofs");
    Ok(dir)
}

fn route_label(route: &TransferRoute) -> &'static str {
    match route {
        TransferRoute::Lan => "lan",
        TransferRoute::P2p => "p2p",
        TransferRoute::Relay => "relay",
        TransferRoute::Cache => "cache",
    }
}

async fn materialise_mock_payload(files: &[TrackedFile]) -> Result<Vec<TrackedFile>> {
    let mut results = Vec::new();
    for tracked in files {
        if let Some(parent) = tracked.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("unable to create directory {}", parent.display()))?;
        }
        let mut data = vec![0u8; MOCK_RECEIVE_FILE_SIZE as usize];
        for (idx, byte) in data.iter_mut().enumerate() {
            *byte = (idx % 251) as u8;
        }
        tokio::fs::write(&tracked.path, &data)
            .await
            .with_context(|| format!("failed to write mock payload {}", tracked.path.display()))?;
        results.push(TrackedFile {
            name: tracked.name.clone(),
            size: MOCK_RECEIVE_FILE_SIZE,
            path: tracked.path.clone(),
        });
    }
    Ok(results)
}
