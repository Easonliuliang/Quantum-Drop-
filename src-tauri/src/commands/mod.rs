mod state;
pub mod types;

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, EventTarget, Manager, State};
use tokio::time::{sleep, timeout};

use crate::{
    attestation::{compute_file_attestation, write_proof_of_transition, ProofOfTransition},
    config::{AdaptiveChunkPolicy, ConfigStore, RuntimeSettings},
    crypto,
    resume::{derive_chunk_size, ChunkCatalog, ResumeStore},
    signaling::SessionTicket,
    store::{
        DeviceRecord, EntitlementRecord, IdentityRecord, IdentityStore, TransferRecord,
        TransferStore,
    },
    transport::{Frame, RouteKind, Router, SelectedRoute, SessionDesc},
};

use state::{TrackedFile, TransferTask};
use types::{
    AuthenticatedPayload, ChunkPolicyPayload, CommandError, DeviceRegistrationPayload,
    DeviceResponse, DevicesQueryPayload, DevicesResponse, DeviceUpdatePayload, EntitlementDto,
    EntitlementUpdatePayload, ErrorCode, ExportPotResponse, GenerateCodeResponse, HeartbeatPayload,
    IdentityRefPayload, IdentityRegistrationPayload, IdentityResponse, P2pSmokeTestResponse,
    ResumeProgressDto, SettingsPayload, SignedPathsPayload, SignedReceivePayload, TaskResponse,
    TransferDirection, TransferLifecycleEvent, TransferPhase, TransferProgressEvent,
    TransferRoute, TransferStatus, TransferSummary, VerifyPotResponse,
};

const MOCK_RECEIVE_FILE_SIZE: u64 = 2 * 1024 * 1024;

pub use state::AppState as SharedState;

#[tauri::command]
pub async fn auth_register_identity(
    store: State<'_, IdentityStore>,
    payload: IdentityRegistrationPayload,
) -> Result<IdentityResponse, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    if payload.public_key.trim().is_empty() {
        return Err(CommandError::invalid("public_key is required"));
    }
    let record = store
        .register_identity(
            payload.identity_id.trim(),
            payload.public_key.trim(),
            payload.label.as_deref(),
        )
        .map_err(CommandError::from)?;
    Ok(to_identity_response(&record))
}

#[tauri::command]
pub async fn auth_register_device(
    app: AppHandle,
    store: State<'_, IdentityStore>,
    payload: DeviceRegistrationPayload,
) -> Result<DeviceResponse, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    if payload.device_id.trim().is_empty() {
        return Err(CommandError::invalid("device_id is required"));
    }
    if payload.public_key.trim().is_empty() {
        return Err(CommandError::invalid("device public_key is required"));
    }
    if payload
        .signature
        .as_deref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(CommandError::invalid(
            "device signature is required for registration",
        ));
    }

    let identity = store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;

    let device_id = payload.device_id.trim();
    let public_key = payload.public_key.trim();
    let signature = payload.signature.as_deref().unwrap().trim();

    verify_device_signature(&identity, device_id, public_key, signature)?;

    let record = store
        .register_device(
            &identity.identity_id,
            device_id,
            public_key,
            payload.name.as_deref(),
            "active",
        )
        .map_err(CommandError::from)?;
    emit_devices_update(&app, &store, &identity.identity_id);
    Ok(to_device_response(&record))
}

#[tauri::command]
pub async fn auth_list_devices(
    store: State<'_, IdentityStore>,
    payload: DevicesQueryPayload,
) -> Result<DevicesResponse, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let devices = store
        .list_devices(payload.identity_id.trim())
        .map_err(CommandError::from)?;
    let items = devices.iter().map(to_device_response).collect();
    Ok(DevicesResponse { items })
}

#[tauri::command]
pub async fn auth_load_entitlement(
    store: State<'_, IdentityStore>,
    payload: IdentityRefPayload,
) -> Result<EntitlementDto, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let record = store
        .get_entitlement(payload.identity_id.trim())
        .map_err(CommandError::from)?;
    let dto = record
        .as_ref()
        .map(to_entitlement_dto)
        .unwrap_or_else(|| default_entitlement(payload.identity_id.trim()));
    Ok(dto)
}

#[tauri::command]
pub async fn auth_update_entitlement(
    app: AppHandle,
    store: State<'_, IdentityStore>,
    payload: EntitlementUpdatePayload,
) -> Result<EntitlementDto, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    if payload.plan.trim().is_empty() {
        return Err(CommandError::invalid("plan is required"));
    }
    store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let record = store
        .set_entitlement(
            payload.identity_id.trim(),
            payload.plan.trim(),
            payload.expires_at,
            &payload.features,
        )
        .map_err(CommandError::from)?;
    emit_devices_update(&app, &store, payload.identity_id.trim());
    Ok(to_entitlement_dto(&record))
}

#[tauri::command]
pub async fn auth_heartbeat_device(
    app: AppHandle,
    store: State<'_, IdentityStore>,
    auth: AuthenticatedPayload<HeartbeatPayload>,
) -> Result<DeviceResponse, CommandError> {
    let capabilities_value = auth.payload.capabilities.unwrap_or_default();
    let status_value = auth.payload.status.unwrap_or_else(|| "active".to_string());
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "heartbeat",
    )?;
    let record = store
        .touch_device(
            auth.identity_id.trim(),
            auth.device_id.trim(),
            None,
            Some(status_value.as_str()),
            Some(capabilities_value.as_slice()),
        )
        .map_err(CommandError::from)?;
    emit_devices_update(&app, &store, auth.identity_id.trim());
    Ok(to_device_response(&record))
}

#[tauri::command]
pub async fn auth_update_device(
    app: AppHandle,
    store: State<'_, IdentityStore>,
    auth: AuthenticatedPayload<DeviceUpdatePayload>,
) -> Result<DeviceResponse, CommandError> {
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "update_device",
    )?;
    let caps_slice = auth
        .payload
        .capabilities
        .as_ref()
        .map(|values| values.as_slice());
    let record = store
        .touch_device(
            auth.identity_id.trim(),
            auth.device_id.trim(),
            auth.payload.name.as_deref(),
            auth.payload.status.as_deref(),
            caps_slice,
        )
        .map_err(CommandError::from)?;
    emit_devices_update(&app, &store, auth.identity_id.trim());
    Ok(to_device_response(&record))
}

#[tauri::command]
pub async fn courier_generate_code(
    state: State<'_, SharedState>,
    config: State<'_, ConfigStore>,
    identity_store: State<'_, IdentityStore>,
    auth: AuthenticatedPayload<GeneratePayload>,
) -> Result<GenerateCodeResponse, CommandError> {
    verify_request(
        &identity_store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "generate",
    )?;
    if auth.payload.paths.is_empty() {
        return Err(CommandError::invalid("At least one file is required"));
    }
    let files = collect_files(&auth.payload.paths).map_err(CommandError::from)?;
    let code = crypto::generate_task_code(6);
    let session_key = crypto::derive_mock_session_key();
    let task = TransferTask::new(
        TransferDirection::Send,
        Some(code.clone()),
        files,
        session_key,
    );
    let task = state.insert_task(task).await;

    let settings = config.get();
    let ttl = auth
        .payload
        .expire_sec
        .unwrap_or(settings.code_expire_sec)
        .max(60);
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
    store: State<'_, IdentityStore>,
    auth: AuthenticatedPayload<SignedPathsPayload>,
    code: String,
) -> Result<TaskResponse, CommandError> {
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "send",
    )?;
    if auth.payload.paths.is_empty() {
        return Err(CommandError::invalid("At least one file is required"));
    }
    let files = collect_files(&auth.payload.paths).map_err(CommandError::from)?;
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
        return Err(CommandError::code_expired());
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
    store: State<'_, IdentityStore>,
    auth: AuthenticatedPayload<SignedReceivePayload>,
) -> Result<TaskResponse, CommandError> {
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "receive",
    )?;
    let save_dir_path = Path::new(&auth.payload.save_dir);
    if !save_dir_path.exists() {
        fs::create_dir_all(save_dir_path)
            .map_err(|err| CommandError::from_io(&err, "failed to prepare save directory"))?;
    }
    if !save_dir_path.is_dir() {
        return Err(CommandError::invalid("save_dir must be a directory"));
    }

    let mock_file_path = save_dir_path.join(format!("courier-receive-{}.bin", auth.payload.code));
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
        Some(auth.payload.code.clone()),
        vec![tracked_file],
        session_key,
    );
    let task = state.insert_task(task).await;
    state.track_code(&auth.payload.code, &task.task_id).await;

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
) -> Result<(), CommandError> {
    let updated = state
        .set_status(&task_id, TransferStatus::Cancelled)
        .await
        .ok_or_else(CommandError::not_found)?;

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
    if let Ok(store) = ResumeStore::from_app(&app) {
        if let Err(err) = store.remove(&task_id) {
            eprintln!("failed to cleanup resume catalog for {task_id}: {err}");
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn courier_resume(
    app: AppHandle,
    state: State<'_, SharedState>,
    task_id: String,
) -> Result<TaskResponse, CommandError> {
    let existing = state
        .get_task(&task_id)
        .await
        .ok_or_else(CommandError::not_found)?;
    if matches!(
        existing.status,
        TransferStatus::Completed | TransferStatus::Cancelled
    ) {
        return Err(CommandError::invalid("Transfer already finalised"));
    }
    state.set_status(&task_id, TransferStatus::Pending).await;
    spawn_transfer_runner(&app, state.inner().clone(), task_id.clone());
    Ok(TaskResponse { task_id })
}

#[tauri::command]
pub async fn courier_p2p_smoke_test(app: AppHandle) -> Result<P2pSmokeTestResponse, CommandError> {
    let router = Router::p2p_only(&app);
    let session = SessionDesc::new("p2p-smoke-test");

    let SelectedRoute {
        route, mut stream, ..
    } = router
        .connect(&session)
        .await
        .map_err(|err| CommandError::route_unreachable(format!("p2p connect failed: {err}")))?;

    let payload = vec![0_u8; 64 * 1024];
    stream
        .send(Frame::Data(payload.clone()))
        .await
        .map_err(|err| CommandError::route_unreachable(format!("p2p send failed: {err}")))?;

    let mut echoed: Option<u64> = None;
    for _ in 0..3 {
        let frame = match timeout(Duration::from_secs(5), stream.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(err)) => {
                stream.close().await.ok();
                return Err(CommandError::route_unreachable(format!(
                    "p2p recv failed: {err}"
                )));
            }
            Err(_) => {
                stream.close().await.ok();
                return Err(CommandError::route_unreachable("p2p echo timed out"));
            }
        };

        match frame {
            Frame::Data(bytes) => {
                echoed = Some(bytes.len() as u64);
                break;
            }
            Frame::Control(_) => continue,
        }
    }

    stream.close().await.ok();
    let echoed = echoed.ok_or_else(|| CommandError::route_unreachable("p2p echo missing"))?;

    Ok(P2pSmokeTestResponse {
        route: route.label().to_string(),
        bytes_echoed: echoed,
    })
}

#[tauri::command]
pub async fn courier_relay_smoke_test(
    _app: AppHandle,
) -> Result<P2pSmokeTestResponse, CommandError> {
    #[cfg(not(feature = "transport-relay"))]
    {
        let _ = _app;
        return Err(CommandError::route_unreachable(
            "relay transport disabled at build time",
        ));
    }

    #[cfg(feature = "transport-relay")]
    {
        let router = Router::new(vec![RouteKind::Relay]);
        let session = SessionDesc::new("relay-smoke-test");

        let SelectedRoute {
            route, mut stream, ..
        } = router.connect(&session).await.map_err(|err| {
            CommandError::route_unreachable(format!("relay connect failed: {err}"))
        })?;

        if route != RouteKind::Relay {
            stream.close().await.ok();
            return Err(CommandError::route_unreachable(
                "relay route unavailable (fallback engaged)",
            ));
        }

        let payload = vec![0_u8; 32 * 1024];
        stream
            .send(Frame::Data(payload.clone()))
            .await
            .map_err(|err| CommandError::route_unreachable(format!("relay send failed: {err}")))?;

        let mut echoed: Option<u64> = None;
        for _ in 0..3 {
            let frame = match timeout(Duration::from_secs(5), stream.recv()).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(err)) => {
                    stream.close().await.ok();
                    return Err(CommandError::route_unreachable(format!(
                        "relay recv failed: {err}"
                    )));
                }
                Err(_) => {
                    stream.close().await.ok();
                    return Err(CommandError::route_unreachable("relay echo timed out"));
                }
            };

            match frame {
                Frame::Data(bytes) => {
                    echoed = Some(bytes.len() as u64);
                    break;
                }
                Frame::Control(_) => continue,
            }
        }

        stream.close().await.ok();
        let echoed = echoed.ok_or_else(|| CommandError::route_unreachable("relay echo missing"))?;

        Ok(P2pSmokeTestResponse {
            route: route.label().to_string(),
            bytes_echoed: echoed,
        })
    }
}

#[tauri::command]
pub async fn export_pot(
    app: AppHandle,
    state: State<'_, SharedState>,
    store: State<'_, TransferStore>,
    task_id: String,
) -> Result<ExportPotResponse, CommandError> {
    let proof_dir = default_proofs_dir(&app).map_err(CommandError::from)?;
    fs::create_dir_all(&proof_dir)
        .map_err(|err| CommandError::from_io(&err, "failed to prepare proofs directory"))?;

    let maybe_task = state.get_task(&task_id).await;
    let mut source_path = maybe_task.as_ref().and_then(|task| task.pot_path.clone());

    if source_path.is_none() {
        let record = store
            .get(&task_id)
            .map_err(CommandError::from)?
            .ok_or_else(CommandError::not_found)?;
        source_path = record.pot_path.map(PathBuf::from);
    }

    let source_path = source_path
        .ok_or_else(|| CommandError::invalid("Proof of Transition not yet available"))?;
    if !source_path.exists() {
        return Err(CommandError::verify_failed(format!(
            "PoT artefact missing at {}",
            source_path.display()
        )));
    }

    let destination = proof_dir.join(format!("{task_id}.pot.json"));
    if source_path != destination {
        fs::copy(&source_path, &destination)
            .map_err(|err| CommandError::from_io(&err, "failed to export PoT file"))?;
    } else {
        // ensure file metadata accessible
        fs::metadata(&destination)
            .map_err(|err| CommandError::from_io(&err, "failed to access PoT file"))?;
    }

    if let Some(task) = maybe_task {
        state.set_pot_path(&task.task_id, destination.clone()).await;
    }

    Ok(ExportPotResponse {
        pot_path: destination.display().to_string(),
    })
}

#[tauri::command]
pub async fn verify_pot(pot_path: String) -> Result<VerifyPotResponse, CommandError> {
    let path = PathBuf::from(&pot_path);
    if !path.exists() {
        return Err(CommandError::invalid("PoT file not found"));
    }

    let file = fs::File::open(&path)
        .map_err(|err| CommandError::from_io(&err, "failed to open PoT file"))?;
    let proof: ProofOfTransition = serde_json::from_reader(file)
        .map_err(|err| CommandError::verify_failed(format!("invalid PoT JSON payload: {err}")))?;

    let reason = validate_proof(&proof);
    Ok(VerifyPotResponse {
        valid: reason.is_none(),
        reason,
    })
}

#[tauri::command]
pub fn load_settings(config: State<'_, ConfigStore>) -> Result<SettingsPayload, CommandError> {
    Ok(to_settings_payload(config.get()))
}

#[tauri::command]
pub fn update_settings(
    config: State<'_, ConfigStore>,
    payload: SettingsPayload,
) -> Result<SettingsPayload, CommandError> {
    let runtime = RuntimeSettings {
        preferred_routes: payload.preferred_routes.clone(),
        code_expire_sec: payload.code_expire_sec,
        relay_enabled: payload.relay_enabled,
        chunk_policy: AdaptiveChunkPolicy {
            enabled: payload.chunk_policy.adaptive,
            min_bytes: payload.chunk_policy.min_bytes,
            max_bytes: payload.chunk_policy.max_bytes,
        },
        quantum_mode: payload.quantum_mode,
        minimal_quantum_ui: payload.minimal_quantum_ui,
        quantum_intensity: payload.quantum_intensity,
        quantum_speed: payload.quantum_speed,
        animations_enabled: payload.animations_enabled,
        audio_enabled: payload.audio_enabled,
        enable_3d_quantum: payload.enable3d_quantum,
        quantum_3d_quality: payload.quantum3d_quality.clone(),
        quantum_3d_fps: payload.quantum3d_fps,
        wormhole_mode: payload.wormhole_mode,
    };
    let updated = config.update(runtime).map_err(CommandError::from)?;
    Ok(to_settings_payload(updated))
}

#[tauri::command]
pub async fn list_transfers(
    state: State<'_, SharedState>,
    store: State<'_, TransferStore>,
    limit: Option<usize>,
) -> Result<Vec<TransferSummary>, CommandError> {
    let mut persisted: Vec<TransferSummary> = store
        .list_transfers(limit, None)
        .map_err(CommandError::from)?
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

fn to_settings_payload(settings: RuntimeSettings) -> SettingsPayload {
    SettingsPayload {
        preferred_routes: settings.preferred_routes,
        code_expire_sec: settings.code_expire_sec,
        relay_enabled: settings.relay_enabled,
        chunk_policy: ChunkPolicyPayload {
            adaptive: settings.chunk_policy.enabled,
            min_bytes: settings.chunk_policy.min_bytes,
            max_bytes: settings.chunk_policy.max_bytes,
        },
        quantum_mode: settings.quantum_mode,
        minimal_quantum_ui: settings.minimal_quantum_ui,
        quantum_intensity: settings.quantum_intensity,
        quantum_speed: settings.quantum_speed,
        animations_enabled: settings.animations_enabled,
        audio_enabled: settings.audio_enabled,
        enable3d_quantum: settings.enable_3d_quantum,
        quantum3d_quality: settings.quantum_3d_quality,
        quantum3d_fps: settings.quantum_3d_fps,
        wormhole_mode: settings.wormhole_mode,
    }
}

fn to_identity_response(record: &IdentityRecord) -> IdentityResponse {
    IdentityResponse {
        identity_id: record.identity_id.clone(),
        public_key: record.public_key.clone(),
        label: record.label.clone(),
        created_at: record.created_at,
    }
}

fn to_device_response(record: &DeviceRecord) -> DeviceResponse {
    DeviceResponse {
        device_id: record.device_id.clone(),
        identity_id: record.identity_id.clone(),
        public_key: record.public_key.clone(),
        name: record.name.clone(),
        status: record.status.clone(),
        created_at: record.created_at,
        last_seen_at: record.last_seen_at,
        capabilities: record.capabilities.clone(),
    }
}

fn to_entitlement_dto(record: &EntitlementRecord) -> EntitlementDto {
    EntitlementDto {
        identity_id: record.identity_id.clone(),
        plan: record.plan.clone(),
        expires_at: record.expires_at,
        features: record.features.clone(),
        updated_at: record.updated_at,
    }
}

fn default_entitlement(identity_id: &str) -> EntitlementDto {
    EntitlementDto {
        identity_id: identity_id.to_string(),
        plan: "free".into(),
        expires_at: None,
        features: Vec::new(),
        updated_at: chrono::Utc::now().timestamp_millis(),
    }
}

fn validate_proof(proof: &ProofOfTransition) -> Option<String> {
    if proof.version.trim() != "1" {
        return Some("Unsupported PoT version".into());
    }
    if proof.files.is_empty() {
        return Some("No attested files in proof".into());
    }
    if chrono::DateTime::parse_from_rfc3339(&proof.timestamp).is_err() {
        return Some("Timestamp invalid".into());
    }
    if proof.route.trim().is_empty() {
        return Some("Route missing from PoT".into());
    }
    if proof.attest.receiver_signature.trim().is_empty() {
        return Some("Missing receiver signature".into());
    }
    if proof.attest.algo.trim().is_empty() {
        return Some("Missing signature algorithm".into());
    }
    if proof
        .files
        .iter()
        .any(|file| file.cid.trim().is_empty() || file.chunk_hashes_sample.is_empty())
    {
        return Some("Attestation missing Merkle sample".into());
    }
    None
}

fn emit_devices_update(app: &AppHandle, store: &IdentityStore, identity_id: &str) {
    if let Ok(devices) = store.list_devices(identity_id) {
        let items: Vec<DeviceResponse> = devices.iter().map(to_device_response).collect();
        let event = DevicesUpdateEvent {
            identity_id: identity_id.to_string(),
            items,
        };
        let _ = app.emit_to(EventTarget::app(), "identity_devices_updated", event);
    }
}

fn verify_device_signature(
    identity: &IdentityRecord,
    device_id: &str,
    device_public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), CommandError> {
    let identity_key_bytes =
        decode_hex_to_array::<32>(&identity.public_key, "identity public key")?;
    let verifying_key = VerifyingKey::from_bytes(&identity_key_bytes)
        .map_err(|_| CommandError::invalid("identity public key is invalid"))?;

    // Validate device public key format even if not used directly for verification yet.
    let _ = decode_hex_to_array::<32>(device_public_key_hex, "device public key")?;
    let signature_bytes = decode_hex_to_array::<64>(signature_hex, "device signature")?;
    let signature = EdSignature::from_bytes(&signature_bytes);
    let message = format!("register:{device_id}:{device_public_key_hex}");
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| CommandError::invalid("device signature verification failed"))?;
    Ok(())
}

fn decode_hex_to_array<const N: usize>(input: &str, field: &str) -> Result<[u8; N], CommandError> {
    let trimmed = input.trim();
    let decoded = hex::decode(trimmed)
        .map_err(|_| CommandError::invalid(format!("{field} must be hex-encoded")))?;
    if decoded.len() != N {
        return Err(CommandError::invalid(format!(
            "{field} must be {N} bytes, got {}",
            decoded.len()
        )));
    }
    let mut array = [0u8; N];
    array.copy_from_slice(&decoded);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{pot::ProofSignature, FileAttestation};
    use crate::commands::types::ErrorCode;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    fn sample_attestation() -> FileAttestation {
        FileAttestation {
            name: "artifact.bin".into(),
            size: 1024,
            cid: "b3:abcdef".into(),
            merkle_root: "sha256:deadbeef".into(),
            chunks: 1,
            chunk_hashes_sample: vec!["sha256:deadbeef".into()],
        }
    }

    fn sample_proof() -> ProofOfTransition {
        ProofOfTransition {
            version: "1".into(),
            task_id: "task_123".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            sender_fingerprint: "ed25519:sender".into(),
            receiver_fingerprint: "ed25519:receiver".into(),
            route: "relay".into(),
            files: vec![sample_attestation()],
            attest: ProofSignature {
                receiver_signature: "ed25519:sig".into(),
                algo: "ed25519".into(),
            },
        }
    }

    #[test]
    fn settings_round_trip_preserves_wormhole_flags() {
        let runtime = RuntimeSettings {
            enable_3d_quantum: false,
            quantum_3d_quality: "high".into(),
            quantum_3d_fps: 45,
            animations_enabled: false,
            audio_enabled: false,
            wormhole_mode: false,
            ..RuntimeSettings::default()
        };
        let payload = super::to_settings_payload(runtime.clone());
        assert!(!payload.enable3d_quantum);
        assert_eq!(payload.quantum3d_quality, "high");
        assert_eq!(payload.quantum3d_fps, 45);
        assert!(!payload.animations_enabled);
        assert!(!payload.audio_enabled);
        assert!(!payload.wormhole_mode);

        let reconstructed = RuntimeSettings {
            preferred_routes: payload.preferred_routes.clone(),
            code_expire_sec: payload.code_expire_sec,
            relay_enabled: payload.relay_enabled,
            chunk_policy: AdaptiveChunkPolicy {
                enabled: payload.chunk_policy.adaptive,
                min_bytes: payload.chunk_policy.min_bytes,
                max_bytes: payload.chunk_policy.max_bytes,
            },
            quantum_mode: payload.quantum_mode,
            minimal_quantum_ui: payload.minimal_quantum_ui,
            quantum_intensity: payload.quantum_intensity,
            quantum_speed: payload.quantum_speed,
            animations_enabled: payload.animations_enabled,
            audio_enabled: payload.audio_enabled,
            enable_3d_quantum: payload.enable3d_quantum,
            quantum_3d_quality: payload.quantum3d_quality.clone(),
            quantum_3d_fps: payload.quantum3d_fps,
            wormhole_mode: payload.wormhole_mode,
        };
        assert!(!reconstructed.enable_3d_quantum);
        assert!(!reconstructed.animations_enabled);
        assert!(!reconstructed.audio_enabled);
        assert!(!reconstructed.wormhole_mode);
        assert_eq!(reconstructed.quantum_3d_quality, "high");
        assert_eq!(reconstructed.quantum_3d_fps, 45);
    }

    #[test]
    fn validate_proof_accepts_valid_payload() {
        let proof = sample_proof();
        assert!(validate_proof(&proof).is_none());
    }

    #[test]
    fn validate_proof_rejects_missing_files() {
        let mut proof = sample_proof();
        proof.files.clear();
        let error = validate_proof(&proof);
        assert!(error.is_some());
        assert!(error.unwrap().contains("No attested files"));
    }

    fn setup_identity_store() -> (tempfile::TempDir, IdentityStore) {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("identities.sqlite3");
        let store = IdentityStore::with_path(db_path).expect("store");
        (temp_dir, store)
    }

    fn register_identity_and_device(store: &IdentityStore) -> (SigningKey, String, String) {
        let mut rng = OsRng;
        let identity_key = SigningKey::generate(&mut rng);
        let identity_id = format!("id_{}", Uuid::new_v4().simple());
        let identity_public = hex::encode(identity_key.verifying_key().to_bytes());
        store
            .register_identity(&identity_id, &identity_public, Some("测试身份"))
            .expect("register identity");

        let device_key = SigningKey::generate(&mut rng);
        let device_id = format!("dev_{}", Uuid::new_v4().simple());
        let device_public = hex::encode(device_key.verifying_key().to_bytes());
        store
            .register_device(
                &identity_id,
                &device_id,
                &device_public,
                Some("同频终端"),
                "active",
            )
            .expect("register device");
        (identity_key, identity_id, device_id)
    }

    #[test]
    fn verify_request_accepts_active_and_standby_devices() {
        let (_guard, store) = setup_identity_store();
        let (identity_key, identity_id, device_id) = register_identity_and_device(&store);

        let heartbeat_signature = identity_key
            .sign(format!("heartbeat:{identity_id}:{device_id}").as_bytes());
        super::verify_request(
            &store,
            &identity_id,
            &device_id,
            &hex::encode(heartbeat_signature.to_bytes()),
            "heartbeat",
        )
        .expect("heartbeat should validate");

        let capabilities = vec!["ui:minimal-panel".to_string()];
        store
            .touch_device(
                &identity_id,
                &device_id,
                None,
                Some("standby"),
                Some(capabilities.as_slice()),
            )
            .expect("touch device");

        let update_signature = identity_key
            .sign(format!("update_device:{identity_id}:{device_id}").as_bytes());
        super::verify_request(
            &store,
            &identity_id,
            &device_id,
            &hex::encode(update_signature.to_bytes()),
            "update_device",
        )
        .expect("standby device can update");

        let refreshed = store
            .get_device(&identity_id, &device_id)
            .expect("fetch device")
            .expect("device exists");
        assert_eq!(refreshed.status, "standby");
        assert_eq!(refreshed.capabilities, capabilities);
    }

    #[test]
    fn verify_request_rejects_invalid_signatures() {
        let (_guard, store) = setup_identity_store();
        let (identity_key, identity_id, device_id) = register_identity_and_device(&store);

        let bad_signature = identity_key
            .sign(format!("update_device:{}:{}:noise", identity_id, device_id).as_bytes());
        let error = super::verify_request(
            &store,
            &identity_id,
            &device_id,
            &hex::encode(bad_signature.to_bytes()),
            "update_device",
        )
        .expect_err("should reject tampered signature");
        assert_eq!(error.code, ErrorCode::EInvalidInput);
        assert!(error
            .message
            .to_ascii_lowercase()
            .contains("signature verification failed"));
    }

    #[test]
    fn touch_device_allows_renaming_and_capabilities() {
        let (_guard, store) = setup_identity_store();
        let (_identity_key, identity_id, device_id) = register_identity_and_device(&store);

        let capabilities = vec!["ui:minimal-panel".to_string(), "transport:mock".to_string()];
        store
            .touch_device(
                &identity_id,
                &device_id,
                Some("量子终端"),
                Some("active"),
                Some(capabilities.as_slice()),
            )
            .expect("touch device metadata");
        let snapshot = store
            .get_device(&identity_id, &device_id)
            .expect("load device")
            .expect("device exists");
        assert_eq!(snapshot.name.as_deref(), Some("量子终端"));
        assert_eq!(snapshot.status, "active");
        assert_eq!(snapshot.capabilities, capabilities);
    }


    #[test]
    fn verify_pot_command_validates_success() {
        let proof = sample_proof();
        let mut temp = NamedTempFile::new().expect("temp file");
        serde_json::to_writer(&mut temp, &proof).expect("write proof");
        let path = temp.path().display().to_string();
        let result = tauri::async_runtime::block_on(verify_pot(path));
        let response = result.expect("command response");
        assert!(response.valid);
        assert!(response.reason.is_none());
    }

    #[test]
    fn verify_pot_command_flags_invalid_json() {
        let mut temp = NamedTempFile::new().expect("temp file");
        write!(temp, "{{}}").expect("write invalid json");
        let path = temp.path().display().to_string();
        let result = tauri::async_runtime::block_on(verify_pot(path));
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.code, ErrorCode::EVerifyFail);
    }

    #[test]
    fn verify_pot_command_reports_invalid_structure() {
        let mut temp = NamedTempFile::new().expect("temp file");
        let payload = json!({
            "version": "1",
            "files": [],
            "route": "lan",
            "attest": { "receiver_signature": "", "algo": "" },
            "task_id": "task",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "sender_fingerprint": "sender",
            "receiver_fingerprint": "receiver"
        });
        serde_json::to_writer(&mut temp, &payload).expect("write payload");
        let path = temp.path().display().to_string();
        let result = tauri::async_runtime::block_on(verify_pot(path));
        let response = result.expect("command response");
        assert!(!response.valid);
        assert!(response
            .reason
            .unwrap_or_default()
            .contains("No attested files"));
    }
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
            let error = err;
            let error_code = error.code.clone();
            let error_message = error.message.clone();
            let display_message = match error_code {
                ErrorCode::EUnknown => error_message.clone(),
                _ => format!("{} ({:?})", error_message, error_code),
            };
            emit_log(
                &app_handle,
                &task_id_clone,
                format!(
                    "Transfer failed with code {:?}: {}",
                    error_code, error_message
                ),
            );
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
                    message: Some(display_message.clone()),
                    resume: None,
                },
            );
            emit_event(
                &app_handle,
                "transfer_failed",
                &TransferLifecycleEvent {
                    task_id: task_id_clone,
                    direction,
                    code: None,
                    message: Some(display_message),
                },
            );
        }
    });
}

async fn simulate_transfer(
    app: AppHandle,
    state: SharedState,
    task_id: String,
) -> Result<(), CommandError> {
    let task = state
        .get_task(&task_id)
        .await
        .ok_or_else(CommandError::not_found)?;

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
            resume: None,
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
            resume: None,
        },
    );
    sleep(Duration::from_millis(200)).await;

    let session = SessionDesc::new(task_id.clone());
    let SelectedRoute {
        route: selected_route,
        mut stream,
        attempt_notes,
    } = router.connect(&session).await.map_err(|err| {
        CommandError::route_unreachable(format!("transport selection failed: {err}"))
    })?;
    emit_log(
        &app,
        &task_id,
        format!("Selected transport route {}", selected_route.label()),
    );
    let route = TransferRoute::from(selected_route.clone());
    for note in &attempt_notes {
        emit_log(&app, &task_id, format!("Route attempt · {}", note));
    }

    let handshake_start = Instant::now();
    stream
        .send(Frame::Control("handshake".into()))
        .await
        .map_err(|err| {
            CommandError::route_unreachable(format!("transport handshake failed: {err}"))
        })?;
    let handshake_elapsed = match stream.recv().await {
        Ok(frame) => {
            let elapsed = handshake_start.elapsed();
            emit_log(&app, &task_id, format!("Control frame echo: {:?}", frame));
            elapsed
        }
        Err(err) => {
            let elapsed = handshake_start.elapsed();
            emit_log(
                &app,
                &task_id,
                format!("Handshake acknowledgement missing: {err}"),
            );
            elapsed
        }
    };

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
            resume: None,
        },
    );

    let mut tracked_files = task.files.clone();

    let mut total_bytes: u64 = tracked_files.iter().map(|f| f.size).sum();
    if total_bytes == 0 {
        total_bytes = MOCK_RECEIVE_FILE_SIZE;
    }
    let settings = app.state::<ConfigStore>().get();
    let weak_network = matches!(selected_route, RouteKind::Relay)
        || handshake_elapsed > Duration::from_millis(250);
    let suggested_chunk = derive_chunk_size(
        &settings.chunk_policy,
        &selected_route,
        handshake_elapsed,
        weak_network,
    );
    let resume_store = ResumeStore::from_app(&app).map_err(CommandError::from)?;
    let mut catalog = match resume_store.load(&task_id).map_err(CommandError::from)? {
        Some(mut existing) => {
            existing.reconcile_total_bytes(total_bytes);
            if existing.chunk_size != suggested_chunk {
                emit_log(
                    &app,
                    &task_id,
                    format!(
                        "Resuming with stored chunk size {} MiB",
                        existing.chunk_size / (1024 * 1024)
                    ),
                );
            }
            existing
        }
        None => {
            let created = ChunkCatalog::new(total_bytes, suggested_chunk);
            resume_store
                .store(&task_id, &created)
                .map_err(CommandError::from)?;
            emit_log(
                &app,
                &task_id,
                format!(
                    "Initial chunk catalog: {} chunks at {} MiB",
                    created.total_chunks,
                    created.chunk_size / (1024 * 1024)
                ),
            );
            created
        }
    };

    let mut acknowledged_bytes = catalog
        .received_chunks
        .iter()
        .enumerate()
        .filter(|(_, flag)| **flag)
        .map(|(idx, _)| catalog.chunk_length(idx as u64))
        .sum::<u64>();
    if acknowledged_bytes > catalog.total_bytes {
        acknowledged_bytes = catalog.total_bytes;
    }
    let pending_indices = catalog.missing_indices();
    emit_log(
        &app,
        &task_id,
        format!(
            "{} chunks pending out of {}",
            pending_indices.len(),
            catalog.total_chunks
        ),
    );

    let total_chunks = catalog.total_chunks;
    let bytes_total = catalog.total_bytes;

    if !pending_indices.is_empty() {
        emit_progress(
            &app,
            TransferProgressEvent {
                task_id: task_id.clone(),
                phase: TransferPhase::Transferring,
                progress: Some(
                    (0.25 + (acknowledged_bytes as f32 / bytes_total as f32) * 0.5).min(0.75),
                ),
                bytes_sent: Some(acknowledged_bytes),
                bytes_total: Some(bytes_total),
                speed_bps: Some(8 * 1024 * 1024),
                route: Some(route.clone()),
                message: Some(format!(
                    "Resuming transfer · {} remaining chunks",
                    pending_indices.len()
                )),
                resume: Some(resume_snapshot(&catalog)),
            },
        );
    }

    for chunk_index in pending_indices.iter() {
        let chunk_len = catalog.chunk_length(*chunk_index);
        let mut payload = vec![0u8; chunk_len as usize];
        for (offset, byte) in payload.iter_mut().enumerate() {
            *byte = ((*chunk_index as usize + offset) % 251) as u8;
        }
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let digest = hasher.finalize();
        let digest_hex = hex::encode(digest);
        stream
            .send(Frame::Data(payload))
            .await
            .map_err(|err| CommandError::route_unreachable(format!("transport failed: {err}")))?;
        catalog.mark_received(*chunk_index);
        resume_store
            .store(&task_id, &catalog)
            .map_err(CommandError::from)?;
        acknowledged_bytes = acknowledged_bytes
            .saturating_add(chunk_len)
            .min(bytes_total);
        emit_log(
            &app,
            &task_id,
            format!(
                "Chunk {}/{} confirmed ({} bytes, sha256:{})",
                *chunk_index + 1,
                total_chunks,
                chunk_len,
                digest_hex
            ),
        );
        let fraction = if bytes_total == 0 {
            0.0
        } else {
            acknowledged_bytes as f32 / bytes_total as f32
        };
        emit_progress(
            &app,
            TransferProgressEvent {
                task_id: task_id.clone(),
                phase: TransferPhase::Transferring,
                progress: Some((0.25 + fraction * 0.5).min(0.75)),
                bytes_sent: Some(acknowledged_bytes),
                bytes_total: Some(bytes_total),
                speed_bps: Some(8 * 1024 * 1024),
                route: Some(route.clone()),
                message: Some(format!(
                    "Streaming payload · chunk {}/{}",
                    *chunk_index + 1,
                    total_chunks
                )),
                resume: Some(resume_snapshot(&catalog)),
            },
        );
        sleep(Duration::from_millis(180)).await;
    }

    if catalog.is_complete() {
        emit_log(
            &app,
            &task_id,
            "All chunks acknowledged; ready to finalise".into(),
        );
    }

    stream.close().await.ok();

    if matches!(task.direction, TransferDirection::Receive) {
        tracked_files = materialise_mock_payload(&tracked_files)
            .await
            .map_err(CommandError::from)?;
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
            bytes_sent: Some(bytes_total),
            bytes_total: Some(bytes_total),
            speed_bps: Some(4 * 1024 * 1024),
            route: Some(route.clone()),
            message: Some("Finalising transfer & generating proof".into()),
            resume: Some(resume_snapshot(&catalog)),
        },
    );

    let mut attestations = Vec::new();
    for tracked in &tracked_files {
        let attestation = compute_file_attestation(&tracked.path).map_err(|err| {
            CommandError::from(anyhow!(
                "unable to attest file {}: {err}",
                tracked.path.display()
            ))
        })?;
        attestations.push(attestation);
    }

    let proofs_dir = default_proofs_dir(&app).map_err(CommandError::from)?;
    let route_label_str = route_label(&route).to_string();
    let pot_path =
        write_proof_of_transition(&task_id, &attestations, &route_label_str, &proofs_dir)
            .map_err(CommandError::from)?;
    state.set_pot_path(&task_id, pot_path.clone()).await;
    if let Some(task_snapshot) = state.set_status(&task_id, TransferStatus::Completed).await {
        persist_transfer_snapshot(
            &app,
            &task_snapshot,
            Some(bytes_total),
            Some(bytes_total),
            Some(route_label_str.clone()),
        );
    }
    if let Err(err) = resume_store.remove(&task_id) {
        eprintln!("failed to cleanup resume catalog for {task_id}: {err}");
    }

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Done,
            progress: Some(1.0),
            bytes_sent: Some(bytes_total),
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(route.clone()),
            message: Some("Transfer completed".into()),
            resume: Some(resume_snapshot(&catalog)),
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

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DevicesUpdateEvent {
    identity_id: String,
    items: Vec<DeviceResponse>,
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
    route.label()
}

fn resume_snapshot(catalog: &ChunkCatalog) -> ResumeProgressDto {
    ResumeProgressDto {
        chunk_size: catalog.chunk_size,
        total_chunks: catalog.total_chunks,
        received_chunks: catalog.received_chunks.clone(),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratePayload {
    pub paths: Vec<String>,
    pub expire_sec: Option<i64>,
}

fn verify_request(
    identity_store: &IdentityStore,
    identity_id: &str,
    device_id: &str,
    signature_hex: &str,
    purpose: &str,
) -> Result<(), CommandError> {
    if identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    if device_id.trim().is_empty() {
        return Err(CommandError::invalid("device_id is required"));
    }
    let device = identity_store
        .get_device(identity_id.trim(), device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let device_status = device.status.to_ascii_lowercase();
    let allowed = matches!(device_status.as_str(), "active" | "standby");
    if !allowed {
        return Err(CommandError::invalid("device not active"));
    }
    let identity = identity_store
        .get_identity(identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;

    let identity_key_bytes =
        decode_hex_to_array::<32>(&identity.public_key, "identity public key")?;
    let verifying_key = VerifyingKey::from_bytes(&identity_key_bytes)
        .map_err(|_| CommandError::invalid("identity public key invalid"))?;

    if purpose == "register" {
        return Ok(());
    }

    let signature = decode_hex_to_array::<64>(signature_hex, "request signature")?;
    let signature = EdSignature::from_bytes(&signature);
    let message = format!("{purpose}:{identity_id}:{device_id}");
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| CommandError::invalid("signature verification failed"))?;
    Ok(())
}
