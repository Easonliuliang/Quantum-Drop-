mod state;
pub mod types;

use std::{
    collections::HashSet,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
use futures::{stream::FuturesUnordered, StreamExt};
use if_addrs::{get_if_addrs, IfAddr};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, EventTarget, Manager, State};
use tokio::time::{sleep, timeout};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    task::spawn_blocking,
};
use uuid::Uuid;

use crate::{
    attestation::{compute_file_attestation, write_proof_of_transition, TransitionReceipt},
    audit::{log_simple_event, AuditLogger},
    config::{AdaptiveChunkPolicy, ConfigStore, RuntimeSettings},
    crypto::{
        self, decode_public_key, encode_public_key_hex, SessionCipher, SessionPublicKey,
        SessionSecretBytes,
    },
    license::{LicenseError, LicenseManager},
    metrics::RouteMetricsRegistry,
    resume::{derive_chunk_size, ChunkCatalog, ResumeStore},
    security::SecurityConfig,
    services::mdns::{MdnsRegistry, SenderInfo as MdnsSenderInfo},
    signaling::SessionTicket,
    store::{
        DeviceRecord, EntitlementRecord, IdentityRecord, IdentityStore, TransferRecord,
        TransferStore,
    },
    transport::{
        adapter::{WebRtcHint, WebRtcRole},
        Frame, LanQuic, RouteKind, Router, SelectedRoute, SessionDesc, TransportError,
        TransportStream,
    },
};

use state::{LanMode, TrackedFile, TransferTask};
use types::{
    AuditLogDto, AuthenticatedPayload, ChunkPolicyPayload, CommandError, ConnectByCodePayload,
    DeviceRegistrationPayload, DeviceResponse, DeviceUpdatePayload, DevicesQueryPayload,
    DevicesResponse, EntitlementDto, EntitlementUpdatePayload, ErrorCode, ExportPotResponse,
    GenerateCodeResponse, HeartbeatPayload, IdentityRefPayload, IdentityRegistrationPayload,
    IdentityResponse, LicenseActivatePayload, LicenseStatusDto, P2pSmokeTestResponse,
    ResumeProgressDto, RouteMetricsDto, SenderInfoDto, SettingsPayload, SignedPathsPayload,
    SignedReceivePayload, TaskResponse, TransferDirection, TransferLifecycleEvent, TransferPhase,
    TransferProgressEvent, TransferRoute, TransferStatsDto, TransferStatus, TransferSummary,
    VerifyPotResponse, WebRtcReceiverPayload, WebRtcSenderPayload,
};

const MOCK_RECEIVE_FILE_SIZE: u64 = 2 * 1024 * 1024;
const MULTI_STREAM_THRESHOLD: u64 = 64 * 1024 * 1024;
const MID_STREAM_THRESHOLD: u64 = 8 * 1024 * 1024;
const DEFAULT_PARALLEL_CHUNKS: usize = 2;
const MAX_PARALLEL_CHUNKS: usize = 4;

pub use state::AppState as SharedState;

fn recommended_lan_streams(
    total_bytes: u64,
    policy: &AdaptiveChunkPolicy,
    success_rate: Option<f32>,
) -> usize {
    let mut configured = policy.lan_streams.clamp(1, MAX_PARALLEL_CHUNKS);
    if let Some(rate) = success_rate {
        if rate < 0.5 {
            configured = 1;
        } else if rate < 0.8 {
            configured = configured.min(2);
        }
    }
    if total_bytes == 0 {
        return configured;
    }
    if total_bytes >= MULTI_STREAM_THRESHOLD {
        configured
    } else if total_bytes >= MID_STREAM_THRESHOLD {
        configured.min(DEFAULT_PARALLEL_CHUNKS.max(1))
    } else {
        1
    }
}

#[tauri::command]
pub async fn auth_register_identity(
    app: AppHandle,
    store: State<'_, IdentityStore>,
    payload: IdentityRegistrationPayload,
) -> Result<IdentityResponse, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    if payload.public_key.trim().is_empty() {
        return Err(CommandError::invalid("public_key is required"));
    }
    let identity_id = payload.identity_id.trim().to_string();
    let record = store
        .register_identity(
            identity_id.as_str(),
            payload.public_key.trim(),
            payload.label.as_deref(),
        )
        .map_err(CommandError::from)?;
    log_simple_event(
        &app,
        "identity.registered",
        Some(identity_id.as_str()),
        None,
        None,
        json!({ "label": payload.label }),
    );
    Ok(to_identity_response(&record))
}

#[tauri::command]
pub async fn auth_register_device(
    app: AppHandle,
    store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
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

    let license_record = license
        .active_license(payload.identity_id.trim())
        .map_err(CommandError::from)?;
    license
        .enforce_device_limit(&license_record)
        .map_err(CommandError::license_violation)?;

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
    log_simple_event(
        &app,
        "device.registered",
        Some(identity.identity_id.as_str()),
        Some(record.device_id.as_str()),
        None,
        json!({ "name": record.name, "status": record.status }),
    );
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
    app: AppHandle,
    state: State<'_, SharedState>,
    config: State<'_, ConfigStore>,
    identity_store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
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
    let total_size: u64 = files.iter().map(|file| file.size).sum();
    let license_snapshot = license
        .active_license(auth.identity_id.trim())
        .map_err(CommandError::from)?;
    license
        .enforce_file_size(&license_snapshot, total_size)
        .map_err(CommandError::license_violation)?;
    let identity_record = identity_store
        .get_identity(auth.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let device_record = identity_store
        .get_device(auth.identity_id.trim(), auth.device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let (session_secret, session_public) = SessionSecretBytes::generate();
    let code = crypto::generate_task_code(6);
    let session_key = crypto::derive_mock_session_key();
    let mut task = TransferTask::new(
        TransferDirection::Send,
        Some(code.clone()),
        files,
        session_key,
    );
    task.session_secret = Some(session_secret.clone());
    task.public_key = Some(session_public.clone());
    task.identity_id = Some(auth.identity_id.clone());
    task.identity_public_key = Some(identity_record.public_key.clone());
    task.device_id = Some(auth.device_id.clone());
    task.device_name = device_record.name.clone();
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
        public_key: encode_public_key_hex(&session_public),
    };
    log_simple_event(
        &app,
        "pairing_code.generated",
        Some(auth.identity_id.trim()),
        Some(auth.device_id.trim()),
        Some(response.task_id.as_str()),
        json!({
            "code": response.code,
            "files": auth.payload.paths.len(),
        }),
    );
    Ok(response)
}

#[tauri::command]
pub async fn courier_send(
    app: AppHandle,
    state: State<'_, SharedState>,
    store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
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
    let device_record = store
        .get_device(auth.identity_id.trim(), auth.device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let device_label = device_record
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&device_record.device_id)
        .to_string();

    let task = if let Some(existing) = maybe_task {
        state
            .update_task(&existing.task_id, |task| {
                task.files = files.clone();
                task.status = TransferStatus::InProgress;
                task.lan_mode = Some(LanMode::Sender {
                    device_name: Some(device_label.clone()),
                });
                task.device_name = Some(device_label.clone());
            })
            .await
            .unwrap_or(existing)
    } else {
        return Err(CommandError::code_expired());
    };

    spawn_transfer_runner(&app, state.inner().clone(), task.task_id.clone());
    log_simple_event(
        &app,
        "transfer.send.requested",
        Some(auth.identity_id.trim()),
        Some(auth.device_id.trim()),
        Some(task.task_id.as_str()),
        json!({
            "code": code,
            "files": task.files.len(),
        }),
    );

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
    let save_dir_path = prepare_save_dir(&auth.payload.save_dir)?;
    let host = auth.payload.host.trim();
    if host.is_empty() {
        return Err(CommandError::invalid("host is required"));
    }
    if auth.payload.port == 0 {
        return Err(CommandError::invalid("port must be non-zero"));
    }
    let identity_record = store
        .get_identity(auth.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let device_record = store
        .get_device(auth.identity_id.trim(), auth.device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let sender_key = decode_public_key(&auth.payload.sender_public_key)
        .map_err(|err| CommandError::invalid(format!("invalid sender public key: {err}")))?;
    let cert_fp_str = auth.payload.sender_cert_fingerprint.trim();
    if cert_fp_str.len() != 64 {
        return Err(CommandError::invalid(
            "sender_cert_fingerprint must be 64 hex characters",
        ));
    }
    hex::decode(cert_fp_str)
        .map_err(|_| CommandError::invalid("sender_cert_fingerprint must be hex"))?;
    let cert_fp = cert_fp_str.to_string();
    let (session_secret, session_public_key) = SessionSecretBytes::generate();

    let updated_task = init_receive_task(
        state.inner(),
        &auth.identity_id,
        &identity_record.public_key,
        &auth.device_id,
        device_record.name.clone(),
        &auth.payload.code,
        &save_dir_path,
        host.to_string(),
        auth.payload.port,
        session_secret,
        session_public_key,
        sender_key,
        Some(cert_fp),
    )
    .await?;

    spawn_transfer_runner(&app, state.inner().clone(), updated_task.task_id.clone());
    log_simple_event(
        &app,
        "transfer.receive.manual",
        Some(auth.identity_id.trim()),
        Some(auth.device_id.trim()),
        Some(updated_task.task_id.as_str()),
        json!({
            "host": host,
            "port": auth.payload.port,
        }),
    );

    Ok(TaskResponse {
        task_id: updated_task.task_id,
    })
}

#[tauri::command]
pub async fn courier_connect_by_code(
    app: AppHandle,
    state: State<'_, SharedState>,
    store: State<'_, IdentityStore>,
    mdns: State<'_, MdnsRegistry>,
    auth: AuthenticatedPayload<ConnectByCodePayload>,
) -> Result<TaskResponse, CommandError> {
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "receive",
    )?;
    let save_dir_path = prepare_save_dir(&auth.payload.save_dir)?;
    let identity_record = store
        .get_identity(auth.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let device_record = store
        .get_device(auth.identity_id.trim(), auth.device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let sender_info = mdns
        .discover_sender(&auth.payload.code, Duration::from_secs(10))
        .await
        .map_err(|err| CommandError::route_unreachable(format!("{err}")))?;
    let peer_key = decode_public_key(&sender_info.public_key)
        .map_err(|err| CommandError::invalid(format!("invalid sender public key: {err}")))?;
    let (session_secret, session_public_key) = SessionSecretBytes::generate();

    let updated_task = init_receive_task(
        state.inner(),
        &auth.identity_id,
        &identity_record.public_key,
        &auth.device_id,
        device_record.name.clone(),
        &auth.payload.code,
        &save_dir_path,
        sender_info.host.clone(),
        sender_info.port,
        session_secret,
        session_public_key,
        peer_key,
        if sender_info.cert_fingerprint.is_empty() {
            None
        } else {
            Some(sender_info.cert_fingerprint.clone())
        },
    )
    .await?;

    emit_log(
        &app,
        &updated_task.task_id,
        format!(
            "Discovered sender at {}:{}, device {}",
            sender_info.host, sender_info.port, sender_info.device_name
        ),
    );
    spawn_transfer_runner(&app, state.inner().clone(), updated_task.task_id.clone());
    log_simple_event(
        &app,
        "transfer.receive.auto",
        Some(auth.identity_id.trim()),
        Some(auth.device_id.trim()),
        Some(updated_task.task_id.as_str()),
        json!({
            "code": auth.payload.code,
            "host": sender_info.host,
            "port": sender_info.port,
        }),
    );
    Ok(TaskResponse {
        task_id: updated_task.task_id,
    })
}

#[tauri::command]
pub async fn courier_start_webrtc_sender(
    app: AppHandle,
    state: State<'_, SharedState>,
    store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
    auth: AuthenticatedPayload<WebRtcSenderPayload>,
) -> Result<TaskResponse, CommandError> {
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "webrtc_send",
    )?;
    if auth.payload.file_paths.is_empty() {
        return Err(CommandError::invalid("至少需要选择一个文件"));
    }
    let code = auth.payload.code.trim().to_ascii_uppercase();
    if code.is_empty() {
        return Err(CommandError::invalid("code is required"));
    }
    let files = collect_files(&auth.payload.file_paths).map_err(CommandError::from)?;
    let total_size: u64 = files.iter().map(|file| file.size).sum();
    let license_snapshot = license
        .active_license(auth.identity_id.trim())
        .map_err(CommandError::from)?;
    license
        .enforce_file_size(&license_snapshot, total_size)
        .map_err(CommandError::license_violation)?;
    let usage_snapshot = license
        .ensure_p2p_quota(&license_snapshot)
        .map_err(CommandError::license_violation)?;
    let identity_record = store
        .get_identity(auth.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let device_record = store
        .get_device(auth.identity_id.trim(), auth.device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let (session_secret, session_public) = SessionSecretBytes::generate();
    let session_key = crypto::derive_mock_session_key();

    let mut task = TransferTask::new(
        TransferDirection::Send,
        Some(code.clone()),
        files,
        session_key,
    );
    task.session_secret = Some(session_secret);
    task.public_key = Some(session_public);
    task.identity_id = Some(auth.identity_id.clone());
    task.identity_public_key = Some(identity_record.public_key.clone());
    task.device_id = Some(auth.device_id.clone());
    let device_label = auth
        .payload
        .device_name
        .clone()
        .or(device_record.name.clone())
        .unwrap_or_else(|| device_record.device_id.clone());
    task.device_name = Some(device_label.clone());
    task.preferred_routes = Some(vec![RouteKind::P2p]);

    let task = state.insert_task(task).await;
    state.track_code(&code, &task.task_id).await;

    emit_log(
        &app,
        &task.task_id,
        format!("WebRTC 发送任务启动，设备：{device_label} · 配对码 {code}"),
    );

    spawn_transfer_runner(&app, state.inner().clone(), task.task_id.clone());
    license
        .record_p2p_usage(&usage_snapshot)
        .map_err(|err| CommandError::unknown(format!("record license usage failed: {err}")))?;
    log_simple_event(
        &app,
        "transfer.webrtc.send",
        Some(auth.identity_id.trim()),
        Some(auth.device_id.trim()),
        Some(task.task_id.as_str()),
        json!({
            "code": code,
            "files": task.files.len(),
        }),
    );
    Ok(TaskResponse {
        task_id: task.task_id,
    })
}

#[tauri::command]
pub async fn courier_start_webrtc_receiver(
    app: AppHandle,
    state: State<'_, SharedState>,
    store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
    auth: AuthenticatedPayload<WebRtcReceiverPayload>,
) -> Result<TaskResponse, CommandError> {
    verify_request(
        &store,
        auth.identity_id.as_str(),
        auth.device_id.as_str(),
        &auth.signature,
        "webrtc_receive",
    )?;
    let code = auth.payload.code.trim().to_ascii_uppercase();
    if code.is_empty() {
        return Err(CommandError::invalid("code is required"));
    }
    let save_dir_path = prepare_save_dir(&auth.payload.save_dir)?;
    let license_snapshot = license
        .active_license(auth.identity_id.trim())
        .map_err(CommandError::from)?;
    license
        .ensure_p2p_quota(&license_snapshot)
        .map_err(CommandError::license_violation)?;
    let identity_record = store
        .get_identity(auth.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let device_record = store
        .get_device(auth.identity_id.trim(), auth.device_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::invalid("device not registered"))?;
    let (session_secret, session_public) = SessionSecretBytes::generate();
    let session_key = crypto::derive_mock_session_key();

    let mut task = TransferTask::new(
        TransferDirection::Receive,
        Some(code.clone()),
        Vec::new(),
        session_key,
    );
    task.session_secret = Some(session_secret);
    task.public_key = Some(session_public);
    task.save_dir = Some(save_dir_path.clone());
    task.identity_id = Some(auth.identity_id.clone());
    task.identity_public_key = Some(identity_record.public_key.clone());
    task.device_id = Some(auth.device_id.clone());
    let device_label = auth
        .payload
        .device_name
        .clone()
        .or(device_record.name.clone())
        .unwrap_or_else(|| device_record.device_id.clone());
    task.device_name = Some(device_label.clone());
    task.preferred_routes = Some(vec![RouteKind::P2p]);

    let task = state.insert_task(task).await;
    state.track_code(&code, &task.task_id).await;

    emit_log(
        &app,
        &task.task_id,
        format!(
            "WebRTC 接收任务就绪，设备：{device_label} · 配对码 {code} · 保存目录 {}",
            save_dir_path.display()
        ),
    );

    spawn_transfer_runner(&app, state.inner().clone(), task.task_id.clone());
    log_simple_event(
        &app,
        "transfer.webrtc.receive",
        Some(auth.identity_id.trim()),
        Some(auth.device_id.trim()),
        Some(task.task_id.as_str()),
        json!({
            "code": code,
        }),
    );
    Ok(TaskResponse {
        task_id: task.task_id,
    })
}

#[tauri::command]
pub async fn courier_list_senders(
    mdns: State<'_, MdnsRegistry>,
) -> Result<Vec<SenderInfoDto>, CommandError> {
    let items = mdns
        .list_senders(Duration::from_secs(5))
        .await
        .map_err(|err| CommandError::route_unreachable(format!("{err}")))?;
    Ok(items.into_iter().map(SenderInfoDto::from).collect())
}

#[tauri::command]
pub async fn license_get_status(
    store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
    payload: IdentityRefPayload,
) -> Result<LicenseStatusDto, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let status = license
        .status(payload.identity_id.trim())
        .map_err(CommandError::from)?;
    Ok(status.into())
}

#[tauri::command]
pub async fn license_activate(
    store: State<'_, IdentityStore>,
    license: State<'_, LicenseManager>,
    app: AppHandle,
    payload: LicenseActivatePayload,
) -> Result<LicenseStatusDto, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    license
        .activate_license(payload.identity_id.trim(), &payload.license_blob)
        .map_err(CommandError::license_violation)?;
    let status = license
        .status(payload.identity_id.trim())
        .map_err(CommandError::from)?;
    log_simple_event(
        &app,
        "license.activated",
        Some(payload.identity_id.trim()),
        None,
        None,
        json!({
            "tier": status.tier,
            "expiresAt": status.expires_at,
        }),
    );
    Ok(status.into())
}

#[tauri::command]
pub async fn transfer_stats(
    store: State<'_, TransferStore>,
    identities: State<'_, IdentityStore>,
    payload: IdentityRefPayload,
) -> Result<TransferStatsDto, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    identities
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let stats = store
        .stats_for_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?;
    Ok(stats.into())
}

#[tauri::command]
pub async fn audit_get_logs(
    store: State<'_, IdentityStore>,
    audit: State<'_, AuditLogger>,
    payload: IdentityRefPayload,
    limit: Option<u32>,
) -> Result<Vec<AuditLogDto>, CommandError> {
    if payload.identity_id.trim().is_empty() {
        return Err(CommandError::invalid("identity_id is required"));
    }
    store
        .get_identity(payload.identity_id.trim())
        .map_err(CommandError::from)?
        .ok_or_else(CommandError::not_found)?;
    let capped = limit.unwrap_or(100).min(500) as usize;
    let entries = audit
        .query(payload.identity_id.trim(), Some(capped))
        .map_err(CommandError::from)?;
    Ok(entries.into_iter().map(AuditLogDto::from).collect())
}

#[tauri::command]
pub async fn security_get_config(
    security: State<'_, SecurityConfig>,
) -> Result<SecurityConfig, CommandError> {
    Ok(security.inner().clone())
}

#[tauri::command]
pub async fn courier_route_metrics(
    metrics: State<'_, RouteMetricsRegistry>,
) -> Result<Vec<RouteMetricsDto>, CommandError> {
    let snapshots = metrics.snapshot();
    Ok(snapshots.into_iter().map(RouteMetricsDto::from).collect())
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
    license: State<'_, LicenseManager>,
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
    let identity_id = existing
        .identity_id
        .clone()
        .ok_or_else(|| CommandError::invalid("task missing identity context"))?;
    let license_snapshot = license
        .active_license(identity_id.trim())
        .map_err(CommandError::from)?;
    if !license_snapshot.limits.resume_enabled {
        return Err(CommandError::license_violation(LicenseError::new(
            "RESUME_DISABLED",
            "当前权益不支持断点续传，请升级到 Pro 版以启用该功能。",
        )));
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
    let receipt: TransitionReceipt = serde_json::from_reader(file)
        .map_err(|err| CommandError::verify_failed(format!("invalid PoT JSON payload: {err}")))?;

    let reason = validate_proof(&receipt);
    Ok(VerifyPotResponse {
        valid: reason.is_none(),
        reason,
        receipt: Some(receipt),
    })
}

#[tauri::command]
pub async fn get_pot_commitment(
    pot_path: String,
    is_sender: bool,
) -> Result<String, CommandError> {
    let path = PathBuf::from(&pot_path);
    if !path.exists() {
        return Err(CommandError::invalid("PoT file not found"));
    }

    let file = fs::File::open(&path)
        .map_err(|err| CommandError::from_io(&err, "failed to open PoT file"))?;
    let receipt: TransitionReceipt = serde_json::from_reader(file)
        .map_err(|err| CommandError::verify_failed(format!("invalid PoT JSON payload: {err}")))?;

    let commitment = if is_sender {
        receipt.compute_sender_commitment()
    } else {
        receipt.compute_receiver_commitment()
            .map_err(|err| CommandError::verify_failed(format!("failed to compute receiver commitment: {err}")))?
    };

    Ok(hex::encode(commitment))
}

#[tauri::command]
pub async fn sign_pot(
    pot_path: String,
    signature: String,
    is_sender: bool,
) -> Result<VerifyPotResponse, CommandError> {
    let path = PathBuf::from(&pot_path);
    if !path.exists() {
        return Err(CommandError::invalid("PoT file not found"));
    }

    let file = fs::File::open(&path)
        .map_err(|err| CommandError::from_io(&err, "failed to open PoT file"))?;
    let mut receipt: TransitionReceipt = serde_json::from_reader(file)
        .map_err(|err| CommandError::verify_failed(format!("invalid PoT JSON payload: {err}")))?;

    if is_sender {
        receipt.sender_signature = Some(signature);
    } else {
        receipt.receiver_signature = Some(signature);
        if receipt.timestamp_complete.is_none() {
            receipt.complete();
        }
    }

    let proof_json = serde_json::to_vec_pretty(&receipt)
        .map_err(|err| CommandError::from_io(&std::io::Error::new(std::io::ErrorKind::Other, err), "failed to serialize proof"))?;
    
    let mut file = fs::File::create(&path)
        .map_err(|err| CommandError::from_io(&err, "failed to write PoT file"))?;
    file.write_all(&proof_json)
        .map_err(|err| CommandError::from_io(&err, "failed to write proof data"))?;

    let reason = validate_proof(&receipt);
    Ok(VerifyPotResponse {
        valid: reason.is_none(),
        reason,
        receipt: Some(receipt),
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
            lan_streams: payload.chunk_policy.lan_streams,
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
            lan_streams: settings.chunk_policy.lan_streams,
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

fn validate_proof(receipt: &TransitionReceipt) -> Option<String> {
    if receipt.version != 1 {
        return Some("Unsupported PoT version".into());
    }
    if receipt.files.is_empty() {
        return Some("No attested files in proof".into());
    }
    if receipt.route_type.trim().is_empty() {
        return Some("Route missing from PoT".into());
    }
    // For MVP, we might not have signatures yet, but check if structure is valid
    if receipt
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
                lan_streams: payload.chunk_policy.lan_streams,
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

        let heartbeat_signature =
            identity_key.sign(format!("heartbeat:{identity_id}:{device_id}").as_bytes());
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

        let update_signature =
            identity_key.sign(format!("update_device:{identity_id}:{device_id}").as_bytes());
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
                    route_attempts: None,
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

    if let Some(lan_mode) = task.lan_mode.clone() {
        return run_lan_transfer(app, state, task, lan_mode).await;
    }

    emit_log(
        &app,
        &task_id,
        format!("Transfer session key {}", task.session_key),
    );

    let router = if let Some(routes) = task.preferred_routes.clone() {
        Router::from_app_with_routes(&app, routes)
    } else {
        Router::from_app(&app)
    };
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
            route_attempts: None,
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
            route_attempts: Some(candidate_labels.clone()),
            message: Some("Exchanging pairing code".into()),
            resume: None,
        },
    );
    sleep(Duration::from_millis(200)).await;

    let session_label = task.code.clone().unwrap_or_else(|| task_id.clone());
    let mut session = SessionDesc::new(session_label);
    #[cfg(feature = "transport-webrtc")]
    {
        let role = if matches!(task.direction, TransferDirection::Send) {
            WebRtcRole::Offerer
        } else {
            WebRtcRole::Answerer
        };
        session.webrtc = Some(WebRtcHint {
            role,
            identity_id: task.identity_id.clone(),
            device_id: task.device_id.clone(),
            device_name: task.device_name.clone(),
            signer_public_key: task.identity_public_key.clone(),
        });
    }
    let SelectedRoute {
        route: selected_route,
        stream,
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

    let result = secure_router_stream(&app, stream, &task, &selected_route, state.clone()).await;
    let (mut stream, peer_public, handshake_elapsed) = match result {
        Ok(tuple) => tuple,
        Err(err) => {
            if let Some(registry) = app.try_state::<RouteMetricsRegistry>() {
                registry.record(
                    selected_route.clone(),
                    Duration::ZERO,
                    false,
                    Some(&err.message),
                );
            }
            return Err(err);
        }
    };
    emit_log(
        &app,
        &task_id,
        format!(
            "Encrypted session established · peer key {}",
            encode_public_key_hex(&peer_public)
        ),
    );
    if let Some(registry) = app.try_state::<RouteMetricsRegistry>() {
        registry.record(selected_route.clone(), handshake_elapsed, true, None);
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
            route_attempts: Some(candidate_labels.clone()),
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
    let route_metrics = app.try_state::<RouteMetricsRegistry>();
    let observed_latency = if let Some(registry) = route_metrics.as_ref() {
        if let Some(avg) = registry.avg_latency(&selected_route) {
            (avg + handshake_elapsed) / 2
        } else {
            handshake_elapsed
        }
    } else {
        handshake_elapsed
    };
    let historical_success = route_metrics
        .as_ref()
        .and_then(|registry| registry.success_rate(&selected_route));
    let weak_network = matches!(selected_route, RouteKind::Relay)
        || observed_latency > Duration::from_millis(250)
        || historical_success.map(|rate| rate < 0.45).unwrap_or(false);
    let suggested_chunk = derive_chunk_size(
        &settings.chunk_policy,
        &selected_route,
        observed_latency,
        weak_network,
        historical_success,
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
                route_attempts: None,
                message: Some(format!(
                    "Resuming transfer · {} remaining chunks",
                    pending_indices.len()
                )),
                resume: Some(resume_snapshot(&catalog)),
            },
        );
    }

    let mut chunk_iter = pending_indices.into_iter();
    let mut pending_jobs: FuturesUnordered<_> = FuturesUnordered::new();
    let desired_parallel = if bytes_total >= MULTI_STREAM_THRESHOLD {
        MAX_PARALLEL_CHUNKS
    } else if bytes_total >= 8 * 1024 * 1024 {
        DEFAULT_PARALLEL_CHUNKS
    } else {
        1
    };
    let parallelism = desired_parallel.min(MAX_PARALLEL_CHUNKS).max(1);
    let mut active_workers = 0usize;
    while active_workers < parallelism {
        if let Some(index) = chunk_iter.next() {
            let len = catalog.chunk_length(index);
            pending_jobs.push(spawn_blocking(move || prepare_mock_chunk(index, len)));
            active_workers += 1;
        } else {
            break;
        }
    }

    while let Some(result) = pending_jobs.next().await {
        let chunk = result.map_err(|err| {
            CommandError::route_unreachable(format!("chunk worker failed: {err}"))
        })?;
        let PreparedChunk {
            index,
            len,
            payload,
            digest_hex,
        } = chunk;

        stream
            .send(Frame::Data(payload))
            .await
            .map_err(|err| CommandError::route_unreachable(format!("transport failed: {err}")))?;
        catalog.mark_received(index);
        resume_store
            .store(&task_id, &catalog)
            .map_err(CommandError::from)?;
        acknowledged_bytes = acknowledged_bytes.saturating_add(len).min(bytes_total);
        emit_log(
            &app,
            &task_id,
            format!(
                "Chunk {}/{} confirmed ({} bytes, sha256:{})",
                index + 1,
                total_chunks,
                len,
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
                route_attempts: None,
                message: Some(format!(
                    "Streaming payload · chunk {}/{}",
                    index + 1,
                    total_chunks
                )),
                resume: Some(resume_snapshot(&catalog)),
            },
        );
        if let Some(next_index) = chunk_iter.next() {
            let len = catalog.chunk_length(next_index);
            pending_jobs.push(spawn_blocking(move || prepare_mock_chunk(next_index, len)));
        }
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
            route_attempts: None,
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
    
    let (sender_id, receiver_id) = match task.direction {
        TransferDirection::Send => (
            task.identity_public_key.clone().unwrap_or_default(),
            task.peer_public_key.as_ref().map(encode_public_key_hex).unwrap_or_default(),
        ),
        TransferDirection::Receive => (
            task.peer_public_key.as_ref().map(encode_public_key_hex).unwrap_or_default(),
            task.identity_public_key.clone().unwrap_or_default(),
        ),
    };
    
    let receipt = TransitionReceipt::new(
        Uuid::parse_str(&task_id).unwrap_or_default(),
        Uuid::new_v4(),
        sender_id,
        receiver_id,
        attestations,
        route_label_str.clone(),
    );

    let pot_path =
        write_proof_of_transition(&receipt, &proofs_dir)
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
            route_attempts: None,
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

async fn run_lan_transfer(
    app: AppHandle,
    state: SharedState,
    task: TransferTask,
    mode: LanMode,
) -> Result<(), CommandError> {
    emit_log(
        &app,
        &task.task_id,
        format!("Transfer session key {}", task.session_key),
    );

    emit_event(
        &app,
        "transfer_started",
        &TransferLifecycleEvent {
            task_id: task.task_id.clone(),
            direction: task.direction.clone(),
            code: task.code.clone(),
            message: None,
        },
    );
    state
        .set_status(&task.task_id, TransferStatus::InProgress)
        .await;

    match mode {
        LanMode::Sender { .. } => run_lan_sender(app, state, task).await,
        LanMode::Receiver { host, port } => run_lan_receiver(app, state, task, host, port).await,
    }
}

async fn run_lan_sender(
    app: AppHandle,
    state: SharedState,
    task: TransferTask,
) -> Result<(), CommandError> {
    let mut cleanup = MdnsCleanup::new(&app);
    let result = run_lan_sender_impl(app.clone(), state, task, &mut cleanup).await;
    cleanup.finish().await;
    result
}

async fn run_lan_sender_impl(
    app: AppHandle,
    state: SharedState,
    task: TransferTask,
    cleanup: &mut MdnsCleanup,
) -> Result<(), CommandError> {
    if task.files.is_empty() {
        return Err(CommandError::invalid("no files to send"));
    }
    let task_id = task.task_id.clone();
    let session_secret = task
        .session_secret
        .clone()
        .ok_or_else(|| CommandError::invalid("sender session secret missing"))?;
    let sender_public_key = task
        .public_key
        .clone()
        .ok_or_else(|| CommandError::invalid("sender public key missing"))?;
    let files = task.files.clone();
    let bytes_total: u64 = files.iter().map(|f| f.size).sum();
    let settings = app.state::<ConfigStore>().get();
    let initial_success = app
        .try_state::<RouteMetricsRegistry>()
        .and_then(|registry| registry.success_rate(&RouteKind::Lan));
    let lan_streams = recommended_lan_streams(bytes_total, &settings.chunk_policy, initial_success);

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Preparing,
            progress: Some(0.05),
            bytes_sent: None,
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some("Preparing LAN transfer context".into()),
            resume: None,
        },
    );

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Pairing,
            progress: Some(0.15),
            bytes_sent: None,
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some("Waiting for receiver to connect".into()),
            resume: None,
        },
    );

    let quic = LanQuic::with_streams(lan_streams)
        .map_err(|err| CommandError::route_unreachable(err.to_string()))?;
    let listener = quic
        .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
        .map_err(|err| CommandError::route_unreachable(format!("lan bind failed: {err}")))?;
    let cert_fingerprint = quic.certificate_fingerprint();
    state
        .update_task(&task_id, |pending| {
            pending.cert_fingerprint = Some(cert_fingerprint.clone());
        })
        .await;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| CommandError::route_unreachable(format!("lan addr failed: {err}")))?;
    let interfaces = collect_lan_interfaces();
    emit_log(
        &app,
        &task_id,
        format!(
            "LAN listener on {} · share IP: {:?}",
            listen_addr, interfaces
        ),
    );
    emit_log(
        &app,
        &task_id,
        format!("Certificate fingerprint {}", cert_fingerprint),
    );
    let sender_public_hex = Some(encode_public_key_hex(&sender_public_key));
    if let Some(code) = task.code.clone() {
        let device_label = match &task.lan_mode {
            Some(LanMode::Sender { device_name }) => device_name.clone(),
            _ => None,
        };
        if let Some(pub_hex) = sender_public_hex.as_ref() {
            if let Err(err) = cleanup
                .register(
                    &code,
                    &task_id,
                    listen_addr.port(),
                    &interfaces,
                    device_label,
                    pub_hex,
                    Some(&cert_fingerprint),
                )
                .await
            {
                emit_log(
                    &app,
                    &task_id,
                    format!("mDNS registration skipped: {}", err.message),
                );
            }
        } else {
            emit_log(
                &app,
                &task_id,
                "mDNS registration skipped: missing sender public key".into(),
            );
        }
    }

    let mut raw_stream = timeout(Duration::from_secs(60), listener.accept())
        .await
        .map_err(|_| CommandError::route_unreachable("receiver did not connect in time"))?
        .map_err(|err| CommandError::route_unreachable(format!("lan accept failed: {err}")))?;

    let hello = raw_stream.recv().await.map_err(|err| {
        CommandError::route_unreachable(format!("lan handshake read failed: {err}"))
    })?;
    let receiver_public = match hello {
        Frame::Control(text) => match decode_control_message(&text)? {
            LanControlMessage::ReceiverReady { public_key } => decode_public_key(&public_key)
                .map_err(|err| {
                    CommandError::invalid(format!("invalid receiver public key: {err}"))
                })?,
            other => {
                return Err(CommandError::route_unreachable(format!(
                    "unexpected control {:?} during handshake",
                    other
                )));
            }
        },
        _ => {
            return Err(CommandError::route_unreachable(
                "receiver did not initiate handshake",
            ));
        }
    };
    state
        .update_task(&task_id, |pending| {
            pending.peer_public_key = Some(receiver_public.clone());
        })
        .await;

    raw_stream
        .send(encode_control_message(&LanControlMessage::SenderReady {
            addresses: interfaces.clone(),
            port: listen_addr.port(),
            public_key: encode_public_key_hex(&sender_public_key),
            cert_fingerprint: cert_fingerprint.clone(),
        })?)
        .await
        .map_err(|err| CommandError::route_unreachable(format!("lan handshake failed: {err}")))?;

    let shared = session_secret.derive_shared(&receiver_public);
    let mut stream = SecureStream::new(Box::new(raw_stream), SessionCipher::new(shared));

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Connecting,
            progress: Some(0.25),
            bytes_sent: None,
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some("Receiver connected via LAN".into()),
            resume: None,
        },
    );

    let manifest: Vec<LanFileManifestEntry> = files
        .iter()
        .map(|file| LanFileManifestEntry {
            name: file.name.clone(),
            size: file.size,
        })
        .collect();
    stream
        .send(encode_control_message(&LanControlMessage::Manifest {
            files: manifest,
        })?)
        .await
        .map_err(|err| CommandError::route_unreachable(format!("lan send failed: {err}")))?;

    let mut bytes_sent = 0u64;
    let mut last_emit = Instant::now();
    let started = Instant::now();

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Transferring,
            progress: Some(0.3),
            bytes_sent: Some(0),
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some("Sending files over QUIC".into()),
            resume: None,
        },
    );

    for file in &files {
        emit_log(
            &app,
            &task_id,
            format!("Streaming {} ({} bytes)", file.name, file.size),
        );
        stream
            .send(encode_control_message(&LanControlMessage::FileStart {
                name: file.name.clone(),
                size: file.size,
            })?)
            .await
            .map_err(|err| CommandError::route_unreachable(format!("lan send failed: {err}")))?;
        let mut reader = File::open(&file.path).await.map_err(|err| {
            CommandError::from_io(&err, format!("failed to open {}", file.path.display()))
        })?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(|err| CommandError::from_io(&err, "failed to read file chunk"))?;
            if read == 0 {
                break;
            }
            stream
                .send(Frame::Data(buffer[..read].to_vec()))
                .await
                .map_err(|err| {
                    CommandError::route_unreachable(format!("lan send failed: {err}"))
                })?;
            bytes_sent += read as u64;
            if last_emit.elapsed() > Duration::from_millis(350) {
                let elapsed = started.elapsed().as_secs_f32().max(0.001);
                let speed = (bytes_sent as f32 / elapsed) as u64;
                let progress = 0.3 + 0.55 * ((bytes_sent as f32 / bytes_total as f32).min(1.0));
                emit_progress(
                    &app,
                    TransferProgressEvent {
                        task_id: task_id.clone(),
                        phase: TransferPhase::Transferring,
                        progress: Some(progress),
                        bytes_sent: Some(bytes_sent),
                        bytes_total: Some(bytes_total),
                        speed_bps: Some(speed),
                        route: Some(TransferRoute::Lan),
                        route_attempts: None,
                        message: Some(format!("Sending {}", file.name)),
                        resume: None,
                    },
                );
                last_emit = Instant::now();
            }
        }
        stream
            .send(encode_control_message(&LanControlMessage::FileEnd {
                name: file.name.clone(),
            })?)
            .await
            .map_err(|err| CommandError::route_unreachable(format!("lan send failed: {err}")))?;
    }

    stream
        .send(encode_control_message(&LanControlMessage::Done)?)
        .await
        .map_err(|err| CommandError::route_unreachable(format!("lan send failed: {err}")))?;
    stream.close().await.ok();

    emit_log(
        &app,
        &task_id,
        format!("Delivered {} bytes via LAN", bytes_sent),
    );

    finalize_lan_success(&app, &state, &task_id, TransferRoute::Lan, bytes_sent).await
}

async fn run_lan_receiver(
    app: AppHandle,
    state: SharedState,
    task: TransferTask,
    host: String,
    port: u16,
) -> Result<(), CommandError> {
    let save_dir = task
        .save_dir
        .clone()
        .ok_or_else(|| CommandError::invalid("save_dir missing for receive task"))?;
    let task_id = task.task_id.clone();
    let session_secret = task
        .session_secret
        .clone()
        .ok_or_else(|| CommandError::invalid("receiver session secret missing"))?;
    let receiver_public_key = task
        .public_key
        .clone()
        .ok_or_else(|| CommandError::invalid("receiver public key missing"))?;
    let expected_sender_key = task
        .peer_public_key
        .clone()
        .ok_or_else(|| CommandError::invalid("sender public key missing"))?;
    let ip: IpAddr = host
        .parse()
        .map_err(|_| CommandError::invalid("invalid host address"))?;
    let remote_addr = SocketAddr::new(ip, port);

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Preparing,
            progress: Some(0.05),
            bytes_sent: None,
            bytes_total: None,
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some(format!("Connecting to sender {}", remote_addr)),
            resume: None,
        },
    );

    let settings = app.state::<ConfigStore>().get();
    let bytes_hint: u64 = task.files.iter().map(|f| f.size).sum();
    let historical_success = app
        .try_state::<RouteMetricsRegistry>()
        .and_then(|registry| registry.success_rate(&RouteKind::Lan));
    let lan_streams =
        recommended_lan_streams(bytes_hint, &settings.chunk_policy, historical_success);
    let quic = LanQuic::with_streams(lan_streams)
        .map_err(|err| CommandError::route_unreachable(err.to_string()))?;
    let mut raw_stream = quic
        .connect(remote_addr)
        .await
        .map_err(|err| CommandError::route_unreachable(format!("lan connect failed: {err}")))?;

    raw_stream
        .send(encode_control_message(&LanControlMessage::ReceiverReady {
            public_key: encode_public_key_hex(&receiver_public_key),
        })?)
        .await
        .map_err(|err| CommandError::route_unreachable(format!("lan handshake failed: {err}")))?;

    let ready = raw_stream.recv().await.map_err(|err| {
        CommandError::route_unreachable(format!("lan handshake read failed: {err}"))
    })?;
    match ready {
        Frame::Control(text) => match decode_control_message(&text)? {
            LanControlMessage::SenderReady {
                addresses,
                port,
                public_key,
                cert_fingerprint,
            } => {
                let sender_key = decode_public_key(&public_key).map_err(|err| {
                    CommandError::invalid(format!("invalid sender public key: {err}"))
                })?;
                if sender_key != expected_sender_key {
                    return Err(CommandError::invalid(
                        "sender public key mismatch, please verify the code and key",
                    ));
                }
                if let Some(expected_fp) = task.expected_cert_fingerprint.as_ref() {
                    if expected_fp != &cert_fingerprint {
                        return Err(CommandError::invalid(
                            "sender certificate fingerprint mismatch",
                        ));
                    }
                }
                emit_log(
                    &app,
                    &task_id,
                    format!("Sender listening on port {} · {:?}", port, addresses),
                );
            }
            other => {
                return Err(CommandError::route_unreachable(format!(
                    "unexpected control {:?} during handshake",
                    other
                )));
            }
        },
        _ => {
            return Err(CommandError::route_unreachable("sender handshake missing"));
        }
    }

    let shared = session_secret.derive_shared(&expected_sender_key);
    let mut stream = SecureStream::new(Box::new(raw_stream), SessionCipher::new(shared));

    let manifest_msg = stream.recv().await.map_err(|err| {
        CommandError::route_unreachable(format!("failed to read manifest: {err}"))
    })?;
    let manifest = match manifest_msg {
        Frame::Control(text) => match decode_control_message(&text)? {
            LanControlMessage::Manifest { files } => files,
            other => {
                return Err(CommandError::route_unreachable(format!(
                    "unexpected control {:?} when expecting manifest",
                    other
                )));
            }
        },
        _ => {
            return Err(CommandError::route_unreachable(
                "sender did not provide manifest",
            ));
        }
    };

    let bytes_total: u64 = manifest.iter().map(|entry| entry.size).sum();
    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Connecting,
            progress: Some(0.2),
            bytes_sent: Some(0),
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some(format!("Receiving {} files", manifest.len())),
            resume: None,
        },
    );

    let mut bytes_received = 0u64;
    let mut last_emit = Instant::now();
    let start = Instant::now();
    let mut manifest_iter = manifest.into_iter();
    let mut active_file: Option<(String, File, u64, u64, PathBuf)> = None;
    let mut received_files: Vec<TrackedFile> = Vec::new();

    emit_progress(
        &app,
        TransferProgressEvent {
            task_id: task_id.clone(),
            phase: TransferPhase::Transferring,
            progress: Some(0.3),
            bytes_sent: Some(0),
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(TransferRoute::Lan),
            route_attempts: None,
            message: Some("Receiving data".into()),
            resume: None,
        },
    );

    loop {
        let frame = stream
            .recv()
            .await
            .map_err(|err| CommandError::route_unreachable(format!("lan receive failed: {err}")))?;
        match frame {
            Frame::Control(text) => match decode_control_message(&text)? {
                LanControlMessage::FileStart { name, size } => {
                    let entry = manifest_iter.next().unwrap_or(LanFileManifestEntry {
                        name: name.clone(),
                        size,
                    });
                    let dest = unique_destination_path(&save_dir, &entry.name);
                    let file = File::create(&dest).await.map_err(|err| {
                        CommandError::from_io(&err, format!("failed to create {}", dest.display()))
                    })?;
                    emit_log(
                        &app,
                        &task_id,
                        format!("Receiving {} ({} bytes)", entry.name, entry.size),
                    );
                    active_file = Some((entry.name, file, 0, entry.size, dest));
                }
                LanControlMessage::FileEnd { name } => {
                    if let Some((current_name, mut file, written, _target, dest)) =
                        active_file.take()
                    {
                        if current_name != name {
                            return Err(CommandError::route_unreachable("file order mismatch"));
                        }
                        file.flush()
                            .await
                            .map_err(|err| CommandError::from_io(&err, "failed to flush file"))?;
                        received_files.push(TrackedFile {
                            name: current_name,
                            size: written,
                            path: dest,
                        });
                    }
                }
                LanControlMessage::Done => {
                    break;
                }
                other => {
                    emit_log(&app, &task_id, format!("lan control {:?}", other));
                }
            },
            Frame::Data(bytes) => {
                if let Some((name, file, written, total, _dest)) = active_file.as_mut() {
                    file.write_all(&bytes).await.map_err(|err| {
                        CommandError::from_io(&err, format!("write {} failed", name))
                    })?;
                    *written += bytes.len() as u64;
                    bytes_received += bytes.len() as u64;
                    if last_emit.elapsed() > Duration::from_millis(350) {
                        let elapsed = start.elapsed().as_secs_f32().max(0.001);
                        let speed = (bytes_received as f32 / elapsed) as u64;
                        let progress =
                            0.3 + 0.55 * ((bytes_received as f32 / bytes_total as f32).min(1.0));
                        emit_progress(
                            &app,
                            TransferProgressEvent {
                                task_id: task_id.clone(),
                                phase: TransferPhase::Transferring,
                                progress: Some(progress),
                                bytes_sent: Some(bytes_received),
                                bytes_total: Some(bytes_total),
                                speed_bps: Some(speed),
                                route: Some(TransferRoute::Lan),
                                route_attempts: None,
                                message: Some(format!(
                                    "Receiving {} ({}/{})",
                                    name, *written, total
                                )),
                                resume: None,
                            },
                        );
                        last_emit = Instant::now();
                    }
                }
            }
        }
    }

    stream.close().await.ok();

    let received_clone = received_files.clone();
    state
        .update_task(&task_id, |pending| {
            pending.files = received_clone;
        })
        .await;

    emit_log(&app, &task_id, format!("Received {} bytes", bytes_received));

    finalize_lan_success(&app, &state, &task_id, TransferRoute::Lan, bytes_received).await
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
        identity_id: task.identity_id.clone(),
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

fn prepare_mock_chunk(index: u64, len: u64) -> PreparedChunk {
    let mut payload = vec![0u8; len as usize];
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = ((index as usize + offset) % 251) as u8;
    }
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let digest_hex = hex::encode(hasher.finalize());
    PreparedChunk {
        index,
        len,
        payload,
        digest_hex,
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

fn prepare_save_dir(path: &str) -> Result<PathBuf, CommandError> {
    let save_dir_path = Path::new(path);
    if !save_dir_path.exists() {
        fs::create_dir_all(save_dir_path)
            .map_err(|err| CommandError::from_io(&err, "failed to prepare save directory"))?;
    }
    if !save_dir_path.is_dir() {
        return Err(CommandError::invalid("save_dir must be a directory"));
    }
    Ok(save_dir_path.to_path_buf())
}

async fn init_receive_task(
    state: &SharedState,
    identity_id: &str,
    identity_public_key: &str,
    device_id: &str,
    device_name: Option<String>,
    code: &str,
    save_dir_path: &Path,
    host: String,
    port: u16,
    session_secret: SessionSecretBytes,
    session_public_key: SessionPublicKey,
    peer_public_key: SessionPublicKey,
    cert_fingerprint: Option<String>,
) -> Result<TransferTask, CommandError> {
    let session_key = crypto::derive_mock_session_key();
    let mut task = TransferTask::new(
        TransferDirection::Receive,
        Some(code.to_string()),
        Vec::new(),
        session_key,
    );
    task.identity_id = Some(identity_id.to_string());
    task.identity_public_key = Some(identity_public_key.to_string());
    task.device_id = Some(device_id.to_string());
    task.device_name = device_name.clone();
    let task = state.insert_task(task).await;
    state.track_code(code, &task.task_id).await;
    let save_dir_owned = save_dir_path.to_path_buf();
    let updated_task = state
        .update_task(&task.task_id, |pending| {
            pending.save_dir = Some(save_dir_owned.clone());
            pending.lan_mode = Some(LanMode::Receiver {
                host: host.clone(),
                port,
            });
            pending.status = TransferStatus::InProgress;
            pending.session_secret = Some(session_secret.clone());
            pending.public_key = Some(session_public_key.clone());
            pending.peer_public_key = Some(peer_public_key.clone());
            pending.expected_cert_fingerprint = cert_fingerprint.clone();
            pending.device_name = device_name.clone();
        })
        .await
        .unwrap_or(task);
    Ok(updated_task)
}

impl From<MdnsSenderInfo> for SenderInfoDto {
    fn from(value: MdnsSenderInfo) -> Self {
        SenderInfoDto {
            code: value.code,
            device_name: value.device_name,
            host: value.host,
            port: value.port,
            public_key: value.public_key,
            cert_fingerprint: value.cert_fingerprint,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LanControlMessage {
    ReceiverReady {
        public_key: String,
    },
    SenderReady {
        addresses: Vec<String>,
        port: u16,
        public_key: String,
        cert_fingerprint: String,
    },
    Manifest {
        files: Vec<LanFileManifestEntry>,
    },
    FileStart {
        name: String,
        size: u64,
    },
    FileEnd {
        name: String,
    },
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LanFileManifestEntry {
    name: String,
    size: u64,
}

struct PreparedChunk {
    index: u64,
    len: u64,
    payload: Vec<u8>,
    digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum TransportHandshake {
    KeyExchange {
        #[serde(rename = "publicKey")]
        public_key: String,
    },
}

struct SecureStream {
    inner: Box<dyn TransportStream>,
    cipher: SessionCipher,
}

impl SecureStream {
    fn new(inner: Box<dyn TransportStream>, cipher: SessionCipher) -> Self {
        Self { inner, cipher }
    }

    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        let ciphertext = self
            .cipher
            .encrypt_frame(frame)
            .map_err(|err| TransportError::Io(format!("encrypt frame failed: {err}")))?;
        self.inner.send(Frame::Data(ciphertext)).await
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        match self.inner.recv().await? {
            Frame::Data(bytes) => self
                .cipher
                .decrypt_frame(bytes)
                .map_err(|err| TransportError::Io(format!("decrypt frame failed: {err}"))),
            Frame::Control(text) => Err(TransportError::Io(format!(
                "unexpected plaintext control frame after secure session: {text}"
            ))),
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.inner.close().await
    }
}

async fn secure_router_stream(
    app: &AppHandle,
    mut stream: Box<dyn TransportStream>,
    task: &TransferTask,
    route: &RouteKind,
    state: SharedState,
) -> Result<(SecureStream, SessionPublicKey, Duration), CommandError> {
    let start = Instant::now();
    let session_secret = task
        .session_secret
        .clone()
        .ok_or_else(|| CommandError::invalid("session secret missing for encrypted route"))?;
    let local_public = task
        .public_key
        .clone()
        .ok_or_else(|| CommandError::invalid("session public key missing for encrypted route"))?;

    let hello = TransportHandshake::KeyExchange {
        public_key: encode_public_key_hex(&local_public),
    };
    let payload = serde_json::to_string(&hello).map_err(|err| {
        CommandError::route_unreachable(format!("handshake encode failed: {err}"))
    })?;

    let metrics = app.try_state::<RouteMetricsRegistry>();
    let record_result = |success: bool, elapsed: Duration, error: Option<&str>| {
        if let Some(registry) = metrics.as_ref() {
            registry.record(route.clone(), elapsed, success, error);
        }
    };

    stream.send(Frame::Control(payload)).await.map_err(|err| {
        record_result(false, start.elapsed(), Some(&err.to_string()));
        CommandError::route_unreachable(format!("handshake send failed: {err}"))
    })?;

    let peer_message = stream.recv().await.map_err(|err| {
        record_result(false, start.elapsed(), Some(&err.to_string()));
        CommandError::route_unreachable(format!("handshake receive failed: {err}"))
    })?;
    let peer_public_hex = match peer_message {
        Frame::Control(text) => {
            let parsed: TransportHandshake = serde_json::from_str(&text).map_err(|err| {
                record_result(false, start.elapsed(), Some(&err.to_string()));
                CommandError::route_unreachable(format!("handshake decode failed: {err}"))
            })?;
            match parsed {
                TransportHandshake::KeyExchange { public_key } => public_key,
            }
        }
        Frame::Data(_) => {
            record_result(
                false,
                start.elapsed(),
                Some("received data frame during handshake"),
            );
            return Err(CommandError::route_unreachable(
                "handshake expected control frame, received data",
            ));
        }
    };

    let peer_public = decode_public_key(&peer_public_hex).map_err(|err| {
        record_result(false, start.elapsed(), Some(&err.to_string()));
        CommandError::invalid(format!("peer public key invalid: {err}"))
    })?;

    if let Some(expected) = task.peer_public_key.as_ref() {
        if expected != &peer_public {
            record_result(false, start.elapsed(), Some("peer public key mismatch"));
            return Err(CommandError::invalid(
                "peer public key mismatch, please recheck the pairing code",
            ));
        }
    }

    let shared = session_secret.derive_shared(&peer_public);
    state
        .update_task(&task.task_id, |pending| {
            pending.peer_public_key = Some(peer_public.clone());
        })
        .await;

    let elapsed = start.elapsed();
    record_result(true, elapsed, None);
    Ok((
        SecureStream::new(stream, SessionCipher::new(shared)),
        peer_public,
        elapsed,
    ))
}

fn encode_control_message(message: &LanControlMessage) -> Result<Frame, CommandError> {
    serde_json::to_string(message)
        .map(Frame::Control)
        .map_err(|err| CommandError::route_unreachable(format!("control encode failed: {err}")))
}

fn decode_control_message(payload: &str) -> Result<LanControlMessage, CommandError> {
    serde_json::from_str(payload)
        .map_err(|err| CommandError::route_unreachable(format!("control decode failed: {err}")))
}

fn collect_lan_interfaces() -> Vec<String> {
    get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .filter_map(|iface| match iface.addr {
                    IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(v4.ip.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn unique_destination_path(base: &Path, file_name: &str) -> PathBuf {
    let mut candidate = base.join(file_name);
    if !candidate.exists() {
        return candidate;
    }
    let name_path = Path::new(file_name);
    let stem = name_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = name_path.extension().and_then(|s| s.to_str());
    let mut idx = 1;
    loop {
        let next_name = match ext {
            Some(ext) if !ext.is_empty() => format!("{stem}-{idx}.{ext}"),
            _ => format!("{stem}-{idx}"),
        };
        candidate = base.join(&next_name);
        if !candidate.exists() {
            return candidate;
        }
        idx += 1;
    }
}

async fn finalize_lan_success(
    app: &AppHandle,
    state: &SharedState,
    task_id: &str,
    route: TransferRoute,
    bytes_total: u64,
) -> Result<(), CommandError> {
    emit_progress(
        app,
        TransferProgressEvent {
            task_id: task_id.to_string(),
            phase: TransferPhase::Finalizing,
            progress: Some(0.9),
            bytes_sent: Some(bytes_total),
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(route.clone()),
            route_attempts: None,
            message: Some("Generating PoT".into()),
            resume: None,
        },
    );

    let current_task = state
        .get_task(task_id)
        .await
        .ok_or_else(CommandError::not_found)?;
    let mut attestations = Vec::new();
    for tracked in &current_task.files {
        let attestation = compute_file_attestation(&tracked.path).map_err(|err| {
            CommandError::from(anyhow!(
                "unable to attest file {}: {err}",
                tracked.path.display()
            ))
        })?;
        attestations.push(attestation);
    }

    let proofs_dir = default_proofs_dir(app).map_err(CommandError::from)?;
    let route_label = route.label().to_string();
    
    let (sender_id, receiver_id) = match current_task.direction {
        TransferDirection::Send => (
            current_task.identity_public_key.clone().unwrap_or_default(),
            current_task.peer_public_key.as_ref().map(encode_public_key_hex).unwrap_or_default(),
        ),
        TransferDirection::Receive => (
            current_task.peer_public_key.as_ref().map(encode_public_key_hex).unwrap_or_default(),
            current_task.identity_public_key.clone().unwrap_or_default(),
        ),
    };

    let receipt = TransitionReceipt::new(
        Uuid::parse_str(task_id).unwrap_or_default(),
        Uuid::new_v4(),
        sender_id,
        receiver_id,
        attestations,
        route_label.to_string(),
    );

    let pot_path = write_proof_of_transition(&receipt, &proofs_dir)
        .map_err(CommandError::from)?;
    state.set_pot_path(task_id, pot_path.clone()).await;
    if let Some(task_snapshot) = state.set_status(task_id, TransferStatus::Completed).await {
        persist_transfer_snapshot(
            app,
            &task_snapshot,
            Some(bytes_total),
            Some(bytes_total),
            Some(route_label.clone()),
        );
    }

    emit_progress(
        app,
        TransferProgressEvent {
            task_id: task_id.to_string(),
            phase: TransferPhase::Done,
            progress: Some(1.0),
            bytes_sent: Some(bytes_total),
            bytes_total: Some(bytes_total),
            speed_bps: None,
            route: Some(route.clone()),
            route_attempts: None,
            message: Some("Transfer completed".into()),
            resume: None,
        },
    );

    if let Some(task_snapshot) = state.get_task(task_id).await {
        emit_event(
            app,
            "transfer_completed",
            &TransferLifecycleEvent {
                task_id: task_snapshot.task_id.clone(),
                direction: task_snapshot.direction.clone(),
                code: task_snapshot.code.clone(),
                message: Some(pot_path.display().to_string()),
            },
        );
    }
    emit_log(
        app,
        task_id,
        format!("Proof of Transition stored at {}", pot_path.display()),
    );
    Ok(())
}

struct MdnsCleanup {
    app: AppHandle,
    code: Option<String>,
}

impl MdnsCleanup {
    fn new(app: &AppHandle) -> Self {
        Self {
            app: app.clone(),
            code: None,
        }
    }

    async fn register(
        &mut self,
        code: &str,
        task_id: &str,
        port: u16,
        addresses: &[String],
        device_name: Option<String>,
        public_key_hex: &str,
        cert_fingerprint: Option<&str>,
    ) -> Result<(), CommandError> {
        let mdns = self.app.state::<MdnsRegistry>();
        mdns.register_sender(
            code,
            task_id,
            port,
            addresses,
            device_name,
            public_key_hex,
            cert_fingerprint,
        )
        .await
        .map_err(|err| CommandError::route_unreachable(format!("mDNS register failed: {err}")))?;
        self.code = Some(code.to_string());
        Ok(())
    }

    async fn finish(&mut self) {
        if let Some(code) = self.code.take() {
            let mdns = self.app.state::<MdnsRegistry>();
            let _ = mdns.unregister(&code).await;
        }
    }
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
