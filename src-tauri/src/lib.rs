pub mod attestation;
pub mod audit;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod license;
pub mod metrics;
pub mod resume;
pub mod security;
pub mod services;
pub mod signaling;
pub mod store;
pub mod transport;

use audit::AuditLogger;
use commands::{
    audit_get_logs, auth_heartbeat_device, auth_list_devices, auth_load_entitlement,
    auth_register_device, auth_register_identity, auth_update_device, auth_update_entitlement,
    courier_cancel, courier_connect_by_code, courier_generate_code, courier_list_senders,
    courier_p2p_smoke_test, courier_receive, courier_relay_smoke_test, courier_resume,
    courier_route_metrics, courier_send, export_pot, license_activate, license_get_status,
    list_transfers, load_settings, security_get_config, transfer_stats, update_settings, verify_pot,
    SharedState,
};
#[cfg(feature = "transport-webrtc")]
use commands::{courier_start_webrtc_receiver, courier_start_webrtc_sender};
use config::ConfigStore;
use license::LicenseManager;
use metrics::RouteMetricsRegistry;
use security::SecurityConfig;
use serde::Serialize;
use store::{IdentityStore, TransferStore};
use tauri::Manager;
use services::discovery::DiscoveryService;
use services::mdns::MdnsRegistry;

#[derive(Serialize)]
struct HealthCheck {
    status: &'static str,
    version: &'static str,
}

/// Basic command verifying the core runtime is responsive.
#[tauri::command]
fn health_check() -> HealthCheck {
    HealthCheck {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init());

    #[cfg(feature = "transport-ble")]
    {
        builder = builder.plugin(tauri_plugin_ble::init());
    }

    builder
        .setup(|app| {
            // Run legacy data migration (identifier/product rename) before stores initialise
            services::migration::run_legacy_migration(&app.handle());
            let store = TransferStore::initialise(&app.handle())
                .expect("failed to initialise transfer store");
            app.manage(store);
            let config_store =
                ConfigStore::initialise(&app.handle()).expect("failed to initialise config store");
            app.manage(config_store);
            let security = SecurityConfig::load(&app.handle());
            app.manage(security);
            let identity_store = IdentityStore::initialise(&app.handle())
                .expect("failed to initialise identity store");
            let license_manager =
                LicenseManager::new(&identity_store).expect("failed to initialise license manager");
            let audit_logger =
                AuditLogger::new(&app.handle()).expect("failed to initialise audit logger");
            app.manage(identity_store.clone());
            app.manage(license_manager);
            app.manage(audit_logger);
            let mdns = MdnsRegistry::new().expect("failed to initialise mDNS registry");
            app.manage(DiscoveryService::new(mdns, app.handle().clone()));
            app.manage(RouteMetricsRegistry::default());
            Ok(())
        })
        .manage(SharedState::new())
        .invoke_handler({
            #[cfg(feature = "transport-webrtc")]
            {
                tauri::generate_handler![
                    auth_register_identity,
                    auth_register_device,
                    auth_list_devices,
                    auth_load_entitlement,
                    auth_update_entitlement,
                    auth_update_device,
                    auth_heartbeat_device,
                    audit_get_logs,
                    health_check,
                    courier_generate_code,
                    courier_send,
                    courier_receive,
                    courier_connect_by_code,
                    courier_cancel,
                    courier_p2p_smoke_test,
                    courier_relay_smoke_test,
                    courier_resume,
                    courier_route_metrics,
                    export_pot,
                    courier_list_senders,
                    verify_pot,
                    security_get_config,
                    list_transfers,
                    load_settings,
                    update_settings,
                    courier_start_webrtc_sender,
                    courier_start_webrtc_receiver,
                    license_get_status,
                    license_activate,
                    transfer_stats,
                ]
            }
            #[cfg(not(feature = "transport-webrtc"))]
            {
                tauri::generate_handler![
                    auth_register_identity,
                    auth_register_device,
                    auth_list_devices,
                    auth_load_entitlement,
                    auth_update_entitlement,
                    auth_update_device,
                    auth_heartbeat_device,
                    audit_get_logs,
                    health_check,
                    courier_generate_code,
                    courier_send,
                    courier_receive,
                    courier_connect_by_code,
                    courier_cancel,
                    courier_p2p_smoke_test,
                    courier_relay_smoke_test,
                    courier_resume,
                    courier_route_metrics,
                    export_pot,
                    courier_list_senders,
                    verify_pot,
                    security_get_config,
                    list_transfers,
                    load_settings,
                    update_settings,
                    license_get_status,
                    license_activate,
                    transfer_stats,
                ]
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Quantum Drop · 量子快传");
}
