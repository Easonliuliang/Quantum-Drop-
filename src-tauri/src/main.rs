#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod attestation;
mod commands;
mod config;
mod crypto;
mod resume;
mod signaling;
mod store;
mod transport;

use commands::{
    auth_list_devices, auth_load_entitlement, auth_register_device, auth_register_identity,
    auth_update_device, auth_update_entitlement, auth_heartbeat_device, courier_cancel,
    courier_connect_by_code, courier_generate_code, courier_list_senders,
    courier_p2p_smoke_test, courier_receive, courier_relay_smoke_test, courier_resume,
    courier_send, export_pot, list_transfers, load_settings, update_settings, verify_pot,
    SharedState,
};
use config::ConfigStore;
use serde::Serialize;
use store::{IdentityStore, TransferStore};
use tauri::Manager;

mod services;
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Run legacy data migration (identifier/product rename) before stores initialise
            services::migration::run_legacy_migration(&app.handle());
            let store = TransferStore::initialise(&app.handle())
                .expect("failed to initialise transfer store");
            app.manage(store);
            let config_store =
                ConfigStore::initialise(&app.handle()).expect("failed to initialise config store");
            app.manage(config_store);
            let identity_store = IdentityStore::initialise(&app.handle())
                .expect("failed to initialise identity store");
            app.manage(identity_store);
            let mdns = MdnsRegistry::new().expect("failed to initialise mDNS registry");
            app.manage(mdns);
            Ok(())
        })
        .manage(SharedState::new())
        .invoke_handler(tauri::generate_handler![
            auth_register_identity,
            auth_register_device,
            auth_list_devices,
            auth_load_entitlement,
            auth_update_entitlement,
            auth_update_device,
            auth_heartbeat_device,
            health_check,
            courier_generate_code,
            courier_send,
            courier_receive,
            courier_connect_by_code,
            courier_cancel,
            courier_p2p_smoke_test,
            courier_relay_smoke_test,
            courier_resume,
            export_pot,
            courier_list_senders,
            verify_pot,
            list_transfers,
            load_settings,
            update_settings
        ])
        .run(tauri::generate_context!())
        .expect("error while running Quantum Drop · 量子快传");
}
