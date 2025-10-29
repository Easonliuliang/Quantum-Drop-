#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod attestation;
mod commands;
mod crypto;
mod signaling;
mod transport;

use commands::{
    courier_cancel, courier_generate_code, courier_receive, courier_send, export_pot,
    list_transfers, verify_pot, SharedState,
};
use serde::Serialize;

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
        .manage(SharedState::new())
        .invoke_handler(tauri::generate_handler![
            health_check,
            courier_generate_code,
            courier_send,
            courier_receive,
            courier_cancel,
            export_pot,
            verify_pot,
            list_transfers
        ])
        .run(tauri::generate_context!())
        .expect("error while running Courier Agent");
}
