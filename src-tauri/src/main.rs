#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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
        .invoke_handler(tauri::generate_handler![health_check])
        .run(tauri::generate_context!())
        .expect("error while running Courier Agent");
}
