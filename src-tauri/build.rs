use std::fs;
use std::path::Path;

fn main() {
    // Conditionally generate BLE capability file when the feature is enabled.
    // Tauri resolves all files in capabilities/ at build time, so the file must
    // only exist when the plugin is actually compiled in.
    let ble_cap = Path::new("capabilities/ble.json");
    if cfg!(feature = "transport-ble") {
        fs::write(
            ble_cap,
            r#"{
  "$schema": "../../schemas/capability.json",
  "identifier": "ble",
  "description": "BLE discovery capability",
  "windows": ["main"],
  "permissions": [
    "ble:default"
  ]
}
"#,
        )
        .expect("failed to write BLE capability file");
    } else if ble_cap.exists() {
        let _ = fs::remove_file(ble_cap);
    }

    tauri_build::build()
}
