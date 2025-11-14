use std::fs;
use std::io;
use std::path::Path;

use log::{info, warn};
use tauri::{AppHandle, Manager};

/// Attempt to migrate data from the previous app identifier/product folder
/// into the new app data dir. This is a best‑effort, non‑destructive copy:
/// existing files are preserved, only missing files/dirs are copied.
///
/// Rationale: identifier changed from `com.aetheros.courier` to
/// `com.aetheros.quantumdrop`, and product name from "Courier Agent" to
/// "Quantum Drop · 量子快传". On macOS this typically maps to
/// `~/Library/Application Support/<Folder>`; we derive the parent folder from
/// the new dir and probe potential legacy folder names.
pub fn run_legacy_migration(app: &AppHandle) {
    let Ok(new_dir) = app.path().app_data_dir() else {
        return;
    };

    // If new dir already contains identity or proofs, assume migrated/used.
    let new_identity = new_dir.join("identity");
    let new_proofs = new_dir.join("proofs");
    if new_identity.exists() || new_proofs.exists() {
        return;
    }

    let Some(parent) = new_dir.parent() else {
        return;
    };

    // Candidate legacy folder names to probe (sibling of new_dir).
    // Order matters: exact identifier, then product name variants.
    let candidates = [
        "com.aetheros.courier",
        "Courier Agent",
        "CourierAgent",
        "courier-agent",
    ];

    for name in candidates {
        let legacy_dir = parent.join(name);
        if !legacy_dir.exists() || !legacy_dir.is_dir() {
            continue;
        }
        match copy_missing(&legacy_dir, &new_dir) {
            Ok(_) => {
                info!(
                    "migrated legacy data from '{}' to '{}'",
                    legacy_dir.display(),
                    new_dir.display()
                );
                return; // stop after first successful source
            }
            Err(err) => {
                warn!(
                    "legacy migration from '{}' failed: {}",
                    legacy_dir.display(),
                    err
                );
            }
        }
    }
}

fn copy_missing(src_root: &Path, dst_root: &Path) -> io::Result<()> {
    if !dst_root.exists() {
        fs::create_dir_all(dst_root)?;
    }
    copy_dir_recursively(src_root, dst_root)
}

fn copy_dir_recursively(src: &Path, dst: &Path) -> io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursively(&from, &to)?;
        } else if ty.is_file() {
            if !to.exists() {
                // Try copy; ignore errors on a per-file basis to be resilient.
                if let Err(err) = fs::copy(&from, &to) {
                    warn!(
                        "failed to copy '{}' -> '{}': {}",
                        from.display(),
                        to.display(),
                        err
                    );
                }
            }
        }
    }
    Ok(())
}
