use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::FileAttestation;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofOfTransition {
    pub version: String,
    pub task_id: String,
    pub timestamp: String,
    pub sender_fingerprint: String,
    pub receiver_fingerprint: String,
    pub route: String,
    pub files: Vec<FileAttestation>,
    pub attest: ProofSignature,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofSignature {
    pub receiver_signature: String,
    pub algo: String,
}

pub fn write_proof_of_transition(
    task_id: &str,
    files: &[FileAttestation],
    route: &str,
    out_dir: &Path,
) -> Result<PathBuf> {
    fs::create_dir_all(out_dir).with_context(|| {
        format!(
            "failed to create proof output directory {}",
            out_dir.display()
        )
    })?;

    let proof = ProofOfTransition {
        version: "1".to_string(),
        task_id: task_id.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        sender_fingerprint: "ed25519:mock-sender".to_string(),
        receiver_fingerprint: "ed25519:mock-receiver".to_string(),
        route: route.to_string(),
        files: files.to_vec(),
        attest: ProofSignature {
            receiver_signature: format!("ed25519:{}", task_id),
            algo: "ed25519".to_string(),
        },
    };

    let mut proof_path = out_dir.to_path_buf();
    proof_path.push(format!("{}.pot.json", task_id));

    let mut file = File::create(&proof_path)
        .with_context(|| format!("unable to create proof file at {}", proof_path.display()))?;

    let proof_json = serde_json::to_vec_pretty(&proof).context("failed to serialize proof json")?;
    file.write_all(&proof_json)
        .context("failed to write proof data")?;

    Ok(proof_path)
}
