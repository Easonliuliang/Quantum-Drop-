use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::FileAttestation;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransitionReceipt {
    pub version: u8,
    pub transfer_id: Uuid,
    pub session_id: Uuid,
    
    // Identity
    pub sender_identity: String, // Ed25519 Public Key (Hex)
    pub receiver_identity: String, // Ed25519 Public Key (Hex)
    
    // Content
    pub files: Vec<FileAttestation>,
    
    // Context
    pub timestamp_start: DateTime<Utc>,
    pub timestamp_complete: Option<DateTime<Utc>>,
    pub route_type: String, // LAN, P2P, RELAY
    
    // Signatures
    pub sender_signature: Option<String>, // Signs (transfer_id + files_hash + metadata)
    pub receiver_signature: Option<String>, // Signs (sender_signature + timestamp_complete)
}

impl TransitionReceipt {
    pub fn new(
        transfer_id: Uuid,
        session_id: Uuid,
        sender_identity: String,
        receiver_identity: String,
        files: Vec<FileAttestation>,
        route_type: String,
    ) -> Self {
        Self {
            version: 1,
            transfer_id,
            session_id,
            sender_identity,
            receiver_identity,
            files,
            timestamp_start: Utc::now(),
            timestamp_complete: None,
            route_type,
            sender_signature: None,
            receiver_signature: None,
        }
    }

    pub fn complete(&mut self) {
        self.timestamp_complete = Some(Utc::now());
    }

    pub fn sign_sender(&mut self, key: &SigningKey) -> Result<()> {
        let commitment = self.compute_sender_commitment();
        let signature = key.sign(&commitment);
        self.sender_signature = Some(hex::encode(signature.to_bytes()));
        Ok(())
    }

    pub fn sign_receiver(&mut self, key: &SigningKey) -> Result<()> {
        if self.sender_signature.is_none() {
            return Err(anyhow::anyhow!("Sender signature missing"));
        }
        if self.timestamp_complete.is_none() {
            self.complete();
        }
        let commitment = self.compute_receiver_commitment()?;
        let signature = key.sign(&commitment);
        self.receiver_signature = Some(hex::encode(signature.to_bytes()));
        Ok(())
    }

    fn compute_sender_commitment(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[self.version]);
        hasher.update(self.transfer_id.as_bytes());
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.sender_identity.as_bytes());
        hasher.update(self.receiver_identity.as_bytes());
        for file in &self.files {
            hasher.update(file.merkle_root.as_bytes());
            hasher.update(&file.size.to_le_bytes());
        }
        hasher.update(&self.timestamp_start.timestamp_millis().to_le_bytes());
        hasher.update(self.route_type.as_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    fn compute_receiver_commitment(&self) -> Result<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        let sender_sig = self
            .sender_signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Sender signature missing"))?;
        hasher.update(sender_sig.as_bytes());
        
        let ts = self
            .timestamp_complete
            .ok_or_else(|| anyhow::anyhow!("Completion timestamp missing"))?;
        hasher.update(&ts.timestamp_millis().to_le_bytes());
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }
}

pub fn write_proof_of_transition(
    receipt: &TransitionReceipt,
    out_dir: &Path,
) -> Result<PathBuf> {
    fs::create_dir_all(out_dir).with_context(|| {
        format!(
            "failed to create proof output directory {}",
            out_dir.display()
        )
    })?;

    let mut proof_path = out_dir.to_path_buf();
    proof_path.push(format!("{}.pot.json", receipt.transfer_id));

    let mut file = File::create(&proof_path)
        .with_context(|| format!("unable to create proof file at {}", proof_path.display()))?;

    let proof_json = serde_json::to_vec_pretty(receipt).context("failed to serialize proof json")?;
    file.write_all(&proof_json)
        .context("failed to write proof data")?;

    Ok(proof_path)
}
