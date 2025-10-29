use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CID_SALT: &[u8] = b"courier-agent::pot::salt::v1";

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleComputation {
    pub chunks: usize,
    pub chunk_hashes: Vec<String>,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttestation {
    pub name: String,
    pub size: u64,
    pub cid: String,
    pub merkle_root: String,
    pub chunks: usize,
    pub chunk_hashes_sample: Vec<String>,
}

pub fn compute_file_attestation(path: &Path) -> Result<FileAttestation> {
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;

    if !metadata.is_file() {
        return Err(anyhow!("{} is not a regular file", path.display()));
    }

    let mut file =
        File::open(path).with_context(|| format!("unable to open file {}", path.display()))?;

    let MerkleComputation {
        chunks,
        chunk_hashes,
        merkle_root,
    } = compute_merkle(&mut file)?;

    let cid = derive_cid(&merkle_root)?;
    let chunk_hashes_sample = chunk_hashes.iter().take(5).cloned().collect();

    Ok(FileAttestation {
        name: path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string(),
        size: metadata.len(),
        cid,
        merkle_root,
        chunks,
        chunk_hashes_sample,
    })
}

fn derive_cid(merkle_root_hex: &str) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(CID_SALT);
    Ok(format!("b3:{}", hasher.finalize().to_hex()))
}

fn compute_merkle(file: &mut File) -> Result<MerkleComputation> {
    file.seek(SeekFrom::Start(0))
        .context("failed to seek start of file")?;

    let mut chunk_hashes = Vec::new();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .context("failed to read chunk for merkle computation")?;
        if bytes_read == 0 {
            break;
        }
        let digest = sha256_bytes(&buffer[..bytes_read]);
        chunk_hashes.push(format!("sha256:{}", hex::encode(digest)));
        leaves.push(digest);
    }

    if chunk_hashes.is_empty() {
        let digest = sha256_bytes(&[]);
        chunk_hashes.push(format!("sha256:{}", hex::encode(digest)));
        leaves.push(digest);
    }

    let root = compute_merkle_root(&leaves)?;

    Ok(MerkleComputation {
        chunks: chunk_hashes.len(),
        chunk_hashes,
        merkle_root: root,
    })
}

fn compute_merkle_root(leaves: &[[u8; 32]]) -> Result<String> {
    let mut nodes = if leaves.is_empty() {
        vec![sha256_bytes(&[])]
    } else {
        leaves.to_vec()
    };

    while nodes.len() > 1 {
        let mut next_level = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut hasher = Sha256::new();
            hasher.update(&left);
            hasher.update(&right);
            let digest = hasher.finalize();
            next_level.push(slice_to_array(&digest));
        }
        nodes = next_level;
    }

    Ok(format!("sha256:{}", hex::encode(nodes[0])))
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    slice_to_array(&digest)
}

fn slice_to_array(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[0..32]);
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn compute_merkle_for_empty_file() {
        let mut file = NamedTempFile::new().expect("tmp file");
        file.write_all(&[]).expect("write");
        let attestation = compute_file_attestation(file.path()).expect("attestation");
        assert_eq!(attestation.chunks, 1);
        assert!(
            attestation.merkle_root.starts_with("sha256:"),
            "merkle root should use sha256 prefix"
        );
    }

    #[test]
    fn compute_merkle_for_known_content() {
        let mut file = NamedTempFile::new().expect("tmp file");
        file.write_all(b"hello world").expect("write");

        let attestation = compute_file_attestation(file.path()).expect("attestation");
        assert_eq!(attestation.chunks, 1);
        assert_eq!(attestation.size, 11);
        let mut hasher = Sha256::new();
        hasher.update(b"hello world");
        let expected_chunk = format!("sha256:{}", hex::encode(hasher.finalize()));
        assert_eq!(attestation.chunk_hashes_sample[0], expected_chunk);
        assert!(attestation.cid.starts_with("b3:"));
    }

    #[test]
    fn compute_merkle_for_multi_chunk_file() {
        let mut file = NamedTempFile::new().expect("tmp file");
        let total = (CHUNK_SIZE * 2) + 123;
        let payload: Vec<u8> = (0..total).map(|idx| (idx % 251) as u8).collect();
        file.write_all(&payload).expect("write");

        let attestation = compute_file_attestation(file.path()).expect("attestation");
        assert_eq!(attestation.chunks, 3);
        assert_eq!(attestation.chunk_hashes_sample.len(), 3);
        assert_eq!(attestation.size as usize, total);
    }
}
