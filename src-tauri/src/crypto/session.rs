use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::transport::Frame;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionKeyResponse {
    pub public_key: SessionPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionPublicKey {
    pub bytes: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSecretBytes {
    pub bytes: [u8; 32],
}

#[derive(Clone)]
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
}

impl SessionCipher {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared_secret));
        Self {
            cipher,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    pub fn encrypt_frame(&mut self, frame: Frame) -> Result<Vec<u8>, anyhow::Error> {
        let payload = bincode::serialize(&frame)?;
        let nonce = self.next_send_nonce();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload.as_ref())
            .map_err(|err| anyhow::anyhow!("frame encrypt failed: {err}"))?;
        Ok(ciphertext)
    }

    pub fn decrypt_frame(&mut self, ciphertext: Vec<u8>) -> Result<Frame, anyhow::Error> {
        let nonce = self.next_recv_nonce();
        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|err| anyhow::anyhow!("frame decrypt failed: {err}"))?;
        let frame: Frame = bincode::deserialize(&plaintext)?;
        Ok(frame)
    }

    fn next_send_nonce(&mut self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&self.send_nonce.to_be_bytes());
        self.send_nonce = self.send_nonce.wrapping_add(1);
        Nonce::from_slice(&bytes).clone()
    }

    fn next_recv_nonce(&mut self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&self.recv_nonce.to_be_bytes());
        self.recv_nonce = self.recv_nonce.wrapping_add(1);
        Nonce::from_slice(&bytes).clone()
    }
}

pub fn generate_ephemeral_keypair() -> (EphemeralSecret, SessionPublicKey) {
    let secret = EphemeralSecret::new(OsRng);
    let public = SessionPublicKey {
        bytes: X25519PublicKey::from(&secret).to_bytes(),
    };
    (secret, public)
}

pub fn derive_shared_key(secret: EphemeralSecret, peer: &SessionPublicKey) -> [u8; 32] {
    let peer_key = X25519PublicKey::from(peer.bytes);
    let shared = secret.diffie_hellman(&peer_key);
    shared.to_bytes()
}

pub fn derive_shared_key_static(secret: &StaticSecret, peer: &SessionPublicKey) -> [u8; 32] {
    let peer_key = X25519PublicKey::from(peer.bytes);
    let shared = secret.diffie_hellman(&peer_key);
    shared.to_bytes()
}

impl SessionSecretBytes {
    pub fn generate() -> (Self, SessionPublicKey) {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        let public = SessionPublicKey {
            bytes: X25519PublicKey::from(&secret).to_bytes(),
        };
        (
            Self {
                bytes: secret_bytes,
            },
            public,
        )
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn public_key(&self) -> SessionPublicKey {
        let secret = StaticSecret::from(self.bytes);
        SessionPublicKey {
            bytes: X25519PublicKey::from(&secret).to_bytes(),
        }
    }

    pub fn derive_shared(&self, peer: &SessionPublicKey) -> [u8; 32] {
        let secret = StaticSecret::from(self.bytes);
        derive_shared_key_static(&secret, peer)
    }
}

pub fn decode_public_key(hex_str: &str) -> Result<SessionPublicKey, anyhow::Error> {
    let bytes = hex::decode(hex_str.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid public key length");
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(SessionPublicKey { bytes: array })
}

pub fn encode_public_key_hex(key: &SessionPublicKey) -> String {
    hex::encode(key.bytes)
}
