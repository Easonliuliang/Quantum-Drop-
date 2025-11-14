//! Minimal cryptographic facade for the S1 milestone.

pub mod session;

pub use session::{
    decode_public_key, encode_public_key_hex, SessionCipher, SessionPublicKey, SessionSecretBytes,
};

use rand::Rng;

const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn generate_task_code(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CODE_ALPHABET.len());
            CODE_ALPHABET[idx] as char
        })
        .collect()
}

pub fn derive_mock_session_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    format!("mock-key:{}", hex::encode(bytes))
}
