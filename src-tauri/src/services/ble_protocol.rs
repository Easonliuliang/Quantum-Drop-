//! BLE advertisement frame codec and GATT SenderInfo serialization.
//!
//! Pure data module — no BLE hardware dependencies.

use sha2::{Digest, Sha256};

use crate::services::mdns::SenderInfo;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 128-bit custom BLE service UUID for QuantumDrop discovery.
pub const BLE_SERVICE_UUID: &str = "7d2ea8b0-f94c-4b6d-9c8f-3a1b5e6d0f2a";

/// Current advertisement protocol version.
pub const BLE_PROTOCOL_VERSION: u8 = 1;

/// Number of leading SHA-256 bytes used as the code hash.
pub const CODE_HASH_LEN: usize = 6;

// Capability flag bits
pub const CAP_RECEIVABLE: u8 = 0b0000_0001;
pub const CAP_QUIC: u8 = 0b0000_0010;
pub const CAP_WEBRTC: u8 = 0b0000_0100;

/// Total encoded size of [`BleServiceData`].
pub const SERVICE_DATA_LEN: usize = 10;

// ---------------------------------------------------------------------------
// BLE Service Data (10 bytes)
// ---------------------------------------------------------------------------

/// Decoded BLE advertisement service data payload.
///
/// Layout (10 bytes):
/// ```text
/// [0]      protocol version   (1 B)
/// [1..7]   code_hash          (6 B) — SHA-256(code)[..6]
/// [7]      capabilities       (1 B)
/// [8..10]  reserved           (2 B)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleServiceData {
    pub version: u8,
    pub code_hash: [u8; CODE_HASH_LEN],
    pub capabilities: u8,
}

impl BleServiceData {
    /// Create a new service data frame from a plain-text code and capability flags.
    pub fn new(code: &str, capabilities: u8) -> Self {
        Self {
            version: BLE_PROTOCOL_VERSION,
            code_hash: compute_code_hash(code),
            capabilities,
        }
    }

    /// Serialize to a fixed 10-byte array.
    pub fn encode(&self) -> [u8; SERVICE_DATA_LEN] {
        let mut buf = [0u8; SERVICE_DATA_LEN];
        buf[0] = self.version;
        buf[1..7].copy_from_slice(&self.code_hash);
        buf[7] = self.capabilities;
        // buf[8..10] reserved — zeroed
        buf
    }

    /// Deserialize from a byte slice (must be exactly 10 bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self, BleProtocolError> {
        if bytes.len() != SERVICE_DATA_LEN {
            return Err(BleProtocolError::InvalidLength {
                expected: SERVICE_DATA_LEN,
                got: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != BLE_PROTOCOL_VERSION {
            return Err(BleProtocolError::UnsupportedVersion(version));
        }
        let mut code_hash = [0u8; CODE_HASH_LEN];
        code_hash.copy_from_slice(&bytes[1..7]);
        Ok(Self {
            version,
            code_hash,
            capabilities: bytes[7],
        })
    }

    /// Check whether the stored hash matches the given code.
    pub fn matches_code(&self, code: &str) -> bool {
        self.code_hash == compute_code_hash(code)
    }
}

// ---------------------------------------------------------------------------
// GATT SenderInfo helpers
// ---------------------------------------------------------------------------

/// Serialize a [`SenderInfo`] to a JSON string for GATT characteristic reads.
pub fn encode_sender_info(info: &SenderInfo) -> Result<String, serde_json::Error> {
    serde_json::to_string(info)
}

/// Deserialize a [`SenderInfo`] from a JSON string read via GATT.
pub fn decode_sender_info(json: &str) -> Result<SenderInfo, serde_json::Error> {
    serde_json::from_str(json)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the 6-byte code hash: SHA-256(code)[..6].
pub fn compute_code_hash(code: &str) -> [u8; CODE_HASH_LEN] {
    let digest = Sha256::digest(code.as_bytes());
    let mut hash = [0u8; CODE_HASH_LEN];
    hash.copy_from_slice(&digest[..CODE_HASH_LEN]);
    hash
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BleProtocolError {
    #[error("invalid service data length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let sd = BleServiceData::new("test-code-123", CAP_RECEIVABLE | CAP_QUIC);
        let bytes = sd.encode();
        assert_eq!(bytes.len(), SERVICE_DATA_LEN);

        let decoded = BleServiceData::decode(&bytes).unwrap();
        assert_eq!(sd, decoded);
    }

    #[test]
    fn matches_code_positive() {
        let sd = BleServiceData::new("hello-world", CAP_WEBRTC);
        assert!(sd.matches_code("hello-world"));
    }

    #[test]
    fn matches_code_negative() {
        let sd = BleServiceData::new("hello-world", 0);
        assert!(!sd.matches_code("other-code"));
    }

    #[test]
    fn decode_wrong_length() {
        let result = BleServiceData::decode(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_unsupported_version() {
        let mut bytes = [0u8; SERVICE_DATA_LEN];
        bytes[0] = 99;
        let result = BleServiceData::decode(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn code_hash_deterministic() {
        let h1 = compute_code_hash("abc");
        let h2 = compute_code_hash("abc");
        assert_eq!(h1, h2);
        assert_ne!(h1, compute_code_hash("xyz"));
    }

    #[test]
    fn sender_info_roundtrip() {
        let info = SenderInfo {
            code: "test-code".into(),
            device_name: "My Device".into(),
            host: "192.168.1.100".into(),
            port: 9000,
            public_key: "pk-hex".into(),
            cert_fingerprint: "fp-hex".into(),
        };
        let json = encode_sender_info(&info).unwrap();
        let decoded = decode_sender_info(&json).unwrap();
        assert_eq!(info.code, decoded.code);
        assert_eq!(info.device_name, decoded.device_name);
        assert_eq!(info.host, decoded.host);
        assert_eq!(info.port, decoded.port);
        assert_eq!(info.public_key, decoded.public_key);
        assert_eq!(info.cert_fingerprint, decoded.cert_fingerprint);
    }

    #[test]
    fn capability_flags() {
        let combined = CAP_RECEIVABLE | CAP_QUIC | CAP_WEBRTC;
        assert_eq!(combined, 0b0000_0111);
        assert!(combined & CAP_RECEIVABLE != 0);
        assert!(combined & CAP_QUIC != 0);
        assert!(combined & CAP_WEBRTC != 0);
    }
}
