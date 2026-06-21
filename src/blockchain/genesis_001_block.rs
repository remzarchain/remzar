// src/blockchain/genesis_001_block.rs

use crate::network::p2p_006_reqresp::Hash;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{canon_wallet_id_checked, decode_hex_to_64, parse_wallet_address};
use crate::utility::time_policy::TimePolicy;

use hex;
use postcard::{take_from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fs;

use fips204::ml_dsa_65;

/// Zeroed guardian signature for genesis preimage (ML-DSA-65).
const ZERO_GUARDIAN_SIGNATURE: [u8; ml_dsa_65::SIG_LEN] = [0u8; ml_dsa_65::SIG_LEN];

/// Genesis constants used in hash preimage (deterministic, NOT in JSON).
const GENESIS_REWARD: u64 = 0;

/// Maximum human/config genesis data size.
const MAX_GENESIS_DATA_BYTES: usize = 1024;

#[inline]
fn validation_err(message: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: message.into(),
        tx_id: None,
    }
}

#[inline]
fn serialization_err(details: impl Into<String>) -> ErrorDetection {
    ErrorDetection::SerializationError {
        details: details.into(),
    }
}

/// Replay-safe genesis timestamp validation.
fn validate_genesis_timestamp_structural(ts: u64) -> Result<(), ErrorDetection> {
    TimePolicy::validate_unix_secs_structural("GenesisBlock.timestamp", ts)?;

    if ts < GlobalConfiguration::MIN_TIMESTAMP_SECS {
        return Err(validation_err(format!(
            "GenesisBlock timestamp below project minimum: {} < {}",
            ts,
            GlobalConfiguration::MIN_TIMESTAMP_SECS
        )));
    }

    Ok(())
}

/// Serde adapter: serialize/deserialize a 64-byte hash as a 128-char lowercase hex string.
mod serde_hash64_hex {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim();

        if s.len() != 128 {
            return Err(DeError::custom(format!(
                "expected 128 hex chars for 64-byte hash, got {}",
                s.len()
            )));
        }

        let mut out = [0u8; 64];
        hex::decode_to_slice(s, &mut out)
            .map_err(|e| DeError::custom(format!("invalid hex for 64-byte hash: {e}")))?;
        Ok(out)
    }
}

/// Binary postcard storage representation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct GenesisBlockWire {
    #[serde(with = "BigArray")]
    genesis_hash: Hash,
    #[serde(with = "BigArray")]
    merkle_root: Hash,
    #[serde(with = "BigArray")]
    prev_hash: Hash,

    timestamp: u64,
    data: String,
    founder_wallet: Option<String>,
}

/// **The GenesisBlock structure**
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GenesisBlock {
    // JSON-friendly hex strings (still 64-byte canonical in memory)
    #[serde(with = "serde_hash64_hex")]
    pub genesis_hash: Hash,
    #[serde(with = "serde_hash64_hex")]
    pub merkle_root: Hash,
    #[serde(with = "serde_hash64_hex")]
    pub prev_hash: Hash,

    pub timestamp: u64,
    pub data: String,

    /// OPTIONAL: canonical founder wallet id ("r" + 128 lowercase hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub founder_wallet: Option<String>,
}

impl From<&GenesisBlock> for GenesisBlockWire {
    fn from(g: &GenesisBlock) -> Self {
        Self {
            genesis_hash: g.genesis_hash,
            merkle_root: g.merkle_root,
            prev_hash: g.prev_hash,
            timestamp: g.timestamp,
            data: g.data.clone(),
            founder_wallet: g.founder_wallet.clone(),
        }
    }
}

impl From<GenesisBlockWire> for GenesisBlock {
    fn from(w: GenesisBlockWire) -> Self {
        Self {
            genesis_hash: w.genesis_hash,
            merkle_root: w.merkle_root,
            prev_hash: w.prev_hash,
            timestamp: w.timestamp,
            data: w.data,
            founder_wallet: w.founder_wallet,
        }
    }
}

impl GenesisBlock {
    // ───────────────────────── constructors ─────────────────────────

    /// Creates the Genesis Block with a custom timestamp.
    pub fn new_with_timestamp(data: &str, ts: u64) -> Result<Self, ErrorDetection> {
        Self::new_with_timestamp_and_miner(data, ts, "")
    }

    /// Creates the Genesis Block with a custom timestamp.
    pub fn new_with_timestamp_and_miner(
        data: &str,
        ts: u64,
        miner: &str,
    ) -> Result<Self, ErrorDetection> {
        validate_genesis_timestamp_structural(ts)?;

        if data.trim().is_empty() {
            return Err(validation_err("Genesis block data cannot be empty."));
        }

        if data.len() > MAX_GENESIS_DATA_BYTES {
            return Err(validation_err(format!(
                "Genesis block data too large: {} bytes",
                data.len()
            )));
        }

        let founder_wallet = {
            let m = miner.trim();
            if m.is_empty() {
                None
            } else {
                // Strict: must be canonical wallet id. Store canonicalized form.
                parse_wallet_address(m)?;
                Some(canon_wallet_id_checked(m)?)
            }
        };

        // Decode the two constants (64-byte hex each)
        let prev_hash: Hash = decode_hex_to_64(GlobalConfiguration::GENESIS_PREV_HASH_HEX)?;
        let merkle_root: Hash = decode_hex_to_64(GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX)?;

        // Build deterministic preimage aligned with Block::compute_block_hash:
        let mut buf = Vec::with_capacity(64 + 64 + ml_dsa_65::SIG_LEN + 8 + 64);

        buf.extend_from_slice(&prev_hash);
        buf.extend_from_slice(&merkle_root);
        buf.extend_from_slice(&ZERO_GUARDIAN_SIGNATURE);
        buf.extend_from_slice(&GENESIS_REWARD.to_be_bytes());

        // Dummy batch key digest (64 bytes)
        let dummy_hex = RemzarHash::compute_dummy_hash();

        if dummy_hex.len() != 128 {
            return Err(serialization_err(format!(
                "Dummy hash hex length mismatch: expected 128 chars, got {}",
                dummy_hex.len()
            )));
        }

        let mut dummy_bytes: Hash = [0u8; 64];
        hex::decode_to_slice(&dummy_hex, &mut dummy_bytes)
            .map_err(|e| serialization_err(format!("Decode dummy hash: {}", e)))?;
        buf.extend_from_slice(&dummy_bytes);

        // ✅ 64-byte canonical genesis hash
        let genesis_hash: Hash = RemzarHash::compute_bytes_hash(&buf);

        let g = Self {
            genesis_hash,
            merkle_root,
            prev_hash,
            timestamp: ts,
            data: data.to_string(),
            founder_wallet,
        };

        g.validate()?;
        Ok(g)
    }

    /// Creates the Genesis Block using the current runtime UTC UNIX time.
    pub fn new(data: &str) -> Result<Self, ErrorDetection> {
        let ts = TimePolicy::now_unix_secs_runtime()?;
        Self::new_with_timestamp(data, ts)
    }

    // ───────────────────────── helper for Block builder ─────────────────────────

    /// Returns the miner string you should put into the stored genesis `Block.miner`.
    pub fn miner_for_genesis_block(&self) -> String {
        self.founder_wallet.clone().unwrap_or_default()
    }

    /// Convenience: returns the canonical founder wallet if configured.
    pub fn founder_wallet(&self) -> Option<&str> {
        self.founder_wallet.as_deref()
    }

    // ───────────────────────── internal helpers ─────────────────────

    fn recompute_genesis_hash(&self) -> Result<Hash, ErrorDetection> {
        let mut buf = Vec::with_capacity(64 + 64 + ml_dsa_65::SIG_LEN + 8 + 64);

        buf.extend_from_slice(&self.prev_hash);
        buf.extend_from_slice(&self.merkle_root);
        buf.extend_from_slice(&ZERO_GUARDIAN_SIGNATURE);
        buf.extend_from_slice(&GENESIS_REWARD.to_be_bytes());

        let dummy_hex = RemzarHash::compute_dummy_hash();
        if dummy_hex.len() != 128 {
            return Err(serialization_err(format!(
                "Dummy hash hex length mismatch: expected 128 chars, got {}",
                dummy_hex.len()
            )));
        }

        let mut dummy_bytes: Hash = [0u8; 64];
        hex::decode_to_slice(&dummy_hex, &mut dummy_bytes)
            .map_err(|e| serialization_err(format!("Decode dummy hash: {}", e)))?;
        buf.extend_from_slice(&dummy_bytes);

        Ok(RemzarHash::compute_bytes_hash(&buf))
    }

    pub fn genesis_hash_hex(&self) -> String {
        hex::encode(self.genesis_hash)
    }

    // ───────────────────────── serialization ────────────────────────

    /// Serialize for binary storage/network-internal postcard use.
    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate()?;

        let wire = GenesisBlockWire::from(self);

        to_allocvec(&wire).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })
    }

    /// Deserialize binary storage/network-internal postcard bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let (wire, remaining): (GenesisBlockWire, &[u8]) =
            take_from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
                details: e.to_string(),
            })?;

        if remaining.iter().any(|b| *b != 0) {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "GenesisBlock trailing non-zero bytes after postcard payload: {} bytes",
                    remaining.len()
                ),
            });
        }

        let block = Self::from(wire);
        block.validate()?;
        Ok(block)
    }

    pub fn pad_to_max_size(&self) -> Result<Vec<u8>, ErrorDetection> {
        let mut buf = self.serialize()?;

        let max_block_size_usize =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).map_err(|_| {
                ErrorDetection::SerializationError {
                    details: "MAX_BLOCK_SIZE does not fit into usize".into(),
                }
            })?;
        if buf.len() > max_block_size_usize {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "GenesisBlock serialized size {} exceeds MAX_BLOCK_SIZE {}",
                    buf.len(),
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
            });
        }

        if buf.len() < max_block_size_usize {
            buf.resize(max_block_size_usize, 0u8);
        }

        Ok(buf)
    }

    pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
        let buf = self.serialize()?;

        let max_block_size_usize =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).map_err(|_| {
                ErrorDetection::SerializationError {
                    details: "MAX_BLOCK_SIZE does not fit into usize".into(),
                }
            })?;
        if buf.len() > max_block_size_usize {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "GenesisBlock serialized size {} exceeds MAX_BLOCK_SIZE {}",
                    buf.len(),
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
            });
        }

        Ok(buf)
    }

    // ─────────────── validation ────────────────────────

    pub fn validate(&self) -> Result<(), ErrorDetection> {
        let zeros64: Hash = [0u8; 64];

        if self.genesis_hash == zeros64 {
            return Err(validation_err("Genesis hash is all zeros."));
        }
        if self.merkle_root == zeros64 {
            return Err(validation_err("Merkle root is all zeros."));
        }

        validate_genesis_timestamp_structural(self.timestamp)?;

        if self.data.trim().is_empty() {
            return Err(validation_err("Genesis block data is empty."));
        }
        if self.data.len() > MAX_GENESIS_DATA_BYTES {
            return Err(validation_err(format!(
                "Genesis block data too large: {} bytes",
                self.data.len()
            )));
        }

        // Validate optional founder wallet strictly if present.
        if let Some(w) = self.founder_wallet.as_deref() {
            parse_wallet_address(w)?;
            let can = canon_wallet_id_checked(w)?;
            if can != w {
                return Err(validation_err(
                    "GenesisBlock founder_wallet is not canonical",
                ));
            }
        }

        if self.genesis_hash == self.prev_hash
            || self.genesis_hash == self.merkle_root
            || self.prev_hash == self.merkle_root
        {
            return Err(validation_err("Genesis hash fields must all be unique."));
        }

        let recomputed = self.recompute_genesis_hash()?;
        if recomputed != self.genesis_hash {
            return Err(validation_err(format!(
                "GenesisBlock genesis_hash mismatch. expected={}, got={}",
                hex::encode(recomputed),
                hex::encode(self.genesis_hash)
            )));
        }

        Ok(())
    }

    /// Runtime-only freshness check for genesis creation/loading tools.
    pub fn validate_against_now(&self, now: u64) -> Result<(), ErrorDetection> {
        self.validate()?;

        TimePolicy::validate_runtime_future_skew_secs(
            "GenesisBlock.timestamp",
            self.timestamp,
            now,
            GlobalConfiguration::MAX_FUTURE_DRIFT_SECS,
        )
    }

    // ─────────────── Genesis.Json Helper ────────────────────────

    pub fn to_json(&self) -> Result<String, ErrorDetection> {
        self.validate()?;

        serde_json::to_string_pretty(self).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })
    }

    pub fn to_json_file(&self, path: &str) -> Result<(), ErrorDetection> {
        let json = self.to_json()?;
        fs::write(path, json).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })
    }

    pub fn from_json(s: &str) -> Result<Self, ErrorDetection> {
        let g: Self = serde_json::from_str(s).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;
        g.validate()?;
        Ok(g)
    }

    pub fn from_json_file(path: &str) -> Result<Self, ErrorDetection> {
        let meta = fs::metadata(path).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;

        let max_block_size_usize =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).map_err(|_| {
                ErrorDetection::SerializationError {
                    details: "MAX_BLOCK_SIZE does not fit into usize".into(),
                }
            })?;

        let file_len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
        if file_len > max_block_size_usize {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Genesis JSON file too large: {} bytes (cap {})",
                    file_len,
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
            });
        }

        let data = fs::read_to_string(path).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;
        Self::from_json(&data)
    }
}
