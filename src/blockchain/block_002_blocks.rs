//! src/blockchain/block_002_blocks.rs

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked, serde_u8_array_64};
use fips204::ml_dsa_65;
type SigningKey = ml_dsa_65::PrivateKey;
type VerifyingKey = ml_dsa_65::PublicKey;

use postcard::take_from_bytes;
use postcard::to_allocvec;
use serde::{Deserialize, Serialize};

use crate::blockchain::block_001_metadata::BlockMetadata;
use crate::cryptography::ml_dsa_65_004_guardian_signature::GuardianSignature;

const MAX_MINER_LEN: usize = REMZAR_WALLET_LEN;
const MAX_BATCH_KEY_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub metadata: BlockMetadata,
    pub batch_key: Option<String>,
    pub miner: String,
    #[serde(with = "serde_u8_array_64")]
    pub block_hash: [u8; 64],

    pub reward: u64,
}

impl Block {
    // ───────────────────────── constructors ─────────────────────────
    pub fn new(
        metadata: BlockMetadata,
        batch_key: Option<String>,
        miner: String,
        reward: u64,
    ) -> Result<Self, ErrorDetection> {
        Self::validate_batch_key_bound(batch_key.as_deref(), "Block.batch_key")?;

        // Metadata structural checks are deterministic and do not use local wall clock.
        metadata.validate_structural()?;
        metadata.validate_size()?;

        let miner = Self::canonicalize_miner_for_height(&miner, metadata.index)?;

        let mut block = Self {
            metadata,
            batch_key,
            miner,
            block_hash: [0u8; 64],
            reward,
        };

        // Compute the block hash and decode it.
        let hex_hash = block.compute_block_hash()?;
        block.block_hash = Self::decode_hash_hex("Block hash", &hex_hash)?;

        Ok(block)
    }

    pub fn miner_wallet(&self) -> &str {
        &self.miner
    }

    // ──────────────────── signing / verification ────────────────────
    pub fn sign_block(&mut self, sk: &SigningKey) -> Result<(), ErrorDetection> {
        // 1) Create the guardian signature over the serialized metadata+batch_key.
        let signing_data = self.serialize_for_signing()?;
        let sig_bytes = GuardianSignature::sign_batch(sk, &[&signing_data])?;

        // 2) Validate signature length and copy into fixed array (ML-DSA-65).
        if sig_bytes.len() != ml_dsa_65::SIG_LEN {
            return Err(serialization_err(format!(
                "Guardian signature length mismatch: expected {} bytes, got {}",
                ml_dsa_65::SIG_LEN,
                sig_bytes.len()
            )));
        }
        let mut sig_arr = [0u8; ml_dsa_65::SIG_LEN];
        sig_arr.copy_from_slice(&sig_bytes);
        self.metadata.guardian_signature = sig_arr;

        // 3) Recompute block hash now that signature is embedded.
        let new_hex = self.compute_block_hash()?;
        self.block_hash = Self::decode_hash_hex("New block hash", &new_hex)?;

        Ok(())
    }

    pub fn verify_block_signature(&self, vk: &VerifyingKey) -> Result<bool, ErrorDetection> {
        let signing_data = self.serialize_for_signing()?;
        GuardianSignature::verify_batch(vk, &[&signing_data], &self.metadata.guardian_signature)?;
        Ok(true)
    }

    pub fn verify_block_hash(&self) -> Result<bool, ErrorDetection> {
        let hex_hash = self.compute_block_hash()?;
        let computed = Self::decode_hash_hex("Computed block hash", &hex_hash)?;
        Ok(self.block_hash == computed)
    }

    // ──────────────────── (de)serialization helpers ─────────────────
    fn serialize_for_signing(&self) -> Result<Vec<u8>, ErrorDetection> {
        let bk = self.batch_key.as_deref().unwrap_or("");
        to_allocvec(&(&self.metadata, bk)).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Serialize signing payload failed: {e}"),
        })
    }

    /// Consensus-safe storage encoding:
    pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
        // Deterministic sanity checks before emitting bytes. No local wall clock.
        self.validate(None)?;

        let buf = to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Serialize block: {e}"),
        })?;

        let max_block_size_usize =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);
        if buf.len() > max_block_size_usize {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Serialized block too large ({} bytes); exceeds MAX_BLOCK_SIZE {}.",
                    buf.len(),
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
            });
        }

        Ok(buf)
    }

    pub fn deserialize_from_storage(data: &[u8]) -> Result<Self, ErrorDetection> {
        Self::validate_storage_len(data)?;

        // Backward/forward compatible decode:
        let mut block: Block = match postcard::from_bytes::<Block>(data) {
            Ok(decoded_block) => decoded_block,
            Err(_strict_err) => {
                let (decoded_block, rest) = take_from_bytes::<Block>(data).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: format!("Deserialize block (postcard padded fallback): {e}"),
                    }
                })?;

                if rest.iter().any(|trailing_byte| *trailing_byte != 0) {
                    return Err(ErrorDetection::SerializationError {
                        details: format!(
                            "Deserialize block failed: non-zero trailing bytes after postcard payload: {} bytes",
                            rest.len()
                        ),
                    });
                }

                decoded_block
            }
        };

        block.normalize_and_validate_after_decode()?;
        Ok(block)
    }

    /// Deserialize a stored block AND return:
    ///  - actual_size_bytes: the true postcard-encoded bytes (before padding, if any)
    ///  - stored_size_bytes: the raw bytes length from RocksDB
    pub fn deserialize_with_sizes(data: &[u8]) -> Result<(Self, usize, usize), ErrorDetection> {
        Self::validate_storage_len(data)?;

        let stored_size_bytes = data.len();

        // Decode while tracking how many bytes were actually consumed.
        let (mut block, actual_size_bytes) = {
            let (decoded_block, rest) =
                take_from_bytes::<Block>(data).map_err(|e| ErrorDetection::SerializationError {
                    details: format!("Deserialize block (postcard with size tracking): {e}"),
                })?;

            if rest.iter().any(|trailing_byte| *trailing_byte != 0) {
                return Err(ErrorDetection::SerializationError {
                    details: format!(
                        "Deserialize block failed: non-zero trailing bytes after postcard payload: {} bytes",
                        rest.len()
                    ),
                });
            }

            let actual = stored_size_bytes.saturating_sub(rest.len());
            (decoded_block, actual)
        };

        block.normalize_and_validate_after_decode()?;

        if actual_size_bytes == 0 {
            return Err(ErrorDetection::SerializationError {
                details: "Decoded block size computed as 0 bytes; corrupt padding?".into(),
            });
        }

        Ok((block, actual_size_bytes, stored_size_bytes))
    }

    // ───────────────────────── block hashing ────────────────────────
    /// Concatenates critical fields + 64-byte hash of the batch key, then Blake3.
    pub fn compute_block_hash(&self) -> Result<String, ErrorDetection> {
        // 1) 64-byte digest from batch key (or dummy hash if none/empty).
        let key_hex = match self.batch_key.as_deref() {
            Some(bk) if !bk.is_empty() => RemzarHash::compute_bytes_hash_hex(bk.as_bytes()),
            _ => RemzarHash::compute_dummy_hash(),
        };

        // Expect 64 bytes => 128 hex chars.
        if key_hex.len() != 128 {
            return Err(serialization_err(format!(
                "Key hash hex length mismatch: expected 128 chars (64 bytes), got {}",
                key_hex.len()
            )));
        }

        let mut key_bytes = [0u8; 64];
        hex::decode_to_slice(&key_hex, &mut key_bytes).map_err(|e| {
            ErrorDetection::SerializationError {
                details: format!("Failed to decode key hash hex: {}", e),
            }
        })?;

        // 2) assemble buffer → Blake3 (via RemzarHash umbrella).
        let mut buf = Vec::with_capacity(64 + 64 + ml_dsa_65::SIG_LEN + 8 + 64);
        buf.extend_from_slice(&self.metadata.previous_hash);
        buf.extend_from_slice(&self.metadata.merkle_root);
        buf.extend_from_slice(&self.metadata.guardian_signature);
        buf.extend_from_slice(&self.reward.to_be_bytes());
        buf.extend_from_slice(&key_bytes);

        Ok(RemzarHash::compute_bytes_hash_hex(&buf))
    }

    // ───────────────────────── validation ───────────────────────────
    /// Deterministic block validation.
    pub fn validate(&self, prev_ts: Option<u64>) -> Result<(), ErrorDetection> {
        // Deterministic checks first (no local time).
        self.metadata.validate_structural()?;
        self.metadata.validate_size()?; // header-size sanity

        if let Some(previous_timestamp) = prev_ts
            && self.metadata.index > 0
        {
            self.metadata.validate_timestamp(previous_timestamp)?;
        }

        self.validate_miner_canonical()?;
        Self::validate_batch_key_bound(self.batch_key.as_deref(), "Block.batch_key")?;
        self.validate_block_hash_not_zero()?;

        if !self.verify_block_hash()? {
            return Err(validation_err("Block hash mismatch"));
        }

        Ok(())
    }

    /// Strict parent-time validation helper.
    pub fn validate_with_parent_timestamp(
        &self,
        previous_timestamp: u64,
    ) -> Result<(), ErrorDetection> {
        self.validate(Some(previous_timestamp))
    }

    /// Runtime-only timestamp freshness check.
    pub fn validate_against_now(&self, now: u64) -> Result<(), ErrorDetection> {
        self.validate(None)?;
        self.metadata.validate_against_now(now)
    }

    // ───────────────────────── helper ───────────────────────────
    // Returns the stored block_hash as a lowercase hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.block_hash)
    }

    /// Real size of the block when serialized (no padding).
    pub fn encoded_len_unpadded(&self) -> Result<usize, ErrorDetection> {
        postcard::to_allocvec(self).map(|v| v.len()).map_err(|e| {
            ErrorDetection::SerializationError {
                details: format!("Serialize block for size: {e}"),
            }
        })
    }

    pub fn encoded_len_padded(&self) -> usize {
        postcard::to_allocvec(self).map(|v| v.len()).unwrap_or(0)
    }

    // ───────────────────────── internal helpers ─────────────────────

    fn normalize_and_validate_after_decode(&mut self) -> Result<(), ErrorDetection> {
        // Deterministic sanity checks (prevent poison; no wall-clock).
        self.metadata.validate_structural()?;
        self.metadata.validate_size()?;

        self.miner = Self::canonicalize_miner_for_height(&self.miner, self.metadata.index)?;
        Self::validate_batch_key_bound(self.batch_key.as_deref(), "Block: batch_key")?;
        self.validate_block_hash_not_zero()?;

        Ok(())
    }

    fn canonicalize_miner_for_height(miner: &str, height: u64) -> Result<String, ErrorDetection> {
        if miner.trim().is_empty() {
            if height == 0 {
                return Ok(String::new());
            }

            return Err(validation_err("Block.miner missing"));
        }

        let miner = canon_wallet_id_checked(miner)?;

        if miner.len() > MAX_MINER_LEN {
            return Err(validation_err(format!(
                "Block.miner too long ({} bytes)",
                miner.len()
            )));
        }

        Ok(miner)
    }

    fn validate_miner_canonical(&self) -> Result<(), ErrorDetection> {
        if self.miner.trim().is_empty() {
            if self.metadata.index != 0 {
                return Err(validation_err("Block.miner missing"));
            }
            return Ok(());
        }

        let canon = canon_wallet_id_checked(&self.miner)?;
        if canon != self.miner {
            return Err(validation_err("Block.miner is not in canonical form"));
        }

        if self.miner.len() > MAX_MINER_LEN {
            return Err(validation_err(format!(
                "Block.miner too long ({} bytes)",
                self.miner.len()
            )));
        }

        Ok(())
    }

    fn validate_batch_key_bound(
        batch_key: Option<&str>,
        label: &'static str,
    ) -> Result<(), ErrorDetection> {
        if let Some(bk) = batch_key
            && bk.len() > MAX_BATCH_KEY_LEN
        {
            return Err(validation_err(format!(
                "{label} too long ({} bytes)",
                bk.len()
            )));
        }

        Ok(())
    }

    fn validate_storage_len(data: &[u8]) -> Result<(), ErrorDetection> {
        let min_block_size_usize =
            usize::try_from(GlobalConfiguration::MIN_BLOCK_SIZE).unwrap_or(usize::MAX);
        if data.len() < min_block_size_usize {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Block data too short ({} bytes); probably corrupt.",
                    data.len()
                ),
            });
        }

        let max_block_size_usize =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);
        if data.len() > max_block_size_usize {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Block data too large ({} bytes); exceeds MAX_BLOCK_SIZE {}.",
                    data.len(),
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
            });
        }

        Ok(())
    }

    fn validate_block_hash_not_zero(&self) -> Result<(), ErrorDetection> {
        let zeros64 = [0u8; 64];
        if self.metadata.index > 0 && self.block_hash == zeros64 {
            return Err(validation_err(format!(
                "Block: block_hash is all zeros (index {})",
                self.metadata.index
            )));
        }
        Ok(())
    }

    fn decode_hash_hex(label: &'static str, hex_hash: &str) -> Result<[u8; 64], ErrorDetection> {
        if hex_hash.len() != 128 {
            return Err(serialization_err(format!(
                "{label} hex length mismatch: expected 128 chars (64 bytes), got {}",
                hex_hash.len()
            )));
        }

        let mut arr = [0u8; 64];
        hex::decode_to_slice(hex_hash, &mut arr).map_err(|e| {
            ErrorDetection::SerializationError {
                details: format!("Failed to decode {label} hex: {}", e),
            }
        })?;
        Ok(arr)
    }
}

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
