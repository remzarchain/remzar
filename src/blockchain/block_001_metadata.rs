//! src/blockchain/block_001_metadata.rs

use hex;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use fips204::ml_dsa_65;

use crate::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use crate::blockchain::genesis_001_block::GenesisBlock;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::time_policy::TimePolicy;

/// Canonical full-hash size after Blake3-512 migration.
const HASH_BYTES: usize = 64;

/// Canonical hex length for a full hash after Blake3-512 migration.
const HASH_HEX_LEN: usize = HASH_BYTES * 2;

/// Defensive corruption cap for block index in metadata.
///
/// This keeps the existing project behavior intact while naming the guard.
const MAX_METADATA_INDEX_HARD: u64 = 10_000_000;

/// - puzzle proof commitment (if present) is consensus-relevant metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BlockMetadata {
    pub index: u64,
    pub timestamp: u64,

    /// 64-byte previous block hash.
    #[serde(with = "BigArray")]
    pub previous_hash: [u8; 64],

    /// 64-byte Merkle root.
    #[serde(with = "BigArray")]
    pub merkle_root: [u8; 64],

    /// ML-DSA-65 guardian signature.
    #[serde(with = "BigArray")]
    pub guardian_signature: [u8; ml_dsa_65::SIG_LEN],

    /// Optional committed block-level PoR puzzle proof.
    pub puzzle_proof: Option<BlockPuzzleProof>,

    /// Declared block size (bytes).
    pub size: u64,
}

impl BlockMetadata {
    // ───────────────────── Constructors ─────────────────────────────

    pub fn new(
        index: u64,
        timestamp: u64,
        previous_hash: [u8; 64],
        merkle_root: [u8; 64],
        guardian_signature: [u8; ml_dsa_65::SIG_LEN],
        puzzle_proof: Option<BlockPuzzleProof>,
        size: u64,
    ) -> BlockMetadata {
        BlockMetadata {
            index,
            timestamp,
            previous_hash,
            merkle_root,
            guardian_signature,
            puzzle_proof,
            size,
        }
    }

    /// Build from the Genesis block.
    ///
    /// IMPORTANT:
    /// - Genesis carries no puzzle proof.
    /// - With canonical variable-length postcard storage, `size` should reflect what is actually stored.
    pub fn from_genesis(genesis_block: GenesisBlock) -> Result<Self, ErrorDetection> {
        genesis_block.validate()?;

        if genesis_block.merkle_root == [0u8; 64] {
            return Err(validation_err(
                "GenesisBlock merkle_root cannot be all zeros",
            ));
        }

        let genesis_timestamp = TimePolicy::canonical_event_timestamp_from_block(
            "BlockMetadata.genesis.timestamp",
            genesis_block.timestamp,
        )?;

        // Genesis metadata uses a zero guardian signature by design.
        let guardian_signature = [0u8; ml_dsa_65::SIG_LEN];

        // Build metadata first with placeholder size, then compute actual serialized size.
        let mut meta = Self {
            index: 0,
            timestamp: genesis_timestamp,
            previous_hash: genesis_block.prev_hash,
            merkle_root: genesis_block.merkle_root,
            guardian_signature,
            puzzle_proof: None,
            size: 0,
        };

        let encoded =
            postcard::to_allocvec(&meta).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Serialize BlockMetadata failed: {e}"),
            })?;

        let size_u64 =
            u64::try_from(encoded.len()).map_err(|_| ErrorDetection::SerializationError {
                details: "BlockMetadata serialized size does not fit into u64".into(),
            })?;

        meta.size = size_u64;
        meta.validate_structural()?;
        Ok(meta)
    }

    // ───────────────────── Puzzle Proof Helpers ─────────────────────

    /// Set/replace the committed puzzle proof.
    ///
    /// This is structural-only assignment.
    /// Consensus policy about whether a proof is required belongs at higher-level block validation.
    pub fn set_puzzle_proof(&mut self, proof: Option<BlockPuzzleProof>) {
        self.puzzle_proof = proof;
    }

    /// Borrow the current committed puzzle proof, if present.
    pub fn puzzle_proof(&self) -> Option<&BlockPuzzleProof> {
        self.puzzle_proof.as_ref()
    }

    /// Deterministic 64-byte commitment to the puzzle proof.
    ///
    /// Returns `[0; 64]` when no proof is present.
    pub fn puzzle_commitment_bytes(&self) -> Result<[u8; 64], ErrorDetection> {
        match self.puzzle_proof.as_ref() {
            Some(proof) => proof.commitment_bytes(),
            None => Ok([0u8; 64]),
        }
    }

    /// Puzzle commitment as canonical lowercase hex.
    pub fn puzzle_commitment_hex(&self) -> Result<String, ErrorDetection> {
        Ok(hex::encode(self.puzzle_commitment_bytes()?))
    }

    // ───────────────────── Compute & Verify ─────────────────────────

    pub fn compute_hash(&self) -> Result<String, ErrorDetection> {
        RemzarHash::compute_data_hash(self)
    }

    pub fn verify_hash(&self, expected: &str) -> Result<bool, ErrorDetection> {
        let expected = expected.trim();

        if expected.len() != HASH_HEX_LEN {
            return Err(validation_err(format!(
                "BlockMetadata expected hash hex length mismatch: expected {HASH_HEX_LEN} chars, got {}",
                expected.len()
            )));
        }

        Ok(self.compute_hash()? == expected)
    }

    // ────────────────── Merkle Root & Guardian Sig ──────────────────

    pub fn set_merkle_root<T: Serialize + Send + Sync>(
        &mut self,
        transactions: &[T],
    ) -> Result<(), ErrorDetection> {
        let merkle_hex = if transactions.is_empty() {
            RemzarHash::compute_dummy_hash()
        } else {
            RemzarHash::compute_merkle_root(transactions)?
        };

        if merkle_hex.len() != HASH_HEX_LEN {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Merkle root hex must be {HASH_HEX_LEN} chars ({HASH_BYTES} bytes), got {}",
                    merkle_hex.len()
                ),
            });
        }

        let mut merkle_bytes = [0u8; 64];
        hex::decode_to_slice(&merkle_hex, &mut merkle_bytes).map_err(|e| {
            ErrorDetection::SerializationError {
                details: format!("Merkle decode failed: {e}"),
            }
        })?;

        self.merkle_root = merkle_bytes;
        Ok(())
    }

    pub fn set_guardian_signature(&mut self, sig: [u8; ml_dsa_65::SIG_LEN]) {
        self.guardian_signature = sig;
    }

    // ──────────────── Postcard Storage ──────────────────────────────

    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate_structural()?;

        let serialized =
            postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Serialize BlockMetadata failed: {e}"),
            })?;

        if serialized.len() > GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Serialize BlockMetadata failed: serialized size {} exceeds cap {}",
                    serialized.len(),
                    GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES
                ),
            });
        }

        Ok(serialized)
    }

    /// Decode bytes deterministically (no wall-clock usage).
    /// Structural sanity checks included; policy/consensus checks are separate.
    /// Strict canonical decode: rejects trailing or non-canonical bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ErrorDetection> {
        if data.len() > GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Deserialize BlockMetadata failed: payload size {} exceeds cap {}",
                    data.len(),
                    GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES
                ),
            });
        }

        let meta: Self =
            postcard::from_bytes(data).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Deserialize BlockMetadata failed: {e}"),
            })?;

        meta.validate_structural()?;

        let canonical =
            postcard::to_allocvec(&meta).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Re-serialize BlockMetadata after decode failed: {e}"),
            })?;

        if canonical != data {
            return Err(ErrorDetection::SerializationError {
                details:
                    "Deserialize BlockMetadata failed: non-canonical or trailing bytes rejected"
                        .to_string(),
            });
        }

        Ok(meta)
    }

    // ────────────────────── Additional Validation ───────────────────

    /// Structural validation that should be deterministic across nodes.
    /// This intentionally avoids local wall-clock time to prevent stalls/forks from clock skew.
    pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
        if self.index > MAX_METADATA_INDEX_HARD || self.size > GlobalConfiguration::MAX_BLOCK_SIZE {
            return Err(validation_err(format!(
                "BlockMetadata fields out of bounds (corrupt?): index={}, size={}",
                self.index, self.size
            )));
        }

        if self.size < GlobalConfiguration::MIN_BLOCK_SIZE {
            return Err(validation_err(format!(
                "BlockMetadata: size field is implausibly small: {}",
                self.size
            )));
        }

        TimePolicy::validate_unix_secs_structural("BlockMetadata.timestamp", self.timestamp)?;

        // Preserve the existing project-level minimum if it is stricter than
        // the generic TimePolicy UNIX lower bound.
        if self.timestamp < GlobalConfiguration::MIN_TIMESTAMP_SECS {
            return Err(validation_err(format!(
                "BlockMetadata: timestamp below project minimum: {} < {}",
                self.timestamp,
                GlobalConfiguration::MIN_TIMESTAMP_SECS
            )));
        }

        let zeros64 = [0u8; 64];

        // Genesis rules
        if self.index == 0 {
            if self.merkle_root == zeros64 {
                return Err(validation_err(
                    "BlockMetadata: genesis merkle_root is all zeros",
                ));
            }

            if self.puzzle_proof.is_some() {
                return Err(validation_err(
                    "BlockMetadata: genesis must not include puzzle_proof",
                ));
            }

            // zero guardian signature is allowed for genesis in design
            return Ok(());
        }

        // Non-genesis checks
        if self.merkle_root == zeros64 {
            return Err(validation_err(format!(
                "BlockMetadata: merkle_root is all zeros (index {})",
                self.index
            )));
        }

        if self.previous_hash == zeros64 {
            return Err(validation_err(format!(
                "BlockMetadata: previous_hash is all zeros (index {})",
                self.index
            )));
        }

        let zeros_sig = [0u8; ml_dsa_65::SIG_LEN];
        if self.guardian_signature == zeros_sig {
            return Err(validation_err(format!(
                "BlockMetadata: guardian_signature is all zeros (index {})",
                self.index
            )));
        }

        if self.merkle_root == self.previous_hash {
            return Err(validation_err(format!(
                "BlockMetadata: merkle_root == previous_hash (index {})",
                self.index
            )));
        }

        // If present, puzzle proof must be internally valid and metadata-aligned.
        if let Some(proof) = self.puzzle_proof.as_ref() {
            proof.validate_structural()?;

            if proof.height != self.index {
                return Err(validation_err(format!(
                    "BlockMetadata: puzzle_proof.height {} != metadata.index {}",
                    proof.height, self.index
                )));
            }

            if proof.prev_block_hash != self.previous_hash {
                return Err(validation_err(
                    "BlockMetadata: puzzle_proof.prev_block_hash != metadata.previous_hash",
                ));
            }
        }

        Ok(())
    }

    pub fn validate_against_now(&self, now: u64) -> Result<(), ErrorDetection> {
        self.validate_structural()?;

        TimePolicy::validate_runtime_future_skew_secs(
            "BlockMetadata.timestamp",
            self.timestamp,
            now,
            GlobalConfiguration::MAX_FUTURE_DRIFT_SECS,
        )
    }

    /// Validate this block timestamp against its parent timestamp.
    ///
    /// This is replay-safe because it compares chain data to chain data.
    pub fn validate_timestamp(&self, previous_timestamp: u64) -> Result<(), ErrorDetection> {
        TimePolicy::validate_block_timestamp_against_parent(
            self.timestamp,
            previous_timestamp,
            GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
        )
    }

    /// Validate this block timestamp against its parent timestamp with a caller-supplied minimum delta.
    ///
    /// Use `min_delta_secs = 0` for monotonic-only validation, or the block interval
    /// for strict spacing.
    pub fn validate_timestamp_with_min_delta(
        &self,
        previous_timestamp: u64,
        min_delta_secs: u64,
    ) -> Result<(), ErrorDetection> {
        TimePolicy::validate_block_timestamp_against_parent(
            self.timestamp,
            previous_timestamp,
            min_delta_secs,
        )
    }

    pub fn validate_size(&self) -> Result<(), ErrorDetection> {
        if self.size < GlobalConfiguration::MIN_BLOCK_SIZE {
            return Err(validation_err(format!(
                "BlockMetadata.size field ({}) is below minimum ({})",
                self.size,
                GlobalConfiguration::MIN_BLOCK_SIZE
            )));
        }

        if self.size > GlobalConfiguration::MAX_BLOCK_SIZE {
            return Err(validation_err(format!(
                "BlockMetadata.size field ({}) exceeds MAX_BLOCK_SIZE ({})",
                self.size,
                GlobalConfiguration::MAX_BLOCK_SIZE
            )));
        }

        let serialized =
            postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Serialize BlockMetadata failed: {e}"),
            })?;

        let size = serialized.len();

        let max_block_size_usize =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);

        if size > max_block_size_usize {
            return Err(validation_err(format!(
                "BlockMetadata serialized size {size} exceeds maximum allowed {} bytes",
                GlobalConfiguration::MAX_BLOCK_SIZE
            )));
        }

        Ok(())
    }
}

#[inline]
fn validation_err(message: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: message.into(),
        tx_id: None,
    }
}
