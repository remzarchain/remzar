//! src/blockchain/block_003_puzzleproof.rs

use serde::{Deserialize, Serialize};

use crate::consensus::por_002_puzzle_engine::PorPuzzleEngine;
use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{canon_wallet_id_checked, serde_u8_array_64};

const MAX_VALIDATOR_LEN: usize = 256;
const MAX_REASONABLE_HEIGHT: u64 = 10_000_000;

/// Block-committed PoR puzzle proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlockPuzzleProof {
    /// Block height this puzzle proof is tied to.
    pub height: u64,

    /// Canonical Remzar validator wallet:
    /// "r" + 128 lowercase hex chars.
    pub validator: String,

    /// Parent block hash (64 bytes).
    #[serde(with = "serde_u8_array_64")]
    pub prev_block_hash: [u8; 64],

    /// Family-specific deterministic puzzle output:
    pub output: u128,
}

impl BlockPuzzleProof {
    #[inline]
    fn validation_err(msg: impl Into<String>) -> ErrorDetection {
        ErrorDetection::ValidationError {
            message: msg.into(),
            tx_id: None,
        }
    }

    /// Validate and canonicalize a validator string at the boundary.
    #[inline]
    fn canonical_validator_checked(validator: &str) -> Result<String, ErrorDetection> {
        if validator.len() > MAX_VALIDATOR_LEN {
            return Err(Self::validation_err(format!(
                "BlockPuzzleProof.validator too long (len={}, max={})",
                validator.len(),
                MAX_VALIDATOR_LEN
            )));
        }

        canon_wallet_id_checked(validator)
    }

    /// Create a new block-committed puzzle proof.
    pub fn new(
        height: u64,
        validator: String,
        prev_block_hash: [u8; 64],
        output: u128,
    ) -> Result<Self, ErrorDetection> {
        let validator = Self::canonical_validator_checked(&validator)?;

        let proof = Self {
            height,
            validator,
            prev_block_hash,
            output,
        };

        proof.validate_structural()?;
        Ok(proof)
    }

    /// Convert from the gossip/network proof type into the block-committed type.
    pub fn from_gossip(proof: &PorPuzzleProof) -> Result<Self, ErrorDetection> {
        Self::new(
            proof.height,
            proof.validator.clone(),
            proof.prev_block_hash,
            proof.output,
        )
    }

    /// Convert back into the gossip/network proof type.
    #[must_use]
    pub fn to_gossip(&self) -> PorPuzzleProof {
        PorPuzzleProof {
            height: self.height,
            validator: self.validator.clone(),
            prev_block_hash: self.prev_block_hash,
            output: self.output,
        }
    }

    /// Defensive structural validation.
    pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
        // Height plausibility guard.
        if self.height > MAX_REASONABLE_HEIGHT {
            return Err(Self::validation_err(format!(
                "BlockPuzzleProof.height out of bounds: {}",
                self.height
            )));
        }

        // Validator checks.
        if self.validator.trim().is_empty() {
            return Err(Self::validation_err("BlockPuzzleProof.validator is empty"));
        }

        if self.validator.len() > MAX_VALIDATOR_LEN {
            return Err(Self::validation_err(format!(
                "BlockPuzzleProof.validator too long (len={}, max={})",
                self.validator.len(),
                MAX_VALIDATOR_LEN
            )));
        }

        let canon = canon_wallet_id_checked(&self.validator)?;
        if canon != self.validator {
            return Err(Self::validation_err(
                "BlockPuzzleProof.validator is not canonical",
            ));
        }

        // Hash poison / sentinel defense.
        let zeros64 = [0u8; 64];
        let ff64 = [0xFFu8; 64];
        if self.prev_block_hash == zeros64 || self.prev_block_hash == ff64 {
            return Err(Self::validation_err(
                "BlockPuzzleProof.prev_block_hash is an invalid sentinel",
            ));
        }

        // Output must be non-zero if a proof exists.
        // If puzzles are disabled, metadata should store None instead of Some(proof with 0).
        if self.output == 0 {
            return Err(Self::validation_err("BlockPuzzleProof.output cannot be 0"));
        }

        Ok(())
    }

    /// Verify block proof using the existing engine logic.
    pub fn verify_with_engine_checked(
        &self,
        engine: &PorPuzzleEngine,
    ) -> Result<bool, ErrorDetection> {
        self.validate_structural()?;
        self.to_gossip().verify_with_engine_checked(engine)
    }

    /// Back-compat boolean verifier.
    #[must_use]
    pub fn verify_with_engine(&self, engine: &PorPuzzleEngine) -> bool {
        self.verify_with_engine_checked(engine).unwrap_or(false)
    }

    /// Deterministic 64-byte commitment over this committed proof.
    pub fn commitment_bytes(&self) -> Result<[u8; 64], ErrorDetection> {
        let bytes =
            postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Serialize BlockPuzzleProof failed: {e}"),
            })?;

        Ok(RemzarHash::compute_bytes_hash(&bytes))
    }

    /// Commitment as lowercase 128-char hex.
    pub fn commitment_hex(&self) -> Result<String, ErrorDetection> {
        Ok(hex::encode(self.commitment_bytes()?))
    }
}
