// src/consensus/por_004_puzzle_proof.rs

use serde::{Deserialize, Serialize};

use crate::consensus::por_002_puzzle_engine::{
    PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
};
use crate::consensus::por_003_puzzle_pool::PorPuzzlePool;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::helper::serde_u8_array_64;

/// Gossip-friendly proof that a validator solved the POR puzzle at a given
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PorPuzzleProof {
    pub height: u64,
    pub validator: String,
    #[serde(with = "serde_u8_array_64")]
    pub prev_block_hash: [u8; 64],

    pub output: u128,
}

impl PorPuzzleProof {
    #[inline]
    fn validation_err(msg: String) -> ErrorDetection {
        ErrorDetection::ValidationError {
            message: msg,
            tx_id: None,
        }
    }

    #[inline]
    fn max_validator_len() -> usize {
        // Canonical wallet strings are 129 chars ("r" + 128 hex).
        // Keep conservative slack but bound it (defends against untrusted huge strings).
        256usize
    }

    /// Validate and return the canonical validator string.
    #[inline]
    fn canonical_validator(&self) -> Result<String, ErrorDetection> {
        if self.validator.len() > Self::max_validator_len() {
            return Err(Self::validation_err(format!(
                "PorPuzzleProof: validator string too long (len={}, max={})",
                self.validator.len(),
                Self::max_validator_len()
            )));
        }

        // Strict validation + canonicalization ("r"+128 lowercase hex) — single source of truth.
        let canon = canon_wallet_id_checked(&self.validator)?;
        Ok(canon)
    }

    /// Construct a proof from a *local* solution returned by `PorPuzzleEngine`.
    pub fn from_solution(sol: &PorPuzzleSolution) -> Self {
        let PorPuzzleHeader {
            height,
            validator,
            prev_block_hash,
            ..
        } = &sol.header;

        Self {
            height: *height,
            validator: validator.clone(),
            prev_block_hash: *prev_block_hash,
            output: sol.output,
        }
    }

    /// Structural validation for untrusted network input.
    pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
        let validator_can = self.canonical_validator()?;

        if validator_can != self.validator {
            return Err(Self::validation_err(
                "PorPuzzleProof: validator is not canonical".to_string(),
            ));
        }

        if self.height > 10_000_000 {
            return Err(Self::validation_err(format!(
                "PorPuzzleProof: height out of bounds: {}",
                self.height
            )));
        }

        let zeros64 = [0u8; 64];
        let ff64 = [0xFFu8; 64];

        if self.prev_block_hash == zeros64 || self.prev_block_hash == ff64 {
            return Err(Self::validation_err(
                "PorPuzzleProof: prev_block_hash is invalid sentinel".to_string(),
            ));
        }

        if self.output == 0 {
            return Err(Self::validation_err(
                "PorPuzzleProof: output cannot be 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify this proof against a locally-configured `PorPuzzleEngine`.
    pub fn verify_with_engine_checked(
        &self,
        engine: &PorPuzzleEngine,
    ) -> Result<bool, ErrorDetection> {
        self.validate_structural()?;

        let _ = GlobalConfiguration::MAX_ITEM_BYTES;

        let validator_can = self.canonical_validator()?;

        // Re-derive the canonical header using the canonical validator string.
        let header = engine.derive_puzzle(self.height, &validator_can, self.prev_block_hash);

        // Build a synthetic solution using the claimed output and the canonical header.
        let solution = PorPuzzleSolution {
            header,
            output: self.output,
            solved_in_ms: 0, // not consensus-relevant
        };

        Ok(engine.verify(&solution, self.height, &validator_can, self.prev_block_hash))
    }

    /// Back-compat boolean verifier.
    pub fn verify_with_engine(&self, engine: &PorPuzzleEngine) -> bool {
        self.verify_with_engine_checked(engine).unwrap_or_default()
    }

    /// Convenience helper:
    pub fn verify_and_record_checked(
        &self,
        engine: &PorPuzzleEngine,
        pool: &mut PorPuzzlePool,
    ) -> Result<bool, ErrorDetection> {
        self.validate_structural()?;

        let validator_can = self.canonical_validator()?;

        let header = engine.derive_puzzle(self.height, &validator_can, self.prev_block_hash);
        let solution = PorPuzzleSolution {
            header,
            output: self.output,
            solved_in_ms: 0,
        };

        let ok = engine.verify(&solution, self.height, &validator_can, self.prev_block_hash);
        if !ok {
            return Ok(false);
        }

        // Record into pool (pool is bounded + canonicalizes again safely).
        pool.record_success_checked(self.height, &validator_can, self.output)?;

        Ok(true)
    }

    /// Back-compat boolean helper (no panics).
    pub fn verify_and_record(&self, engine: &PorPuzzleEngine, pool: &mut PorPuzzlePool) -> bool {
        self.verify_and_record_checked(engine, pool)
            .unwrap_or_default()
    }
}
