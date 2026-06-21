// src/blockchain/reorg_004_batch_index.rs

use std::sync::Arc;

use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

/// Chain-wide block hash alias.
pub type BlockHash = Hash;

/// Thin wrapper over batch-by-hash storage and canonical batch projection.
#[derive(Clone)]
pub struct ReorgBatchIndex {
    db: Arc<RockDBManager>,
}

impl ReorgBatchIndex {
    /// Create a new batch-index wrapper over the shared DB manager.
    pub fn new(db: Arc<RockDBManager>) -> Self {
        Self { db }
    }

    /// Access the underlying DB manager when orchestration needs it.
    pub fn db(&self) -> &Arc<RockDBManager> {
        &self.db
    }

    // ─────────────────────────────────────────────────────────────
    // Batch-by-block-hash truth
    // ─────────────────────────────────────────────────────────────

    /// Store the exact batch bytes for a block hash.
    pub fn put_batch_by_block_hash(
        &self,
        block_hash: &BlockHash,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        self.db.store_batch_by_block_hash(block_hash, batch_bytes)
    }

    /// Fetch batch bytes by block hash.
    pub fn get_batch_by_block_hash(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<Vec<u8>>, ErrorDetection> {
        self.db.get_batch_by_block_hash(block_hash)
    }

    /// Return true if batch exists for this block hash.
    pub fn has_batch_by_block_hash(&self, block_hash: &BlockHash) -> Result<bool, ErrorDetection> {
        self.db.has_batch_by_block_hash(block_hash)
    }

    // ─────────────────────────────────────────────────────────────
    // Canonical batch projection (legacy-active-chain view)
    // ─────────────────────────────────────────────────────────────

    /// Store canonical batch bytes at a given height.
    pub fn set_canonical_batch_at_height(
        &self,
        height: u64,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        self.db.store_batch_bytes(height, batch_bytes)
    }

    /// Fetch canonical batch bytes at a given height from the legacy projection.
    pub fn get_canonical_batch_at_height(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, ErrorDetection> {
        self.db.get_batch_bytes_by_index(height)
    }

    /// Fetch canonical batch bytes at height, preferring the canonical hash view.
    pub fn get_canonical_batch_with_fallback(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, ErrorDetection> {
        if let Some(block_hash) = self.db.get_canonical_hash_at_height(height)?
            && let Some(bytes) = self.db.get_batch_by_block_hash(&block_hash)?
        {
            return Ok(Some(bytes));
        }

        self.db.get_batch_bytes_by_index(height)
    }

    // ─────────────────────────────────────────────────────────────
    // Ingest helpers
    // ─────────────────────────────────────────────────────────────

    pub fn ingest_canonical_batch(
        &self,
        block_hash: &BlockHash,
        height: u64,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        self.put_batch_by_block_hash(block_hash, batch_bytes)?;
        self.set_canonical_batch_at_height(height, batch_bytes)
    }

    /// Store only batch-by-hash truth.
    pub fn ingest_side_branch_batch(
        &self,
        block_hash: &BlockHash,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        self.put_batch_by_block_hash(block_hash, batch_bytes)
    }

    // ─────────────────────────────────────────────────────────────
    // Canonical remapping on reorg
    // ─────────────────────────────────────────────────────────────

    /// Rewrite the canonical batch projection for one attached block.
    pub fn remap_canonical_batch_to_height(
        &self,
        height: u64,
        block_hash: &BlockHash,
    ) -> Result<(), ErrorDetection> {
        let batch_bytes =
            self.get_batch_by_block_hash(block_hash)?
                .ok_or_else(|| ErrorDetection::NotFound {
                    resource: format!(
                        "batch_by_block_hash for attached block at height {}",
                        height
                    ),
                })?;

        self.set_canonical_batch_at_height(height, &batch_bytes)
    }

    /// Rewrite canonical batches for all attach steps of a reorg.
    pub fn remap_canonical_batches_for_attach_steps(
        &self,
        attach_steps: &[(u64, BlockHash)],
    ) -> Result<(), ErrorDetection> {
        for (height, hash) in attach_steps {
            self.remap_canonical_batch_to_height(*height, hash)?;
        }
        Ok(())
    }

    /// Best-effort canonical remap for attach steps.
    pub fn remap_canonical_batches_best_effort(
        &self,
        attach_steps: &[(u64, BlockHash)],
    ) -> Result<(), ErrorDetection> {
        for (height, hash) in attach_steps {
            if let Some(bytes) = self.get_batch_by_block_hash(hash)? {
                self.set_canonical_batch_at_height(*height, &bytes)?;
            }
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Validation / consistency helpers
    // ─────────────────────────────────────────────────────────────

    /// Ensure canonical batch at height matches batch_by_block_hash of canonical hash.
    pub fn validate_canonical_batch_consistency(&self, height: u64) -> Result<(), ErrorDetection> {
        let canonical_hash = self
            .db
            .get_canonical_hash_at_height(height)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!("canonical hash at height {}", height),
            })?;

        let expected = self
            .get_batch_by_block_hash(&canonical_hash)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!(
                    "batch_by_block_hash for canonical hash at height {}",
                    height
                ),
            })?;

        let actual = self.get_canonical_batch_at_height(height)?.ok_or_else(|| {
            ErrorDetection::NotFound {
                resource: format!("canonical batch projection at height {}", height),
            }
        })?;

        if actual != expected {
            return Err(ErrorDetection::BlockchainError {
                details: format!(
                    "canonical batch mismatch at height {}: tx_batch_{{height}} != batch_by_block_hash",
                    height
                ),
            });
        }

        Ok(())
    }

    /// Return the first height in a range where canonical batch projection is inconsistent.
    pub fn first_inconsistent_canonical_batch(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Option<u64>, ErrorDetection> {
        if from_height > to_height {
            return Ok(None);
        }

        for h in from_height..=to_height {
            match self.validate_canonical_batch_consistency(h) {
                Ok(_) => {}
                Err(_) => return Ok(Some(h)),
            }
        }

        Ok(None)
    }

    // ─────────────────────────────────────────────────────────────
    // Diagnostics
    // ─────────────────────────────────────────────────────────────

    /// Log a summary for a canonical batch slot.
    pub fn log_canonical_batch_summary(&self, height: u64) -> Result<(), ErrorDetection> {
        self.db.get_canonical_hash_at_height(height)?;
        self.get_canonical_batch_at_height(height)?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Migration / repair helpers
    // ─────────────────────────────────────────────────────────────

    /// Backfill batch_by_block_hash from canonical projection for a height range.
    pub fn backfill_batch_by_hash_from_canonical_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), ErrorDetection> {
        if from_height > to_height {
            return Ok(());
        }

        for h in from_height..=to_height {
            let Some(block_hash) = self.db.get_canonical_hash_at_height(h)? else {
                continue;
            };

            if self.has_batch_by_block_hash(&block_hash)? {
                continue;
            }

            let Some(batch_bytes) = self.get_canonical_batch_at_height(h)? else {
                continue;
            };

            self.put_batch_by_block_hash(&block_hash, &batch_bytes)?;
        }

        Ok(())
    }

    /// Rebuild canonical tx_batch_{height} projection from canonical hash view for a range.
    pub fn rebuild_canonical_projection_from_hash_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), ErrorDetection> {
        if from_height > to_height {
            return Ok(());
        }

        for h in from_height..=to_height {
            let Some(block_hash) = self.db.get_canonical_hash_at_height(h)? else {
                continue;
            };

            if let Some(bytes) = self.get_batch_by_block_hash(&block_hash)? {
                self.set_canonical_batch_at_height(h, &bytes)?;
            }
        }

        Ok(())
    }
}
