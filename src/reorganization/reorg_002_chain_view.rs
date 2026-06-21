// src/blockchain/reorg_002_chain_view.rs

use hex;
use std::sync::Arc;

use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::storage::rocksdb_006_manager_ext::CanonicalTipView;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

/// Chain-wide block hash alias.
pub type BlockHash = Hash;

/// Thin wrapper over canonical chain view helpers.
#[derive(Clone)]
pub struct ReorgChainView {
    db: Arc<RockDBManager>,
}

impl ReorgChainView {
    /// Create a new canonical-chain view wrapper.
    pub fn new(db: Arc<RockDBManager>) -> Self {
        Self { db }
    }

    /// Access the underlying DB manager when orchestration needs it.
    pub fn db(&self) -> &Arc<RockDBManager> {
        &self.db
    }

    // ─────────────────────────────────────────────────────────────
    // Canonical height -> hash
    // ─────────────────────────────────────────────────────────────

    /// Set canonical hash at a given height.
    pub fn set_hash_at_height(&self, height: u64, hash: &BlockHash) -> Result<(), ErrorDetection> {
        self.db.set_canonical_hash_at_height(height, hash)
    }

    /// Get canonical hash at a given height.
    pub fn get_hash_at_height(&self, height: u64) -> Result<Option<BlockHash>, ErrorDetection> {
        self.db.get_canonical_hash_at_height(height)
    }

    /// Return true if canonical hash exists at height.
    pub fn has_height(&self, height: u64) -> Result<bool, ErrorDetection> {
        Ok(self.get_hash_at_height(height)?.is_some())
    }

    /// Delete canonical mapping range inclusive.
    pub fn delete_height_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), ErrorDetection> {
        self.db.delete_canonical_hash_range(from_height, to_height)
    }

    // ─────────────────────────────────────────────────────────────
    // Canonical tip helpers
    // ─────────────────────────────────────────────────────────────

    /// Set canonical tip hash + height.
    pub fn set_tip(&self, tip_hash: &BlockHash, tip_height: u64) -> Result<(), ErrorDetection> {
        self.db.set_canonical_tip(tip_hash, tip_height)
    }

    /// Get full canonical tip view.
    pub fn get_tip(&self) -> Result<Option<CanonicalTipView>, ErrorDetection> {
        self.db.get_canonical_tip()
    }

    /// Get canonical tip hash.
    pub fn get_tip_hash(&self) -> Result<Option<BlockHash>, ErrorDetection> {
        self.db.get_canonical_tip_hash()
    }

    /// Get canonical tip height.
    pub fn get_tip_height(&self) -> Result<Option<u64>, ErrorDetection> {
        self.db.get_canonical_tip_height()
    }

    /// Return current canonical tip, falling back to legacy metadata + block_{height}
    /// if the explicit canonical chain view has not yet been initialized.
    pub fn get_tip_with_legacy_fallback(&self) -> Result<Option<CanonicalTipView>, ErrorDetection> {
        if let Some(view) = self.get_tip()? {
            return Ok(Some(view));
        }

        let legacy_height = self.db.get_tip_height()?;
        let legacy_block = self.db.get_block_by_index(legacy_height)?;

        match legacy_block {
            Some(block) => Ok(Some(CanonicalTipView {
                tip_hash: block.block_hash,
                tip_height: block.metadata.index,
            })),
            None => Ok(None),
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Canonical chain path helpers
    // ─────────────────────────────────────────────────────────────

    /// Build the canonical chain as hashes from height 0..=tip.
    pub fn canonical_hashes_up_to(
        &self,
        tip_height: u64,
    ) -> Result<Vec<BlockHash>, ErrorDetection> {
        let capacity = usize::try_from(tip_height)
            .ok()
            .and_then(|v| v.checked_add(1))
            .unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity);

        for h in 0..=tip_height {
            let hash = match self.get_hash_at_height(h)? {
                Some(hash) => hash,
                None => {
                    return Err(ErrorDetection::NotFound {
                        resource: format!("canonical hash missing at height {}", h),
                    });
                }
            };
            out.push(hash);
        }

        Ok(out)
    }

    /// Build canonical `(height, hash)` pairs from height 0..=tip.
    pub fn canonical_steps_up_to(
        &self,
        tip_height: u64,
    ) -> Result<Vec<(u64, BlockHash)>, ErrorDetection> {
        let capacity = usize::try_from(tip_height)
            .ok()
            .and_then(|v| v.checked_add(1))
            .unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity);

        for h in 0..=tip_height {
            let hash = match self.get_hash_at_height(h)? {
                Some(hash) => hash,
                None => {
                    return Err(ErrorDetection::NotFound {
                        resource: format!("canonical hash missing at height {}", h),
                    });
                }
            };
            out.push((h, hash));
        }

        Ok(out)
    }

    /// Build canonical path from `from_height..=to_height`.
    pub fn canonical_steps_in_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, BlockHash)>, ErrorDetection> {
        if from_height > to_height {
            return Ok(Vec::new());
        }

        let capacity = to_height
            .checked_sub(from_height)
            .and_then(|v| v.checked_add(1))
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity);

        for h in from_height..=to_height {
            let hash = match self.get_hash_at_height(h)? {
                Some(hash) => hash,
                None => {
                    return Err(ErrorDetection::NotFound {
                        resource: format!("canonical hash missing at height {}", h),
                    });
                }
            };
            out.push((h, hash));
        }

        Ok(out)
    }

    /// Resolve canonical hash at height to the full block.
    pub fn canonical_block_at_height(
        &self,
        height: u64,
    ) -> Result<Option<crate::blockchain::block_002_blocks::Block>, ErrorDetection> {
        let Some(hash) = self.get_hash_at_height(height)? else {
            return Ok(None);
        };

        Ok(self.db.get_block_by_hash(&hash))
    }

    // ─────────────────────────────────────────────────────────────
    // Initialization / migration helpers
    // ─────────────────────────────────────────────────────────────

    /// Initialize canonical chain view from legacy canonical block_{height} projection.
    pub fn backfill_from_legacy_projection(
        &self,
    ) -> Result<Option<CanonicalTipView>, ErrorDetection> {
        let legacy_tip_height = self.db.get_tip_height()?;
        let mut last_hash: Option<BlockHash> = None;
        let mut last_height: Option<u64> = None;

        for h in 0..=legacy_tip_height {
            let maybe_block = self.db.get_block_by_index(h)?;
            let block = match maybe_block {
                Some(b) => b,
                None => {
                    break;
                }
            };

            self.set_hash_at_height(h, &block.block_hash)?;
            last_hash = Some(block.block_hash);
            last_height = Some(h);
        }

        match (last_hash, last_height) {
            (Some(hash), Some(height)) => {
                self.set_tip(&hash, height)?;
                Ok(Some(CanonicalTipView {
                    tip_hash: hash,
                    tip_height: height,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Ensure canonical chain view exists.
    pub fn ensure_initialized(&self) -> Result<Option<CanonicalTipView>, ErrorDetection> {
        if let Some(view) = self.get_tip()? {
            return Ok(Some(view));
        }
        self.backfill_from_legacy_projection()
    }

    // ─────────────────────────────────────────────────────────────
    // Best-tip / side-branch helpers
    // ─────────────────────────────────────────────────────────────

    /// Return the best known tip using stored block metadata score.
    pub fn choose_better_tip(
        &self,
        current_tip_hash: &BlockHash,
        current_tip_height: u64,
        candidate_tip_hash: &BlockHash,
        candidate_tip_height: u64,
        allow_equal_height_tiebreak: bool,
    ) -> Result<BlockHash, ErrorDetection> {
        if candidate_tip_height > current_tip_height {
            return Ok(*candidate_tip_hash);
        }
        if candidate_tip_height < current_tip_height {
            return Ok(*current_tip_hash);
        }

        if allow_equal_height_tiebreak && candidate_tip_hash < current_tip_hash {
            return Ok(*candidate_tip_hash);
        }

        Ok(*current_tip_hash)
    }

    /// Return a candidate side-branch tip summary for logging / orchestration.
    pub fn summarize_tip(&self, hash: &BlockHash) -> Result<String, ErrorDetection> {
        let meta = self.db.get_block_meta_by_hash(hash)?;
        match meta {
            Some(m) => Ok(format!(
                "hash={} height={} status={:?} parent={} score={}",
                hex::encode(hash),
                m.height,
                m.status,
                hex::encode(m.parent_hash),
                m.cumulative_score
            )),
            None => Ok(format!("hash={} <missing-meta>", hex::encode(hash))),
        }
    }

    /// Best-effort logging for a canonical tip view.
    pub fn log_tip_summary(&self) -> Result<(), ErrorDetection> {
        let _tip_view = self.get_tip_with_legacy_fallback()?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Atomic canonical switch helpers
    // ─────────────────────────────────────────────────────────────

    /// Apply a canonical attach sequence.
    pub fn apply_canonical_attach(
        &self,
        attach_steps: &[(u64, BlockHash)],
    ) -> Result<(), ErrorDetection> {
        if attach_steps.is_empty() {
            return Ok(());
        }

        for (height, hash) in attach_steps {
            self.set_hash_at_height(*height, hash)?;
        }

        let (tip_height, tip_hash) = attach_steps
            .last()
            .map(|(h, hash)| (*h, *hash))
            .ok_or_else(|| ErrorDetection::BlockchainError {
                details: "apply_canonical_attach received empty attach_steps".to_string(),
            })?;

        self.set_tip(&tip_hash, tip_height)
    }

    /// Apply a canonical detach range and then attach a new range.
    pub fn switch_canonical_range(
        &self,
        detach_from_height: Option<u64>,
        detach_to_height: Option<u64>,
        attach_steps: &[(u64, BlockHash)],
    ) -> Result<(), ErrorDetection> {
        if let (Some(from_h), Some(to_h)) = (detach_from_height, detach_to_height) {
            self.delete_height_range(from_h, to_h)?;
        }

        self.apply_canonical_attach(attach_steps)
    }
}
