// src/blockchain/reorg_001_block_index.rs

use std::sync::Arc;

use crate::blockchain::block_002_blocks::Block;
use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::time_policy::{TimePolicy, UNIX_2000_SECS};
use hex;

/// Chain-wide block hash alias.
pub type BlockHash = Hash;

/// Thin index wrapper over hash-indexed block + metadata storage.
#[derive(Clone)]
pub struct ReorgBlockIndex {
    db: Arc<RockDBManager>,
}

impl ReorgBlockIndex {
    /// Create a new block-index wrapper over the shared DB manager.
    pub fn new(db: Arc<RockDBManager>) -> Self {
        Self { db }
    }

    /// Access the underlying DB manager when orchestration needs it.
    pub fn db(&self) -> &Arc<RockDBManager> {
        &self.db
    }

    // ─────────────────────────────────────────────────────────────
    // Runtime timestamp helper
    // ─────────────────────────────────────────────────────────────

    /// Runtime receive timestamp for fork-graph metadata.
    #[inline]
    fn received_at_unix_secs_runtime() -> u64 {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(ts) => ts,
            Err(_) => UNIX_2000_SECS,
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Core store/fetch
    // ─────────────────────────────────────────────────────────────

    /// Store a validated block in the hash index.
    pub fn put_block(&self, block: &Block) -> Result<(), ErrorDetection> {
        let bytes = block.serialize_for_storage()?;
        self.db.index_block_by_hash(&block.block_hash, &bytes)
    }

    /// Store raw block bytes under hash.
    pub fn put_block_bytes(
        &self,
        block_hash: &BlockHash,
        block_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        self.db.index_block_by_hash(block_hash, block_bytes)
    }

    /// Fetch a block by hash.
    pub fn get_block(&self, block_hash: &BlockHash) -> Result<Option<Block>, ErrorDetection> {
        Ok(self.db.get_block_by_hash(block_hash))
    }

    /// Return true if the block exists by hash.
    pub fn has_block(&self, block_hash: &BlockHash) -> bool {
        self.db.has_block_by_hash(block_hash)
    }

    /// Store block metadata by block hash.
    pub fn put_meta(
        &self,
        block_hash: &BlockHash,
        meta: &ForkBlockMeta,
    ) -> Result<(), ErrorDetection> {
        self.db.store_block_meta_by_hash(block_hash, meta)
    }

    /// Fetch block metadata by block hash.
    pub fn get_meta(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<ForkBlockMeta>, ErrorDetection> {
        self.db.get_block_meta_by_hash(block_hash)
    }

    /// Return true if metadata exists for this block.
    pub fn has_meta(&self, block_hash: &BlockHash) -> Result<bool, ErrorDetection> {
        self.db.has_block_meta_by_hash(block_hash)
    }

    /// Store both block and metadata together.
    ///
    /// This is the normal fork-graph ingest path for a validated block.
    pub fn put_block_and_meta(
        &self,
        block: &Block,
        meta: &ForkBlockMeta,
    ) -> Result<(), ErrorDetection> {
        let bytes = block.serialize_for_storage()?;
        self.db
            .ingest_fork_block(&block.block_hash, &bytes, meta, None)
    }

    /// Store block, metadata, and optional batch bytes together.
    pub fn ingest_validated_block(
        &self,
        block: &Block,
        meta: ForkBlockMeta,
        maybe_batch_bytes: Option<&[u8]>,
    ) -> Result<(), ErrorDetection> {
        let bytes = block.serialize_for_storage()?;
        self.db
            .ingest_fork_block(&block.block_hash, &bytes, &meta, maybe_batch_bytes)
    }

    // ─────────────────────────────────────────────────────────────
    // Metadata construction helpers
    // ─────────────────────────────────────────────────────────────

    /// Build metadata for a newly learned block using height as the initial score.
    pub fn make_height_meta(&self, block: &Block, status: ForkBlockStatus) -> ForkBlockMeta {
        ForkBlockMeta {
            parent_hash: block.metadata.previous_hash,
            height: block.metadata.index,
            cumulative_score: block.metadata.index as u128,
            status,
            received_at_unix_secs: Self::received_at_unix_secs_runtime(),
        }
    }

    /// Build metadata with an explicit cumulative score.
    pub fn make_scored_meta(
        &self,
        block: &Block,
        cumulative_score: u128,
        status: ForkBlockStatus,
    ) -> ForkBlockMeta {
        ForkBlockMeta {
            parent_hash: block.metadata.previous_hash,
            height: block.metadata.index,
            cumulative_score,
            status,
            received_at_unix_secs: Self::received_at_unix_secs_runtime(),
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Parent / ancestry helpers
    // ─────────────────────────────────────────────────────────────

    /// Get parent hash from metadata.
    pub fn parent_hash(&self, block_hash: &BlockHash) -> Result<Option<BlockHash>, ErrorDetection> {
        Ok(self.get_meta(block_hash)?.map(|m| m.parent_hash))
    }

    /// Get stored height from metadata.
    pub fn height_of(&self, block_hash: &BlockHash) -> Result<Option<u64>, ErrorDetection> {
        Ok(self.get_meta(block_hash)?.map(|m| m.height))
    }

    /// Get status from metadata.
    pub fn status_of(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<ForkBlockStatus>, ErrorDetection> {
        Ok(self.get_meta(block_hash)?.map(|m| m.status))
    }

    /// Update only block status.
    pub fn set_status(
        &self,
        block_hash: &BlockHash,
        new_status: ForkBlockStatus,
    ) -> Result<(), ErrorDetection> {
        self.db.set_block_meta_status(block_hash, new_status)
    }

    /// Mark block as canonical.
    pub fn mark_canonical(&self, block_hash: &BlockHash) -> Result<(), ErrorDetection> {
        self.set_status(block_hash, ForkBlockStatus::Canonical)
    }

    /// Mark block as side branch.
    pub fn mark_side_branch(&self, block_hash: &BlockHash) -> Result<(), ErrorDetection> {
        self.set_status(block_hash, ForkBlockStatus::SideBranch)
    }

    /// Mark block as orphan.
    pub fn mark_orphan(&self, block_hash: &BlockHash) -> Result<(), ErrorDetection> {
        self.set_status(block_hash, ForkBlockStatus::Orphan)
    }

    /// Return true if the given block's parent metadata exists.
    pub fn has_known_parent(&self, block_hash: &BlockHash) -> Result<bool, ErrorDetection> {
        let Some(meta) = self.get_meta(block_hash)? else {
            return Ok(false);
        };

        // Genesis-style all-zero parent is treated as a known root boundary.
        if meta.parent_hash.iter().all(|b| *b == 0) {
            return Ok(true);
        }

        self.has_meta(&meta.parent_hash)
    }

    /// Fetch the parent block by reading parent_hash from metadata.
    pub fn get_parent_block(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<Block>, ErrorDetection> {
        let Some(meta) = self.get_meta(block_hash)? else {
            return Ok(None);
        };

        if meta.parent_hash.iter().all(|b| *b == 0) {
            return Ok(None);
        }

        self.get_block(&meta.parent_hash)
    }

    /// Fetch the parent metadata by reading parent_hash from metadata.
    pub fn get_parent_meta(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<ForkBlockMeta>, ErrorDetection> {
        let Some(meta) = self.get_meta(block_hash)? else {
            return Ok(None);
        };

        if meta.parent_hash.iter().all(|b| *b == 0) {
            return Ok(None);
        }

        self.get_meta(&meta.parent_hash)
    }

    /// Walk backward from `start_hash`, returning `(height, hash)` pairs from tip backward.
    pub fn build_path_from_tip(
        &self,
        start_hash: &BlockHash,
        max_depth: usize,
    ) -> Result<Vec<(u64, BlockHash)>, ErrorDetection> {
        let mut out = Vec::new();
        let mut current = *start_hash;

        for _ in 0..max_depth {
            let Some(meta) = self.get_meta(&current)? else {
                break;
            };

            out.push((meta.height, current));

            if meta.parent_hash.iter().all(|b| *b == 0) {
                break;
            }

            current = meta.parent_hash;
        }

        Ok(out)
    }

    /// Find the first missing ancestor when walking backward.
    pub fn first_missing_ancestor(
        &self,
        start_hash: &BlockHash,
        max_depth: usize,
    ) -> Result<Option<BlockHash>, ErrorDetection> {
        let mut current = *start_hash;

        for _ in 0..max_depth {
            let Some(meta) = self.get_meta(&current)? else {
                return Ok(Some(current));
            };

            if meta.parent_hash.iter().all(|b| *b == 0) {
                return Ok(None);
            }

            if !self.has_meta(&meta.parent_hash)? {
                return Ok(Some(meta.parent_hash));
            }

            current = meta.parent_hash;
        }

        Ok(None)
    }

    // ─────────────────────────────────────────────────────────────
    // Validation / consistency helpers
    // ─────────────────────────────────────────────────────────────

    /// Validate that a block and its metadata agree on height and parent linkage.
    pub fn validate_block_meta_consistency(
        &self,
        block_hash: &BlockHash,
    ) -> Result<(), ErrorDetection> {
        let block = self
            .get_block(block_hash)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!("block_by_hash({})", hex::encode(block_hash)),
            })?;

        let meta = self
            .get_meta(block_hash)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!("block_meta_by_hash({})", hex::encode(block_hash)),
            })?;

        if block.block_hash != *block_hash {
            return Err(ErrorDetection::BlockchainError {
                details: format!(
                    "hash mismatch in block index for {}",
                    hex::encode(block_hash)
                ),
            });
        }

        if block.metadata.index != meta.height {
            return Err(ErrorDetection::BlockchainError {
                details: format!(
                    "height mismatch for {}: block.index={} meta.height={}",
                    hex::encode(block_hash),
                    block.metadata.index,
                    meta.height
                ),
            });
        }

        if block.metadata.previous_hash != meta.parent_hash {
            return Err(ErrorDetection::BlockchainError {
                details: format!("parent mismatch for {}", hex::encode(block_hash)),
            });
        }

        Ok(())
    }

    /// Best-effort diagnostics for a candidate block tip.
    pub fn log_tip_summary(&self, block_hash: &BlockHash) -> Result<(), ErrorDetection> {
        let _meta = self.get_meta(block_hash)?;
        Ok(())
    }
}
