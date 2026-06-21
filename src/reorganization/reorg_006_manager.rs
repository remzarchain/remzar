//! reorg_006_manager.rs

use std::sync::Arc;
use tracing::debug;

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::blockchain_001_builder::BlockchainBuilder;
use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::network::p2p_006_reqresp::Hash;
use crate::reorganization::reorg_001_block_index::ReorgBlockIndex;
use crate::reorganization::reorg_002_chain_view::ReorgChainView;
use crate::reorganization::reorg_004_batch_index::ReorgBatchIndex;
use crate::reorganization::reorg_005_fork_choice::{ForkAction, ReFork, ReForkConfig, ReorgPlan};
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

/// High-level reorg orchestrator.
pub struct ReorgManager {
    db: Arc<RockDBManager>,
    block_index: ReorgBlockIndex,
    chain_view: ReorgChainView,
    batch_index: ReorgBatchIndex,
    fork: ReFork,
}

impl ReorgManager {
    /// Create a new reorg manager with an explicit `ReForkConfig`.
    pub fn new(db: Arc<RockDBManager>, cfg: ReForkConfig) -> Self {
        let fork = ReFork::new(Arc::clone(&db), cfg);
        Self {
            block_index: ReorgBlockIndex::new(Arc::clone(&db)),
            chain_view: ReorgChainView::new(Arc::clone(&db)),
            batch_index: ReorgBatchIndex::new(Arc::clone(&db)),
            db,
            fork,
        }
    }

    /// Convenience constructor for recommended mainnet defaults.
    pub fn mainnet_default(db: Arc<RockDBManager>) -> Self {
        let fork = ReFork::mainnet_default(Arc::clone(&db));
        Self {
            block_index: ReorgBlockIndex::new(Arc::clone(&db)),
            chain_view: ReorgChainView::new(Arc::clone(&db)),
            batch_index: ReorgBatchIndex::new(Arc::clone(&db)),
            db,
            fork,
        }
    }

    /// Expose a read-only reference to the underlying fork-choice engine.
    pub fn fork_engine(&self) -> &ReFork {
        &self.fork
    }

    /// Core entry point for handling a newly learned block.
    ///
    /// Call this only after:
    /// 1. The block has been fully validated.
    /// 2. The block has been stored by hash.
    /// 3. The block metadata has been stored by hash.
    /// 4. The block batch has been stored by hash when applicable.
    pub fn handle_new_block(
        &self,
        new_block: &Block,
        chain: &mut AccountModelTree,
        builder: Option<&mut BlockchainBuilder>,
    ) -> Result<ForkAction, ErrorDetection> {
        let action = self.fork.on_new_block(new_block)?;

        match &action {
            ForkAction::Stay => Ok(ForkAction::Stay),
            ForkAction::Reorg(plan) => {
                debug!(
                    "[REORG][EXECUTE] applying reorg: old_tip_height={} new_tip_height={} common_ancestor_height={} old_tip_hash={} new_tip_hash={}",
                    plan.old_tip_height,
                    plan.new_tip_height,
                    plan.common_ancestor_height,
                    hex::encode(plan.old_tip_hash),
                    hex::encode(plan.new_tip_hash),
                );

                self.apply_reorg_plan(plan, chain, builder)?;

                debug!(
                    "[REORG][SUCCESS] reorg applied successfully: old_tip_height={} new_tip_height={} common_ancestor_height={} old_tip_hash={} new_tip_hash={}",
                    plan.old_tip_height,
                    plan.new_tip_height,
                    plan.common_ancestor_height,
                    hex::encode(plan.old_tip_hash),
                    hex::encode(plan.new_tip_hash),
                );

                Ok(ForkAction::Reorg(plan.clone()))
            }
            ForkAction::NeedMoreData { .. } => Ok(action),
        }
    }

    /// Apply a precomputed `ReorgPlan`.
    ///
    /// This:
    /// 1. Applies canonical DB reorg through `ReFork`
    /// 2. Remaps canonical batch projection for attached blocks
    /// 3. Rebuilds `AccountModelTree`
    /// 4. Optionally rebuilds `ValidatorState`
    pub fn apply_reorg_plan(
        &self,
        plan: &ReorgPlan,
        chain: &mut AccountModelTree,
        builder: Option<&mut BlockchainBuilder>,
    ) -> Result<(), ErrorDetection> {
        // 1) Apply canonical DB-level reorg.
        self.fork
            .apply_reorg(plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

        // 2) Remap canonical tx_batch_{height} projection from batch_by_block_hash.
        // We prefer best-effort because some blocks may be empty/admin blocks.
        let attach_steps: Vec<(u64, Hash)> =
            plan.attach.iter().map(|s| (s.height, s.hash)).collect();

        self.batch_index
            .remap_canonical_batches_best_effort(&attach_steps)?;

        // 3) Rebuild AccountModelTree from canonical chain.
        chain.reload_from_db_to_height(plan.new_tip_height)?;

        _ = chain.commit();
        _ = chain.flush_balances();

        // 4) Optional validator-state rebuild from canonical chain.
        if let Some(builder) = builder {
            self.rebuild_validator_state(builder, plan.new_tip_height)?;
        }

        Ok(())
    }

    /// Rebuild the canonical validator registry (`ValidatorState`) after reorg.
    ///
    /// IMPORTANT:
    /// - this MUST be a true reset-style rebuild from canonical chain data
    /// - it must NOT replay onto the existing in-memory validator map
    /// - detached-branch registrations must not survive the reorg
    fn rebuild_validator_state(
        &self,
        builder: &mut BlockchainBuilder,
        tip: u64,
    ) -> Result<(), ErrorDetection> {
        // Defensive diagnostics: confirm the canonical tip projection is readable.
        if let Some(canonical_tip_hash) = self.load_canonical_hash_at_height(tip)? {
            let _ = self.block_index.get_block(&canonical_tip_hash)?;
        }

        let vs = builder.validator_state_mut();
        vs.rebuild_from_chain(Some(tip))?;

        Ok(())
    }

    /// Load canonical hash for a height from corrected canonical view first,
    /// then fall back to legacy block_{height}.
    fn load_canonical_hash_at_height(&self, height: u64) -> Result<Option<Hash>, ErrorDetection> {
        if let Some(hash) = self.chain_view.get_hash_at_height(height)? {
            return Ok(Some(hash));
        }

        let legacy_block = self.db.get_block_by_index(height)?;
        Ok(legacy_block.map(|b| b.block_hash))
    }
}
