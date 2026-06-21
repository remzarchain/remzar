//! reorg_005_fork_choice.rs

use std::collections::HashMap;
use std::sync::Arc;

use chrono::DateTime;
use hex;

use crate::blockchain::block_002_blocks::Block;
use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
use crate::network::p2p_006_reqresp::Hash;
use crate::reorganization::reorg_001_block_index::ReorgBlockIndex;
use crate::reorganization::reorg_002_chain_view::ReorgChainView;
use crate::reorganization::reorg_003_branch_score::{
    BranchCandidate, BranchScoreConfig, BranchScoreMode, ReorgBranchScorer,
};
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::time_policy::TimePolicy;

/// Convenience alias for block hashes (chain-wide).
pub type BlockHash = Hash;

/// Configuration for fork choice and reorg limits.
#[derive(Clone, Debug)]
pub struct ReForkConfig {
    /// Maximum number of blocks we are willing to reorg in one operation.
    pub max_reorg_depth: u64,

    /// Whether to allow reorgs when the competing branch has the same
    /// height as the current canonical tip.
    pub allow_equal_height_reorg: bool,

    /// Whether scoring should prefer cumulative PoR when available.
    pub prefer_cumulative_por: bool,
}

impl Default for ReForkConfig {
    fn default() -> Self {
        Self {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        }
    }
}

/// One concrete step in a reorg plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReorgStep {
    pub height: u64,
    pub hash: BlockHash,
}

/// A concrete reorg plan describing how to move from the current canonical tip
#[derive(Clone, Debug)]
pub struct ReorgPlan {
    pub old_tip_height: u64,
    pub old_tip_hash: BlockHash,

    pub new_tip_height: u64,
    pub new_tip_hash: BlockHash,

    pub common_ancestor_height: u64,
    pub common_ancestor_hash: BlockHash,

    pub detach: Vec<ReorgStep>,
    pub attach: Vec<ReorgStep>,
}

impl ReorgPlan {
    pub fn is_noop(&self) -> bool {
        self.detach.is_empty() && self.attach.is_empty()
    }

    pub fn detach_heights(&self) -> Vec<u64> {
        self.detach.iter().map(|s| s.height).collect()
    }

    pub fn attach_heights(&self) -> Vec<u64> {
        self.attach.iter().map(|s| s.height).collect()
    }
}

/// Result of asking fork-choice what to do with a newly learned block.
#[derive(Clone, Debug)]
pub enum ForkAction {
    Stay,
    Reorg(ReorgPlan),

    /// The competing branch might be valid and even better, but ancestry
    /// could not be walked yet because local fork-graph hydration is incomplete.
    NeedMoreData {
        missing_hash: BlockHash,
        context: &'static str,
    },
}

/// Internal result of trying to build a branch path from a tip hash.
#[derive(Clone, Debug)]
enum BranchPathBuild {
    Complete(Vec<(u64, BlockHash)>),
    Missing {
        partial_path: Vec<(u64, BlockHash)>,
        missing_hash: BlockHash,
        context: &'static str,
    },
}

/// Central fork-choice + reorg planner.
pub struct ReFork {
    db: Arc<RockDBManager>,
    block_index: ReorgBlockIndex,
    chain_view: ReorgChainView,
    cfg: ReForkConfig,
    scorer: ReorgBranchScorer,
}

impl ReFork {
    pub fn new(db: Arc<RockDBManager>, cfg: ReForkConfig) -> Self {
        let score_cfg = BranchScoreConfig {
            mode: if cfg.prefer_cumulative_por {
                BranchScoreMode::CumulativePor
            } else {
                BranchScoreMode::HeightOnly
            },
            allow_equal_height_tiebreak: cfg.allow_equal_height_reorg,
            prefer_lower_hash_on_tie: true,
        };

        Self {
            block_index: ReorgBlockIndex::new(Arc::clone(&db)),
            chain_view: ReorgChainView::new(Arc::clone(&db)),
            scorer: ReorgBranchScorer::new(score_cfg),
            db,
            cfg,
        }
    }

    pub fn mainnet_default(db: Arc<RockDBManager>) -> Self {
        Self::new(db, ReForkConfig::default())
    }

    // ─────────────────────────────────────────────────────────────
    // Runtime logging time helper
    // ─────────────────────────────────────────────────────────────

    /// Runtime-only timestamp for fork-choice diagnostics/logs.
    #[inline]
    fn runtime_log_timestamp() -> String {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(now_unix) => {
                let Some(now_i64) = i64::try_from(now_unix).ok() else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(_) => "time_unavailable".to_string(),
        }
    }

    /// Short hash for operator logs only.
    #[inline]
    fn short_hash(hash: &BlockHash) -> String {
        const SHORT_HASH_EDGE_BYTES: usize = 4;
        const SHORT_HASH_FULL_BYTES: usize = 8;

        let hash_bytes: &[u8] = hash.as_ref();

        if hash_bytes.len() <= SHORT_HASH_FULL_BYTES {
            return hex::encode(hash_bytes);
        }

        let Some(prefix) = hash_bytes.get(..SHORT_HASH_EDGE_BYTES) else {
            return hex::encode(hash_bytes);
        };

        let suffix_start = hash_bytes.len().saturating_sub(SHORT_HASH_EDGE_BYTES);
        let Some(suffix) = hash_bytes.get(suffix_start..) else {
            return hex::encode(hash_bytes);
        };

        format!("{}...{}", hex::encode(prefix), hex::encode(suffix))
    }

    // ─────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────

    /// Core entry point.
    pub fn on_new_block(&self, new_block: &Block) -> Result<ForkAction, ErrorDetection> {
        let new_height = new_block.metadata.index;
        let new_hash = new_block.block_hash;

        tracing::debug!(
            "{} [FORK][NEW] height={} hash_short={}",
            Self::runtime_log_timestamp(),
            new_height,
            Self::short_hash(&new_hash)
        );

        let (old_height, old_hash, canonical_tip_block) = self.load_canonical_tip_block()?;

        // Happy path: extends current canonical tip directly.
        if new_block.metadata.previous_hash == old_hash
            && new_height == old_height.saturating_add(1)
        {
            tracing::debug!(
                "{} [FORK] new block extends current tip ({} -> {}), no reorg needed.",
                Self::runtime_log_timestamp(),
                old_height,
                new_height
            );
            return Ok(ForkAction::Stay);
        }

        let current_candidate = self.branch_candidate_from_tip(old_hash, old_height)?;
        let new_candidate = self.branch_candidate_from_tip(new_hash, new_height)?;

        let chosen = self
            .scorer
            .choose_tip(current_candidate, new_candidate)
            .unwrap_or(old_hash);

        let consider_reorg = chosen == new_hash;

        if !consider_reorg {
            tracing::debug!(
                "{} [FORK] candidate not better (cand_h={}, tip_h={}); staying on current chain.",
                Self::runtime_log_timestamp(),
                new_height,
                old_height
            );
            return Ok(ForkAction::Stay);
        }

        let new_path = match self.build_branch_path_from_hash(new_hash)? {
            BranchPathBuild::Complete(path) => path,
            BranchPathBuild::Missing {
                partial_path,
                missing_hash,
                context,
            } => {
                tracing::debug!(
                    "{} [FORK][WAIT] competing branch path incomplete: missing_hash_short={} context={} partial_len={}",
                    Self::runtime_log_timestamp(),
                    Self::short_hash(&missing_hash),
                    context,
                    partial_path.len()
                );
                return Ok(ForkAction::NeedMoreData {
                    missing_hash,
                    context,
                });
            }
        };

        let old_path = match self.build_branch_path_from_hash(canonical_tip_block.block_hash)? {
            BranchPathBuild::Complete(path) => path,
            BranchPathBuild::Missing {
                partial_path,
                missing_hash,
                context,
            } => {
                tracing::debug!(
                    "{} [FORK][WAIT] canonical branch path incomplete: missing_hash_short={} context={} partial_len={}",
                    Self::runtime_log_timestamp(),
                    Self::short_hash(&missing_hash),
                    context,
                    partial_path.len()
                );
                return Ok(ForkAction::NeedMoreData {
                    missing_hash,
                    context,
                });
            }
        };

        if new_path.is_empty() || old_path.is_empty() {
            tracing::debug!(
                "{} [FORK][WARN] failed to build branch paths (new_path_len={}, old_path_len={}); staying.",
                Self::runtime_log_timestamp(),
                new_path.len(),
                old_path.len()
            );
            return Ok(ForkAction::Stay);
        }

        let common = Self::find_common_ancestor(&new_path, &old_path);
        let (common_height, common_hash) = match common {
            Some(pair) => pair,
            None => {
                tracing::debug!(
                    "{} [FORK][WARN] no common ancestor within max_reorg_depth={} (new_tip_h={}, old_tip_h={}); refusing reorg.",
                    Self::runtime_log_timestamp(),
                    self.cfg.max_reorg_depth,
                    new_height,
                    old_height
                );
                return Ok(ForkAction::Stay);
            }
        };

        tracing::debug!(
            "{} [FORK] common_ancestor height={} hash_short={}",
            Self::runtime_log_timestamp(),
            common_height,
            Self::short_hash(&common_hash)
        );

        let (detach, attach) = Self::compute_reorg_steps(&new_path, &old_path, common_hash);

        let detach_depth = detach.len() as u64;
        let attach_depth = attach.len() as u64;

        if detach_depth == 0 && attach_depth == 0 {
            tracing::debug!(
                "{} [FORK] computed reorg plan is NOOP; staying.",
                Self::runtime_log_timestamp()
            );
            return Ok(ForkAction::Stay);
        }

        if detach_depth > self.cfg.max_reorg_depth || attach_depth > self.cfg.max_reorg_depth {
            tracing::debug!(
                "{} [FORK][WARN] reorg exceeds depth bound (detach={} attach={} max={}); refusing.",
                Self::runtime_log_timestamp(),
                detach_depth,
                attach_depth,
                self.cfg.max_reorg_depth
            );
            return Ok(ForkAction::Stay);
        }

        let plan = ReorgPlan {
            old_tip_height: old_height,
            old_tip_hash: old_hash,
            new_tip_height: new_height,
            new_tip_hash: new_hash,
            common_ancestor_height: common_height,
            common_ancestor_hash: common_hash,
            detach,
            attach,
        };

        tracing::debug!(
            "{} [FORK][PLAN] old_tip_h={} old_tip_hash_short={} new_tip_h={} new_tip_hash_short={} common_h={} common_hash_short={} detach={:?} attach={:?}",
            Self::runtime_log_timestamp(),
            plan.old_tip_height,
            Self::short_hash(&plan.old_tip_hash),
            plan.new_tip_height,
            Self::short_hash(&plan.new_tip_hash),
            plan.common_ancestor_height,
            Self::short_hash(&plan.common_ancestor_hash),
            plan.detach.iter().map(|s| s.height).collect::<Vec<_>>(),
            plan.attach.iter().map(|s| s.height).collect::<Vec<_>>(),
        );

        Ok(ForkAction::Reorg(plan))
    }

    /// Optional integration point for PoR proofs.
    pub fn on_puzzle_proof_for_branch(&self, proof: &PorPuzzleProof) {
        tracing::debug!(
            "{} [FORK][POR] proof for h={} validator_present={} prev_hash_short={}",
            Self::runtime_log_timestamp(),
            proof.height,
            !proof.validator.is_empty(),
            Self::short_hash(&proof.prev_block_hash)
        );
    }

    /// Apply a previously computed reorg plan.
    pub fn apply_reorg<FRevert, FApply>(
        &self,
        plan: &ReorgPlan,
        mut revert_step: FRevert,
        mut apply_step: FApply,
    ) -> Result<(), ErrorDetection>
    where
        FRevert: FnMut(u64, BlockHash) -> Result<(), ErrorDetection>,
        FApply: FnMut(u64, BlockHash) -> Result<(), ErrorDetection>,
    {
        if plan.is_noop() {
            tracing::debug!(
                "{} [FORK][APPLY] received NOOP reorg plan; nothing to do.",
                Self::runtime_log_timestamp()
            );
            return Ok(());
        }

        tracing::debug!(
            "{} [FORK][APPLY] starting reorg: old_tip={} new_tip={} common={}",
            Self::runtime_log_timestamp(),
            plan.old_tip_height,
            plan.new_tip_height,
            plan.common_ancestor_height
        );

        // 1) Detach old canonical steps.
        for step in &plan.detach {
            tracing::debug!(
                "{} [FORK][APPLY] REVERT height={} hash_short={}",
                Self::runtime_log_timestamp(),
                step.height,
                Self::short_hash(&step.hash)
            );

            // Preserve old canonical block in hash index if needed.
            if let Some(old_block) = self.db.get_block_by_index(step.height)? {
                let old_hash = old_block.block_hash;
                if !self.block_index.has_block(&old_hash)
                    && let Ok(bytes) = old_block.serialize_for_storage()
                {
                    drop(self.block_index.put_block_bytes(&old_hash, &bytes));
                }
            }

            if let Ok(true) = self.block_index.has_meta(&step.hash) {
                drop(self.block_index.mark_side_branch(&step.hash));
            }

            revert_step(step.height, step.hash)?;
        }

        // 2) Remove canonical hash slots above ancestor before attach.
        self.chain_view.delete_height_range(
            plan.common_ancestor_height.saturating_add(1),
            plan.old_tip_height,
        )?;

        // 3) Attach new canonical branch.
        for step in &plan.attach {
            tracing::debug!(
                "{} [FORK][APPLY] ATTACH height={} hash_short={}",
                Self::runtime_log_timestamp(),
                step.height,
                Self::short_hash(&step.hash)
            );

            let block = self.block_index.get_block(&step.hash)?.ok_or_else(|| {
                ErrorDetection::NotFound {
                    resource: format!(
                        "block_by_hash({}) while attaching height {}",
                        hex::encode(step.hash),
                        step.height
                    ),
                }
            })?;

            if block.metadata.index != step.height {
                return Err(ErrorDetection::BlockchainError {
                    details: format!(
                        "reorg attach height mismatch: plan_height={} block.index={} hash={}",
                        step.height,
                        block.metadata.index,
                        hex::encode(step.hash)
                    ),
                });
            }

            let bytes = block.serialize_for_storage()?;

            self.block_index.put_block_bytes(&step.hash, &bytes)?;
            self.db.store_latest_block(&bytes, step.height)?;
            self.chain_view
                .set_hash_at_height(step.height, &step.hash)?;

            if let Ok(true) = self.block_index.has_meta(&step.hash) {
                self.block_index.mark_canonical(&step.hash)?;
            }

            apply_step(step.height, step.hash)?;
        }

        // 4) Update canonical tip view.
        self.chain_view
            .set_tip(&plan.new_tip_hash, plan.new_tip_height)?;

        tracing::debug!(
            "{} [FORK][APPLY] reorg complete; canonical tip is now height={} hash_short={}",
            Self::runtime_log_timestamp(),
            plan.new_tip_height,
            Self::short_hash(&plan.new_tip_hash)
        );

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    /// Load canonical tip from canonical chain view first,
    /// then fall back to legacy tip_height + block_{height}.
    fn load_canonical_tip_block(&self) -> Result<(u64, BlockHash, Block), ErrorDetection> {
        if let Some(tip_view) = self.chain_view.get_tip_with_legacy_fallback()? {
            let block = self
                .block_index
                .get_block(&tip_view.tip_hash)?
                .ok_or_else(|| ErrorDetection::NotFound {
                    resource: format!(
                        "canonical tip block by hash {}",
                        hex::encode(tip_view.tip_hash)
                    ),
                })?;

            return Ok((tip_view.tip_height, tip_view.tip_hash, block));
        }

        Err(ErrorDetection::NotFound {
            resource: "canonical tip view".to_string(),
        })
    }

    fn branch_candidate_from_tip(
        &self,
        tip_hash: BlockHash,
        fallback_height: u64,
    ) -> Result<BranchCandidate, ErrorDetection> {
        let cumulative_por = self
            .block_index
            .get_meta(&tip_hash)?
            .map(|m| m.cumulative_score)
            .unwrap_or(fallback_height as u128);

        Ok(BranchCandidate::new(
            tip_hash,
            fallback_height,
            cumulative_por,
        ))
    }

    /// Build a truncated path from persisted fork metadata, not canonical height slots.
    fn build_branch_path_from_hash(
        &self,
        tip_hash: BlockHash,
    ) -> Result<BranchPathBuild, ErrorDetection> {
        let mut path = Vec::new();
        let mut current = tip_hash;

        let max_depth = usize::try_from(self.cfg.max_reorg_depth).map_err(|_| {
            ErrorDetection::BlockchainError {
                details: format!(
                    "max_reorg_depth does not fit usize: {}",
                    self.cfg.max_reorg_depth
                ),
            }
        })?;
        let loop_bound =
            max_depth
                .checked_add(1)
                .ok_or_else(|| ErrorDetection::BlockchainError {
                    details: format!("max_reorg_depth overflow when adding 1: {}", max_depth),
                })?;

        for _ in 0..loop_bound {
            let meta = match self.block_index.get_meta(&current)? {
                Some(m) => m,
                None => {
                    return Ok(BranchPathBuild::Missing {
                        partial_path: path,
                        missing_hash: current,
                        context: "missing_meta_for_current_hash",
                    });
                }
            };

            path.push((meta.height, current));

            // Reached genesis / root.
            if meta.height == 0 || meta.parent_hash == [0u8; 64] {
                return Ok(BranchPathBuild::Complete(path));
            }

            if !self.block_index.has_block(&meta.parent_hash) {
                return Ok(BranchPathBuild::Missing {
                    partial_path: path,
                    missing_hash: meta.parent_hash,
                    context: "missing_block_for_parent_hash",
                });
            }

            if !self.block_index.has_meta(&meta.parent_hash)? {
                return Ok(BranchPathBuild::Missing {
                    partial_path: path,
                    missing_hash: meta.parent_hash,
                    context: "missing_meta_for_parent_hash",
                });
            }

            current = meta.parent_hash;
        }

        Ok(BranchPathBuild::Complete(path))
    }

    /// Find highest common block between two truncated paths, comparing by hash.
    fn find_common_ancestor(
        new_path: &[(u64, BlockHash)],
        old_path: &[(u64, BlockHash)],
    ) -> Option<(u64, BlockHash)> {
        let mut map = HashMap::<BlockHash, u64>::with_capacity(new_path.len());
        for (h, hash) in new_path {
            map.insert(*hash, *h);
        }

        let mut best: Option<(u64, BlockHash)> = None;

        for (h_old, hash_old) in old_path {
            if map.contains_key(hash_old) {
                match best {
                    Some((best_h, _)) if *h_old <= best_h => {}
                    _ => best = Some((*h_old, *hash_old)),
                }
            }
        }

        best
    }

    /// Compute detach/attach steps given two paths and the common ancestor hash.
    fn compute_reorg_steps(
        new_path: &[(u64, BlockHash)],
        old_path: &[(u64, BlockHash)],
        common_hash: BlockHash,
    ) -> (Vec<ReorgStep>, Vec<ReorgStep>) {
        let mut detach = Vec::new();
        for (h, hash) in old_path {
            if *hash == common_hash {
                break;
            }
            detach.push(ReorgStep {
                height: *h,
                hash: *hash,
            });
        }

        let mut attach_rev = Vec::new();
        for (h, hash) in new_path {
            if *hash == common_hash {
                break;
            }
            attach_rev.push(ReorgStep {
                height: *h,
                hash: *hash,
            });
        }
        attach_rev.reverse();

        (detach, attach_rev)
    }
}
