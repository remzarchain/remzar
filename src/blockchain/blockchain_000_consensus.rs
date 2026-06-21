//! blockchain_000_consensus.rs

use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::validatorstate::ValidatorState;
use crate::consensus::por_000_ephemeral_registration::RegistryData;
use crate::consensus::por_001_consensus_config::PorConsensusConfig;
use crate::consensus::por_002_puzzle_engine::PorPuzzleEngine;
use crate::consensus::por_002_puzzle_engine::PorPuzzleSolution;
use crate::consensus::por_003_puzzle_pool::PorPuzzlePool;
use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
use crate::consensus::por_005_time_management::TimeManager;
use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
use crate::consensus::por_006_committee_eligibility::CommitteeEligibilityConfig;
use crate::consensus::por_007_leader_schedule::LeaderSchedule;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;

use chrono::DateTime;
use std::collections::HashMap;
use std::sync::Arc;

/// Maximum number of unknown-parent puzzle proofs retained globally.
const MAX_BUFFERED_UNKNOWN_PARENT_PROOFS: usize = 256;

/// Maximum number of unknown-parent puzzle proofs retained for one parent hash.
const MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT: usize = 32;

/// Maximum future distance, measured from the local proposal height, for
const MAX_UNKNOWN_PARENT_FUTURE_HEIGHT_DISTANCE: u64 = 8;

/// Consensus engine for puzzle flow + local proposer authorization.
pub struct BlockchainConsensus {
    db_manager: Arc<RockDBManager>,

    /// Snapshot of the runtime registry injected by orchestration.
    wallet_registry: RegistryData,

    /// Shared runtime/local mint-readiness policy.
    committee_eligibility: CommitteeEligibility,

    /// Canonical on-chain validator registry (membership only).
    validator_state: ValidatorState,

    /// Time manager (slot clock + derived intervals).
    tm: Arc<TimeManager>,

    local_wallet: String,

    /// POR puzzle engine (local delay + deterministic proof verification).
    por_engine: PorPuzzleEngine,

    /// In-memory pool of puzzle winners (RAM-only, keyed by block height).
    puzzle_pool: PorPuzzlePool,

    /// cryptographically valid.
    pending_proofs_by_prev_hash: HashMap<[u8; 64], Vec<PorPuzzleProof>>,

    /// Stash the most recent POR puzzle proof so the caller can gossip it.
    pending_puzzle_proof: Option<PorPuzzleProof>,

    /// Runtime/orchestration catch-up gate.
    runtime_rejoin_catchup_gate_active: bool,
    runtime_rejoin_catchup_reason: Option<String>,

    /// Runtime signal that branch hydration / recovery is still active.
    runtime_branch_hydration_active: bool,

    /// Optional runtime-observed canonical tip context that proposal attempts.
    runtime_canonical_tip_height: Option<u64>,
    runtime_canonical_tip_hash: Option<[u8; 64]>,

    /// Most recent canonical tip height for which `ValidatorState` was rebuilt.
    validator_state_rebuilt_at_tip: Option<u64>,

    /// Canonical leader scheduler.
    leader_schedule: LeaderSchedule,
}

impl BlockchainConsensus {
    #[must_use = "BlockchainConsensus::new returns a consensus engine that should be retained by the block builder"]
    pub fn new(
        db_manager: Arc<RockDBManager>,
        local_wallet: String,
        tm: Arc<TimeManager>,
    ) -> Result<Self, ErrorDetection> {
        let tip = db_manager.get_tip_height()?;

        // Canonicalize local wallet once so all comparisons are CANONICAL ONLY.
        let local_wallet = canon_wallet_id_checked(&local_wallet)?;

        // Consensus config from globals ONLY.
        let por_cfg = PorConsensusConfig::from_globals();
        por_cfg.validate()?;
        let por_engine = PorPuzzleEngine::new(por_cfg);

        let cfg = por_engine.config();
        tracing::debug!(
            "{} [POR][CONFIG] tip={} puzzle_kind={:?} target_block_time={}s max_local_puzzle_ms={} mode=MANDATORY_ON",
            Self::runtime_log_timestamp(),
            tip,
            cfg.puzzle_kind,
            cfg.target_block_time.as_secs(),
            cfg.max_local_puzzle_ms
        );

        // Canonical on-chain validator state, backed by RocksDB.
        let validator_state = ValidatorState::load_or_new((*db_manager).clone())?;
        let leader_schedule = LeaderSchedule::new(local_wallet.clone())?;

        let committee_cfg = CommitteeEligibilityConfig::from_globals();
        committee_cfg.validate()?;

        Ok(Self {
            db_manager,
            wallet_registry: RegistryData::new(),
            committee_eligibility: CommitteeEligibility::new(committee_cfg),
            validator_state,
            tm,
            local_wallet,
            por_engine,
            puzzle_pool: PorPuzzlePool::new(),
            pending_proofs_by_prev_hash: HashMap::new(),
            pending_puzzle_proof: None,
            runtime_rejoin_catchup_gate_active: false,
            runtime_rejoin_catchup_reason: None,
            runtime_branch_hydration_active: false,
            runtime_canonical_tip_height: None,
            runtime_canonical_tip_hash: None,
            validator_state_rebuilt_at_tip: Some(tip),
            leader_schedule,
        })
    }

    pub fn local_wallet(&self) -> &String {
        &self.local_wallet
    }

    /// Immutable access to the canonical validator registry.
    pub fn validator_state(&self) -> &ValidatorState {
        &self.validator_state
    }

    /// Mutable access so the orchestration loop can apply committed blocks and
    /// rebuild the on-chain validator snapshot.
    pub fn validator_state_mut(&mut self) -> &mut ValidatorState {
        &mut self.validator_state
    }

    /// Immutable access to runtime/local mint-readiness policy.
    pub fn committee_eligibility(&self) -> &CommitteeEligibility {
        &self.committee_eligibility
    }

    /// Mutable access so orchestration can refresh live-wallet and runtime
    /// health signals used for local mint suppression.
    pub fn committee_eligibility_mut(&mut self) -> &mut CommitteeEligibility {
        &mut self.committee_eligibility
    }

    /// Replace the runtime/local mint-readiness object entirely.
    pub fn set_committee_eligibility(&mut self, ce: CommitteeEligibility) {
        self.committee_eligibility = ce;
    }

    /// Refresh the runtime registry snapshot (called by orchestration each tick).
    pub fn set_registry(&mut self, reg: RegistryData) {
        let live_wallets = reg.sorted_wallets();
        self.wallet_registry = reg;

        if let Err(e) = self
            .committee_eligibility
            .replace_live_wallets(live_wallets)
        {
            tracing::debug!(
                "{} [COMMITTEE][LIVE][ERROR] failed to refresh runtime live-wallet view: {:?}",
                Self::runtime_log_timestamp(),
                e
            );
        }
    }

    /// Peek at the most recent POR puzzle proof, if any.
    pub fn pending_puzzle_proof(&self) -> Option<&PorPuzzleProof> {
        self.pending_puzzle_proof.as_ref()
    }

    /// Take and clear the most recent POR puzzle proof (for gossip).
    pub fn take_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
        self.pending_puzzle_proof.take()
    }

    /// Clear any staged local puzzle proof without using it for block assembly.
    pub fn clear_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
        self.pending_puzzle_proof.take()
    }

    /// Mark whether orchestration is still holding this node in catch-up mode.
    pub fn set_runtime_rejoin_catchup_gate(&mut self, active: bool, reason: Option<String>) {
        self.runtime_rejoin_catchup_gate_active = active;
        self.runtime_rejoin_catchup_reason = if active { reason } else { None };

        if active {
            let catchup_reason = self
                .runtime_rejoin_catchup_reason
                .clone()
                .unwrap_or_else(|| "runtime catch-up gate active".to_string());

            self.clear_staged_local_puzzle_proof_with_reason(&catchup_reason);
        }
    }

    pub fn runtime_rejoin_catchup_gate_active(&self) -> bool {
        self.runtime_rejoin_catchup_gate_active
    }

    /// Mark whether branch hydration / recovery is still active locally.
    pub fn set_runtime_branch_hydration_active(&mut self, active: bool) {
        self.runtime_branch_hydration_active = active;

        if active {
            self.clear_staged_local_puzzle_proof_with_reason("runtime branch hydration active");
        }
    }

    pub fn runtime_branch_hydration_active(&self) -> bool {
        self.runtime_branch_hydration_active
    }

    /// Publish the runtime-observed canonical tip context.
    pub fn set_runtime_canonical_tip_context(&mut self, tip_height: u64, tip_hash: [u8; 64]) {
        self.runtime_canonical_tip_height = Some(tip_height);
        self.runtime_canonical_tip_hash = Some(tip_hash);
    }

    pub fn clear_runtime_canonical_tip_context(&mut self) {
        self.runtime_canonical_tip_height = None;
        self.runtime_canonical_tip_hash = None;
    }

    pub fn note_validator_state_rebuilt_to_tip(&mut self, tip_height: u64) {
        self.validator_state_rebuilt_at_tip = Some(tip_height);
    }

    pub fn validator_state_rebuilt_at_tip(&self) -> Option<u64> {
        self.validator_state_rebuilt_at_tip
    }

    /// Reset all local proposal-safety state after a successful catch-up / reorg rebuild.
    pub fn reset_runtime_proposal_safety_state(
        &mut self,
        canonical_tip_height: u64,
        canonical_tip_hash: [u8; 64],
    ) {
        self.runtime_rejoin_catchup_gate_active = false;
        self.runtime_rejoin_catchup_reason = None;
        self.runtime_branch_hydration_active = false;
        self.runtime_canonical_tip_height = Some(canonical_tip_height);
        self.runtime_canonical_tip_hash = Some(canonical_tip_hash);
        self.validator_state_rebuilt_at_tip = Some(canonical_tip_height);

        let _ = self.clear_buffered_unknown_parent_puzzle_proofs_for_liveness(
            "runtime proposal safety state reset after catch-up / reorg rebuild",
        );
    }

    #[inline]
    fn has_known_parent_hash(&self, parent_hash: &[u8; 64]) -> bool {
        self.db_manager.get_block_by_hash(parent_hash).is_some()
    }

    #[inline]
    fn same_proof_identity(a: &PorPuzzleProof, b: &PorPuzzleProof) -> bool {
        a.height == b.height
            && a.prev_block_hash == b.prev_block_hash
            && a.output == b.output
            && a.validator.eq_ignore_ascii_case(&b.validator)
    }

    fn total_buffered_puzzle_proofs(&self) -> usize {
        self.pending_proofs_by_prev_hash
            .values()
            .map(std::vec::Vec::len)
            .sum()
    }

    pub fn pending_buffered_puzzle_proof_total(&self) -> usize {
        self.total_buffered_puzzle_proofs()
    }

    pub fn pending_buffered_puzzle_proof_count_for_parent(&self, parent_hash: [u8; 64]) -> usize {
        self.pending_proofs_by_prev_hash
            .get(&parent_hash)
            .map(std::vec::Vec::len)
            .unwrap_or(0)
    }

    /// Operator/emergency liveness valve.
    pub fn clear_buffered_unknown_parent_puzzle_proofs_for_liveness(
        &mut self,
        reason: &str,
    ) -> usize {
        let removed = self.total_buffered_puzzle_proofs();

        if removed > 0 {
            tracing::debug!(
                "{} [POR][PUZZLE][GC][CLEAR_ALL] removed {} buffered unknown-parent proof(s) reason={}",
                Self::runtime_log_timestamp(),
                removed,
                reason,
            );
        }

        self.pending_proofs_by_prev_hash.clear();
        removed
    }

    fn replay_buffered_puzzle_proofs_with_known_parents(&mut self) -> usize {
        let known_parent_hashes: Vec<[u8; 64]> = self
            .pending_proofs_by_prev_hash
            .keys()
            .copied()
            .filter(|parent_hash| self.has_known_parent_hash(parent_hash))
            .collect();

        let mut admitted = 0usize;

        for parent_hash in known_parent_hashes {
            admitted =
                admitted.saturating_add(self.replay_buffered_puzzle_proofs_for_parent(parent_hash));
        }

        admitted
    }

    fn drop_one_buffered_puzzle_proof_for_liveness(&mut self, reason: &'static str) -> bool {
        let Some(parent_hash) = self
            .pending_proofs_by_prev_hash
            .iter()
            .max_by_key(|(_, proofs)| proofs.len())
            .map(|(parent_hash, _)| *parent_hash)
        else {
            return false;
        };

        let removed = {
            let Some(proofs) = self.pending_proofs_by_prev_hash.get_mut(&parent_hash) else {
                return false;
            };

            proofs.pop()
        };

        let should_remove_bucket = self
            .pending_proofs_by_prev_hash
            .get(&parent_hash)
            .map(|proofs| proofs.is_empty())
            .unwrap_or(false);

        if should_remove_bucket {
            self.pending_proofs_by_prev_hash.remove(&parent_hash);
        }

        if let Some(proof) = removed {
            tracing::debug!(
                "{} [POR][PUZZLE][GC][DROP_ONE] reason={} height={} validator={} prev_hash={} output={} remaining_buffered={}",
                Self::runtime_log_timestamp(),
                reason,
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output,
                self.total_buffered_puzzle_proofs(),
            );
            return true;
        }

        false
    }

    /// Defensive liveness GC for unknown-parent proofs.
    fn gc_buffered_puzzle_proofs_for_local_proposal(
        &mut self,
        height: u64,
        prev_hash: [u8; 64],
        phase: &'static str,
    ) {
        let before = self.total_buffered_puzzle_proofs();

        let replayed = self.replay_buffered_puzzle_proofs_with_known_parents();

        let max_future_height = height.saturating_add(MAX_UNKNOWN_PARENT_FUTURE_HEIGHT_DISTANCE);

        self.pending_proofs_by_prev_hash.retain(|parent_hash, proofs| {
            proofs.retain(|proof| {
                let malformed = proof.height == 0 || proof.prev_block_hash == [0u8; 64];
                let current_tip_parent = proof.prev_block_hash == prev_hash;
                let stale_for_local_tip = proof.height <= height;
                let too_far_future = proof.height > max_future_height;

                let keep = !(malformed || current_tip_parent || stale_for_local_tip || too_far_future);

                if !keep {
                    tracing::debug!(
                        "{} [POR][PUZZLE][GC][ORPHAN] phase={} drop height={} validator={} prev_hash={} output={} malformed={} current_tip_parent={} stale_for_local_tip={} too_far_future={}",
                        Self::runtime_log_timestamp(),
                        phase,
                        proof.height,
                        proof.validator,
                        hex::encode(*parent_hash),
                        proof.output,
                        malformed,
                        current_tip_parent,
                        stale_for_local_tip,
                        too_far_future,
                    );
                }

                keep
            });

            !proofs.is_empty()
        });

        let oversized_parents: Vec<[u8; 64]> = self
            .pending_proofs_by_prev_hash
            .iter()
            .filter_map(|(parent_hash, proofs)| {
                if proofs.len() > MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT {
                    Some(*parent_hash)
                } else {
                    None
                }
            })
            .collect();

        for parent_hash in oversized_parents {
            if let Some(proofs) = self.pending_proofs_by_prev_hash.get_mut(&parent_hash) {
                let parent_before = proofs.len();
                proofs.truncate(MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT);
                let removed = parent_before.saturating_sub(proofs.len());

                if removed > 0 {
                    tracing::debug!(
                        "{} [POR][PUZZLE][GC][PARENT_CAP] phase={} prev_hash={} removed={} kept={}",
                        Self::runtime_log_timestamp(),
                        phase,
                        hex::encode(parent_hash),
                        removed,
                        proofs.len(),
                    );
                }
            }
        }

        while self.total_buffered_puzzle_proofs() > MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
            if !self.drop_one_buffered_puzzle_proof_for_liveness("global unknown-parent buffer cap")
            {
                break;
            }
        }

        let after = self.total_buffered_puzzle_proofs();
        let processed = before.saturating_sub(after);

        if processed > 0 || replayed > 0 {
            tracing::debug!(
                "{} [POR][PUZZLE][GC][SUMMARY] phase={} h={} prev_hash={} before={} replayed={} after={} max_total={} max_per_parent={} max_future_distance={}",
                Self::runtime_log_timestamp(),
                phase,
                height,
                hex::encode(prev_hash),
                before,
                replayed,
                after,
                MAX_BUFFERED_UNKNOWN_PARENT_PROOFS,
                MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT,
                MAX_UNKNOWN_PARENT_FUTURE_HEIGHT_DISTANCE,
            );
        }
    }

    fn log_buffered_puzzle_proof_liveness_warning(
        &self,
        height: u64,
        prev_hash: [u8; 64],
        phase: &'static str,
    ) {
        let total = self.total_buffered_puzzle_proofs();

        if total == 0 {
            return;
        }

        tracing::debug!(
            "{} [POR][PUZZLE][LIVENESS] phase={} h={} prev_hash={} buffered_unknown_parent_proofs={} action=not_blocking_local_proposal",
            Self::runtime_log_timestamp(),
            phase,
            height,
            hex::encode(prev_hash),
            total,
        );

        for (parent_hash, proofs) in self.pending_proofs_by_prev_hash.iter().take(8) {
            tracing::debug!(
                "{} [POR][PUZZLE][LIVENESS][BUCKET] prev_hash={} count={}",
                Self::runtime_log_timestamp(),
                hex::encode(parent_hash),
                proofs.len(),
            );

            for proof in proofs.iter().take(4) {
                tracing::debug!(
                    "{} [POR][PUZZLE][LIVENESS][PROOF] height={} validator={} prev_hash={} output={}",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                    proof.output,
                );
            }
        }
    }

    fn buffer_verified_unknown_parent_proof(&mut self, proof: &PorPuzzleProof) -> bool {
        let existing_for_parent = self
            .pending_proofs_by_prev_hash
            .get(&proof.prev_block_hash)
            .map(std::vec::Vec::len)
            .unwrap_or(0);

        if self
            .pending_proofs_by_prev_hash
            .get(&proof.prev_block_hash)
            .map(|bucket| {
                bucket
                    .iter()
                    .any(|existing| Self::same_proof_identity(existing, proof))
            })
            .unwrap_or(false)
        {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][BUFFERED_DUP] height={} validator={} prev_hash={} output={} pending_for_parent={} total_pending={}",
                Self::runtime_log_timestamp(),
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output,
                existing_for_parent,
                self.total_buffered_puzzle_proofs(),
            );
            return true;
        }

        if existing_for_parent >= MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][DROP_PARENT_CAP] height={} validator={} prev_hash={} output={} pending_for_parent={} max_per_parent={} total_pending={}",
                Self::runtime_log_timestamp(),
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output,
                existing_for_parent,
                MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT,
                self.total_buffered_puzzle_proofs(),
            );
            return true;
        }

        while self.total_buffered_puzzle_proofs() >= MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
            if !self.drop_one_buffered_puzzle_proof_for_liveness(
                "global unknown-parent buffer cap before insert",
            ) {
                break;
            }
        }

        if self.total_buffered_puzzle_proofs() >= MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][DROP_GLOBAL_CAP] height={} validator={} prev_hash={} output={} max_total={}",
                Self::runtime_log_timestamp(),
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output,
                MAX_BUFFERED_UNKNOWN_PARENT_PROOFS,
            );
            return true;
        }

        self.pending_proofs_by_prev_hash
            .entry(proof.prev_block_hash)
            .or_default()
            .push(proof.clone());

        let pending_for_parent = self
            .pending_proofs_by_prev_hash
            .get(&proof.prev_block_hash)
            .map(std::vec::Vec::len)
            .unwrap_or(0);

        tracing::debug!(
            "{} [POR][PUZZLE][RECV][BUFFERED] height={} validator={} prev_hash={} output={} pending_for_parent={} total_pending={}",
            Self::runtime_log_timestamp(),
            proof.height,
            proof.validator,
            hex::encode(proof.prev_block_hash),
            proof.output,
            pending_for_parent,
            self.total_buffered_puzzle_proofs(),
        );

        true
    }

    fn record_verified_proof_in_active_pool(
        &mut self,
        proof: &PorPuzzleProof,
        path_label: &'static str,
    ) -> bool {
        if let Err(e) =
            self.puzzle_pool
                .record_success_checked(proof.height, &proof.validator, proof.output)
        {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][POOL_ERR] path={} height={} validator_id={} output_present=true err={}",
                Self::runtime_log_timestamp(),
                path_label,
                proof.height,
                Self::wallet_short(&proof.validator),
                e
            );
            return false;
        }

        tracing::debug!(
            "{} [POR][PUZZLE][RECV][OK][{}] height={} validator_id={} prev_hash={} output_present=true",
            Self::runtime_log_timestamp(),
            path_label,
            proof.height,
            Self::wallet_short(&proof.validator),
            Self::hash_short(&proof.prev_block_hash),
        );

        true
    }

    fn gc_buffered_puzzle_proofs_below(&mut self, height: u64) {
        let before = self.total_buffered_puzzle_proofs();

        let replayed = self.replay_buffered_puzzle_proofs_with_known_parents();

        self.pending_proofs_by_prev_hash.retain(|parent_hash, proofs| {
            proofs.retain(|proof| {
                let keep = proof.height >= height && proof.height != 0 && proof.prev_block_hash != [0u8; 64];

                if !keep {
                    tracing::debug!(
                        "{} [POR][PUZZLE][GC] removed buffered proof height={} validator={} prev_hash={} output={} cutoff_height={}",
                        Self::runtime_log_timestamp(),
                        proof.height,
                        proof.validator,
                        hex::encode(*parent_hash),
                        proof.output,
                        height,
                    );
                }

                keep
            });
            !proofs.is_empty()
        });

        while self.total_buffered_puzzle_proofs() > MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
            if !self.drop_one_buffered_puzzle_proof_for_liveness(
                "global unknown-parent buffer cap during gc_below",
            ) {
                break;
            }
        }

        let after = self.total_buffered_puzzle_proofs();
        let processed = before.saturating_sub(after);

        if processed > 0 || replayed > 0 {
            tracing::debug!(
                "{} [POR][PUZZLE][GC] removed_or_replayed={} replayed={} below_height={} remaining_buffered={}",
                Self::runtime_log_timestamp(),
                processed,
                replayed,
                height,
                after
            );
        }
    }

    /// Replay previously buffered proofs that were waiting on `parent_hash`.
    pub fn replay_buffered_puzzle_proofs_for_parent(&mut self, parent_hash: [u8; 64]) -> usize {
        if !self.has_known_parent_hash(&parent_hash) {
            tracing::debug!(
                "{} [POR][PUZZLE][REPLAY][SKIP] parent still unknown prev_hash={} buffered_for_parent={} total_pending={}",
                Self::runtime_log_timestamp(),
                hex::encode(parent_hash),
                self.pending_buffered_puzzle_proof_count_for_parent(parent_hash),
                self.total_buffered_puzzle_proofs(),
            );
            return 0;
        }

        let Some(buffered) = self.pending_proofs_by_prev_hash.remove(&parent_hash) else {
            return 0;
        };

        let parent_idx = match self.db_manager.get_block_by_hash(&parent_hash) {
            Some(parent_block) => parent_block.metadata.index,
            None => {
                // Defensive: if the parent disappeared between the initial guard and now,
                // re-buffer the proofs and exit safely.
                for proof in buffered {
                    let _ = self.buffer_verified_unknown_parent_proof(&proof);
                }
                return 0;
            }
        };

        let mut admitted = 0usize;
        let total = buffered.len();

        tracing::debug!(
            "{} [POR][PUZZLE][REPLAY] parent_hash={} parent_idx={} buffered_count={}",
            Self::runtime_log_timestamp(),
            hex::encode(parent_hash),
            parent_idx,
            total,
        );

        for proof in buffered {
            let expected_h = parent_idx.saturating_add(1);
            let path_label = if expected_h == proof.height {
                "REPLAY_MAIN"
            } else {
                "REPLAY_BRANCH"
            };

            if self.record_verified_proof_in_active_pool(&proof, path_label) {
                admitted = admitted.saturating_add(1);
            }
        }

        tracing::debug!(
            "{} [POR][PUZZLE][REPLAY][DONE] parent_hash={} admitted={} dropped={} remaining_pending={}",
            Self::runtime_log_timestamp(),
            hex::encode(parent_hash),
            admitted,
            total.saturating_sub(admitted),
            self.total_buffered_puzzle_proofs(),
        );

        admitted
    }

    /// Handle an incoming gossiped POR puzzle proof.
    pub fn on_puzzle_proof(&mut self, proof: &PorPuzzleProof) -> bool {
        if proof.height == 0 {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][INVALID] genesis-height puzzle proof is not allowed",
                Self::runtime_log_timestamp(),
            );
            return false;
        }

        if let Err(e) = canon_wallet_id_checked(&proof.validator) {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][INVALID] non-canonical validator wallet in proof: {:?}",
                Self::runtime_log_timestamp(),
                e
            );
            return false;
        }

        let parent_block = self.db_manager.get_block_by_hash(&proof.prev_block_hash);

        match parent_block.as_ref() {
            Some(parent_block) => {
                let parent_idx = parent_block.metadata.index;
                let expected_h = parent_idx.saturating_add(1);

                if expected_h != proof.height {
                    tracing::debug!(
                        "{} [POR][PUZZLE][RECV][BRANCH] proof for h={} builds on parent_idx={} (expected_h={}); treating as valid branch-level proof.",
                        Self::runtime_log_timestamp(),
                        proof.height,
                        parent_idx,
                        expected_h
                    );
                } else {
                    tracing::debug!(
                        "{} [POR][PUZZLE][RECV][MAIN] proof for h={} builds on local-known parent_idx={}",
                        Self::runtime_log_timestamp(),
                        proof.height,
                        parent_idx
                    );
                }
            }
            None => {
                tracing::debug!(
                    "{} [POR][PUZZLE][RECV][WARN] unknown parent hash for proof h={} prev_hash={}; verifying and buffering proof until parent branch is known.",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    hex::encode(proof.prev_block_hash)
                );
            }
        }

        if !proof.verify_with_engine(&self.por_engine) {
            tracing::debug!(
                "{} [POR][PUZZLE][RECV][INVALID] height={} validator={} prev_hash={} output={}",
                Self::runtime_log_timestamp(),
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output
            );
            return false;
        }

        match parent_block {
            Some(parent_block) => {
                let parent_idx = parent_block.metadata.index;
                let expected_h = parent_idx.saturating_add(1);
                let path_label = if expected_h == proof.height {
                    "ACTIVE_MAIN"
                } else {
                    "ACTIVE_BRANCH"
                };

                self.record_verified_proof_in_active_pool(proof, path_label)
            }
            None => self.buffer_verified_unknown_parent_proof(proof),
        }
    }

    fn should_skip_register_tx_for_wallet(
        &self,
        wallet_can: &str,
        height: u64,
    ) -> Result<bool, ErrorDetection> {
        let is_canonically_known = self.validator_state.is_canonically_known(wallet_can)?;
        let meta = self.validator_state.meta_for(wallet_can);

        match meta.as_ref() {
            Some(m) => {
                tracing::debug!(
                    "{} [MINT][REG][CHECK] wallet_present=true h={} meta_present=true join_height={} last_renew_height={} exit_height_present={} is_canonically_known={}",
                    Self::runtime_log_timestamp(),
                    height,
                    m.join_height,
                    m.last_renew_height,
                    m.exit_height.is_some(),
                    is_canonically_known
                );
            }
            None => {
                tracing::debug!(
                    "{} [MINT][REG][CHECK] wallet_present=true h={} meta_present=false is_canonically_known={}",
                    Self::runtime_log_timestamp(),
                    height,
                    is_canonically_known
                );
            }
        }

        if is_canonically_known {
            return Ok(true);
        }

        Ok(false)
    }

    /// Collect deterministic RegisterNodeTx values for wallets that are present.
    pub fn collect_register_node_txs_for_block(&self, height: u64) -> Vec<RegisterNodeTx> {
        let mut out = Vec::new();

        let wallets = self.wallet_registry.sorted_wallets();
        if wallets.is_empty() {
            return out;
        }

        tracing::debug!(
            "{} [MINT][REG] scanning {} runtime wallets for canonical registration at height={}",
            Self::runtime_log_timestamp(),
            wallets.len(),
            height
        );

        for wallet in wallets {
            let wallet_id_input = Self::wallet_short(&wallet);

            let wallet_can = match canon_wallet_id_checked(&wallet) {
                Ok(w) => w,
                Err(_) => {
                    tracing::debug!(
                        "{} [MINT][REG] skip non-canonical wallet_id={} at h={} reason=canonicalization_failed",
                        Self::runtime_log_timestamp(),
                        wallet_id_input,
                        height
                    );
                    continue;
                }
            };

            let wallet_id = Self::wallet_short(&wallet_can);

            match self.should_skip_register_tx_for_wallet(&wallet_can, height) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => {
                    tracing::debug!(
                        "{} [MINT][REG] WARN canonical registration guard failed for wallet_id={} at h={} reason=validator_state_lookup_failed; skipping for safety",
                        Self::runtime_log_timestamp(),
                        wallet_id,
                        height
                    );
                    continue;
                }
            }

            if !self.wallet_registry.is_registered(&wallet_can) {
                tracing::debug!(
                    "{} [MINT][REG] skip wallet_id={} at h={} reason=no_longer_present_in_runtime_registry",
                    Self::runtime_log_timestamp(),
                    wallet_id,
                    height
                );
                continue;
            }

            match RegisterNodeTx::new(wallet_can.clone()) {
                Ok(reg_tx) => {
                    tracing::debug!(
                        "{} [MINT][REG] including RegisterNodeTx wallet_id={} height={}",
                        Self::runtime_log_timestamp(),
                        wallet_id,
                        height
                    );
                    out.push(reg_tx);
                }
                Err(_) => {
                    tracing::debug!(
                        "{} [MINT][REG] ERROR constructing RegisterNodeTx wallet_id={} height={} reason=tx_construction_failed",
                        Self::runtime_log_timestamp(),
                        wallet_id,
                        height
                    );
                }
            }
        }

        if !out.is_empty() {
            tracing::debug!(
                "{} [MINT][REG] will include {} RegisterNodeTx in block at height={}",
                Self::runtime_log_timestamp(),
                out.len(),
                height
            );
        }

        out
    }

    pub fn reward_eligible_at(&self, wallet: &str, height: u64) -> bool {
        self.validator_state.reward_eligible_at(wallet, height)
    }

    /// Immutable, non-staging mint preflight for the orchestration runtime.
    pub fn local_wallet_can_attempt_mint_at(
        &self,
        height: u64,
        prev_hash: [u8; 64],
    ) -> Result<(), ErrorDetection> {
        self.ensure_orchestration_mint_preflight_context(height, prev_hash)?;

        let snapshot = LeaderSchedule::committee_snapshot(
            &self.validator_state,
            &self.committee_eligibility,
            &self.tm,
            prev_hash,
            height,
        )?;

        let local_in_committee = snapshot.contains_wallet(&self.local_wallet);

        if !local_in_committee {
            tracing::debug!(
                "{} [MINT][PREFLIGHT] result=skip h={} prev_hash={} local_wallet={} reason=not_in_canonical_committee",
                Self::runtime_log_timestamp(),
                height,
                Self::hash_short(&prev_hash),
                Self::wallet_short(&self.local_wallet),
            );

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "local wallet is not in canonical committee at height {}",
                    height
                ),
                tx_id: None,
            });
        }

        if let Some(reasons) = self.runtime_mint_suppression_reasons() {
            tracing::debug!(
                "{} [MINT][PREFLIGHT] result=skip h={} prev_hash={} local_wallet={} reason=runtime_policy details={}",
                Self::runtime_log_timestamp(),
                height,
                Self::hash_short(&prev_hash),
                Self::wallet_short(&self.local_wallet),
                reasons,
            );

            return Err(ErrorDetection::ValidationError {
                message: format!("local mint suppressed by runtime policy: {reasons}"),
                tx_id: None,
            });
        }

        tracing::debug!(
            "{} [MINT][PREFLIGHT] result=pass h={} prev_hash={} local_wallet={} canonical_committee=true runtime_policy=eligible",
            Self::runtime_log_timestamp(),
            height,
            Self::hash_short(&prev_hash),
            Self::wallet_short(&self.local_wallet),
        );

        Ok(())
    }

    pub fn gc_puzzle_pool_below(&mut self, height: u64) {
        self.puzzle_pool.gc_below(height);
        self.gc_buffered_puzzle_proofs_below(height);
    }

    fn has_staged_local_puzzle_for_current_context(
        &self,
        height: u64,
        prev_hash: [u8; 64],
    ) -> bool {
        match self.pending_puzzle_proof.as_ref() {
            Some(proof) => {
                proof.height == height
                    && proof.prev_block_hash == prev_hash
                    && proof.validator.eq_ignore_ascii_case(&self.local_wallet)
            }
            None => false,
        }
    }

    /// This prevents reusing a proof from an earlier height or parent.
    fn invalidate_stale_staged_local_puzzle(&mut self, height: u64, prev_hash: [u8; 64]) {
        let should_clear = match self.pending_puzzle_proof.as_ref() {
            Some(proof) => {
                !(proof.height == height
                    && proof.prev_block_hash == prev_hash
                    && proof.validator.eq_ignore_ascii_case(&self.local_wallet))
            }
            None => false,
        };

        if should_clear {
            if let Some(proof) = self.pending_puzzle_proof.as_ref() {
                tracing::debug!(
                    "{} [POR][PUZZLE][CACHE] clearing stale staged proof old_height={} old_prev_hash={} new_height={} new_prev_hash={}",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    hex::encode(proof.prev_block_hash),
                    height,
                    hex::encode(prev_hash),
                );
            }
            self.pending_puzzle_proof = None;
        }
    }

    fn clear_staged_local_puzzle_proof_with_reason(&mut self, reason: &str) {
        if let Some(proof) = self.pending_puzzle_proof.take() {
            tracing::debug!(
                "{} [POR][PUZZLE][CACHE] dropped staged local proof reason={} height={} validator={} prev_hash={}",
                Self::runtime_log_timestamp(),
                reason,
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
            );
        }
    }

    /// Immutable guard used by orchestration before entering the builder mint path.
    fn ensure_orchestration_mint_preflight_context(
        &self,
        height: u64,
        prev_hash: [u8; 64],
    ) -> Result<(), ErrorDetection> {
        if height == 0 {
            tracing::debug!(
                "{} [MINT][PREFLIGHT] result=skip h=0 reason=invalid_height",
                Self::runtime_log_timestamp(),
            );
            return Err(ErrorDetection::ValidationError {
                message: "orchestration mint preflight called for height=0".into(),
                tx_id: None,
            });
        }

        if prev_hash == [0u8; 64] {
            tracing::debug!(
                "{} [MINT][PREFLIGHT] result=skip h={} reason=zero_prev_hash",
                Self::runtime_log_timestamp(),
                height,
            );
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "orchestration mint preflight called with zero prev_hash for height {}",
                    height
                ),
                tx_id: None,
            });
        }

        if !self.has_known_parent_hash(&prev_hash) {
            tracing::debug!(
                "{} [MINT][PREFLIGHT] result=skip h={} prev_hash={} reason=unknown_local_parent",
                Self::runtime_log_timestamp(),
                height,
                Self::hash_short(&prev_hash),
            );
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "orchestration mint preflight blocked: parent hash is not known locally for height {}",
                    height
                ),
                tx_id: None,
            });
        }

        let required_tip = height.saturating_sub(1);

        match self.validator_state_rebuilt_at_tip {
            Some(rebuilt_tip) if rebuilt_tip >= required_tip => {}
            Some(rebuilt_tip) => {
                tracing::debug!(
                    "{} [MINT][PREFLIGHT] result=skip h={} required_tip={} rebuilt_tip={} reason=stale_validator_state",
                    Self::runtime_log_timestamp(),
                    height,
                    required_tip,
                    rebuilt_tip,
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "orchestration mint preflight blocked: validator state rebuilt only through tip {}, required {} for height {}",
                        rebuilt_tip, required_tip, height,
                    ),
                    tx_id: None,
                });
            }
            None => {
                tracing::debug!(
                    "{} [MINT][PREFLIGHT] result=skip h={} required_tip={} reason=missing_validator_state_rebuild_marker",
                    Self::runtime_log_timestamp(),
                    height,
                    required_tip,
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "orchestration mint preflight blocked: validator state rebuild marker missing for height {}",
                        height
                    ),
                    tx_id: None,
                });
            }
        }

        match (
            self.runtime_canonical_tip_height,
            self.runtime_canonical_tip_hash,
        ) {
            (Some(runtime_tip_height), Some(runtime_tip_hash))
                if runtime_tip_height == required_tip && runtime_tip_hash == prev_hash => {}
            (Some(runtime_tip_height), Some(runtime_tip_hash)) => {
                tracing::debug!(
                    "{} [MINT][PREFLIGHT] result=skip h={} required_tip={} observed_tip={} prev_hash={} observed_hash={} reason=canonical_tip_context_mismatch",
                    Self::runtime_log_timestamp(),
                    height,
                    required_tip,
                    runtime_tip_height,
                    Self::hash_short(&prev_hash),
                    Self::hash_short(&runtime_tip_hash),
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "orchestration mint preflight blocked: canonical tip context mismatch for height {}",
                        height
                    ),
                    tx_id: None,
                });
            }
            (None, None) => {
                tracing::debug!(
                    "{} [MINT][PREFLIGHT] result=skip h={} required_tip={} reason=missing_canonical_tip_context",
                    Self::runtime_log_timestamp(),
                    height,
                    required_tip,
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "orchestration mint preflight blocked: canonical tip context missing for height {}",
                        height
                    ),
                    tx_id: None,
                });
            }
            _ => {
                tracing::debug!(
                    "{} [MINT][PREFLIGHT] result=skip h={} required_tip={} reason=incomplete_canonical_tip_context",
                    Self::runtime_log_timestamp(),
                    height,
                    required_tip,
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "orchestration mint preflight blocked: incomplete canonical tip context for height {}",
                        height
                    ),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }

    /// Local proposal safety guard.
    fn ensure_runtime_local_proposal_safety(
        &mut self,
        height: u64,
        prev_hash: [u8; 64],
        phase: &'static str,
    ) -> Result<(), ErrorDetection> {
        if !self.has_known_parent_hash(&prev_hash) {
            self.clear_staged_local_puzzle_proof_with_reason(
                "local parent hash is not known while staging/building",
            );
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "local proposal blocked during {}: parent hash is not known locally for h={} prev_hash={}",
                    phase,
                    height,
                    hex::encode(prev_hash),
                ),
                tx_id: None,
            });
        }

        // Orphan/unknown-parent proof maintenance is intentionally non-blocking.
        self.gc_buffered_puzzle_proofs_for_local_proposal(height, prev_hash, phase);
        self.log_buffered_puzzle_proof_liveness_warning(height, prev_hash, phase);

        if self.runtime_branch_hydration_active {
            self.clear_staged_local_puzzle_proof_with_reason(
                "branch hydration / recovery still active",
            );
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "local proposal blocked during {}: branch hydration / recovery still active",
                    phase,
                ),
                tx_id: None,
            });
        }

        if self.runtime_rejoin_catchup_gate_active {
            let catchup_reason = self
                .runtime_rejoin_catchup_reason
                .clone()
                .unwrap_or_else(|| "runtime catch-up gate active".to_string());

            self.clear_staged_local_puzzle_proof_with_reason(&catchup_reason);
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "local proposal blocked during {}: catch-up gate active ({})",
                    phase,
                    self.runtime_rejoin_catchup_reason
                        .as_deref()
                        .unwrap_or("unspecified"),
                ),
                tx_id: None,
            });
        }

        if let Some(rebuilt_tip) = self.validator_state_rebuilt_at_tip {
            let required_tip = height.saturating_sub(1);
            if rebuilt_tip < required_tip {
                self.clear_staged_local_puzzle_proof_with_reason(
                    "validator state not rebuilt to required canonical tip",
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local proposal blocked during {}: validator state rebuilt only through tip {}, required at least {} for block height {}",
                        phase, rebuilt_tip, required_tip, height,
                    ),
                    tx_id: None,
                });
            }
        }

        if let (Some(runtime_tip_height), Some(runtime_tip_hash)) = (
            self.runtime_canonical_tip_height,
            self.runtime_canonical_tip_hash,
        ) {
            let required_tip = height.saturating_sub(1);
            if runtime_tip_height != required_tip || runtime_tip_hash != prev_hash {
                self.clear_staged_local_puzzle_proof_with_reason(
                    "runtime canonical tip context mismatch",
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local proposal blocked during {}: runtime canonical tip mismatch (observed_tip_height={} required_tip_height={} observed_tip_hash={} required_prev_hash={})",
                        phase,
                        runtime_tip_height,
                        required_tip,
                        hex::encode(runtime_tip_hash),
                        hex::encode(prev_hash),
                    ),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }

    fn runtime_mint_suppression_reasons(&self) -> Option<String> {
        let decision = self.committee_eligibility.decide_wallet(&self.local_wallet);

        if decision.eligible {
            return None;
        }

        Some(if decision.reasons.is_empty() {
            "unknown".to_string()
        } else {
            decision
                .reasons
                .iter()
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        })
    }

    /// Local runtime producer-policy check used before staging / reusing local puzzle work.
    fn ensure_local_runtime_mint_eligibility_for_staging(&self) -> Result<(), ErrorDetection> {
        if let Some(reasons) = self.runtime_mint_suppression_reasons() {
            tracing::debug!(
                "{} [MINT][RUNTIME_POLICY] result=deny local_wallet={} details={}",
                Self::runtime_log_timestamp(),
                Self::wallet_short(&self.local_wallet),
                reasons,
            );

            return Err(ErrorDetection::ValidationError {
                message: format!("local mint suppressed by runtime policy: {reasons}"),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Ensure this node is allowed to stage / reuse local puzzle work for height.
    fn ensure_local_can_stage_puzzle_for_context(
        &self,
        height: u64,
        prev_hash: [u8; 64],
    ) -> Result<(), ErrorDetection> {
        let snapshot = LeaderSchedule::committee_snapshot(
            &self.validator_state,
            &self.committee_eligibility,
            &self.tm,
            prev_hash,
            height,
        )?;

        if !snapshot.contains_wallet(&self.local_wallet) {
            tracing::debug!(
                "{} [MINT][COMMITTEE] result=deny h={} prev_hash={} local_wallet={} reason=not_in_canonical_committee",
                Self::runtime_log_timestamp(),
                height,
                Self::hash_short(&prev_hash),
                Self::wallet_short(&self.local_wallet),
            );

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "local wallet is not in canonical committee at height {}",
                    height
                ),
                tx_id: None,
            });
        }

        self.ensure_local_runtime_mint_eligibility_for_staging()?;
        Ok(())
    }

    /// Ensure we have a staged local puzzle proof for the current mint context.
    fn ensure_staged_local_puzzle_for_block(
        &mut self,
        height: u64,
        prev_hash: [u8; 64],
    ) -> Result<(), ErrorDetection> {
        self.ensure_runtime_local_proposal_safety(height, prev_hash, "prestage")?;
        self.invalidate_stale_staged_local_puzzle(height, prev_hash);

        if self.has_staged_local_puzzle_for_current_context(height, prev_hash) {
            tracing::debug!(
                "{} [POR][PUZZLE][CACHE] reusing staged local proof for h={} prev_hash={}",
                Self::runtime_log_timestamp(),
                height,
                hex::encode(prev_hash),
            );
            return Ok(());
        }

        self.ensure_local_can_stage_puzzle_for_context(height, prev_hash)?;
        self.run_local_puzzle_for_block(height, prev_hash)
    }

    /// Main consensus gate invoked by the block builder before assembly.
    pub fn assert_can_build_block(
        &mut self,
        height: u64,
        prev_hash: [u8; 64],
        bypass_leader: bool,
    ) -> Result<(), ErrorDetection> {
        if bypass_leader {
            return Err(ErrorDetection::ValidationError {
                message: "bypass_leader is disabled (fork lever)".into(),
                tx_id: None,
            });
        }

        if height == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "assert_can_build_block called for height=0".into(),
                tx_id: None,
            });
        }

        if prev_hash == [0u8; 64] {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "assert_can_build_block called with zero prev_hash for non-genesis height {}",
                    height
                ),
                tx_id: None,
            });
        }

        self.ensure_runtime_local_proposal_safety(height, prev_hash, "build_gate_precheck")?;
        self.ensure_staged_local_puzzle_for_block(height, prev_hash)?;
        self.ensure_runtime_local_proposal_safety(height, prev_hash, "build_gate_poststage")?;

        // Final canonical leader authorization happens AFTER the proof is
        // staged/reused, so later failover rounds do not pay full puzzle-start delay.
        let now = Self::now_unix()?;
        let auth = self.leader_schedule.assert_local_can_mint_now(
            &self.validator_state,
            &self.committee_eligibility,
            &self.tm,
            prev_hash,
            height,
            now,
        )?;

        let cfg = self.por_engine.config();

        let leader_match = auth
            .trace
            .decision
            .leader
            .eq_ignore_ascii_case(&self.local_wallet);

        let local_in_committee = auth.trace.snapshot.contains_wallet(&self.local_wallet);

        tracing::debug!(
            "{} [MINT][GATE] h={} now={} elapsed={}s round={} in_round={}s tau={}s puzzle_kind={:?} committee_len={} leader_match={} local_in_committee={} gate=authorized",
            Self::runtime_log_timestamp(),
            auth.trace.decision.height,
            auth.trace.observed_time_unix,
            auth.trace.elapsed_secs,
            auth.trace.decision.round,
            auth.trace.in_round_secs,
            auth.trace.failover_window_secs,
            cfg.puzzle_kind,
            auth.trace.decision.committee_len,
            leader_match,
            local_in_committee,
        );

        if !self.has_staged_local_puzzle_for_current_context(height, prev_hash) {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "staged local puzzle proof missing or mismatched for h={}",
                    height,
                ),
                tx_id: None,
            });
        }

        self.ensure_runtime_local_proposal_safety(height, prev_hash, "build_gate_final")?;

        Ok(())
    }

    fn run_local_puzzle_for_block(
        &mut self,
        height: u64,
        prev_hash: [u8; 64],
    ) -> Result<(), ErrorDetection> {
        if height == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "run_local_puzzle_for_block called for height=0".into(),
                tx_id: None,
            });
        }

        if prev_hash == [0u8; 64] {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "run_local_puzzle_for_block called with zero prev_hash for height {}",
                    height
                ),
                tx_id: None,
            });
        }

        self.ensure_runtime_local_proposal_safety(height, prev_hash, "local_puzzle_solve")?;

        let cfg = self.por_engine.config();

        let header = self
            .por_engine
            .derive_puzzle(height, &self.local_wallet, prev_hash);

        let solution: PorPuzzleSolution = self.por_engine.solve_locally_checked(&header)?;

        self.puzzle_pool
            .record_success_checked(height, &self.local_wallet, solution.output)?;

        let proof = PorPuzzleProof::from_solution(&solution);

        let validator_local = proof.validator.eq_ignore_ascii_case(&self.local_wallet);
        let height_match = proof.height == height;
        let prev_match = proof.prev_block_hash == prev_hash;

        if !validator_local {
            return Err(ErrorDetection::ValidationError {
                message: format!("local puzzle proof validator mismatch at h={}", height),
                tx_id: None,
            });
        }

        if !height_match {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "local puzzle proof height mismatch: proof.height={} expected={}",
                    proof.height, height
                ),
                tx_id: None,
            });
        }

        if !prev_match {
            return Err(ErrorDetection::ValidationError {
                message: format!("local puzzle proof prev_hash mismatch at h={}", height),
                tx_id: None,
            });
        }

        self.pending_puzzle_proof = Some(proof.clone());

        tracing::debug!(
            "{} [POR][PUZZLE] h={} solved=true solved_in_ms={} target_delay_s={} local_proof=true",
            Self::runtime_log_timestamp(),
            height,
            solution.solved_in_ms,
            cfg.target_block_time.as_secs(),
        );

        tracing::debug!(
            "{} [POR][PUZZLE][PROOF] staged=true h={} validator_local={} height_match={} prev_match={}",
            Self::runtime_log_timestamp(),
            proof.height,
            validator_local,
            height_match,
            prev_match,
        );

        if cfg.max_local_puzzle_ms > 0 && solution.solved_in_ms > cfg.max_local_puzzle_ms {
            tracing::debug!(
                "{} [POR][PUZZLE][WARN] local puzzle solve exceeded soft cap: solved_ms={} cap_ms={}",
                Self::runtime_log_timestamp(),
                solution.solved_in_ms,
                cfg.max_local_puzzle_ms
            );
        }

        Ok(())
    }

    fn wallet_short(wallet: &str) -> String {
        let wallet = wallet.trim();
        let chars: Vec<char> = wallet.chars().collect();

        if chars.len() <= 18 {
            return wallet.to_string();
        }

        let prefix: String = chars.iter().take(10).collect();
        let mut suffix_chars: Vec<char> = chars.iter().rev().take(8).copied().collect();
        suffix_chars.reverse();
        let suffix: String = suffix_chars.into_iter().collect();

        format!("{prefix}...{suffix}")
    }

    fn hash_short(hash: &[u8; 64]) -> String {
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

    #[inline]
    fn now_unix() -> Result<u64, ErrorDetection> {
        TimePolicy::now_unix_secs_runtime()
    }

    /// Runtime-only UTC display timestamp for operator logs.
    #[inline]
    fn runtime_log_timestamp() -> String {
        match Self::now_unix() {
            Ok(now_unix) => {
                let Some(now_i64) = i64::try_from(now_unix).ok() else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(_) => "time_unavailable".to_string(),
        }
    }
}
