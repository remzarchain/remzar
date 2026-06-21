//! p2p_002_sync_handlers

use super::p2p_001_sync_builders::{
    MAX_MULTIADDR_BYTES, MAX_RETRIES, P2pSync, RemzarHashBytes, ZERO_HASH_64,
    exceeds_consensus_cap, log_consensus_drop, usize_to_u64_saturating,
};
use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::blockchain_001_builder::BlockchainBuilder;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::network::p2p_006_reqresp::{BlockTxRequest, BlockTxResponse};
use crate::network::p2p_018_last_resort_guards::{LastResortDecision, LastResortDrop};
use crate::reorganization::reorg_001_block_index::ReorgBlockIndex;
use crate::reorganization::reorg_002_chain_view::ReorgChainView;
use crate::reorganization::reorg_004_batch_index::ReorgBatchIndex;
use crate::reorganization::reorg_005_fork_choice::ForkAction;
use crate::reorganization::reorg_007_branch_hydration::HydrationReason;
use crate::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::time_policy::TimePolicy;
use libp2p::{Multiaddr, PeerId, request_response::OutboundRequestId, swarm::Swarm};
use std::{
    collections::HashSet,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Instant,
};

pub(super) struct BatchTxResponseContext {
    pub(super) origin_peer: PeerId,
    pub(super) idx: u64,
    pub(super) expected_block_hash: Option<RemzarHashBytes>,
    pub(super) retries_left: u8,
}

/* ─────────────────────────────────────────────────────────────
Live sync-handler guardrails
───────────────────────────────────────────────────────────── */

/// Limit how much branch-hydration work one swarm tick can issue.
const MAX_HYDRATION_REQUESTS_PER_TICK: usize = 8;

/// Bound retry peer scans over the gossip peer set.
const MAX_RETRY_PEER_SCAN: usize = 128;

/// A block response to a GetBlockByIndex request must match the requested index.
const BLOCK_INDEX_MISMATCH_BADNESS: i32 = 15;

/// Bad batch/block payloads are more serious than a transient NotFound.
const MALFORMED_RESPONSE_BADNESS: i32 = 5;

impl P2pSync {
    fn canonical_block_at_height(&self, height: u64) -> Option<Block> {
        self.db.get_block_by_index(height).ok().flatten()
    }

    fn is_same_canonical_block(&self, block: &Block) -> bool {
        self.canonical_block_at_height(block.metadata.index)
            .map(|existing| existing.block_hash == block.block_hash)
            .unwrap_or(false)
    }

    fn has_reorg_parent_meta(&self, block: &Block) -> bool {
        if block.metadata.index == 0 || block.metadata.previous_hash == ZERO_HASH_64 {
            return true;
        }

        let block_index = ReorgBlockIndex::new(std::sync::Arc::clone(&self.db));
        block_index
            .has_meta(&block.metadata.previous_hash)
            .unwrap_or(false)
    }

    fn has_reorg_block_and_meta(&self, hash: &RemzarHashBytes) -> bool {
        let block_index = ReorgBlockIndex::new(std::sync::Arc::clone(&self.db));
        let has_block = block_index.has_block(hash);
        let has_meta = block_index.has_meta(hash).unwrap_or(false);
        has_block && has_meta
    }

    fn has_reorg_batch_for_block_hash(&self, hash: &RemzarHashBytes) -> bool {
        let batch_index = ReorgBatchIndex::new(std::sync::Arc::clone(&self.db));
        batch_index
            .get_batch_by_block_hash(hash)
            .ok()
            .flatten()
            .is_some()
    }

    fn block_for_batch_response(
        &self,
        idx: u64,
        expected_block_hash: Option<RemzarHashBytes>,
    ) -> Option<Block> {
        match expected_block_hash {
            Some(hash) => self.db.get_block_by_hash(&hash),
            None => self.db.get_block_by_index(idx).ok().flatten(),
        }
    }

    fn replay_buffered_puzzle_proofs_for_parent_if_known(
        &mut self,
        parent_hash: RemzarHashBytes,
        miner: &mut Option<&mut BlockchainBuilder>,
    ) {
        let Some(miner) = miner.as_deref_mut() else {
            return;
        };

        let admitted = miner
            .consensus_mut()
            .replay_buffered_puzzle_proofs_for_parent(parent_hash);

        let _ = admitted;
    }

    fn pick_known_hydration_peer(&self) -> Option<PeerId> {
        self.pq_ready_peers
            .iter()
            .copied()
            .next()
            .or_else(|| self.admitted_peers.iter().copied().next())
    }

    fn preserve_missing_block_sync_target(&mut self, idx: u64) {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        let target = self
            .sync_target
            .max(self.queued_sync_target.unwrap_or(0))
            .max(idx)
            .max(local_tip);

        self.sync_target = target;
        self.downloaded = local_tip;
        self.total_to_download = target;

        if idx > local_tip {
            self.queued_sync_target = Some(target);
            self.syncing = true;
            self.has_synced = false;
        }
    }

    #[inline]
    fn retry_block_if_possible(&mut self, origin_peer: PeerId, idx: u64, retries_left: u8) {
        if retries_left > 0 {
            self.push_block_retry(origin_peer, idx, retries_left.saturating_sub(1));
        }
    }

    #[inline]
    fn retry_batch_if_possible(
        &mut self,
        origin_peer: PeerId,
        idx: u64,
        retries_left: u8,
        expected_block_hash: Option<RemzarHashBytes>,
        applied_height: u64,
    ) {
        if retries_left > 0 && (expected_block_hash.is_some() || idx > applied_height) {
            self.push_batch_retry(origin_peer, idx, retries_left.saturating_sub(1));
        }
    }

    #[inline]
    fn report_malformed_response(&mut self, origin_peer: PeerId, badness: i32) {
        self.last_resort
            .report_misbehavior(Instant::now(), origin_peer, badness);
    }

    fn pick_notfound_retry_peer(
        &self,
        swarm: &Swarm<RemzarBehaviour>,
        failed_peer: PeerId,
        idx: u64,
    ) -> Option<PeerId> {
        // First choice: a different connected PQ-ready gossip peer that is not
        // already serving the same block index.
        swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .map(|(peer, _)| *peer)
            .filter(|peer| *peer != failed_peer)
            .filter(|peer| swarm.is_connected(peer))
            .filter(|peer| self.is_pq_ready(peer))
            .find(|peer| {
                !self
                    .pending_blocks
                    .values()
                    .any(|(pending_peer, pending_idx, _)| {
                        *pending_peer == *peer && *pending_idx == idx
                    })
            })
            // Second choice: any different connected peer.
            // issue_block_request_if_absent / PQ gate will still protect the actual send path.
            .or_else(|| {
                swarm
                    .behaviour()
                    .gossipsub
                    .all_peers()
                    .map(|(peer, _)| *peer)
                    .filter(|peer| *peer != failed_peer)
                    .find(|peer| swarm.is_connected(peer))
            })
    }

    fn branch_hydration_active(&self) -> bool {
        self.branch_hydration.tracked_len() > 0 || self.branch_hydration.inflight_len() > 0
    }

    fn publish_runtime_proposal_safety_to_miner(
        &self,
        miner: &mut Option<&mut BlockchainBuilder>,
        catchup_active: bool,
        catchup_reason: Option<String>,
    ) {
        let hydration_active = self.branch_hydration_active();
        let tip_height = self.db.get_tip_height().unwrap_or(0);
        let tip_hash = self
            .canonical_hash_at_height(tip_height)
            .unwrap_or(ZERO_HASH_64);

        if let Some(m) = miner.as_deref_mut() {
            let consensus = m.consensus_mut();
            consensus.set_runtime_rejoin_catchup_gate(catchup_active, catchup_reason);
            consensus.set_runtime_branch_hydration_active(hydration_active);

            if tip_height == 0 || tip_hash != ZERO_HASH_64 {
                consensus.set_runtime_canonical_tip_context(tip_height, tip_hash);
            }
        }
    }

    fn note_miner_validator_state_aligned_to_current_tip(
        &self,
        miner: &mut Option<&mut BlockchainBuilder>,
    ) {
        let tip_height = self.db.get_tip_height().unwrap_or(0);
        let tip_hash = self
            .canonical_hash_at_height(tip_height)
            .unwrap_or(ZERO_HASH_64);

        if let Some(m) = miner.as_deref_mut() {
            let consensus = m.consensus_mut();
            consensus.note_validator_state_rebuilt_to_tip(tip_height);

            if tip_height == 0 || tip_hash != ZERO_HASH_64 {
                consensus.set_runtime_canonical_tip_context(tip_height, tip_hash);
            }
        }
    }

    fn maybe_reset_miner_proposal_safety(&self, miner: &mut Option<&mut BlockchainBuilder>) {
        if !self.has_synced || self.syncing || self.branch_hydration_active() {
            return;
        }

        let tip_height = self.db.get_tip_height().unwrap_or(0);
        let tip_hash = self
            .canonical_hash_at_height(tip_height)
            .unwrap_or(ZERO_HASH_64);

        if tip_height > 0 && tip_hash == ZERO_HASH_64 {
            return;
        }

        if let Some(m) = miner.as_deref_mut() {
            m.consensus_mut()
                .reset_runtime_proposal_safety_state(tip_height, tip_hash);
        }
    }

    /// Refresh runtime sync pointers from the canonical chain view after a reorg
    /// may have changed the active tip underneath the sync loop.
    fn refresh_sync_tracking_from_canonical_view(&mut self) {
        let chain_view = ReorgChainView::new(std::sync::Arc::clone(&self.db));

        if let Ok(Some(view)) = chain_view.get_tip_with_legacy_fallback() {
            self.last_synced_index = Some(view.tip_height);
            self.last_synced_hash = Some(view.tip_hash);
            self.downloaded = view.tip_height;
            self.total_to_download = self.sync_target.max(view.tip_height);
        }

        self.update_sync_pointers();
        self.update_sync_state();
    }

    fn handle_competing_block_with_reorg_manager(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        origin_peer: PeerId,
        block: &Block,
        retries_left: u8,
        miner: &mut Option<&mut BlockchainBuilder>,
    ) {
        self.publish_runtime_proposal_safety_to_miner(
            miner,
            true,
            Some("competing branch handling in progress".to_string()),
        );

        if !self.has_reorg_batch_for_block_hash(&block.block_hash) {
            let issued = self.issue_batch_request_by_hash_if_absent(
                swarm,
                origin_peer,
                block.metadata.index,
                block.block_hash,
                retries_left,
            );

            let _ = issued;

            self.syncing = true;
            self.update_sync_state();
            return;
        }

        match self
            .reorg_manager
            .handle_new_block(block, &mut self.chain, miner.as_deref_mut())
        {
            Ok(ForkAction::Stay) => {
                self.syncing = true;
                self.refresh_sync_tracking_from_canonical_view();
                self.note_miner_validator_state_aligned_to_current_tip(miner);
                self.publish_runtime_proposal_safety_to_miner(
                    miner,
                    !self.has_synced || self.syncing,
                    Some(
                        "competing block evaluated; canonical tip unchanged during recovery"
                            .to_string(),
                    ),
                );
                self.maybe_reset_miner_proposal_safety(miner);
            }
            Ok(ForkAction::Reorg(_plan)) => {
                self.syncing = true;
                self.refresh_sync_tracking_from_canonical_view();
                self.note_miner_validator_state_aligned_to_current_tip(miner);
                self.publish_runtime_proposal_safety_to_miner(
                    miner,
                    !self.has_synced || self.syncing,
                    Some(
                        "reorg applied from competing branch; validator state rebuilt before proposal resume".to_string(),
                    ),
                );
                self.maybe_reset_miner_proposal_safety(miner);
                self.request_next_block(swarm, origin_peer);
            }
            Ok(ForkAction::NeedMoreData {
                missing_hash,
                context,
            }) => {
                self.queue_branch_hydration_by_hash(
                    origin_peer,
                    missing_hash,
                    block.metadata.index.checked_sub(1),
                    HydrationReason::ForkChoiceNeedMoreData,
                    context,
                );
                self.branch_hydration
                    .note_child_waiting_on_parent(missing_hash, block.block_hash);
                self.drive_branch_hydration_requests(swarm);
                self.syncing = true;
                self.refresh_sync_tracking_from_canonical_view();
                self.publish_runtime_proposal_safety_to_miner(
                    miner,
                    true,
                    Some("branch hydration required before fork choice can complete".to_string()),
                );
            }
            Err(_e) => {
                self.queue_branch_hydration(origin_peer, block, retries_left);
                self.drive_branch_hydration_requests(swarm);
                self.syncing = true;
                self.refresh_sync_tracking_from_canonical_view();
                self.publish_runtime_proposal_safety_to_miner(
                    miner,
                    true,
                    Some(
                        "hydration retry queued after competing-branch reorg-manager failure"
                            .to_string(),
                    ),
                );
            }
        }
    }

    fn queue_branch_hydration(&mut self, origin_peer: PeerId, block: &Block, retries_left: u8) {
        if retries_left > 0 {
            let next_retries = retries_left.saturating_sub(1);
            self.push_block_retry(origin_peer, block.metadata.index, next_retries);
        }

        if block.metadata.index > 0 {
            self.push_block_retry(
                origin_peer,
                block.metadata.index.saturating_sub(1),
                MAX_RETRIES,
            );
        }

        if block.metadata.index > 0 && block.metadata.previous_hash != ZERO_HASH_64 {
            self.branch_hydration.note_need_more_data(
                origin_peer,
                block.metadata.previous_hash,
                block.metadata.index.checked_sub(1),
                HydrationReason::MissingParent,
                "competing block parent metadata missing during sync",
            );
            self.branch_hydration
                .note_child_waiting_on_parent(block.metadata.previous_hash, block.block_hash);
        }
    }

    fn queue_branch_hydration_by_hash(
        &mut self,
        origin_peer: PeerId,
        missing_hash: RemzarHashBytes,
        source_height: Option<u64>,
        reason: HydrationReason,
        context: &'static str,
    ) {
        self.branch_hydration.note_need_more_data(
            origin_peer,
            missing_hash,
            source_height,
            reason,
            context,
        );
    }

    pub(super) fn drive_branch_hydration_requests(&mut self, swarm: &mut Swarm<RemzarBehaviour>) {
        for _ in 0..MAX_HYDRATION_REQUESTS_PER_TICK {
            let Some((peer, hash)) = self.branch_hydration.next_request() else {
                break;
            };

            if !swarm.is_connected(&peer) {
                continue;
            }

            if !self.is_pq_ready(&peer) {
                continue;
            }

            let req_id = swarm
                .behaviour_mut()
                .blocktx
                .send_request(&peer, BlockTxRequest::GetBlock { hash });

            self.branch_hydration.mark_issued(req_id, hash);
        }
    }

    fn log_reorg_ingest_state(&self, block: &Block) {
        let block_index = ReorgBlockIndex::new(std::sync::Arc::clone(&self.db));

        let this_has_block = block_index.has_block(&block.block_hash);
        let this_has_meta = block_index.has_meta(&block.block_hash).unwrap_or(false);
        let parent_has_block = block_index.has_block(&block.metadata.previous_hash);
        let parent_has_meta = block_index
            .has_meta(&block.metadata.previous_hash)
            .unwrap_or(false);

        let _ = (
            this_has_block,
            this_has_meta,
            parent_has_block,
            parent_has_meta,
        );
    }

    fn persist_sync_block_into_reorg_graph(&self, block: &Block) -> Result<(), ErrorDetection> {
        let block_index = ReorgBlockIndex::new(std::sync::Arc::clone(&self.db));

        let (cumulative_score, status) = match block_index
            .get_meta(&block.metadata.previous_hash)?
        {
            Some(parent_meta) => (
                parent_meta.cumulative_score.saturating_add(1),
                ForkBlockStatus::Validated,
            ),
            None if block.metadata.index == 0 || block.metadata.previous_hash == ZERO_HASH_64 => {
                (0u128, ForkBlockStatus::Validated)
            }
            None => (block.metadata.index as u128, ForkBlockStatus::Orphan),
        };

        let received_at_unix_secs = TimePolicy::now_unix_secs_runtime()?;

        let meta = ForkBlockMeta {
            parent_hash: block.metadata.previous_hash,
            height: block.metadata.index,
            cumulative_score,
            status,
            received_at_unix_secs,
        };

        block_index.put_block_and_meta(block, &meta)
    }

    fn persist_sync_batch_into_reorg_graph(
        &self,
        header: &Block,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        let block_index = ReorgBlockIndex::new(std::sync::Arc::clone(&self.db));
        let chain_view = ReorgChainView::new(std::sync::Arc::clone(&self.db));
        let batch_index = ReorgBatchIndex::new(std::sync::Arc::clone(&self.db));

        batch_index.put_batch_by_block_hash(&header.block_hash, batch_bytes)?;

        let prior_tip = chain_view.get_tip_with_legacy_fallback()?;
        let extends_old_canonical_tip = match prior_tip {
            Some(view) => {
                header.metadata.previous_hash == view.tip_hash
                    && header.metadata.index == view.tip_height.saturating_add(1)
            }
            None => header.metadata.index == 0 || header.metadata.previous_hash == ZERO_HASH_64,
        };

        if extends_old_canonical_tip {
            chain_view.set_hash_at_height(header.metadata.index, &header.block_hash)?;
            block_index.mark_canonical(&header.block_hash)?;
            chain_view.set_tip(&header.block_hash, header.metadata.index)?;
            batch_index.set_canonical_batch_at_height(header.metadata.index, batch_bytes)?;
        } else {
            block_index.mark_side_branch(&header.block_hash)?;
        }

        Ok(())
    }

    pub(super) fn handle_batch_tx_response(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        ctx: BatchTxResponseContext,
        response: BlockTxResponse,
        mut miner: Option<&mut BlockchainBuilder>,
    ) {
        let BatchTxResponseContext {
            origin_peer,
            idx,
            expected_block_hash,
            retries_left,
        } = ctx;

        self.publish_runtime_proposal_safety_to_miner(
            &mut miner,
            true,
            Some("sync batch response processing in progress".to_string()),
        );

        match response {
            BlockTxResponse::BatchData(batch_bytes) => {
                if exceeds_consensus_cap(batch_bytes.len()) {
                    log_consensus_drop("BatchData", idx, &origin_peer, batch_bytes.len());
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 2);

                    let applied = self.db.get_addr_index_height().unwrap_or(0);
                    if retries_left > 0 && (expected_block_hash.is_some() || idx > applied) {
                        let next_retries = retries_left.saturating_sub(1);
                        self.push_batch_retry(origin_peer, idx, next_retries);
                    }
                    return;
                }

                let now = Instant::now();
                match self.last_resort.check_bytes(
                    now,
                    origin_peer,
                    usize_to_u64_saturating(batch_bytes.len()),
                ) {
                    LastResortDecision::Allow => {}
                    LastResortDecision::Drop(drop) => {
                        self.handle_last_resort_drop(
                            swarm,
                            origin_peer,
                            drop,
                            "BlockTx(Response::BatchData)",
                        );

                        let applied = self.db.get_addr_index_height().unwrap_or(0);
                        if retries_left > 0 && (expected_block_hash.is_some() || idx > applied) {
                            let next_retries = retries_left.saturating_sub(1);
                            self.push_batch_retry(origin_peer, idx, next_retries);
                        }
                        return;
                    }
                }

                let canonical_mode = expected_block_hash.is_none();
                let applied = self.db.get_addr_index_height().unwrap_or(0);

                if canonical_mode && idx <= applied {
                    return;
                }

                let header = match self.block_for_batch_response(idx, expected_block_hash) {
                    Some(b) => b,
                    None => {
                        self.syncing = false;
                        return;
                    }
                };

                let batch = match catch_unwind(AssertUnwindSafe(|| {
                    TransactionBatch::deserialize(&batch_bytes)
                })) {
                    Ok(Ok(b)) => b,
                    Ok(Err(_)) | Err(_) => {
                        self.report_malformed_response(origin_peer, MALFORMED_RESPONSE_BADNESS);
                        self.retry_batch_if_possible(
                            origin_peer,
                            idx,
                            retries_left,
                            expected_block_hash,
                            applied,
                        );
                        return;
                    }
                };

                let computed_root =
                    match catch_unwind(AssertUnwindSafe(|| batch.compute_merkle_root())) {
                        Ok(Ok(r)) => r,
                        Ok(Err(_)) | Err(_) => {
                            self.report_malformed_response(origin_peer, MALFORMED_RESPONSE_BADNESS);
                            self.retry_batch_if_possible(
                                origin_peer,
                                idx,
                                retries_left,
                                expected_block_hash,
                                applied,
                            );
                            return;
                        }
                    };

                if header.metadata.merkle_root != computed_root {
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 25);

                    if canonical_mode {
                        _ = self.db.delete(
                            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                            format!("tx_batch_{:010}", idx).as_bytes(),
                        );
                    }

                    if retries_left > 0 && (expected_block_hash.is_some() || idx > applied) {
                        let next_retries = retries_left.saturating_sub(1);
                        self.push_batch_retry(origin_peer, idx, next_retries);
                    }
                    return;
                }

                // Canonical straight-line sync:
                // apply directly to the live chain, then persist both canonical and hash-keyed views.
                if canonical_mode {
                    if let Err(_e) = self.db.store_batch_bytes(idx, &batch_bytes) {
                        if retries_left > 0 && idx > applied {
                            let next_retries = retries_left.saturating_sub(1);
                            self.push_batch_retry(origin_peer, idx, next_retries);
                        }
                        return;
                    }

                    if let Err(_e) = self.chain.apply_batch(&batch) {
                        if retries_left > 0 && idx > applied {
                            let next_retries = retries_left.saturating_sub(1);
                            self.push_batch_retry(origin_peer, idx, next_retries);
                        }
                        return;
                    }

                    if let Err(_e) = self.chain.commit() {
                        if retries_left > 0 && idx > applied {
                            let next_retries = retries_left.saturating_sub(1);
                            self.push_batch_retry(origin_peer, idx, next_retries);
                        }
                        return;
                    }

                    _ = self.chain.flush_balances();

                    if let Some(m) = miner.as_deref_mut() {
                        match m.validator_state_mut().apply_block(&header, &batch) {
                            Ok(()) => {
                                m.consensus_mut().note_validator_state_rebuilt_to_tip(idx);
                                m.consensus_mut()
                                    .set_runtime_canonical_tip_context(idx, header.block_hash);
                            }
                            Err(_e) => {}
                        }
                    }

                    if let Err(_e) = self.mempool.remove_transactions_in_batch(&batch) {}

                    if let Err(_e) = self.persist_sync_batch_into_reorg_graph(&header, &batch_bytes)
                    {
                    }

                    self.last_synced_index = Some(idx);
                    self.last_synced_hash = Some(header.block_hash);
                    self.downloaded = idx;
                    self.total_to_download = self.sync_target;
                    _ = self.db.set_latest_block_index(idx);
                    _ = self.db.set_tip_height(idx);
                    _ = self.db.set_addr_index_height(idx);

                    match self.reorg_manager.handle_new_block(
                        &header,
                        &mut self.chain,
                        miner.as_deref_mut(),
                    ) {
                        Ok(ForkAction::Stay) => {
                            self.note_miner_validator_state_aligned_to_current_tip(&mut miner);
                        }
                        Ok(ForkAction::Reorg(_)) => {
                            self.update_sync_pointers();
                            self.note_miner_validator_state_aligned_to_current_tip(&mut miner);
                        }
                        Ok(ForkAction::NeedMoreData {
                            missing_hash,
                            context,
                        }) => {
                            self.queue_branch_hydration_by_hash(
                                origin_peer,
                                missing_hash,
                                idx.checked_sub(1),
                                HydrationReason::ForkChoiceNeedMoreData,
                                context,
                            );
                            self.drive_branch_hydration_requests(swarm);
                            self.publish_runtime_proposal_safety_to_miner(
                                &mut miner,
                                true,
                                Some(
                                    "fork-choice needs more data during canonical sync".to_string(),
                                ),
                            );
                        }
                        Err(_e) => {}
                    }

                    self.update_sync_state();
                    self.publish_runtime_proposal_safety_to_miner(
                        &mut miner,
                        !self.has_synced || self.syncing,
                        Some("canonical sync progress update".to_string()),
                    );
                    self.maybe_reset_miner_proposal_safety(&mut miner);
                    self.request_next_block(swarm, origin_peer);
                    return;
                }

                // Competing-branch batch-by-hash hydration:
                // do NOT apply directly to the live canonical chain here.
                if let Err(_e) = self.persist_sync_batch_into_reorg_graph(&header, &batch_bytes) {
                    if retries_left > 0 {
                        let next_retries = retries_left.saturating_sub(1);
                        self.push_batch_retry(origin_peer, idx, next_retries);
                    }
                    return;
                }

                self.handle_competing_block_with_reorg_manager(
                    swarm,
                    origin_peer,
                    &header,
                    retries_left,
                    &mut miner,
                );
            }

            BlockTxResponse::NotFound => {
                let applied = self.db.get_addr_index_height().unwrap_or(0);
                if retries_left > 0 && (expected_block_hash.is_some() || idx > applied) {
                    let next_retries = retries_left.saturating_sub(1);
                    self.push_batch_retry(origin_peer, idx, next_retries);
                }
            }

            _ => {}
        }

        self.update_sync_state();
        self.publish_runtime_proposal_safety_to_miner(
            &mut miner,
            !self.has_synced || self.syncing,
            Some("batch response processing complete".to_string()),
        );
        self.maybe_reset_miner_proposal_safety(&mut miner);
    }

    pub(super) fn handle_block_tx_response(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        origin_peer: PeerId,
        idx: u64,
        retries_left: u8,
        response: BlockTxResponse,
        mut miner: Option<&mut BlockchainBuilder>,
    ) {
        self.update_sync_pointers();
        self.publish_runtime_proposal_safety_to_miner(
            &mut miner,
            true,
            Some("sync block response processing in progress".to_string()),
        );

        let tip_height = self.db.get_tip_height().unwrap_or(0);
        let _ = tip_height;

        match response {
            BlockTxResponse::BlockData(block) => {
                if block.metadata.index != idx {
                    self.report_malformed_response(origin_peer, BLOCK_INDEX_MISMATCH_BADNESS);
                    self.retry_block_if_possible(origin_peer, idx, retries_left);
                    return;
                }

                let canonical_bytes =
                    match catch_unwind(AssertUnwindSafe(|| block.serialize_for_storage())) {
                        Ok(Ok(b)) => b,
                        Ok(Err(_)) | Err(_) => {
                            self.report_malformed_response(origin_peer, MALFORMED_RESPONSE_BADNESS);
                            self.retry_block_if_possible(origin_peer, idx, retries_left);
                            return;
                        }
                    };

                if exceeds_consensus_cap(canonical_bytes.len()) {
                    log_consensus_drop(
                        "BlockData(canonical)",
                        idx,
                        &origin_peer,
                        canonical_bytes.len(),
                    );
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 2);
                    if retries_left > 0 {
                        let next_retries = retries_left.saturating_sub(1);
                        self.push_block_retry(origin_peer, idx, next_retries);
                    }
                    return;
                }

                let now = Instant::now();
                match self.last_resort.check_bytes(
                    now,
                    origin_peer,
                    usize_to_u64_saturating(canonical_bytes.len()),
                ) {
                    LastResortDecision::Allow => {}
                    LastResortDecision::Drop(drop) => {
                        self.handle_last_resort_drop(
                            swarm,
                            origin_peer,
                            drop,
                            "BlockTx(Response::BlockData)",
                        );
                        if retries_left > 0 {
                            let next_retries = retries_left.saturating_sub(1);
                            self.push_block_retry(origin_peer, idx, next_retries);
                        }
                        return;
                    }
                }

                if idx == 0 {
                    match self.db.get_block_by_index(0).ok().flatten() {
                        Some(existing_block) if existing_block.block_hash == block.block_hash => {
                            self.replay_buffered_puzzle_proofs_for_parent_if_known(
                                existing_block.block_hash,
                                &mut miner,
                            );

                            if self.last_synced_index.is_none() {
                                self.last_synced_index = Some(0);
                                self.last_synced_hash = Some(existing_block.block_hash);
                            }

                            self.request_next_block(swarm, origin_peer);
                            return;
                        }
                        Some(_) => {
                            self.syncing = false;
                            return;
                        }
                        None => {}
                    }

                    if block.metadata.index != 0 || block.metadata.previous_hash != ZERO_HASH_64 {
                        self.syncing = false;
                        return;
                    }

                    let got_hash = block.hash_hex();
                    match &self.expected_genesis_hash {
                        Some(exp) if &got_hash != exp => {
                            self.syncing = false;
                            return;
                        }
                        _ => {}
                    }

                    match catch_unwind(AssertUnwindSafe(|| block.validate(Some(0)))) {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) | Err(_) => {
                            self.report_malformed_response(origin_peer, MALFORMED_RESPONSE_BADNESS);
                            self.syncing = false;
                            return;
                        }
                    }

                    if self.chain.add_block((*block).clone()).is_err()
                        || self.chain.commit().is_err()
                    {
                        self.syncing = false;
                        return;
                    }

                    _ = self
                        .db
                        .store_latest_block(&canonical_bytes, block.metadata.index);
                    _ = self
                        .db
                        .index_block_by_hash(&block.block_hash, &canonical_bytes);
                    _ = self.db.set_latest_block_index(block.metadata.index);
                    _ = self.db.set_tip_height(0);
                    _ = self.db.set_addr_index_height(0);

                    self.replay_buffered_puzzle_proofs_for_parent_if_known(
                        block.block_hash,
                        &mut miner,
                    );

                    if let Err(_e) = self.persist_sync_block_into_reorg_graph(&block) {
                    } else {
                        let block_index = ReorgBlockIndex::new(std::sync::Arc::clone(&self.db));
                        let chain_view = ReorgChainView::new(std::sync::Arc::clone(&self.db));
                        _ = block_index.mark_canonical(&block.block_hash);
                        _ = chain_view.set_hash_at_height(0, &block.block_hash);
                        _ = chain_view.set_tip(&block.block_hash, 0);
                    }

                    self.last_synced_index = Some(0);
                    self.last_synced_hash = Some(block.block_hash);
                    self.downloaded = 0;
                    self.total_to_download = self.sync_target;

                    self.request_next_block(swarm, origin_peer);
                    return;
                }

                let current_tip = self.db.get_tip_height().unwrap_or(0);
                if idx <= current_tip && self.is_same_canonical_block(&block) {
                    self.replay_buffered_puzzle_proofs_for_parent_if_known(
                        block.block_hash,
                        &mut miner,
                    );

                    return;
                }

                match catch_unwind(AssertUnwindSafe(|| block.validate(None))) {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => {
                        self.report_malformed_response(origin_peer, 25);
                        self.syncing = false;
                        return;
                    }
                }

                drop(self.persist_sync_block_into_reorg_graph(&block));

                let expected_idx = self.last_synced_index.unwrap_or(0).saturating_add(1);
                let expected_prev = match self.expected_prev() {
                    Ok(h) => h,
                    Err(_e) => {
                        self.syncing = false;
                        return;
                    }
                };

                if block.metadata.index != expected_idx
                    || block.metadata.previous_hash != expected_prev
                {
                    _ = self
                        .db
                        .index_block_by_hash(&block.block_hash, &canonical_bytes);

                    self.replay_buffered_puzzle_proofs_for_parent_if_known(
                        block.block_hash,
                        &mut miner,
                    );

                    self.log_reorg_ingest_state(&block);

                    if !self.has_reorg_parent_meta(&block) {
                        self.queue_branch_hydration(origin_peer, &block, retries_left);
                        self.drive_branch_hydration_requests(swarm);
                        self.syncing = true;
                        self.update_sync_state();
                        self.publish_runtime_proposal_safety_to_miner(
                            &mut miner,
                            true,
                            Some("parent hydration queued for competing block".to_string()),
                        );
                        return;
                    }

                    if !self.has_reorg_block_and_meta(&block.block_hash) {
                        self.queue_branch_hydration(origin_peer, &block, retries_left);
                        self.drive_branch_hydration_requests(swarm);
                        self.syncing = true;
                        self.update_sync_state();
                        self.publish_runtime_proposal_safety_to_miner(
                            &mut miner,
                            true,
                            Some("competing block hydration retry queued".to_string()),
                        );
                        return;
                    }

                    self.handle_competing_block_with_reorg_manager(
                        swarm,
                        origin_peer,
                        &block,
                        retries_left,
                        &mut miner,
                    );
                    return;
                }

                if self.chain.add_block((*block).clone()).is_err() || self.chain.commit().is_err() {
                    self.syncing = false;
                    return;
                }

                _ = self
                    .db
                    .store_latest_block(&canonical_bytes, block.metadata.index);
                _ = self
                    .db
                    .index_block_by_hash(&block.block_hash, &canonical_bytes);

                self.replay_buffered_puzzle_proofs_for_parent_if_known(
                    block.block_hash,
                    &mut miner,
                );

                let issued =
                    self.issue_batch_request_if_absent(swarm, origin_peer, idx, MAX_RETRIES);

                let _ = issued;

                self.note_miner_validator_state_aligned_to_current_tip(&mut miner);
            }

            BlockTxResponse::NotFound => {
                self.preserve_missing_block_sync_target(idx);

                let local_tip = self.db.get_tip_height().unwrap_or(0);

                // If another path already imported the block, continue normal sync.
                if idx <= local_tip || self.db_has_block_index(idx) {
                    self.request_next_block(swarm, origin_peer);
                    return;
                }

                if retries_left > 0 {
                    let next_retries = retries_left.saturating_sub(1);

                    if let Some(retry_peer) =
                        self.pick_notfound_retry_peer(&*swarm, origin_peer, idx)
                    {
                        self.push_block_retry(retry_peer, idx, next_retries);
                    } else if swarm.is_connected(&origin_peer) && self.is_pq_ready(&origin_peer) {
                        self.push_block_retry(origin_peer, idx, next_retries);
                    }

                    self.update_sync_state();
                    return;
                }

                // Retries are exhausted. Do not mark synced. Do not drop the target.
                self.syncing = true;
                self.has_synced = false;
                self.queued_sync_target = Some(
                    self.sync_target
                        .max(self.queued_sync_target.unwrap_or(0))
                        .max(idx)
                        .max(local_tip),
                );

                self.update_sync_state();
                return;
            }

            BlockTxResponse::TxData(_) | BlockTxResponse::BatchData(_) => {
                self.report_malformed_response(origin_peer, MALFORMED_RESPONSE_BADNESS);
                self.retry_block_if_possible(origin_peer, idx, retries_left);
            }
        }

        self.update_sync_state();
        self.publish_runtime_proposal_safety_to_miner(
            &mut miner,
            !self.has_synced || self.syncing,
            Some("block response processing complete".to_string()),
        );
        self.maybe_reset_miner_proposal_safety(&mut miner);
    }

    pub fn handle_fork(
        &mut self,
        new_tip_hash: RemzarHashBytes,
    ) -> std::result::Result<(), String> {
        let block = match self.db.get_block_by_hash(&new_tip_hash) {
            Some(b) => b,
            None => {
                let msg = format!("handle_fork: unknown block hash {:02x?}", new_tip_hash);
                return Err(msg);
            }
        };

        match self
            .reorg_manager
            .handle_new_block(&block, &mut self.chain, None)
        {
            Ok(ForkAction::Stay) => {
                self.refresh_sync_tracking_from_canonical_view();
                Ok(())
            }
            Ok(ForkAction::Reorg(_plan)) => {
                self.refresh_sync_tracking_from_canonical_view();
                Ok(())
            }
            Ok(ForkAction::NeedMoreData {
                missing_hash,
                context,
            }) => {
                let Some(peer) = self.pick_known_hydration_peer() else {
                    return Ok(());
                };

                self.queue_branch_hydration_by_hash(
                    peer,
                    missing_hash,
                    block.metadata.index.checked_sub(1),
                    HydrationReason::ForkChoiceNeedMoreData,
                    context,
                );
                Ok(())
            }
            Err(e) => Err(format!("reorg manager error: {:?}", e)),
        }
    }

    pub(super) fn db_has_block_index(&self, idx: u64) -> bool {
        self.db.get_block_by_index(idx).ok().flatten().is_some()
    }

    pub(super) fn filter_multiaddr_bounds(&self, addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
        let mut seen = HashSet::<Vec<u8>>::new();

        addrs
            .into_iter()
            .filter(|a| {
                let bytes = a.to_vec();
                !bytes.is_empty() && bytes.len() <= MAX_MULTIADDR_BYTES && seen.insert(bytes)
            })
            .collect()
    }

    pub(super) fn handle_last_resort_drop(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        drop: LastResortDrop,
        context: &'static str,
    ) {
        let _ = context;

        let disconnect = matches!(
            drop,
            LastResortDrop::PeerCoolingDown | LastResortDrop::CounterOverflow
        );

        if disconnect {
            self.cleanup_pending_for_peer(&*swarm, peer, false);
            self.clear_pq_peer_state(&peer);
            self.admitted_peers.remove(&peer);
            self.peer_ip.remove(&peer);

            if let Err(_e) = swarm.disconnect_peer_id(peer) {}
        }
    }

    pub(super) fn push_block_retry(&mut self, peer: PeerId, idx: u64, retries_left: u8) {
        let enqueued = self.enqueue_block_retry_if_absent(peer, idx, retries_left);

        let _ = enqueued;
    }

    pub(super) fn push_batch_retry(&mut self, peer: PeerId, idx: u64, retries_left: u8) {
        let enqueued = self.enqueue_batch_retry_if_absent(peer, idx, retries_left);

        let _ = enqueued;
    }

    pub(super) fn pick_retry_peer(
        &self,
        swarm: &Swarm<RemzarBehaviour>,
        exclude: PeerId,
    ) -> Option<PeerId> {
        swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .map(|(p, _)| *p)
            .filter(|p| *p != exclude)
            .filter(|p| swarm.is_connected(p))
            .filter(|p| self.is_pq_ready(p) || self.admitted_peers.contains(p))
            .take(MAX_RETRY_PEER_SCAN)
            .next()
    }

    pub(super) fn cleanup_pending_for_peer(
        &mut self,
        swarm: &Swarm<RemzarBehaviour>,
        peer: PeerId,
        allow_same_peer: bool,
    ) {
        let version_ids: Vec<OutboundRequestId> = self
            .pending_versions
            .iter()
            .filter_map(|(rid, p)| if *p == peer { Some(*rid) } else { None })
            .collect();
        for rid in version_ids {
            _ = self.pending_versions.remove(&rid);
        }

        let block_ids: Vec<OutboundRequestId> = self
            .pending_blocks
            .iter()
            .filter_map(|(rid, (p, _, _))| if *p == peer { Some(*rid) } else { None })
            .collect();
        for rid in block_ids {
            if let Some((origin_peer, idx, retries_left)) = self.pending_blocks.remove(&rid)
                && retries_left > 0
            {
                let next_retries = retries_left.saturating_sub(1);
                let retry_peer = self
                    .pick_retry_peer(swarm, origin_peer)
                    .or(if allow_same_peer {
                        Some(origin_peer)
                    } else {
                        None
                    });

                if let Some(p) = retry_peer {
                    self.push_block_retry(p, idx, next_retries);
                }
            }
        }

        let batch_ids: Vec<OutboundRequestId> = self
            .pending_batches
            .iter()
            .filter_map(|(rid, req)| if req.peer == peer { Some(*rid) } else { None })
            .collect();
        for rid in batch_ids {
            if let Some(req) = self.pending_batches.remove(&rid) {
                let applied = self.db.get_addr_index_height().unwrap_or(0);
                if req.retries_left > 0 && (req.expected_block_hash.is_some() || req.idx > applied)
                {
                    let next_retries = req.retries_left.saturating_sub(1);
                    let retry_peer = self
                        .pick_retry_peer(swarm, req.peer)
                        .or(if allow_same_peer {
                            Some(req.peer)
                        } else {
                            None
                        });

                    if let Some(p) = retry_peer {
                        self.push_batch_retry(p, req.idx, next_retries);
                    }
                }
            }
        }

        self.branch_hydration.on_peer_disconnected(peer);
    }
}
