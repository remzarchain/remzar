//! src/network/p2p_sync_007_helper.rs

use super::p2p_001_sync_builders::{
    MAX_BATCH_QUEUE, MAX_BLOCK_QUEUE, MAX_PENDING_BATCHES, MAX_PENDING_BLOCKS, P2pSync,
    PendingBatchRequest, RemzarHashBytes,
};
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::network::p2p_006_reqresp::BlockTxRequest;
use libp2p::{PeerId, request_response::OutboundRequestId, swarm::Swarm};

impl P2pSync {
    #[inline(always)]
    pub(super) fn is_block_idx_reserved(&self, idx: u64) -> bool {
        self.reserved_block_indices.contains(&idx)
    }

    /// True if this batch index is currently reserved for an outbound send.
    #[inline(always)]
    pub(super) fn is_batch_idx_reserved(&self, idx: u64) -> bool {
        self.reserved_batch_indices.contains(&idx)
    }

    /// True if this block index is already in-flight, reserved, or queued.
    #[inline(always)]
    pub(super) fn is_block_idx_in_flight_or_reserved_or_queued(&self, idx: u64) -> bool {
        self.is_block_idx_reserved(idx)
            || self.pending_blocks.values().any(|(_, i, _)| *i == idx)
            || self.block_queue.iter().any(|(_, i, _)| *i == idx)
    }

    /// True if this batch index is already in-flight, reserved, or queued.
    #[inline(always)]
    pub(super) fn is_batch_idx_in_flight_or_reserved_or_queued(&self, idx: u64) -> bool {
        self.is_batch_idx_reserved(idx)
            || self.pending_batches.values().any(|req| req.idx == idx)
            || self.batch_queue.iter().any(|(_, i, _)| *i == idx)
    }

    // ============================================================
    // ADMISSION CHECKS
    // ============================================================

    #[inline(always)]
    pub(super) fn can_request_block_idx(&self, idx: u64) -> bool {
        if self.db_has_block_index(idx) {
            return false;
        }

        if self.pending_blocks.len() >= MAX_PENDING_BLOCKS {
            return false;
        }

        !self.is_block_idx_in_flight_or_reserved_or_queued(idx)
    }

    /// Batch request may be sent only if:
    #[inline(always)]
    pub(super) fn can_request_batch_idx(&self, idx: u64) -> bool {
        let applied = self.db.get_addr_index_height().unwrap_or(0);
        if idx <= applied {
            return false;
        }

        if self.pending_batches.len() >= MAX_PENDING_BATCHES {
            return false;
        }

        !self.is_batch_idx_in_flight_or_reserved_or_queued(idx)
    }

    // ============================================================
    // RESERVATION LAYER
    // ============================================================

    pub(super) fn reserve_block_idx_for_request(&mut self, idx: u64) -> bool {
        if !self.can_request_block_idx(idx) {
            return false;
        }

        self.reserved_block_indices.insert(idx)
    }

    /// Reserve a batch index for immediate outbound request issuance.
    pub(super) fn reserve_batch_idx_for_request(&mut self, idx: u64) -> bool {
        if !self.can_request_batch_idx(idx) {
            return false;
        }

        self.reserved_batch_indices.insert(idx)
    }

    /// Finalize a successful block request issue by moving the index from
    /// reservation state into `pending_blocks`.
    #[inline(always)]
    pub(super) fn mark_block_request_pending(
        &mut self,
        req_id: OutboundRequestId,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
    ) {
        self.reserved_block_indices.remove(&idx);
        self.pending_blocks
            .insert(req_id, (peer, idx, retries_left));
    }

    /// Finalize a successful canonical/index-based batch request issue by moving
    /// the index from reservation state into `pending_batches`.
    #[inline(always)]
    pub(super) fn mark_batch_request_pending(
        &mut self,
        req_id: OutboundRequestId,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
    ) {
        self.reserved_batch_indices.remove(&idx);
        self.pending_batches.insert(
            req_id,
            PendingBatchRequest {
                peer,
                idx,
                retries_left,
                expected_block_hash: None,
            },
        );
    }

    /// Finalize a successful hash-based competing-branch batch request issue by
    /// moving the index from reservation state into `pending_batches`.
    #[inline(always)]
    pub(super) fn mark_batch_request_pending_by_hash(
        &mut self,
        req_id: OutboundRequestId,
        peer: PeerId,
        idx: u64,
        expected_block_hash: RemzarHashBytes,
        retries_left: u8,
    ) {
        self.reserved_batch_indices.remove(&idx);
        self.pending_batches.insert(
            req_id,
            PendingBatchRequest {
                peer,
                idx,
                retries_left,
                expected_block_hash: Some(expected_block_hash),
            },
        );
    }

    // ============================================================
    // HIGH-LEVEL ISSUE HELPERS
    // ============================================================

    pub(super) fn issue_block_request_if_absent(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
    ) -> bool {
        if !self.reserve_block_idx_for_request(idx) {
            return false;
        }

        let req_id = swarm
            .behaviour_mut()
            .blocktx
            .send_request(&peer, BlockTxRequest::GetBlockByIndex { index: idx });

        self.mark_block_request_pending(req_id, peer, idx, retries_left);
        true
    }

    pub(super) fn issue_batch_request_if_absent(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
    ) -> bool {
        if !self.reserve_batch_idx_for_request(idx) {
            return false;
        }

        let req_id = swarm
            .behaviour_mut()
            .blocktx
            .send_request(&peer, BlockTxRequest::GetBatchByIndex { index: idx });

        self.mark_batch_request_pending(req_id, peer, idx, retries_left);
        true
    }

    pub(super) fn issue_batch_request_by_hash_if_absent(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        idx: u64,
        block_hash: RemzarHashBytes,
        retries_left: u8,
    ) -> bool {
        if !self.reserve_batch_idx_for_request(idx) {
            return false;
        }

        let req_id = swarm
            .behaviour_mut()
            .blocktx
            .send_request(&peer, BlockTxRequest::GetBatchByHash { hash: block_hash });

        self.mark_batch_request_pending_by_hash(req_id, peer, idx, block_hash, retries_left);
        true
    }

    // ============================================================
    // RETRY QUEUE HELPERS
    // ============================================================

    /// Queue a block retry only when it is still useful and not already represented
    /// in reservation state, the in-flight map, or the retry queue.
    pub(super) fn enqueue_block_retry_if_absent(
        &mut self,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
    ) -> bool {
        if self.db_has_block_index(idx) {
            return false;
        }

        if self.block_queue.len() >= MAX_BLOCK_QUEUE {
            return false;
        }

        if self.is_block_idx_in_flight_or_reserved_or_queued(idx) {
            return false;
        }

        self.block_queue.push_back((peer, idx, retries_left));
        true
    }

    /// Queue a batch retry only when it is still useful and not already represented
    /// in reservation state, the in-flight map, or the retry queue.
    pub(super) fn enqueue_batch_retry_if_absent(
        &mut self,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
    ) -> bool {
        let applied = self.db.get_addr_index_height().unwrap_or(0);
        if idx <= applied {
            return false;
        }

        if self.batch_queue.len() >= MAX_BATCH_QUEUE {
            return false;
        }

        if self.is_batch_idx_in_flight_or_reserved_or_queued(idx) {
            return false;
        }

        self.batch_queue.push_back((peer, idx, retries_left));
        true
    }
}
