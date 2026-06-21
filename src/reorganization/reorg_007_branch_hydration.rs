// src/blockchain/reorg_007_branch_hydration.rs

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::blockchain::block_002_blocks::Block;
use crate::network::p2p_006_reqresp::Hash;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::time_policy::TimePolicy;
use chrono::DateTime;
use hex;
use libp2p::{PeerId, request_response::OutboundRequestId};

/// Canonical chain block hash alias.
pub type BlockHash = Hash;

/// Small bounded config for hydration behavior.
#[derive(Debug, Clone)]
pub struct HydrationConfig {
    /// Maximum retry attempts per missing hash.
    pub max_retries_per_hash: u8,

    /// Minimum delay before retrying the same hash again.
    pub retry_cooldown: Duration,

    /// Hard cap on the number of queued missing hashes we track at once.
    pub max_tracked_hashes: usize,

    /// Whether to follow the received block's parent hash automatically when
    /// that parent is still missing.
    pub auto_chase_parent: bool,
}

impl Default for HydrationConfig {
    fn default() -> Self {
        Self {
            max_retries_per_hash: 6,
            retry_cooldown: Duration::from_millis(800),
            max_tracked_hashes: 4096,
            auto_chase_parent: true,
        }
    }
}

/// hash is being hydrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydrationReason {
    /// Fork-choice explicitly needs this hash to continue walking ancestry.
    ForkChoiceNeedMoreData,

    /// This hash is the parent of a newly received competing block.
    MissingParent,

    /// Caller manually asked to hydrate this hash.
    Explicit,
}

/// Internal state for one missing hash being tracked.
#[derive(Debug, Clone)]
struct PendingHash {
    hash: BlockHash,
    origin_peer: PeerId,
    source_height: Option<u64>,
    reason: HydrationReason,
    context: &'static str,

    first_seen_at: Instant,
    last_attempt_at: Option<Instant>,
    last_failure_at: Option<Instant>,
    retries_left: u8,

    /// Children waiting on this parent hash.
    waiting_children: HashSet<BlockHash>,

    /// Whether the hash is currently in-flight over the network.
    in_flight: bool,

    /// Whether we have concluded that this hash cannot currently be fetched.
    exhausted: bool,
}

impl PendingHash {
    fn new(
        hash: BlockHash,
        origin_peer: PeerId,
        source_height: Option<u64>,
        reason: HydrationReason,
        context: &'static str,
        cfg: &HydrationConfig,
    ) -> Self {
        Self {
            hash,
            origin_peer,
            source_height,
            reason,
            context,
            first_seen_at: Instant::now(),
            last_attempt_at: None,
            last_failure_at: None,
            retries_left: cfg.max_retries_per_hash,
            waiting_children: HashSet::new(),
            in_flight: false,
            exhausted: false,
        }
    }

    fn can_attempt_now(&self, now: Instant, cfg: &HydrationConfig) -> bool {
        if self.exhausted || self.in_flight || self.retries_left == 0 {
            return false;
        }

        match self.last_attempt_at {
            Some(last) => now.duration_since(last) >= cfg.retry_cooldown,
            None => true,
        }
    }
}

/// High-level result of consuming a newly received hydration block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationAdvance {
    /// The received block was accepted and no further parent chase is needed.
    AcceptedComplete { hash: BlockHash },

    /// The received block was accepted, but its parent is still missing and
    /// should now be hydrated next.
    AcceptedNeedsParent {
        hash: BlockHash,
        missing_parent: BlockHash,
    },

    /// The received block was accepted, and some children were waiting on it.
    AcceptedUnblockedChildren {
        hash: BlockHash,
        children_unblocked: Vec<BlockHash>,
    },

    /// The received block was not relevant to outstanding hydration state.
    Ignored,
}

/// Result of a request failure / not-found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationFailure {
    RetryScheduled { hash: BlockHash, retries_left: u8 },
    Exhausted { hash: BlockHash },
    UnknownRequest,
}

/// Public helper/orchestrator for hash-directed branch hydration.
///
/// This is intended to be embedded in sync runtime state, e.g. inside `P2pSync`.
#[derive(Debug)]
pub struct Hydration {
    cfg: HydrationConfig,

    /// Pending/missing hashes keyed by hash.
    pending_by_hash: HashMap<BlockHash, PendingHash>,

    /// Reverse map from outbound request ID -> requested hash.
    inflight_by_request: HashMap<OutboundRequestId, BlockHash>,

    /// Fair scheduling queue of hashes that should be attempted.
    ready_queue: VecDeque<BlockHash>,
}

impl Hydration {
    pub fn new(cfg: HydrationConfig) -> Self {
        Self {
            cfg,
            pending_by_hash: HashMap::new(),
            inflight_by_request: HashMap::new(),
            ready_queue: VecDeque::new(),
        }
    }

    pub fn default_mainnet() -> Self {
        Self::new(HydrationConfig::default())
    }

    /// Return number of currently tracked missing hashes.
    pub fn tracked_len(&self) -> usize {
        self.pending_by_hash.len()
    }

    /// Return number of currently in-flight hydration requests.
    pub fn inflight_len(&self) -> usize {
        self.inflight_by_request.len()
    }

    /// Return whether a hash is already being tracked.
    pub fn is_tracking(&self, hash: &BlockHash) -> bool {
        self.pending_by_hash.contains_key(hash)
    }

    /// Return whether a hash is currently in-flight.
    pub fn is_inflight_hash(&self, hash: &BlockHash) -> bool {
        self.pending_by_hash
            .get(hash)
            .map(|p| p.in_flight)
            .unwrap_or(false)
    }

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
            Err(..) => "time_unavailable".to_string(),
        }
    }

    /// Main entry point when fork-choice says it needs more data for a hash.
    pub fn note_need_more_data(
        &mut self,
        origin_peer: PeerId,
        missing_hash: BlockHash,
        source_height: Option<u64>,
        reason: HydrationReason,
        context: &'static str,
    ) {
        if self.pending_by_hash.len() >= self.cfg.max_tracked_hashes
            && !self.pending_by_hash.contains_key(&missing_hash)
        {
            return;
        }

        let mut should_enqueue = false;

        match self.pending_by_hash.get_mut(&missing_hash) {
            Some(existing) => {
                existing.origin_peer = origin_peer;
                existing.source_height = existing.source_height.or(source_height);
                existing.reason = reason;
                existing.context = context;

                if !existing.in_flight && !existing.exhausted {
                    should_enqueue = true;
                }
            }
            None => {
                let pending = PendingHash::new(
                    missing_hash,
                    origin_peer,
                    source_height,
                    reason,
                    context,
                    &self.cfg,
                );
                self.pending_by_hash.insert(missing_hash, pending);
                should_enqueue = true;
            }
        }

        if should_enqueue {
            self.enqueue_once(missing_hash);
        }
    }

    /// Record that `child_hash` is blocked on `parent_hash`.
    pub fn note_child_waiting_on_parent(&mut self, parent_hash: BlockHash, child_hash: BlockHash) {
        if let Some(parent) = self.pending_by_hash.get_mut(&parent_hash) {
            parent.waiting_children.insert(child_hash);
        }
    }

    /// Ask the hydration scheduler which hash should be requested next.
    pub fn next_request(&mut self) -> Option<(PeerId, BlockHash)> {
        let now = Instant::now();

        let queue_len = self.ready_queue.len();
        for _ in 0..queue_len {
            let hash = self.ready_queue.pop_front()?;

            let Some(pending) = self.pending_by_hash.get(&hash) else {
                continue;
            };

            if pending.can_attempt_now(now, &self.cfg) {
                return Some((pending.origin_peer, hash));
            }

            if !pending.exhausted && pending.retries_left > 0 {
                self.ready_queue.push_back(hash);
            }
        }

        None
    }

    /// Mark that a network request was successfully issued for `hash`.
    pub fn mark_issued(&mut self, request_id: OutboundRequestId, hash: BlockHash) {
        let Some(pending) = self.pending_by_hash.get_mut(&hash) else {
            return;
        };

        pending.in_flight = true;
        pending.last_attempt_at = Some(Instant::now());
        self.inflight_by_request.insert(request_id, hash);
    }

    /// Handle a request failure such as timeout / outbound failure.
    pub fn on_request_failed(&mut self, request_id: OutboundRequestId) -> HydrationFailure {
        let Some(hash) = self.inflight_by_request.remove(&request_id) else {
            return HydrationFailure::UnknownRequest;
        };

        self.on_hash_request_failed(hash)
    }

    /// Handle a NotFound response for a specific request.
    pub fn on_not_found(&mut self, request_id: OutboundRequestId) -> HydrationFailure {
        let Some(hash) = self.inflight_by_request.remove(&request_id) else {
            return HydrationFailure::UnknownRequest;
        };

        self.on_hash_request_failed(hash)
    }

    fn on_hash_request_failed(&mut self, hash: BlockHash) -> HydrationFailure {
        let (exhausted, retries_left) = {
            let Some(pending) = self.pending_by_hash.get_mut(&hash) else {
                return HydrationFailure::UnknownRequest;
            };

            pending.in_flight = false;
            pending.last_failure_at = Some(Instant::now());

            if pending.retries_left > 0 {
                pending.retries_left = pending.retries_left.saturating_sub(1);
            }

            if pending.retries_left == 0 {
                pending.exhausted = true;
            }

            (pending.exhausted, pending.retries_left)
        };

        if exhausted {
            HydrationFailure::Exhausted { hash }
        } else {
            self.enqueue_once(hash);
            HydrationFailure::RetryScheduled { hash, retries_left }
        }
    }

    /// Consume a received hydration block.
    pub fn on_block_received<PersistFn, ParentFn>(
        &mut self,
        request_id: OutboundRequestId,
        block: &Block,
        mut persist_block: PersistFn,
        mut has_parent_meta: ParentFn,
    ) -> Result<HydrationAdvance, ErrorDetection>
    where
        PersistFn: FnMut(&Block) -> Result<(), ErrorDetection>,
        ParentFn: FnMut(&BlockHash) -> bool,
    {
        let Some(expected_hash) = self.inflight_by_request.remove(&request_id) else {
            return Ok(HydrationAdvance::Ignored);
        };

        let Some(mut pending) = self.pending_by_hash.remove(&expected_hash) else {
            return Ok(HydrationAdvance::Ignored);
        };

        pending.in_flight = false;

        if block.block_hash != expected_hash {
            if pending.retries_left > 0 {
                pending.retries_left = pending.retries_left.saturating_sub(1);
            }

            let exhausted = pending.retries_left == 0;
            pending.exhausted = exhausted;

            self.pending_by_hash.insert(expected_hash, pending);

            if !exhausted {
                self.enqueue_once(expected_hash);
            }

            return Ok(HydrationAdvance::Ignored);
        }

        persist_block(block)?;

        let waiting_children: Vec<BlockHash> = pending.waiting_children.iter().copied().collect();

        let is_genesis_parent =
            block.metadata.index == 0 || block.metadata.previous_hash == [0u8; 64];

        if self.cfg.auto_chase_parent
            && !is_genesis_parent
            && !has_parent_meta(&block.metadata.previous_hash)
        {
            let missing_parent = block.metadata.previous_hash;

            self.note_need_more_data(
                pending.origin_peer,
                missing_parent,
                block.metadata.index.checked_sub(1),
                HydrationReason::MissingParent,
                "received block but parent meta still missing",
            );
            self.note_child_waiting_on_parent(missing_parent, block.block_hash);

            return Ok(HydrationAdvance::AcceptedNeedsParent {
                hash: block.block_hash,
                missing_parent,
            });
        }

        if !waiting_children.is_empty() {
            for child in &waiting_children {
                self.enqueue_once(*child);
            }

            return Ok(HydrationAdvance::AcceptedUnblockedChildren {
                hash: block.block_hash,
                children_unblocked: waiting_children,
            });
        }

        Ok(HydrationAdvance::AcceptedComplete {
            hash: block.block_hash,
        })
    }

    /// Best-effort cleanup if the caller learns that a hash is already fully
    /// present locally and no hydration is needed anymore.
    pub fn clear_if_known(&mut self, hash: &BlockHash) {
        self.pending_by_hash.remove(hash);
        self.ready_queue.retain(|h| h != hash);
    }

    /// Drop all outstanding requests and pending hashes for a peer.
    pub fn on_peer_disconnected(&mut self, peer: PeerId) {
        let affected_hashes: Vec<BlockHash> = self
            .pending_by_hash
            .iter()
            .filter_map(|(hash, p)| (p.origin_peer == peer).then_some(*hash))
            .collect();

        let mut hashes_to_requeue = Vec::new();

        for hash in &affected_hashes {
            let should_requeue = {
                if let Some(p) = self.pending_by_hash.get_mut(hash) {
                    p.in_flight = false;
                    p.last_failure_at = Some(Instant::now());

                    if p.retries_left > 0 {
                        p.retries_left = p.retries_left.saturating_sub(1);
                    }

                    if p.retries_left == 0 {
                        p.exhausted = true;
                        false
                    } else {
                        true
                    }
                } else {
                    false
                }
            };

            if should_requeue {
                hashes_to_requeue.push(*hash);
            }
        }

        for hash in hashes_to_requeue {
            self.enqueue_once(hash);
        }

        self.inflight_by_request.retain(|_, hash| {
            self.pending_by_hash
                .get(hash)
                .map(|p| p.origin_peer != peer)
                .unwrap_or(false)
        });
    }

    /// Human-friendly diagnostic snapshot.
    pub fn snapshot_lines(&self) -> Vec<String> {
        let now = Instant::now();
        let mut out = Vec::with_capacity(self.pending_by_hash.len());

        for p in self.pending_by_hash.values().map(|pending| pending.hash) {
            if let Some(pending) = self.pending_by_hash.get(&p) {
                let age_ms = now.duration_since(pending.first_seen_at).as_millis();
                out.push(format!(
                    "hash={} peer={} in_flight={} exhausted={} retries_left={} age_ms={} source_height={:?} reason={:?} context={}",
                    hex::encode(pending.hash),
                    pending.origin_peer,
                    pending.in_flight,
                    pending.exhausted,
                    pending.retries_left,
                    age_ms,
                    pending.source_height,
                    pending.reason,
                    pending.context,
                ));
            }
        }

        out
    }

    /// Emit a concise runtime summary.
    pub fn log_summary(&self) {
        tracing::debug!(
            "{} [HYDRATION] tracked={} inflight={} queued={}",
            Self::runtime_log_timestamp(),
            self.pending_by_hash.len(),
            self.inflight_by_request.len(),
            self.ready_queue.len(),
        );
    }

    fn enqueue_once(&mut self, hash: BlockHash) {
        if !self.ready_queue.iter().any(|h| h == &hash) {
            self.ready_queue.push_back(hash);
        }
    }
}
