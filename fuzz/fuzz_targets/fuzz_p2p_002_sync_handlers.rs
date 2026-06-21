// fuzz/fuzz_targets/fuzz_p2p_002_sync_handlers.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

use libp2p::{identity, PeerId};
use postcard::{take_from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

type Hash64 = [u8; 64];

const ZERO_HASH_64: Hash64 = [0u8; 64];
const MAX_RETRIES: u8 = 6;
const MAX_BLOCK_SIZE: usize = 1024 * 1024;
const MAX_TRACKED_HASHES: usize = 4096;
const MAX_RETRY_QUEUE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlockMetadata {
    index: u64,
    #[serde(with = "BigArray")]
    previous_hash: Hash64,
    #[serde(with = "BigArray")]
    merkle_root: Hash64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Block {
    metadata: BlockMetadata,
    #[serde(with = "BigArray")]
    block_hash: Hash64,
    payload: Vec<u8>,
}

impl Block {
    fn deserialize_from_storage(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }

    fn deserialize_with_sizes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }

    fn serialize_for_storage(&self) -> Result<Vec<u8>, postcard::Error> {
        to_allocvec(self)
    }

    fn encoded_len_unpadded(&self) -> usize {
        self.serialize_for_storage().map(|v| v.len()).unwrap_or(0)
    }

    fn encoded_len_padded(&self) -> usize {
        let n = self.encoded_len_unpadded();
        if n == 0 {
            return 0;
        }
        n.checked_next_power_of_two().unwrap_or(usize::MAX)
    }

    fn hash_hex(&self) -> String {
        hex::encode(self.block_hash)
    }

    fn compute_block_hash(metadata: &BlockMetadata, payload: &[u8]) -> Hash64 {
        let bytes = to_allocvec(&(metadata, payload)).unwrap_or_default();
        hash64(&bytes)
    }

    fn verify_block_hash(&self) -> bool {
        self.block_hash == Self::compute_block_hash(&self.metadata, &self.payload)
    }

    fn validate(&self, expected_index: Option<u64>) -> Result<(), &'static str> {
        if self.payload.len() > MAX_BLOCK_SIZE {
            return Err("payload exceeds MAX_BLOCK_SIZE");
        }

        if let Some(expected) = expected_index {
            if self.metadata.index != expected {
                return Err("unexpected block index");
            }
        }

        if self.metadata.index == 0 && self.metadata.previous_hash != ZERO_HASH_64 {
            return Err("genesis previous_hash must be zero");
        }

        if !self.verify_block_hash() {
            return Err("block hash mismatch");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TransactionBatch {
    txs: Vec<Vec<u8>>,
}

impl TransactionBatch {
    fn deserialize(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }

    fn serialize(&self) -> Result<Vec<u8>, postcard::Error> {
        to_allocvec(self)
    }

    fn compute_merkle_root(&self) -> Result<Hash64, &'static str> {
        let bytes = self.serialize().map_err(|_| "serialize batch")?;
        Ok(hash64(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum BlockTxRequest {
    GetBlock {
        #[serde(with = "BigArray")]
        hash: Hash64,
    },
    GetTx {
        #[serde(with = "BigArray")]
        hash: Hash64,
    },
    GetBlockByIndex { index: u64 },
    GetBatchByIndex { index: u64 },
    GetBatchByHash {
        #[serde(with = "BigArray")]
        hash: Hash64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum BlockTxResponse {
    BlockData(Box<Block>),
    BatchData(Vec<u8>),
    TxData(Vec<u8>),
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ActionClass {
    Version,
    BlockTxGetBlock,
    BlockTxGetBatch,
    BlockTxGetTx,
    Gossip,
    Kad,
    Identify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastResortDecision {
    Allow,
    Drop(LastResortDrop),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastResortDrop {
    NotAdmitted,
    PeerRateLimited,
    IpRateLimited,
    PeerInflightCap,
    GlobalInflightCap,
    DuplicateRequest,
    PeerByteBudgetExceeded,
    GlobalByteBudgetExceeded,
    PeerCoolingDown,
}

#[derive(Debug, Clone)]
struct LastResortConfig {
    require_admission_for: Vec<ActionClass>,

    peer_bucket_capacity: u64,
    peer_refill_per_sec: u64,

    enable_ip_bucket: bool,
    ip_bucket_capacity: u64,
    ip_refill_per_sec: u64,

    max_inflight_per_peer: u64,
    max_inflight_global: u64,

    dup_window: Duration,
    dup_max_entries_per_peer: usize,

    peer_bytes_capacity: u64,
    peer_bytes_refill_per_sec: u64,
    global_bytes_capacity: u64,
    global_bytes_refill_per_sec: u64,

    badness_threshold: i32,
    cooldown: Duration,
    badness_decay_per_sec: i32,
}

impl Default for LastResortConfig {
    fn default() -> Self {
        Self {
            require_admission_for: vec![
                ActionClass::BlockTxGetBlock,
                ActionClass::BlockTxGetBatch,
                ActionClass::BlockTxGetTx,
            ],

            peer_bucket_capacity: 600,
            peer_refill_per_sec: 200,

            enable_ip_bucket: false,
            ip_bucket_capacity: 6000,
            ip_refill_per_sec: 600,

            max_inflight_per_peer: 64,
            max_inflight_global: 2048,

            dup_window: Duration::from_millis(100),
            dup_max_entries_per_peer: 1024,

            peer_bytes_capacity: 16 * 1024 * 1024,
            peer_bytes_refill_per_sec: 2 * 1024 * 1024,
            global_bytes_capacity: 128 * 1024 * 1024,
            global_bytes_refill_per_sec: 16 * 1024 * 1024,

            badness_threshold: 100,
            cooldown: Duration::from_secs(120),
            badness_decay_per_sec: 5,
        }
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: u64,
    cap: u64,
    refill_per_sec: u64,
    last: Instant,
}

impl Bucket {
    fn new(cap: u64, refill_per_sec: u64, now: Instant) -> Self {
        Self {
            tokens: cap,
            cap,
            refill_per_sec,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now
            .checked_duration_since(self.last)
            .unwrap_or(Duration::ZERO);

        self.last = now;

        let whole = dt.as_secs().saturating_mul(self.refill_per_sec);
        let frac = u64::from(dt.subsec_nanos())
            .saturating_mul(self.refill_per_sec)
            / 1_000_000_000;

        self.tokens = self.tokens.saturating_add(whole).saturating_add(frac).min(self.cap);
    }

    fn try_take(&mut self, now: Instant, cost: u64) -> bool {
        self.refill(now);

        if self.tokens >= cost {
            self.tokens = self.tokens.saturating_sub(cost);
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct PeerGuardState {
    bucket: Bucket,
    bytes: Bucket,
    recent: VecDeque<(u64, Instant)>,
    badness: i32,
    last_decay: Instant,
    cooldown_until: Option<Instant>,
    inflight: u64,
}

impl PeerGuardState {
    fn new(cfg: &LastResortConfig, now: Instant) -> Self {
        Self {
            bucket: Bucket::new(cfg.peer_bucket_capacity, cfg.peer_refill_per_sec, now),
            bytes: Bucket::new(cfg.peer_bytes_capacity, cfg.peer_bytes_refill_per_sec, now),
            recent: VecDeque::new(),
            badness: 0,
            last_decay: now,
            cooldown_until: None,
            inflight: 0,
        }
    }

    fn decay_badness(&mut self, cfg: &LastResortConfig, now: Instant) {
        let dt = now
            .checked_duration_since(self.last_decay)
            .unwrap_or(Duration::ZERO);

        self.last_decay = now;

        if cfg.badness_decay_per_sec <= 0 {
            return;
        }

        let dec = i32::try_from(
            dt.as_secs()
                .saturating_mul(u64::try_from(cfg.badness_decay_per_sec).unwrap_or(0)),
        )
        .unwrap_or(i32::MAX);

        self.badness = self.badness.saturating_sub(dec).max(0);
    }

    fn add_badness(&mut self, cfg: &LastResortConfig, now: Instant, points: i32) {
        self.decay_badness(cfg, now);
        self.badness = self.badness.saturating_add(points.max(1));

        if self.badness >= cfg.badness_threshold {
            self.cooldown_until = now.checked_add(cfg.cooldown);
            self.badness = cfg.badness_threshold;
        }
    }

    fn cooling_down(&mut self, cfg: &LastResortConfig, now: Instant) -> bool {
        self.decay_badness(cfg, now);

        match self.cooldown_until {
            Some(t) if now < t => true,
            Some(_) => {
                self.cooldown_until = None;
                false
            }
            None => false,
        }
    }

    fn prune_recent(&mut self, now: Instant, window: Duration) {
        while let Some((_, t)) = self.recent.front().copied() {
            if now.checked_duration_since(t).unwrap_or(Duration::ZERO) > window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
    }

    fn has_recent(&self, key: u64) -> bool {
        self.recent.iter().any(|(k, _)| *k == key)
    }

    fn push_recent(&mut self, key: u64, now: Instant, max: usize) {
        self.recent.push_back((key, now));

        while self.recent.len() > max {
            self.recent.pop_front();
        }
    }
}

#[derive(Debug)]
struct LastResortGuards {
    cfg: LastResortConfig,
    peers: HashMap<PeerId, PeerGuardState>,
    global_bytes: Bucket,
    global_inflight: u64,
}

impl LastResortGuards {
    fn new(cfg: LastResortConfig, now: Instant) -> Self {
        Self {
            global_bytes: Bucket::new(
                cfg.global_bytes_capacity,
                cfg.global_bytes_refill_per_sec,
                now,
            ),
            cfg,
            peers: HashMap::new(),
            global_inflight: 0,
        }
    }

    fn dup_key_from_str(s: &str) -> u64 {
        const FNV_OFFSET: u64 = 14695981039346656037;
        const FNV_PRIME: u64 = 1099511628211;

        let mut h = FNV_OFFSET;

        for &b in s.as_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }

        h
    }

    fn is_sync_action(action: ActionClass) -> bool {
        matches!(
            action,
            ActionClass::BlockTxGetBlock
                | ActionClass::BlockTxGetBatch
                | ActionClass::BlockTxGetTx
        )
    }

    fn check_action(&mut self, req: LastResortActionRequest) -> LastResortDecision {
        if !req.admitted && self.cfg.require_admission_for.contains(&req.action) {
            return LastResortDecision::Drop(LastResortDrop::NotAdmitted);
        }

        let ps = self
            .peers
            .entry(req.peer_id)
            .or_insert_with(|| PeerGuardState::new(&self.cfg, req.now));

        if ps.cooling_down(&self.cfg, req.now) {
            return LastResortDecision::Drop(LastResortDrop::PeerCoolingDown);
        }

        if let Some(k) = req.dup_key {
            ps.prune_recent(req.now, self.cfg.dup_window);

            let is_duplicate = ps.has_recent(k);

            if is_duplicate && !Self::is_sync_action(req.action) {
                ps.add_badness(&self.cfg, req.now, 2);
                return LastResortDecision::Drop(LastResortDrop::DuplicateRequest);
            }

            if !is_duplicate {
                ps.push_recent(k, req.now, self.cfg.dup_max_entries_per_peer);
            }
        }

        let cost = u64::from(req.cost_tokens.max(1));

        if !ps.bucket.try_take(req.now, cost) {
            ps.add_badness(&self.cfg, req.now, 3);
            return LastResortDecision::Drop(LastResortDrop::PeerRateLimited);
        }

        if self.cfg.enable_ip_bucket {
            let _ = self.cfg.ip_bucket_capacity;
            let _ = self.cfg.ip_refill_per_sec;
            return LastResortDecision::Allow;
        }

        LastResortDecision::Allow
    }

    fn try_begin_inflight(&mut self, now: Instant, peer: &PeerId) -> LastResortDecision {
        let ps = self
            .peers
            .entry(*peer)
            .or_insert_with(|| PeerGuardState::new(&self.cfg, now));

        if ps.cooling_down(&self.cfg, now) {
            return LastResortDecision::Drop(LastResortDrop::PeerCoolingDown);
        }

        if ps.inflight >= self.cfg.max_inflight_per_peer {
            ps.add_badness(&self.cfg, now, 4);
            return LastResortDecision::Drop(LastResortDrop::PeerInflightCap);
        }

        if self.global_inflight >= self.cfg.max_inflight_global {
            ps.add_badness(&self.cfg, now, 1);
            return LastResortDecision::Drop(LastResortDrop::GlobalInflightCap);
        }

        ps.inflight = ps.inflight.saturating_add(1);
        self.global_inflight = self.global_inflight.saturating_add(1);

        LastResortDecision::Allow
    }

    fn finish_inflight(&mut self, peer: &PeerId) {
        if let Some(ps) = self.peers.get_mut(peer) {
            ps.inflight = ps.inflight.saturating_sub(1);
        }

        self.global_inflight = self.global_inflight.saturating_sub(1);
    }

    fn check_bytes(&mut self, now: Instant, peer: PeerId, bytes: u64) -> LastResortDecision {
        let ps = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerGuardState::new(&self.cfg, now));

        if ps.cooling_down(&self.cfg, now) {
            return LastResortDecision::Drop(LastResortDrop::PeerCoolingDown);
        }

        if !ps.bytes.try_take(now, bytes) {
            ps.add_badness(&self.cfg, now, 5);
            return LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded);
        }

        if !self.global_bytes.try_take(now, bytes) {
            ps.add_badness(&self.cfg, now, 2);
            return LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded);
        }

        LastResortDecision::Allow
    }

    fn report_misbehavior(&mut self, now: Instant, peer: PeerId, points: i32) {
        let ps = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerGuardState::new(&self.cfg, now));

        ps.add_badness(&self.cfg, now, points);
    }

    fn on_peer_disconnected(&mut self, peer: PeerId) {
        if let Some(ps) = self.peers.remove(&peer) {
            self.global_inflight = self.global_inflight.saturating_sub(ps.inflight);
        }
    }
}

#[derive(Debug, Clone)]
struct LastResortActionRequest {
    now: Instant,
    peer_id: PeerId,
    admitted: bool,
    action: ActionClass,
    cost_tokens: u32,
    dup_key: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum HydrationReason {
    ForkChoiceNeedMoreData,
    MissingParent,
    Explicit,
}

#[derive(Debug, Clone)]
struct HydrationConfig {
    max_retries_per_hash: u8,
    retry_cooldown: Duration,
    max_tracked_hashes: usize,
    auto_chase_parent: bool,
}

impl Default for HydrationConfig {
    fn default() -> Self {
        Self {
            max_retries_per_hash: 6,
            retry_cooldown: Duration::from_millis(0),
            max_tracked_hashes: MAX_TRACKED_HASHES,
            auto_chase_parent: true,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingHash {
    origin_peer: PeerId,
    source_height: Option<u64>,
    reason: HydrationReason,
    context: &'static str,
    first_seen_at: Instant,
    last_attempt_at: Option<Instant>,
    retries_left: u8,
    waiting_children: HashSet<Hash64>,
    in_flight: bool,
    exhausted: bool,
}

#[derive(Debug)]
struct Hydration {
    cfg: HydrationConfig,
    pending_by_hash: HashMap<Hash64, PendingHash>,
    ready_queue: VecDeque<Hash64>,
}

impl Hydration {
    fn new(cfg: HydrationConfig) -> Self {
        Self {
            cfg,
            pending_by_hash: HashMap::new(),
            ready_queue: VecDeque::new(),
        }
    }

    fn tracked_len(&self) -> usize {
        self.pending_by_hash.len()
    }

    fn inflight_len(&self) -> usize {
        self.pending_by_hash.values().filter(|p| p.in_flight).count()
    }

    fn is_tracking(&self, hash: &Hash64) -> bool {
        self.pending_by_hash.contains_key(hash)
    }

    fn is_inflight_hash(&self, hash: &Hash64) -> bool {
        self.pending_by_hash
            .get(hash)
            .map(|p| p.in_flight)
            .unwrap_or(false)
    }

    fn note_need_more_data(
        &mut self,
        origin_peer: PeerId,
        missing_hash: Hash64,
        source_height: Option<u64>,
        reason: HydrationReason,
        context: &'static str,
    ) {
        if self.pending_by_hash.len() >= self.cfg.max_tracked_hashes
            && !self.pending_by_hash.contains_key(&missing_hash)
        {
            return;
        }

        match self.pending_by_hash.get_mut(&missing_hash) {
            Some(existing) => {
                existing.origin_peer = origin_peer;
                existing.source_height = existing.source_height.or(source_height);
                existing.reason = reason;
                existing.context = context;

                if !existing.in_flight && !existing.exhausted {
                    self.enqueue_once(missing_hash);
                }
            }
            None => {
                self.pending_by_hash.insert(
                    missing_hash,
                    PendingHash {
                        origin_peer,
                        source_height,
                        reason,
                        context,
                        first_seen_at: Instant::now(),
                        last_attempt_at: None,
                        retries_left: self.cfg.max_retries_per_hash,
                        waiting_children: HashSet::new(),
                        in_flight: false,
                        exhausted: false,
                    },
                );

                self.enqueue_once(missing_hash);
            }
        }
    }

    fn note_child_waiting_on_parent(&mut self, parent_hash: Hash64, child_hash: Hash64) {
        if let Some(parent) = self.pending_by_hash.get_mut(&parent_hash) {
            parent.waiting_children.insert(child_hash);
        }
    }

    fn next_request(&mut self) -> Option<(PeerId, Hash64)> {
        let now = Instant::now();
        let queue_len = self.ready_queue.len();

        for _ in 0..queue_len {
            let hash = self.ready_queue.pop_front()?;

            let Some(pending) = self.pending_by_hash.get_mut(&hash) else {
                continue;
            };

            if pending.exhausted || pending.in_flight || pending.retries_left == 0 {
                continue;
            }

            let can_attempt = match pending.last_attempt_at {
                Some(last) => {
                    now.checked_duration_since(last).unwrap_or(Duration::ZERO)
                        >= self.cfg.retry_cooldown
                }
                None => true,
            };

            if can_attempt {
                pending.in_flight = true;
                pending.last_attempt_at = Some(now);
                return Some((pending.origin_peer, hash));
            }

            self.ready_queue.push_back(hash);
        }

        None
    }

    fn clear_if_known(&mut self, hash: &Hash64) {
        self.pending_by_hash.remove(hash);
        self.ready_queue.retain(|h| h != hash);
    }

    fn mark_failed_by_hash(&mut self, hash: Hash64) {
        let Some(pending) = self.pending_by_hash.get_mut(&hash) else {
            return;
        };

        pending.in_flight = false;

        if pending.retries_left > 0 {
            pending.retries_left = pending.retries_left.saturating_sub(1);
        }

        if pending.retries_left == 0 {
            pending.exhausted = true;
        } else {
            self.enqueue_once(hash);
        }
    }

    fn on_peer_disconnected(&mut self, peer: PeerId) {
        let affected = self
            .pending_by_hash
            .iter()
            .filter_map(|(hash, p)| (p.origin_peer == peer).then_some(*hash))
            .collect::<Vec<_>>();

        for hash in affected {
            self.mark_failed_by_hash(hash);
        }
    }

    fn snapshot_lines(&self) -> Vec<String> {
        let now = Instant::now();

        self.pending_by_hash
            .iter()
            .map(|(hash, p)| {
                format!(
                    "hash={} peer={} inflight={} exhausted={} retries_left={} age_ms={} height={:?} reason={:?} context={}",
                    hex::encode(hash),
                    p.origin_peer,
                    p.in_flight,
                    p.exhausted,
                    p.retries_left,
                    now.checked_duration_since(p.first_seen_at)
                        .unwrap_or(Duration::ZERO)
                        .as_millis(),
                    p.source_height,
                    p.reason,
                    p.context,
                )
            })
            .collect()
    }

    fn enqueue_once(&mut self, hash: Hash64) {
        if !self.ready_queue.iter().any(|h| h == &hash) {
            self.ready_queue.push_back(hash);
        }
    }
}

#[derive(Debug, Clone)]
struct BranchScoreConfig {
    mode: BranchScoreMode,
    allow_equal_height_tiebreak: bool,
    prefer_lower_hash_on_tie: bool,
}

#[derive(Debug, Clone)]
enum BranchScoreMode {
    HeightOnly,
    CumulativePor,
}

#[derive(Debug, Clone, Copy)]
struct BranchCandidate {
    tip_hash: Hash64,
    height: u64,
    cumulative_por: u128,
}

impl BranchCandidate {
    fn new(tip_hash: Hash64, height: u64, cumulative_por: u128) -> Self {
        Self {
            tip_hash,
            height,
            cumulative_por,
        }
    }
}

#[derive(Debug, Clone)]
struct ReorgBranchScorer {
    cfg: BranchScoreConfig,
}

impl ReorgBranchScorer {
    fn new(cfg: BranchScoreConfig) -> Self {
        Self { cfg }
    }

    fn candidate_beats_current(
        &self,
        current: BranchCandidate,
        candidate: BranchCandidate,
    ) -> bool {
        match self.cfg.mode {
            BranchScoreMode::HeightOnly => {
                if candidate.height > current.height {
                    return true;
                }

                if candidate.height < current.height {
                    return false;
                }
            }
            BranchScoreMode::CumulativePor => {
                if candidate.cumulative_por > current.cumulative_por {
                    return true;
                }

                if candidate.cumulative_por < current.cumulative_por {
                    return false;
                }

                if candidate.height > current.height {
                    return true;
                }

                if candidate.height < current.height {
                    return false;
                }
            }
        }

        if !self.cfg.allow_equal_height_tiebreak {
            return false;
        }

        if candidate.tip_hash == current.tip_hash {
            return false;
        }

        if self.cfg.prefer_lower_hash_on_tie {
            candidate.tip_hash < current.tip_hash
        } else {
            candidate.tip_hash > current.tip_hash
        }
    }

    fn choose_tip(
        &self,
        current: BranchCandidate,
        candidate: BranchCandidate,
    ) -> Option<Hash64> {
        if self.candidate_beats_current(current, candidate) {
            Some(candidate.tip_hash)
        } else {
            Some(current.tip_hash)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MemoryBlockRetry {
    peer: PeerId,
    idx: u64,
    retries_left: u8,
}

#[derive(Debug, Clone)]
struct MemoryBatchRetry {
    peer: PeerId,
    idx: u64,
    expected_block_hash: Option<Hash64>,
    retries_left: u8,
}

#[derive(Debug, Clone)]
struct MemoryBatchTxResponseContext {
    origin_peer: PeerId,
    idx: u64,
    expected_block_hash: Option<Hash64>,
    retries_left: u8,
}

struct MemorySyncHarness {
    canonical_blocks_by_height: HashMap<u64, Block>,
    blocks_by_hash: HashMap<Hash64, Block>,

    batches_by_height: HashMap<u64, Vec<u8>>,
    batches_by_block_hash: HashMap<Hash64, Vec<u8>>,

    block_retries: VecDeque<MemoryBlockRetry>,
    batch_retries: VecDeque<MemoryBatchRetry>,

    admitted_peers: HashSet<PeerId>,
    pq_ready_peers: HashSet<PeerId>,

    branch_hydration: Hydration,
    last_resort: LastResortGuards,

    has_synced: bool,
    syncing: bool,
    last_synced_index: Option<u64>,
    last_synced_hash: Option<Hash64>,
    downloaded: u64,
    sync_target: u64,
    total_to_download: u64,
    addr_index_height: u64,
}

impl MemorySyncHarness {
    fn new(now: Instant) -> Self {
        Self {
            canonical_blocks_by_height: HashMap::new(),
            blocks_by_hash: HashMap::new(),

            batches_by_height: HashMap::new(),
            batches_by_block_hash: HashMap::new(),

            block_retries: VecDeque::new(),
            batch_retries: VecDeque::new(),

            admitted_peers: HashSet::new(),
            pq_ready_peers: HashSet::new(),

            branch_hydration: Hydration::new(HydrationConfig::default()),
            last_resort: LastResortGuards::new(LastResortConfig::default(), now),

            has_synced: false,
            syncing: false,
            last_synced_index: None,
            last_synced_hash: None,
            downloaded: 0,
            sync_target: 0,
            total_to_download: 0,
            addr_index_height: 0,
        }
    }

    fn exceeds_consensus_cap(len: usize) -> bool {
        len > MAX_BLOCK_SIZE
    }

    fn usize_to_u64_saturating(n: usize) -> u64 {
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    fn tip_height(&self) -> u64 {
        self.canonical_blocks_by_height
            .keys()
            .copied()
            .max()
            .unwrap_or(0)
    }

    fn canonical_hash_at_height(&self, height: u64) -> Option<Hash64> {
        self.canonical_blocks_by_height
            .get(&height)
            .map(|b| b.block_hash)
    }

    fn canonical_block_at_height(&self, height: u64) -> Option<Block> {
        self.canonical_blocks_by_height.get(&height).cloned()
    }

    fn block_by_hash(&self, hash: &Hash64) -> Option<Block> {
        self.blocks_by_hash.get(hash).cloned()
    }

    fn is_same_canonical_block(&self, block: &Block) -> bool {
        self.canonical_block_at_height(block.metadata.index)
            .map(|existing| existing.block_hash == block.block_hash)
            .unwrap_or(false)
    }

    fn has_reorg_parent_meta_memory(&self, block: &Block) -> bool {
        if block.metadata.index == 0 || block.metadata.previous_hash == ZERO_HASH_64 {
            return true;
        }

        self.blocks_by_hash.contains_key(&block.metadata.previous_hash)
    }

    fn has_reorg_block_and_meta_memory(&self, hash: &Hash64) -> bool {
        self.blocks_by_hash.contains_key(hash)
    }

    fn has_reorg_batch_for_block_hash_memory(&self, hash: &Hash64) -> bool {
        self.batches_by_block_hash.contains_key(hash)
    }

    fn block_for_batch_response(
        &self,
        idx: u64,
        expected_block_hash: Option<Hash64>,
    ) -> Option<Block> {
        match expected_block_hash {
            Some(hash) => self.block_by_hash(&hash),
            None => self.canonical_block_at_height(idx),
        }
    }

    fn pick_known_hydration_peer(&self) -> Option<PeerId> {
        self.pq_ready_peers
            .iter()
            .copied()
            .next()
            .or_else(|| self.admitted_peers.iter().copied().next())
    }

    fn branch_hydration_active(&self) -> bool {
        self.branch_hydration.tracked_len() > 0 || self.branch_hydration.inflight_len() > 0
    }

    fn update_sync_state(&mut self) {
        self.downloaded = self.last_synced_index.unwrap_or(self.downloaded);
        self.total_to_download = self.sync_target.max(self.downloaded);

        self.has_synced = self.downloaded >= self.total_to_download;
        self.syncing = !self.has_synced || self.branch_hydration_active();
    }

    fn update_sync_pointers(&mut self) {
        let tip = self.tip_height();

        if let Some(block) = self.canonical_block_at_height(tip) {
            self.last_synced_index = Some(block.metadata.index);
            self.last_synced_hash = Some(block.block_hash);
            self.downloaded = block.metadata.index;
        }
    }

    fn refresh_sync_tracking_from_canonical_view_memory(&mut self) {
        self.update_sync_pointers();
        self.update_sync_state();
    }

    fn enqueue_block_retry_if_absent(&mut self, peer: PeerId, idx: u64, retries_left: u8) -> bool {
        if self.block_retries.len() >= MAX_RETRY_QUEUE {
            return false;
        }

        if self
            .block_retries
            .iter()
            .any(|r| r.peer == peer && r.idx == idx)
        {
            return false;
        }

        self.block_retries.push_back(MemoryBlockRetry {
            peer,
            idx,
            retries_left,
        });

        true
    }

    fn enqueue_batch_retry_if_absent(
        &mut self,
        peer: PeerId,
        idx: u64,
        expected_block_hash: Option<Hash64>,
        retries_left: u8,
    ) -> bool {
        if self.batch_retries.len() >= MAX_RETRY_QUEUE {
            return false;
        }

        if self.batch_retries.iter().any(|r| {
            r.peer == peer && r.idx == idx && r.expected_block_hash == expected_block_hash
        }) {
            return false;
        }

        self.batch_retries.push_back(MemoryBatchRetry {
            peer,
            idx,
            expected_block_hash,
            retries_left,
        });

        true
    }

    fn push_block_retry(&mut self, peer: PeerId, idx: u64, retries_left: u8) {
        let _ = self.enqueue_block_retry_if_absent(peer, idx, retries_left);
    }

    fn push_batch_retry(
        &mut self,
        peer: PeerId,
        idx: u64,
        expected_block_hash: Option<Hash64>,
        retries_left: u8,
    ) {
        let _ = self.enqueue_batch_retry_if_absent(peer, idx, expected_block_hash, retries_left);
    }

    fn queue_branch_hydration(&mut self, origin_peer: PeerId, block: &Block, retries_left: u8) {
        if retries_left > 0 {
            self.push_block_retry(
                origin_peer,
                block.metadata.index,
                retries_left.saturating_sub(1),
            );
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
                "memory fuzz parent missing",
            );

            self.branch_hydration
                .note_child_waiting_on_parent(block.metadata.previous_hash, block.block_hash);
        }
    }

    fn queue_branch_hydration_by_hash(
        &mut self,
        origin_peer: PeerId,
        missing_hash: Hash64,
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

    fn drive_branch_hydration_requests_memory(&mut self) {
        for _ in 0..16 {
            let Some((peer, hash)) = self.branch_hydration.next_request() else {
                break;
            };

            if !self.pq_ready_peers.contains(&peer) {
                self.queue_branch_hydration_by_hash(
                    peer,
                    hash,
                    None,
                    HydrationReason::Explicit,
                    "memory fuzz peer not pq ready",
                );

                continue;
            }

            let _req = BlockTxRequest::GetBlock { hash };
        }
    }

    fn persist_sync_block_into_memory_graph(&mut self, block: &Block) {
        self.blocks_by_hash.insert(block.block_hash, block.clone());
    }

    fn persist_sync_batch_into_memory_graph(&mut self, header: &Block, batch_bytes: &[u8]) {
        self.batches_by_block_hash
            .insert(header.block_hash, batch_bytes.to_vec());

        let tip_height = self.tip_height();

        let extends_tip = if let Some(tip_hash) = self.canonical_hash_at_height(tip_height) {
            header.metadata.previous_hash == tip_hash
                && header.metadata.index == tip_height.saturating_add(1)
        } else {
            header.metadata.index == 0 || header.metadata.previous_hash == ZERO_HASH_64
        };

        if extends_tip {
            self.canonical_blocks_by_height
                .insert(header.metadata.index, header.clone());

            self.batches_by_height
                .insert(header.metadata.index, batch_bytes.to_vec());
        }
    }

    fn handle_competing_block_with_memory_reorg_manager(
        &mut self,
        origin_peer: PeerId,
        block: &Block,
        retries_left: u8,
    ) {
        if !self.has_reorg_batch_for_block_hash_memory(&block.block_hash) {
            self.push_batch_retry(
                origin_peer,
                block.metadata.index,
                Some(block.block_hash),
                retries_left,
            );

            self.syncing = true;
            self.update_sync_state();
            return;
        }

        let current_tip_height = self.tip_height();
        let current_tip_hash = self
            .canonical_hash_at_height(current_tip_height)
            .unwrap_or(ZERO_HASH_64);

        let current = BranchCandidate::new(
            current_tip_hash,
            current_tip_height,
            current_tip_height as u128,
        );

        let candidate =
            BranchCandidate::new(block.block_hash, block.metadata.index, block.metadata.index as u128);

        let scorer = ReorgBranchScorer::new(BranchScoreConfig {
            mode: BranchScoreMode::HeightOnly,
            allow_equal_height_tiebreak: false,
            prefer_lower_hash_on_tie: true,
        });

        if scorer.candidate_beats_current(current, candidate) {
            self.canonical_blocks_by_height
                .insert(block.metadata.index, block.clone());

            self.last_synced_index = Some(block.metadata.index);
            self.last_synced_hash = Some(block.block_hash);
            self.downloaded = block.metadata.index;
        } else {
            self.queue_branch_hydration(origin_peer, block, retries_left);
        }

        self.refresh_sync_tracking_from_canonical_view_memory();
    }

    fn handle_block_tx_response_memory(
        &mut self,
        origin_peer: PeerId,
        idx: u64,
        retries_left: u8,
        response: BlockTxResponse,
    ) {
        self.update_sync_pointers();

        match response {
            BlockTxResponse::BlockData(block) => {
                let canonical_bytes = match block.serialize_for_storage() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.last_resort
                            .report_misbehavior(Instant::now(), origin_peer, 2);

                        if retries_left > 0 {
                            self.push_block_retry(
                                origin_peer,
                                idx,
                                retries_left.saturating_sub(1),
                            );
                        }

                        return;
                    }
                };

                if Self::exceeds_consensus_cap(canonical_bytes.len()) {
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 2);

                    if retries_left > 0 {
                        self.push_block_retry(origin_peer, idx, retries_left.saturating_sub(1));
                    }

                    return;
                }

                match self.last_resort.check_bytes(
                    Instant::now(),
                    origin_peer,
                    Self::usize_to_u64_saturating(canonical_bytes.len()),
                ) {
                    LastResortDecision::Allow => {}
                    LastResortDecision::Drop(_) => {
                        if retries_left > 0 {
                            self.push_block_retry(
                                origin_peer,
                                idx,
                                retries_left.saturating_sub(1),
                            );
                        }

                        return;
                    }
                }

                if idx == 0 {
                    if block.metadata.index != 0 || block.metadata.previous_hash != ZERO_HASH_64 {
                        self.syncing = false;
                        return;
                    }

                    if block.validate(Some(0)).is_err() {
                        self.syncing = false;
                        return;
                    }

                    self.blocks_by_hash.insert(block.block_hash, (*block).clone());
                    self.canonical_blocks_by_height
                        .insert(block.metadata.index, (*block).clone());

                    self.last_synced_index = Some(0);
                    self.last_synced_hash = Some(block.block_hash);
                    self.downloaded = 0;
                    self.update_sync_state();
                    return;
                }

                let current_tip = self.tip_height();

                if idx <= current_tip && self.is_same_canonical_block(&block) {
                    return;
                }

                if block.validate(None).is_err() {
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 25);

                    self.syncing = false;
                    return;
                }

                self.persist_sync_block_into_memory_graph(&block);

                let expected_idx = self.last_synced_index.unwrap_or(0).saturating_add(1);

                let expected_prev = self
                    .last_synced_hash
                    .or_else(|| self.canonical_hash_at_height(current_tip))
                    .unwrap_or(ZERO_HASH_64);

                if block.metadata.index != expected_idx || block.metadata.previous_hash != expected_prev {
                    if !self.has_reorg_parent_meta_memory(&block) {
                        self.queue_branch_hydration(origin_peer, &block, retries_left);
                        self.drive_branch_hydration_requests_memory();
                        self.syncing = true;
                        self.update_sync_state();
                        return;
                    }

                    if !self.has_reorg_block_and_meta_memory(&block.block_hash) {
                        self.queue_branch_hydration(origin_peer, &block, retries_left);
                        self.drive_branch_hydration_requests_memory();
                        self.syncing = true;
                        self.update_sync_state();
                        return;
                    }

                    self.handle_competing_block_with_memory_reorg_manager(
                        origin_peer,
                        &block,
                        retries_left,
                    );

                    return;
                }

                self.blocks_by_hash.insert(block.block_hash, (*block).clone());

                self.canonical_blocks_by_height
                    .insert(block.metadata.index, (*block).clone());

                self.last_synced_index = Some(block.metadata.index);
                self.last_synced_hash = Some(block.block_hash);
                self.downloaded = block.metadata.index;

                self.push_batch_retry(origin_peer, idx, None, MAX_RETRIES);
            }

            BlockTxResponse::NotFound => {
                if retries_left > 0 {
                    self.push_block_retry(origin_peer, idx, retries_left.saturating_sub(1));
                }
            }

            BlockTxResponse::TxData(_) | BlockTxResponse::BatchData(_) => {}
        }

        self.update_sync_state();
    }

    fn handle_batch_tx_response_memory(
        &mut self,
        ctx: MemoryBatchTxResponseContext,
        response: BlockTxResponse,
    ) {
        let MemoryBatchTxResponseContext {
            origin_peer,
            idx,
            expected_block_hash,
            retries_left,
        } = ctx;

        match response {
            BlockTxResponse::BatchData(batch_bytes) => {
                if Self::exceeds_consensus_cap(batch_bytes.len()) {
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 2);

                    if retries_left > 0
                        && (expected_block_hash.is_some() || idx > self.addr_index_height)
                    {
                        self.push_batch_retry(
                            origin_peer,
                            idx,
                            expected_block_hash,
                            retries_left.saturating_sub(1),
                        );
                    }

                    return;
                }

                match self.last_resort.check_bytes(
                    Instant::now(),
                    origin_peer,
                    Self::usize_to_u64_saturating(batch_bytes.len()),
                ) {
                    LastResortDecision::Allow => {}
                    LastResortDecision::Drop(_) => {
                        if retries_left > 0
                            && (expected_block_hash.is_some() || idx > self.addr_index_height)
                        {
                            self.push_batch_retry(
                                origin_peer,
                                idx,
                                expected_block_hash,
                                retries_left.saturating_sub(1),
                            );
                        }

                        return;
                    }
                }

                let canonical_mode = expected_block_hash.is_none();

                if canonical_mode && idx <= self.addr_index_height {
                    return;
                }

                let Some(header) = self.block_for_batch_response(idx, expected_block_hash) else {
                    self.syncing = false;
                    return;
                };

                let batch = match TransactionBatch::deserialize(&batch_bytes) {
                    Ok(batch) => batch,
                    Err(_) => {
                        self.last_resort
                            .report_misbehavior(Instant::now(), origin_peer, 5);

                        if retries_left > 0
                            && (expected_block_hash.is_some() || idx > self.addr_index_height)
                        {
                            self.push_batch_retry(
                                origin_peer,
                                idx,
                                expected_block_hash,
                                retries_left.saturating_sub(1),
                            );
                        }

                        return;
                    }
                };

                let computed_root = match batch.compute_merkle_root() {
                    Ok(root) => root,
                    Err(_) => {
                        self.last_resort
                            .report_misbehavior(Instant::now(), origin_peer, 5);

                        if retries_left > 0
                            && (expected_block_hash.is_some() || idx > self.addr_index_height)
                        {
                            self.push_batch_retry(
                                origin_peer,
                                idx,
                                expected_block_hash,
                                retries_left.saturating_sub(1),
                            );
                        }

                        return;
                    }
                };

                if header.metadata.merkle_root != computed_root {
                    self.last_resort
                        .report_misbehavior(Instant::now(), origin_peer, 25);

                    if canonical_mode {
                        self.batches_by_height.remove(&idx);
                    }

                    if retries_left > 0
                        && (expected_block_hash.is_some() || idx > self.addr_index_height)
                    {
                        self.push_batch_retry(
                            origin_peer,
                            idx,
                            expected_block_hash,
                            retries_left.saturating_sub(1),
                        );
                    }

                    return;
                }

                if canonical_mode {
                    self.batches_by_height.insert(idx, batch_bytes.clone());
                    self.persist_sync_batch_into_memory_graph(&header, &batch_bytes);

                    self.last_synced_index = Some(idx);
                    self.last_synced_hash = Some(header.block_hash);
                    self.downloaded = idx;
                    self.addr_index_height = idx;
                } else {
                    self.persist_sync_batch_into_memory_graph(&header, &batch_bytes);

                    self.handle_competing_block_with_memory_reorg_manager(
                        origin_peer,
                        &header,
                        retries_left,
                    );
                }
            }

            BlockTxResponse::NotFound => {
                if retries_left > 0
                    && (expected_block_hash.is_some() || idx > self.addr_index_height)
                {
                    self.push_batch_retry(
                        origin_peer,
                        idx,
                        expected_block_hash,
                        retries_left.saturating_sub(1),
                    );
                }
            }

            BlockTxResponse::BlockData(_) | BlockTxResponse::TxData(_) => {}
        }

        self.update_sync_state();
    }

    fn handle_fork_memory(&mut self, new_tip_hash: Hash64) -> Result<(), String> {
        let Some(block) = self.block_by_hash(&new_tip_hash) else {
            return Err(format!("memory fuzz unknown hash {}", hex::encode(new_tip_hash)));
        };

        self.handle_competing_block_with_memory_reorg_manager(make_peer(1), &block, MAX_RETRIES);
        self.refresh_sync_tracking_from_canonical_view_memory();

        Ok(())
    }

    fn cleanup_pending_for_peer_memory(&mut self, peer: PeerId, allow_same_peer: bool) {
        let retry_peer = if allow_same_peer {
            Some(peer)
        } else {
            self.admitted_peers.iter().copied().find(|p| *p != peer)
        };

        let mut kept_blocks = VecDeque::new();
        let mut block_requeues = Vec::new();

        while let Some(req) = self.block_retries.pop_front() {
            if req.peer == peer {
                if req.retries_left > 0 {
                    if let Some(p) = retry_peer {
                        block_requeues.push(MemoryBlockRetry {
                            peer: p,
                            idx: req.idx,
                            retries_left: req.retries_left.saturating_sub(1),
                        });
                    }
                }
            } else {
                kept_blocks.push_back(req);
            }
        }

        self.block_retries = kept_blocks;

        for req in block_requeues {
            self.push_block_retry(req.peer, req.idx, req.retries_left);
        }

        let mut kept_batches = VecDeque::new();
        let mut batch_requeues = Vec::new();

        while let Some(req) = self.batch_retries.pop_front() {
            if req.peer == peer {
                if req.retries_left > 0
                    && (req.expected_block_hash.is_some() || req.idx > self.addr_index_height)
                {
                    if let Some(p) = retry_peer {
                        batch_requeues.push(MemoryBatchRetry {
                            peer: p,
                            idx: req.idx,
                            expected_block_hash: req.expected_block_hash,
                            retries_left: req.retries_left.saturating_sub(1),
                        });
                    }
                }
            } else {
                kept_batches.push_back(req);
            }
        }

        self.batch_retries = kept_batches;

        for req in batch_requeues {
            self.push_batch_retry(
                req.peer,
                req.idx,
                req.expected_block_hash,
                req.retries_left,
            );
        }

        self.branch_hydration.on_peer_disconnected(peer);
        self.last_resort.on_peer_disconnected(peer);
    }

    fn drain_some_retries_memory(&mut self) {
        for _ in 0..8 {
            if let Some(req) = self.block_retries.pop_front() {
                let response = if let Some(block) = self.canonical_block_at_height(req.idx) {
                    BlockTxResponse::BlockData(Box::new(block))
                } else {
                    BlockTxResponse::NotFound
                };

                self.handle_block_tx_response_memory(req.peer, req.idx, req.retries_left, response);
            }

            if let Some(req) = self.batch_retries.pop_front() {
                let response = if let Some(bytes) = req
                    .expected_block_hash
                    .and_then(|h| self.batches_by_block_hash.get(&h).cloned())
                    .or_else(|| self.batches_by_height.get(&req.idx).cloned())
                {
                    BlockTxResponse::BatchData(bytes)
                } else {
                    BlockTxResponse::NotFound
                };

                self.handle_batch_tx_response_memory(
                    MemoryBatchTxResponseContext {
                        origin_peer: req.peer,
                        idx: req.idx,
                        expected_block_hash: req.expected_block_hash,
                        retries_left: req.retries_left,
                    },
                    response,
                );
            }
        }
    }
}

fn hash64(data: &[u8]) -> Hash64 {
    let h1 = blake3::hash(data);

    let mut seed = Vec::with_capacity(data.len().saturating_add(32));
    seed.extend_from_slice(h1.as_bytes());
    seed.extend_from_slice(data);

    let h2 = blake3::hash(&seed);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(h1.as_bytes());
    out[32..].copy_from_slice(h2.as_bytes());
    out
}

fn read_u8(data: &[u8], pos: &mut usize) -> u8 {
    let v = data.get(*pos).copied().unwrap_or(0);
    *pos = pos.saturating_add(1);
    v
}

fn read_u64(data: &[u8], pos: &mut usize) -> u64 {
    let mut out = [0u8; 8];

    for b in &mut out {
        *b = read_u8(data, pos);
    }

    u64::from_le_bytes(out)
}

fn read_u128(data: &[u8], pos: &mut usize) -> u128 {
    let mut out = [0u8; 16];

    for b in &mut out {
        *b = read_u8(data, pos);
    }

    u128::from_le_bytes(out)
}

fn read_hash(data: &[u8], pos: &mut usize) -> Hash64 {
    let mut out = [0u8; 64];

    for b in &mut out {
        *b = read_u8(data, pos);
    }

    out
}

fn read_bytes(data: &[u8], pos: &mut usize, max: usize) -> Vec<u8> {
    let requested = usize::from(read_u8(data, pos));
    let len = requested.min(max);

    let mut out = Vec::with_capacity(len);

    for _ in 0..len {
        out.push(read_u8(data, pos));
    }

    out
}

fn make_peer(seed: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes.fill(seed);

    let keypair = identity::Keypair::ed25519_from_bytes(bytes)
        .unwrap_or_else(|_| identity::Keypair::generate_ed25519());

    PeerId::from(keypair.public())
}

fn synth_batch(data: &[u8], pos: &mut usize) -> TransactionBatch {
    let count = usize::from(read_u8(data, pos) % 16);
    let mut txs = Vec::with_capacity(count);

    for _ in 0..count {
        txs.push(read_bytes(data, pos, 512));
    }

    TransactionBatch { txs }
}

fn synth_block_with_root(
    data: &[u8],
    pos: &mut usize,
    index: u64,
    previous_hash: Hash64,
    merkle_root: Hash64,
) -> Block {
    let payload = read_bytes(data, pos, 1024);

    let metadata = BlockMetadata {
        index,
        previous_hash,
        merkle_root,
    };

    let block_hash = Block::compute_block_hash(&metadata, &payload);

    Block {
        metadata,
        block_hash,
        payload,
    }
}

fn synth_block(data: &[u8], pos: &mut usize, index: u64, previous_hash: Hash64) -> Block {
    let merkle_root = read_hash(data, pos);
    synth_block_with_root(data, pos, index, previous_hash, merkle_root)
}

fn fuzz_block_bytes(data: &[u8]) {
    if data.len() > MAX_BLOCK_SIZE {
        return;
    }

    let _ = Block::deserialize_from_storage(data);
    let _ = Block::deserialize_with_sizes(data);

    if let Ok(block) = Block::deserialize_from_storage(data) {
        if block.payload.len() > MAX_BLOCK_SIZE {
            return;
        }

        let _ = block.validate(None);
        let _ = block.verify_block_hash();
        let _ = block.serialize_for_storage();
        let _ = block.encoded_len_unpadded();
        let _ = block.encoded_len_padded();
        let _ = block.hash_hex();
    }
}

fn fuzz_batch_bytes(data: &[u8]) {
    if data.len() > MAX_BLOCK_SIZE {
        return;
    }

    let _ = TransactionBatch::deserialize(data);

    if let Ok(batch) = TransactionBatch::deserialize(data) {
        let _ = batch.compute_merkle_root();
        let _ = batch.serialize();
    }
}

fn fuzz_reqresp_postcard(data: &[u8]) {
    if data.len() > MAX_BLOCK_SIZE {
        return;
    }

    let _ = take_from_bytes::<BlockTxRequest>(data);
    let _ = take_from_bytes::<BlockTxResponse>(data);

    if let Ok((req, rest)) = take_from_bytes::<BlockTxRequest>(data) {
        let _ = to_allocvec(&req);
        let _ = rest.len();
    }

    if let Ok((resp, rest)) = take_from_bytes::<BlockTxResponse>(data) {
        match &resp {
            BlockTxResponse::BlockData(block) => {
                if block.payload.len() <= MAX_BLOCK_SIZE {
                    let _ = block.serialize_for_storage();
                    let _ = block.validate(None);
                }
            }
            BlockTxResponse::BatchData(bytes) => {
                if bytes.len() <= MAX_BLOCK_SIZE {
                    let _ = TransactionBatch::deserialize(bytes);
                }
            }
            BlockTxResponse::TxData(bytes) => {
                let _ = bytes.len() <= MAX_BLOCK_SIZE;
            }
            BlockTxResponse::NotFound => {}
        }

        let _ = to_allocvec(&resp);
        let _ = rest.len();
    }
}

fn fuzz_last_resort(data: &[u8], pos: &mut usize) {
    let now = Instant::now();

    let cfg = LastResortConfig {
        peer_bucket_capacity: u64::from(read_u8(data, pos)).max(1),
        peer_refill_per_sec: u64::from(read_u8(data, pos)),

        enable_ip_bucket: read_u8(data, pos) & 1 == 1,
        ip_bucket_capacity: u64::from(read_u8(data, pos)).max(1),
        ip_refill_per_sec: u64::from(read_u8(data, pos)),

        max_inflight_per_peer: u64::from(read_u8(data, pos)).max(1),
        max_inflight_global: u64::from(read_u8(data, pos)).max(1),

        dup_window: Duration::from_millis(u64::from(read_u8(data, pos))),
        dup_max_entries_per_peer: usize::from(read_u8(data, pos)).max(1),

        peer_bytes_capacity: read_u64(data, pos).max(1),
        peer_bytes_refill_per_sec: read_u64(data, pos),
        global_bytes_capacity: read_u64(data, pos).max(1),
        global_bytes_refill_per_sec: read_u64(data, pos),

        badness_threshold: i32::from(read_u8(data, pos)).max(1),
        cooldown: Duration::from_millis(u64::from(read_u8(data, pos))),
        badness_decay_per_sec: i32::from(read_u8(data, pos)),

        ..LastResortConfig::default()
    };

    let mut guards = LastResortGuards::new(cfg, now);
    let peer = make_peer(read_u8(data, pos));

    for i in 0..32u64 {
        let action = match read_u8(data, pos) % 7 {
            0 => ActionClass::Version,
            1 => ActionClass::BlockTxGetBlock,
            2 => ActionClass::BlockTxGetBatch,
            3 => ActionClass::BlockTxGetTx,
            4 => ActionClass::Gossip,
            5 => ActionClass::Kad,
            _ => ActionClass::Identify,
        };

        let dup_key = if read_u8(data, pos) & 1 == 1 {
            Some(LastResortGuards::dup_key_from_str(match action {
                ActionClass::Version => "Version",
                ActionClass::BlockTxGetBlock => "GetBlock",
                ActionClass::BlockTxGetBatch => "GetBatch",
                ActionClass::BlockTxGetTx => "GetTx",
                ActionClass::Gossip => "Gossip",
                ActionClass::Kad => "Kad",
                ActionClass::Identify => "Identify",
            }))
        } else {
            Some(i)
        };

        let decision = guards.check_action(LastResortActionRequest {
            now: now + Duration::from_millis(u64::from(read_u8(data, pos))),
            peer_id: peer,
            admitted: read_u8(data, pos) & 1 == 1,
            action,
            cost_tokens: u32::from(read_u8(data, pos)).max(1),
            dup_key,
        });

        match decision {
            LastResortDecision::Allow => {
                let _ = guards.try_begin_inflight(now, &peer);
                let _ = guards.check_bytes(now, peer, read_u64(data, pos));
                guards.finish_inflight(&peer);
            }
            LastResortDecision::Drop(_) => {
                guards.report_misbehavior(now, peer, i32::from(read_u8(data, pos)).max(1));
            }
        }
    }

    guards.on_peer_disconnected(peer);
}

fn fuzz_branch_score(data: &[u8], pos: &mut usize) {
    let current_hash = read_hash(data, pos);
    let candidate_hash = read_hash(data, pos);

    let current = BranchCandidate::new(current_hash, read_u64(data, pos), read_u128(data, pos));
    let candidate = BranchCandidate::new(candidate_hash, read_u64(data, pos), read_u128(data, pos));

    let cfg = BranchScoreConfig {
        mode: if read_u8(data, pos) & 1 == 1 {
            BranchScoreMode::CumulativePor
        } else {
            BranchScoreMode::HeightOnly
        },
        allow_equal_height_tiebreak: read_u8(data, pos) & 1 == 1,
        prefer_lower_hash_on_tie: read_u8(data, pos) & 1 == 1,
    };

    let scorer = ReorgBranchScorer::new(cfg);
    let _ = scorer.choose_tip(current, candidate);
    let _ = scorer.candidate_beats_current(current, candidate);
}

fn fuzz_hydration(data: &[u8], pos: &mut usize) {
    let cfg = HydrationConfig {
        max_retries_per_hash: read_u8(data, pos).max(1),
        retry_cooldown: Duration::from_millis(u64::from(read_u8(data, pos))),
        max_tracked_hashes: usize::from(read_u8(data, pos)).max(1),
        auto_chase_parent: read_u8(data, pos) & 1 == 1,
    };

    let mut hydration = Hydration::new(cfg.clone());
    let peer = make_peer(read_u8(data, pos));

    for _ in 0..64 {
        let hash = read_hash(data, pos);
        let height = Some(read_u64(data, pos));

        let reason = match read_u8(data, pos) % 3 {
            0 => HydrationReason::ForkChoiceNeedMoreData,
            1 => HydrationReason::MissingParent,
            _ => HydrationReason::Explicit,
        };

        hydration.note_need_more_data(peer, hash, height, reason, "memory fuzz hydration");

        if cfg.auto_chase_parent && read_u8(data, pos) & 1 == 1 {
            let child = read_hash(data, pos);
            hydration.note_child_waiting_on_parent(hash, child);
        }

        let _ = hydration.next_request();
        let _ = hydration.tracked_len();
        let _ = hydration.inflight_len();
        let _ = hydration.is_tracking(&hash);
        let _ = hydration.is_inflight_hash(&hash);

        if read_u8(data, pos) & 1 == 1 {
            hydration.clear_if_known(&hash);
        }
    }

    hydration.on_peer_disconnected(peer);
    let _ = hydration.snapshot_lines();
}

fn fuzz_memory_sync_handlers(data: &[u8], pos: &mut usize) {
    let now = Instant::now();
    let mut harness = MemorySyncHarness::new(now);

    let peer_a = make_peer(read_u8(data, pos));
    let peer_b = make_peer(read_u8(data, pos));

    harness.admitted_peers.insert(peer_a);
    harness.pq_ready_peers.insert(peer_a);

    if read_u8(data, pos) & 1 == 1 {
        harness.admitted_peers.insert(peer_b);
    }

    if read_u8(data, pos) & 1 == 1 {
        harness.pq_ready_peers.insert(peer_b);
    }

    harness.sync_target = read_u64(data, pos) % 256;

    for _ in 0..32 {
        let op = read_u8(data, pos) % 11;

        match op {
            0 => {
                let raw = data.get(*pos..).unwrap_or(&[]);

                if let Ok(block) = Block::deserialize_from_storage(raw) {
                    harness.handle_block_tx_response_memory(
                        peer_a,
                        block.metadata.index,
                        MAX_RETRIES,
                        BlockTxResponse::BlockData(Box::new(block)),
                    );
                } else {
                    harness.handle_block_tx_response_memory(
                        peer_a,
                        read_u64(data, pos),
                        MAX_RETRIES,
                        BlockTxResponse::NotFound,
                    );
                }
            }

            1 => {
                let idx = read_u64(data, pos) % 256;

                let expected = if read_u8(data, pos) & 1 == 1 {
                    Some(read_hash(data, pos))
                } else {
                    None
                };

                let bytes = data.get(*pos..).unwrap_or(&[]).to_vec();

                harness.handle_batch_tx_response_memory(
                    MemoryBatchTxResponseContext {
                        origin_peer: peer_a,
                        idx,
                        expected_block_hash: expected,
                        retries_left: MAX_RETRIES,
                    },
                    BlockTxResponse::BatchData(bytes),
                );
            }

            2 => {
                harness.handle_block_tx_response_memory(
                    peer_a,
                    read_u64(data, pos) % 256,
                    read_u8(data, pos),
                    BlockTxResponse::NotFound,
                );
            }

            3 => {
                harness.handle_batch_tx_response_memory(
                    MemoryBatchTxResponseContext {
                        origin_peer: peer_a,
                        idx: read_u64(data, pos) % 256,
                        expected_block_hash: None,
                        retries_left: read_u8(data, pos),
                    },
                    BlockTxResponse::NotFound,
                );
            }

            4 => {
                let hash = read_hash(data, pos);
                let _ = harness.handle_fork_memory(hash);
            }

            5 => {
                harness.cleanup_pending_for_peer_memory(peer_a, read_u8(data, pos) & 1 == 1);
            }

            6 => {
                harness.push_block_retry(peer_a, read_u64(data, pos) % 256, read_u8(data, pos));
            }

            7 => {
                let expected = if read_u8(data, pos) & 1 == 1 {
                    Some(read_hash(data, pos))
                } else {
                    None
                };

                harness.push_batch_retry(
                    peer_a,
                    read_u64(data, pos) % 256,
                    expected,
                    read_u8(data, pos),
                );
            }

            8 => {
                let tip_height = harness.tip_height();
                let prev = harness
                    .canonical_hash_at_height(tip_height)
                    .unwrap_or(ZERO_HASH_64);

                let idx = if harness.canonical_blocks_by_height.is_empty() {
                    0
                } else {
                    tip_height.saturating_add(1)
                };

                let prev_hash = if idx == 0 { ZERO_HASH_64 } else { prev };
                let block = synth_block(data, pos, idx, prev_hash);

                harness.handle_block_tx_response_memory(
                    peer_a,
                    idx,
                    MAX_RETRIES,
                    BlockTxResponse::BlockData(Box::new(block)),
                );
            }

            9 => {
                let batch = synth_batch(data, pos);
                let root = batch.compute_merkle_root().unwrap_or(ZERO_HASH_64);
                let batch_bytes = batch.serialize().unwrap_or_default();

                let tip_height = harness.tip_height();
                let prev = harness
                    .canonical_hash_at_height(tip_height)
                    .unwrap_or(ZERO_HASH_64);

                let idx = if harness.canonical_blocks_by_height.is_empty() {
                    0
                } else {
                    tip_height.saturating_add(1)
                };

                let prev_hash = if idx == 0 { ZERO_HASH_64 } else { prev };
                let block = synth_block_with_root(data, pos, idx, prev_hash, root);

                harness.handle_block_tx_response_memory(
                    peer_a,
                    idx,
                    MAX_RETRIES,
                    BlockTxResponse::BlockData(Box::new(block.clone())),
                );

                harness.handle_batch_tx_response_memory(
                    MemoryBatchTxResponseContext {
                        origin_peer: peer_a,
                        idx,
                        expected_block_hash: None,
                        retries_left: MAX_RETRIES,
                    },
                    BlockTxResponse::BatchData(batch_bytes),
                );
            }

            _ => {
                harness.drain_some_retries_memory();
            }
        }

        harness.update_sync_state();
    }

    let _ = harness.pick_known_hydration_peer();
    let _ = harness.branch_hydration_active();
    let _ = harness.tip_height();
    let _ = harness.block_retries.len();
    let _ = harness.batch_retries.len();
}

fn fuzz_consensus_caps(data: &[u8], pos: &mut usize) {
    let len = usize::try_from(read_u64(data, pos)).unwrap_or(usize::MAX);

    if len > MAX_BLOCK_SIZE {
        return;
    }

    let bounded = data.get(..data.len().min(MAX_BLOCK_SIZE)).unwrap_or(data);

    fuzz_batch_bytes(bounded);
    fuzz_block_bytes(bounded);
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut pos = 0usize;
    let mode = read_u8(data, &mut pos) % 8;

    match mode {
        0 => fuzz_block_bytes(data),
        1 => fuzz_batch_bytes(data),
        2 => fuzz_reqresp_postcard(data),
        3 => fuzz_last_resort(data, &mut pos),
        4 => fuzz_branch_score(data, &mut pos),
        5 => fuzz_hydration(data, &mut pos),
        6 => fuzz_memory_sync_handlers(data, &mut pos),
        _ => fuzz_consensus_caps(data, &mut pos),
    }
});