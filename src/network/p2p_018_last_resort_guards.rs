use libp2p::PeerId;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::network::p2p_019_inflight_limiter::{
    InflightDecision, InflightDrop, InflightLimiter, InflightPermit,
};
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

/* ─────────────────────────────────────────────────────────────
   Production knobs / hard bounds (pure networking wiring)
───────────────────────────────────────────────────────────── */

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const MAX_TRACKED_PEERS: usize = 7_500;
const MAX_TRACKED_IPS: usize = 7_500;

#[inline(always)]
fn consensus_max_block_bytes_u64() -> u64 {
    // Fall back to 1 MiB if the configured value is ever zero; this is wiring-only.
    if GlobalConfiguration::MAX_BLOCK_SIZE == 0 {
        MIB
    } else {
        GlobalConfiguration::MAX_BLOCK_SIZE
    }
}

/// What to do when a guard check fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastResortDecision {
    Allow,
    Drop(LastResortDrop),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastResortDrop {
    NotAdmitted,
    PeerRateLimited,
    IpRateLimited,
    PeerInflightCap,
    GlobalInflightCap,
    DuplicateRequest,
    PeerByteBudgetExceeded,
    GlobalByteBudgetExceeded,
    PeerCoolingDown,
    CounterOverflow,
}

/// Actions / “cost domains” you want to rate-limit.
/// Keep this small and coarse; don’t overfit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionClass {
    Version,
    BlockTxGetBlock,
    BlockTxGetBatch,
    BlockTxGetTx,
    Gossip,
    Kad,
    Identify,
}

#[derive(Debug, Clone)]
pub struct LastResortActionRequest {
    pub now: Instant,
    pub peer_id: PeerId,
    pub admitted: bool,
    pub peer_ip: Option<IpAddr>,
    pub action: ActionClass,
    pub cost_tokens: u32,
    pub dup_key: Option<u64>,
}

/// Guards config knobs.
/// Defaults are production-friendly and future-proof (byte budgets scale with MAX_BLOCK_SIZE).
#[derive(Debug, Clone)]
pub struct LastResortConfig {
    /// If a peer is not admitted, drop requests of these classes.
    /// (You can allow Version/Identify even pre-admission.)
    pub require_admission_for: Vec<ActionClass>,

    /// Per-peer token bucket: max tokens and refill rate (tokens per second).
    pub peer_bucket_capacity: u32,
    pub peer_refill_per_sec: u32,

    /// Optional per-IP token bucket (helps against PeerId churn).
    pub enable_ip_bucket: bool,
    pub ip_bucket_capacity: u32,
    pub ip_refill_per_sec: u32,

    /// In-flight request caps.
    pub max_inflight_per_peer: u32,
    pub max_inflight_global: u32,

    /// Duplicate suppression window (per peer): store keys briefly.
    pub dup_window: Duration,
    pub dup_max_entries_per_peer: usize,

    /// Byte budgets (per-second-ish token bucket but in bytes).
    /// Use this for outgoing responses and/or expensive payload reception.
    pub peer_bytes_capacity: u64,
    pub peer_bytes_refill_per_sec: u64,
    pub global_bytes_capacity: u64,
    pub global_bytes_refill_per_sec: u64,

    /// Misbehavior scoring
    pub badness_threshold: i32,
    pub cooldown: Duration,
    pub badness_decay_per_sec: i32,
}

impl Default for LastResortConfig {
    fn default() -> Self {
        let max_block = consensus_max_block_bytes_u64();

        // These match the “production” numbers you listed when MAX_BLOCK_SIZE ≈ 1 MiB:
        let peer_bytes_capacity = max_block.saturating_mul(16).max(16 * MIB);
        let peer_bytes_refill_per_sec = max_block.saturating_mul(2).max(2 * MIB);

        let global_bytes_capacity = peer_bytes_capacity.saturating_mul(8).max(128 * MIB);
        let global_bytes_refill_per_sec = peer_bytes_refill_per_sec.saturating_mul(8).max(16 * MIB);

        Self {
            // Typical: require admission for anything that hits DB or heavy parsing.
            require_admission_for: vec![
                ActionClass::BlockTxGetBlock,
                ActionClass::BlockTxGetBatch,
                ActionClass::BlockTxGetTx,
            ],

            // higher burst + higher sustained to avoid sync stalls.
            // peer: burst 600, sustained 200 tokens/sec
            peer_bucket_capacity: 600,
            peer_refill_per_sec: 200,

            // per-IP bucket to resist PeerId churn.
            // NOTE: honest nodes behind one NAT, lower strictness
            // by increasing these further or disabling enable_ip_bucket.
            enable_ip_bucket: true,
            ip_bucket_capacity: 6000,
            ip_refill_per_sec: 600,

            // inflight caps as concurrency circuit breakers.
            max_inflight_per_peer: 64,
            max_inflight_global: 2048,

            // short dup window (prevents spammy tight loops, doesn’t break normal retries).
            dup_window: Duration::from_millis(100),
            dup_max_entries_per_peer: 1024,

            // future-proof byte budgets.
            peer_bytes_capacity,
            peer_bytes_refill_per_sec,
            global_bytes_capacity,
            global_bytes_refill_per_sec,

            // Misbehavior scoring stays conservative.
            badness_threshold: 100,
            cooldown: Duration::from_secs(120),
            badness_decay_per_sec: 5,
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Integer-only refill helpers (clippy::float_arithmetic safe)
───────────────────────────────────────────────────────────── */

#[inline(always)]
fn refill_add_u64(dt: Duration, per_sec: u64) -> u64 {
    if per_sec == 0 {
        return 0;
    }

    // Integer approximation of: per_sec * (dt_secs + dt_nanos/1e9)
    let secs = dt.as_secs();
    let nanos = u64::from(dt.subsec_nanos());

    let whole = secs.saturating_mul(per_sec);
    let frac = nanos
        .saturating_mul(per_sec)
        .checked_div(1_000_000_000)
        .unwrap_or(0);

    whole.saturating_add(frac)
}

#[inline(always)]
fn refill_add_u32(dt: Duration, per_sec: u32) -> u32 {
    let add_u64 = refill_add_u64(dt, u64::from(per_sec));
    u32::try_from(add_u64).unwrap_or(u32::MAX)
}

/// Simple token bucket for u32 tokens.
#[derive(Debug, Clone)]
struct Bucket32 {
    tokens: u32,
    cap: u32,
    refill_per_sec: u32,
    last: Instant,
}

impl Bucket32 {
    fn new(cap: u32, refill_per_sec: u32, now: Instant) -> Self {
        Self {
            tokens: cap,
            cap,
            refill_per_sec,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.duration_since(self.last);
        self.last = now;

        let add = refill_add_u32(dt, self.refill_per_sec);
        self.tokens = self.tokens.saturating_add(add).min(self.cap);
    }

    fn try_take(&mut self, now: Instant, cost: u32) -> bool {
        self.refill(now);
        if self.tokens >= cost {
            self.tokens = self.tokens.saturating_sub(cost);
            true
        } else {
            false
        }
    }
}

/// Byte bucket for u64 “byte tokens”.
#[derive(Debug, Clone)]
struct Bucket64 {
    tokens: u64,
    cap: u64,
    refill_per_sec: u64,
    last: Instant,
}

impl Bucket64 {
    fn new(cap: u64, refill_per_sec: u64, now: Instant) -> Self {
        Self {
            tokens: cap,
            cap,
            refill_per_sec,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.duration_since(self.last);
        self.last = now;

        let add = refill_add_u64(dt, self.refill_per_sec);
        self.tokens = self.tokens.saturating_add(add).min(self.cap);
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

/// Used for duplicate suppression.
/// Key should be cheap to compute (e.g., "GetBlockByIndex:12345").
#[derive(Debug, Clone)]
struct RecentKeys {
    q: VecDeque<(u64, Instant)>,
}

impl RecentKeys {
    fn new() -> Self {
        Self { q: VecDeque::new() }
    }

    fn prune(&mut self, now: Instant, window: Duration) {
        while let Some((_, t)) = self.q.front().copied() {
            if now.duration_since(t) > window {
                self.q.pop_front();
            } else {
                break;
            }
        }
    }

    fn contains(&self, h: u64) -> bool {
        self.q.iter().any(|(x, _)| *x == h)
    }

    fn push(&mut self, h: u64, now: Instant, max: usize) {
        self.q.push_back((h, now));
        while self.q.len() > max {
            self.q.pop_front();
        }
    }
}

/// Per-peer state.
#[derive(Debug, Clone)]
struct PeerState {
    bucket: Bucket32,
    bytes: Bucket64,
    recent: RecentKeys,
    badness: i32,
    last_decay: Instant,
    cooldown_until: Option<Instant>,
}

impl PeerState {
    fn new(cfg: &LastResortConfig, now: Instant) -> Self {
        Self {
            bucket: Bucket32::new(cfg.peer_bucket_capacity, cfg.peer_refill_per_sec, now),
            bytes: Bucket64::new(cfg.peer_bytes_capacity, cfg.peer_bytes_refill_per_sec, now),
            recent: RecentKeys::new(),
            badness: 0,
            last_decay: now,
            cooldown_until: None,
        }
    }

    fn decay_badness(&mut self, cfg: &LastResortConfig, now: Instant) {
        let dt = now.duration_since(self.last_decay);
        self.last_decay = now;

        if cfg.badness_decay_per_sec <= 0 {
            return;
        }

        let dec_u64 = refill_add_u64(dt, u64::try_from(cfg.badness_decay_per_sec).unwrap_or(0));
        let dec = i32::try_from(dec_u64).unwrap_or(i32::MAX);

        self.badness = self.badness.saturating_sub(dec).max(0);
    }

    fn add_badness(&mut self, cfg: &LastResortConfig, now: Instant, points: i32) {
        self.decay_badness(cfg, now);
        self.badness = self.badness.saturating_add(points);
        if self.badness >= cfg.badness_threshold {
            self.cooldown_until = now.checked_add(cfg.cooldown);
            // Keep badness from growing unbounded.
            self.badness = cfg.badness_threshold;
        }
    }

    fn is_cooling_down(&mut self, cfg: &LastResortConfig, now: Instant) -> bool {
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
}

/// Decision for in-flight acquisition: Allow returns an RAII permit.
pub enum LastResortInflightDecision {
    Allow(InflightPermit),
    Drop(LastResortDrop),
}

/// The “last resort” guard engine.
#[derive(Debug)]
pub struct LastResortGuards {
    cfg: LastResortConfig,

    peer: HashMap<PeerId, PeerState>,
    ip: HashMap<IpAddr, Bucket32>,

    bytes_global: Bucket64,

    // RAII permit-based inflight limiter (no manual end_inflight).
    inflight: InflightLimiter,
}

impl LastResortGuards {
    pub fn new(cfg: LastResortConfig, now: Instant) -> Self {
        let inflight = InflightLimiter::new(cfg.max_inflight_per_peer, cfg.max_inflight_global);

        Self {
            bytes_global: Bucket64::new(
                cfg.global_bytes_capacity,
                cfg.global_bytes_refill_per_sec,
                now,
            ),
            inflight,
            cfg,
            peer: HashMap::new(),
            ip: HashMap::new(),
        }
    }

    pub fn cfg(&self) -> &LastResortConfig {
        &self.cfg
    }

    /// Call on disconnect to clean state (optional but helps memory).
    pub fn on_peer_disconnected(&mut self, peer: PeerId) {
        self.peer.remove(&peer);
    }

    #[inline(always)]
    fn bound_maps(&mut self) {
        if self.peer.len() > MAX_TRACKED_PEERS {
            self.peer.clear();
        }
        if self.ip.len() > MAX_TRACKED_IPS {
            self.ip.clear();
        }
    }

    #[inline(always)]
    fn is_sync_retrieval_action(action: ActionClass) -> bool {
        matches!(
            action,
            ActionClass::BlockTxGetBlock | ActionClass::BlockTxGetBatch | ActionClass::BlockTxGetTx
        )
    }

    /// Decide whether to allow an incoming “action” from a peer.
    pub fn check_action(&mut self, req: LastResortActionRequest) -> LastResortDecision {
        self.bound_maps();

        let LastResortActionRequest {
            now,
            peer_id,
            admitted,
            peer_ip,
            action,
            cost_tokens,
            dup_key,
        } = req;

        // Admission gating (cheap).
        if !admitted && self.cfg.require_admission_for.contains(&action) {
            return LastResortDecision::Drop(LastResortDrop::NotAdmitted);
        }

        let ps = self
            .peer
            .entry(peer_id)
            .or_insert_with(|| PeerState::new(&self.cfg, now));

        if ps.is_cooling_down(&self.cfg, now) {
            return LastResortDecision::Drop(LastResortDrop::PeerCoolingDown);
        }

        // Duplicate suppression
        if let Some(k) = dup_key {
            ps.recent.prune(now, self.cfg.dup_window);

            let is_duplicate = ps.recent.contains(k);
            let is_sync_action = Self::is_sync_retrieval_action(action);

            if is_duplicate && !is_sync_action {
                // For non-sync protocol surfaces, duplicates can indicate spam.
                ps.add_badness(&self.cfg, now, 2);
                return LastResortDecision::Drop(LastResortDrop::DuplicateRequest);
            }

            if !is_duplicate {
                ps.recent.push(k, now, self.cfg.dup_max_entries_per_peer);
            }
        }

        let cost = cost_tokens.max(1);

        // Per-peer rate limit
        if !ps.bucket.try_take(now, cost) {
            ps.add_badness(&self.cfg, now, 3);
            return LastResortDecision::Drop(LastResortDrop::PeerRateLimited);
        }

        // Optional per-IP rate limit (helps against PeerId churn)
        if self.cfg.enable_ip_bucket
            && let Some(ip) = peer_ip
        {
            let b = self.ip.entry(ip).or_insert_with(|| {
                Bucket32::new(self.cfg.ip_bucket_capacity, self.cfg.ip_refill_per_sec, now)
            });

            if !b.try_take(now, cost) {
                ps.add_badness(&self.cfg, now, 2);
                return LastResortDecision::Drop(LastResortDrop::IpRateLimited);
            }
        }

        LastResortDecision::Allow
    }

    /// Track in-flight requests (RAII).
    pub fn try_begin_inflight(
        &mut self,
        now: Instant,
        peer_id: &PeerId,
    ) -> LastResortInflightDecision {
        self.bound_maps();

        let ps = self
            .peer
            .entry(*peer_id)
            .or_insert_with(|| PeerState::new(&self.cfg, now));

        if ps.is_cooling_down(&self.cfg, now) {
            return LastResortInflightDecision::Drop(LastResortDrop::PeerCoolingDown);
        }

        match self.inflight.try_acquire(peer_id) {
            InflightDecision::Allow(permit) => LastResortInflightDecision::Allow(permit),

            InflightDecision::Drop(InflightDrop::PeerCap) => {
                ps.add_badness(&self.cfg, now, 4);
                LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
            }

            InflightDecision::Drop(InflightDrop::GlobalCap) => {
                ps.add_badness(&self.cfg, now, 1);
                LastResortInflightDecision::Drop(LastResortDrop::GlobalInflightCap)
            }
        }
    }

    /// Enforce bandwidth/byte budgets (use for sending responses or accepting big payloads).
    pub fn check_bytes(&mut self, now: Instant, peer_id: PeerId, bytes: u64) -> LastResortDecision {
        self.bound_maps();

        let ps = self
            .peer
            .entry(peer_id)
            .or_insert_with(|| PeerState::new(&self.cfg, now));

        if ps.is_cooling_down(&self.cfg, now) {
            return LastResortDecision::Drop(LastResortDrop::PeerCoolingDown);
        }

        if !ps.bytes.try_take(now, bytes) {
            ps.add_badness(&self.cfg, now, 5);
            return LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded);
        }

        if !self.bytes_global.try_take(now, bytes) {
            ps.add_badness(&self.cfg, now, 2);
            return LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded);
        }

        LastResortDecision::Allow
    }

    /// Mark a peer as misbehaving (invalid data, bad merkle, protocol violation).
    pub fn report_misbehavior(&mut self, now: Instant, peer_id: PeerId, points: i32) {
        self.bound_maps();

        let ps = self
            .peer
            .entry(peer_id)
            .or_insert_with(|| PeerState::new(&self.cfg, now));
        ps.add_badness(&self.cfg, now, points.max(1));
    }

    /// Helper: build a cheap duplicate key hash (FNV-1a 64).
    /// Use stable strings like "GetBlockByIndex:12345".
    pub fn dup_key_from_str(s: &str) -> u64 {
        const FNV_OFFSET: u64 = 14695981039346656037;
        const FNV_PRIME: u64 = 1099511628211;
        let mut h = FNV_OFFSET;
        for &b in s.as_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }
}
