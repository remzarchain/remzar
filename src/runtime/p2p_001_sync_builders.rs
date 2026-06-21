//! p2p_001_sync_builders

use crate::blockchain::mempool::MemPool;
use crate::network::p2p_005_pq_fips203kem::PqKemManager;
use crate::network::p2p_007_handshake::{PqInitiatorState, build_default_pq_manager};
use crate::network::p2p_009_events::kad_ready_addrs;
use crate::reorganization::reorg_006_manager::ReorgManager;
use crate::reorganization::reorg_007_branch_hydration::Hydration;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::time_policy::TimePolicy;
use crate::{
    blockchain::transaction_005_tx_account_tree::AccountModelTree,
    network::{
        p2p_003_behaviour::RemzarBehaviour,
        p2p_006_reqresp::Hash,
        p2p_008_broadcast::REGISTER_TOPIC_STR,
        p2p_011_peerbook::PeerBook,
        p2p_012_janitor_peerbook::JanitorBook,
        p2p_017_conn_guard::{ConnGuard, ConnGuardConfig},
        p2p_018_last_resort_guards::{LastResortConfig, LastResortGuards},
    },
    storage::rocksdb_005_manager::RockDBManager,
};

use libp2p::identity;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, request_response::OutboundRequestId, swarm::Swarm};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const REGISTRATION_TOPIC: &str = REGISTER_TOPIC_STR;

pub(super) const MAX_RETRIES: u8 = 3;

pub const REMZAR_HASH_BYTES_LEN: usize = 64;
pub type RemzarHashBytes = Hash;

pub(super) const ZERO_HASH_64: RemzarHashBytes = [0u8; 64];

#[inline(always)]
pub(super) fn genesis_hash_bytes_64() -> RemzarHashBytes {
    const GENESIS_HASH_BYTES_64: RemzarHashBytes = hex_literal::hex!(
        "48ca1f065debb4f4291f1423c3e9da446635e6fbc39e169c2c7b4dfb25b310c95143bc31ab6afb7e63a861abb4807dfc50611765337aa459e3470f682d210e66"
    );
    GENESIS_HASH_BYTES_64
}

/// Global autodial tick throttle (ms)
pub(super) const AUTODIAL_PERIOD_MS: u128 = 10_000;

/// Per-peer redial cooldown (ms)
pub(super) const AUTODIAL_RETRY_PEER_MS: u128 = 12_000;

/// Kad bootstrap throttle (ms)
pub(super) const KAD_BOOTSTRAP_PERIOD_MS: u128 = 20_000;

/// Kad random-walk throttle (ms)
pub(super) const KAD_RANDOM_WALK_PERIOD_MS: u128 = 15_000;

/* ─────────────────────────────────────────────────────────────
Defensive safety caps (no crypto impact)
───────────────────────────────────────────────────────────── */

pub(super) const MAX_PENDING_VERSIONS: usize = 512;
pub(super) const MAX_PENDING_PQ: usize = 512;
pub(super) const MAX_PENDING_BLOCKS: usize = 512;
pub(super) const MAX_PENDING_BATCHES: usize = 512;

pub(super) const MAX_BLOCK_QUEUE: usize = 1024;
pub(super) const MAX_BATCH_QUEUE: usize = 1024;

pub(super) const MAX_HEIGHT_POLL_PEERS: usize = 128;
pub(super) const MAX_AUTODIAL_PEERS_PER_TICK: usize = 32;
pub(super) const MAX_AUTODIAL_ADDRS_PER_PEER: usize = 3;
pub(super) const MAX_MULTIADDR_BYTES: usize = 256;

/// Cap how many PeerBook entries are examined when seeding Kad.
pub(super) const MAX_PEERBOOK_KAD_SEED_PEERS: usize = 256;

/// Cap how many Kad-ready addresses are added per peer per maintenance pass.
pub(super) const MAX_KAD_ADDRS_PER_PEER: usize = 8;

/// Cap remembered per-peer dial timestamps; this map is advisory and may be pruned.
pub(super) const MAX_TRACKED_DIAL_ATTEMPTS: usize = 4096;

/// Cap live PQ-ready/admission/IP side tables. Last-resort/ConnGuard remain authoritative.
pub(super) const MAX_RUNTIME_PEER_SIDE_TABLES: usize = 8192;

/* ─────────────────────────────────────────────────────────────
Consensus-cap helpers
───────────────────────────────────────────────────────────── */

#[inline(always)]
fn consensus_max_bytes() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
}

#[inline(always)]
pub(super) fn exceeds_consensus_cap(n: usize) -> bool {
    n > consensus_max_bytes()
}

#[inline(always)]
pub(super) fn log_consensus_drop(label: &str, idx: u64, peer: &PeerId, n: usize) {
    let _ = (label, idx, peer, n);
}

#[inline(always)]
pub(super) fn usize_to_u64_saturating(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[inline(always)]
pub(super) fn ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }

    None
}

#[inline(always)]
pub(super) fn multiaddr_within_bounds(addr: &Multiaddr) -> bool {
    let len = addr.to_vec().len();
    len > 0 && len <= MAX_MULTIADDR_BYTES
}

fn dedup_multiaddrs_bounded(
    addrs: impl IntoIterator<Item = Multiaddr>,
    max_addrs: usize,
) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    let mut seen = HashSet::<String>::new();

    for addr in addrs {
        if out.len() >= max_addrs {
            break;
        }

        if !multiaddr_within_bounds(&addr) {
            continue;
        }

        let key = addr.to_string();
        if seen.insert(key) {
            out.push(addr);
        }
    }

    out
}

fn kad_ready_addrs_bounded(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    dedup_multiaddrs_bounded(kad_ready_addrs(addrs), MAX_KAD_ADDRS_PER_PEER)
}

// ────────────────────────────────────────────────
// Pending sync request tracking types
// ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PendingBatchRequest {
    pub peer: PeerId,
    pub idx: u64,
    pub retries_left: u8,
    pub expected_block_hash: Option<RemzarHashBytes>,
}

// ────────────────────────────────────────────────
// Data structure
// ────────────────────────────────────────────────
pub struct P2pSync {
    pub chain: AccountModelTree,
    pub db: Arc<RockDBManager>,
    pub mempool: Arc<MemPool>,

    pub(super) syncing: bool,
    pub has_synced: bool,
    pub total_to_download: u64,
    pub downloaded: u64,

    // Existing handshake / sync tracking
    pub pending_versions: HashMap<OutboundRequestId, PeerId>,

    // PQ handshake state
    pub pending_pq: HashMap<OutboundRequestId, PeerId>,
    pub pq_manager: PqKemManager,
    pub pq_initiators: HashMap<PeerId, PqInitiatorState>,
    pub pq_ready_peers: HashSet<PeerId>,

    // Active sync request tracking
    pub pending_blocks: HashMap<OutboundRequestId, (PeerId, u64, u8)>,
    pub pending_batches: HashMap<OutboundRequestId, PendingBatchRequest>,
    pub block_queue: VecDeque<(PeerId, u64, u8)>,
    pub batch_queue: VecDeque<(PeerId, u64, u8)>,

    // Reservation tracking
    pub(crate) reserved_block_indices: HashSet<u64>,
    pub(crate) reserved_batch_indices: HashSet<u64>,

    pub tried_genesis: bool,
    pub expected_genesis_hash: Option<String>,

    pub(super) last_synced_hash: Option<RemzarHashBytes>,
    pub(super) last_synced_index: Option<u64>,

    /// Highest known target height we should sync toward.
    pub(super) sync_target: u64,

    /// Target height discovered before PQ is ready.
    pub(super) queued_sync_target: Option<u64>,

    pub(super) last_peer_dial_attempt_ms: HashMap<PeerId, u128>,

    pub(super) peerbook: Arc<Mutex<PeerBook>>,
    pub(super) janitor: JanitorBook,
    pub(super) conn_guard: ConnGuard,
    pub(super) last_resort: LastResortGuards,
    pub(super) admitted_peers: HashSet<PeerId>,
    pub(super) peer_ip: HashMap<PeerId, IpAddr>,

    pub(super) last_autodial_ms: u128,
    pub(super) last_kad_bootstrap_ms: u128,
    pub(super) last_kad_random_walk_ms: u128,

    pub(super) reorg_manager: ReorgManager,
    pub(super) branch_hydration: Hydration,
}

// ────────────────────────────────────────────────
// Constructors & simple accessors
// ────────────────────────────────────────────────

impl P2pSync {
    pub fn new(
        chain: AccountModelTree,
        db: Arc<RockDBManager>,
        mempool: Arc<MemPool>,
        peerbook: Arc<Mutex<PeerBook>>,
        peerlist_dir: PathBuf,
        expected_genesis_hash: Option<String>,
        reorg_manager: ReorgManager,
    ) -> Self {
        let janitor = JanitorBook::new_with_dir(Arc::clone(&peerbook), peerlist_dir);
        let conn_guard = ConnGuard::new(ConnGuardConfig::default());
        let now = Instant::now();
        let last_resort = LastResortGuards::new(LastResortConfig::default(), now);
        let pq_manager = build_default_pq_manager();

        let mut s = Self {
            chain,
            db,
            mempool,

            syncing: false,
            has_synced: false,
            total_to_download: 0,
            downloaded: 0,

            pending_versions: HashMap::new(),

            pending_pq: HashMap::new(),
            pq_manager,
            pq_initiators: HashMap::new(),
            pq_ready_peers: HashSet::new(),

            pending_blocks: HashMap::new(),
            pending_batches: HashMap::new(),
            block_queue: VecDeque::new(),
            batch_queue: VecDeque::new(),

            reserved_block_indices: HashSet::new(),
            reserved_batch_indices: HashSet::new(),

            expected_genesis_hash,
            tried_genesis: false,

            last_synced_hash: None,
            last_synced_index: None,

            sync_target: 0,
            queued_sync_target: None,

            last_peer_dial_attempt_ms: HashMap::new(),

            peerbook,
            janitor,
            conn_guard,
            last_resort,
            admitted_peers: HashSet::new(),
            peer_ip: HashMap::new(),

            last_autodial_ms: 0,
            last_kad_bootstrap_ms: 0,
            last_kad_random_walk_ms: 0,

            reorg_manager,
            branch_hydration: Hydration::default_mainnet(),
        };

        let local_tip = s.db.get_tip_height().unwrap_or(0);
        s.sync_target = local_tip;
        s.downloaded = local_tip;
        s.total_to_download = local_tip;

        s.update_sync_pointers();
        s.update_sync_state();
        s
    }

    // ────────────────────────────────────────────────
    // Local defensive maintenance helpers
    // ────────────────────────────────────────────────

    #[inline(always)]
    fn trim_queue_to_cap<T>(queue: &mut VecDeque<T>, cap: usize) {
        while queue.len() > cap {
            let _ = queue.pop_back();
        }
    }

    fn compact_sync_queues(&mut self) {
        Self::trim_queue_to_cap(&mut self.block_queue, MAX_BLOCK_QUEUE);
        Self::trim_queue_to_cap(&mut self.batch_queue, MAX_BATCH_QUEUE);
    }

    fn prune_advisory_runtime_tables(&mut self) {
        if self.last_peer_dial_attempt_ms.len() > MAX_TRACKED_DIAL_ATTEMPTS {
            let now_ms = now_millis();
            self.last_peer_dial_attempt_ms.retain(|_, last_ms| {
                now_ms.saturating_sub(*last_ms) <= AUTODIAL_RETRY_PEER_MS.saturating_mul(8)
            });

            if self.last_peer_dial_attempt_ms.len() > MAX_TRACKED_DIAL_ATTEMPTS {
                self.last_peer_dial_attempt_ms.clear();
            }
        }

        if self.pq_ready_peers.len() > MAX_RUNTIME_PEER_SIDE_TABLES {
            self.pq_ready_peers.clear();
        }

        if self.admitted_peers.len() > MAX_RUNTIME_PEER_SIDE_TABLES {
            self.admitted_peers.clear();
        }

        if self.peer_ip.len() > MAX_RUNTIME_PEER_SIDE_TABLES {
            self.peer_ip.clear();
        }
    }

    #[inline(always)]
    fn maintenance_housekeeping(&mut self) {
        self.compact_sync_queues();
        self.prune_advisory_runtime_tables();
    }

    // ────────────────────────────────────────────────
    // PQ state helpers
    // ────────────────────────────────────────────────

    #[inline(always)]
    pub fn is_pq_ready(&self, peer: &PeerId) -> bool {
        self.pq_ready_peers.contains(peer)
    }

    #[inline(always)]
    pub fn mark_pq_ready(&mut self, peer: PeerId) {
        // A ready peer no longer needs an initiator state or pending outbound PQ
        // request for this peer. Keep other peers untouched.
        self.pq_ready_peers.insert(peer);
        self.pq_initiators.remove(&peer);
        self.pending_pq.retain(|_, p| *p != peer);

        if self.pq_ready_peers.len() > MAX_RUNTIME_PEER_SIDE_TABLES {
            self.prune_advisory_runtime_tables();
        }
    }

    #[inline(always)]
    pub fn clear_pq_peer_state(&mut self, peer: &PeerId) {
        // Preserve visible sync progress counters across PQ disconnect cleanup.
        let local_tip = self.db.get_tip_height().unwrap_or(0);
        let visible_total_before = self.total_to_download;
        let visible_downloaded_before = self.downloaded;

        let target = self
            .sync_target
            .max(self.queued_sync_target.unwrap_or(0))
            .max(visible_total_before)
            .max(local_tip);

        self.pq_initiators.remove(peer);
        self.pq_ready_peers.remove(peer);
        self.pending_pq.retain(|_, p| p != peer);

        self.sync_target = target;

        // Keep existing visible progress intact unless a higher known target must
        // be surfaced. Never shrink total/downloaded during PQ state cleanup.
        self.total_to_download = visible_total_before.max(target);
        self.downloaded = visible_downloaded_before.min(self.total_to_download);

        if target > local_tip {
            self.queued_sync_target = Some(target);
        } else {
            self.queued_sync_target = None;
        }

        self.maintenance_housekeeping();
    }

    #[inline(always)]
    pub fn can_issue_more_pq_requests(&self) -> bool {
        self.pending_pq.len() < MAX_PENDING_PQ
    }

    // ────────────────────────────────────────────────
    // Sync target helpers
    // ────────────────────────────────────────────────

    #[inline(always)]
    pub(super) fn effective_sync_target(&self) -> u64 {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        self.sync_target
            .max(self.queued_sync_target.unwrap_or(0))
            .max(local_tip)
    }

    #[inline(always)]
    pub(super) fn canonical_hash_at_height(&self, height: u64) -> Option<RemzarHashBytes> {
        self.db
            .get_block_by_index(height)
            .ok()
            .flatten()
            .map(|block| block.block_hash)
    }

    pub fn seed_bootstrap(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        pid: &PeerId,
        addrs: impl IntoIterator<Item = Multiaddr>,
    ) {
        let addrs_vec: Vec<Multiaddr> = addrs.into_iter().collect();
        let addrs_vec = self.filter_multiaddr_bounds(addrs_vec);
        if addrs_vec.is_empty() {
            return;
        }

        if let Ok(mut pb) = self.peerbook.lock() {
            pb.upsert(pid, addrs_vec.clone(), false);
            _ = pb.save();
        }

        let kad_addrs = kad_ready_addrs_bounded(&addrs_vec);
        for addr in kad_addrs {
            swarm.behaviour_mut().kademlia.add_address(pid, addr);
        }

        _ = swarm.behaviour_mut().kademlia.bootstrap();
        self.maintenance_housekeeping();
    }

    pub fn seed_kad_from_peerbook(&mut self, swarm: &mut Swarm<RemzarBehaviour>) {
        let peers: Vec<(String, Vec<Multiaddr>)> = if let Ok(pb) = self.peerbook.lock() {
            pb.top_n(MAX_PEERBOOK_KAD_SEED_PEERS)
        } else {
            Vec::new()
        };

        let mut added_any = false;

        for (pid_str, addrs) in peers {
            let Ok(peer_id) = pid_str.parse::<PeerId>() else {
                continue;
            };

            let addrs = self.filter_multiaddr_bounds(addrs);
            if addrs.is_empty() {
                continue;
            }

            for addr in kad_ready_addrs_bounded(&addrs) {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                added_any = true;
            }
        }

        if added_any {
            _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        self.maintenance_housekeeping();
    }

    pub fn autodial_known_peers(&mut self, swarm: &mut Swarm<RemzarBehaviour>) {
        let now_ms = now_millis();

        if now_ms.saturating_sub(self.last_autodial_ms) < AUTODIAL_PERIOD_MS {
            return;
        }

        self.last_autodial_ms = now_ms;

        let top: Vec<(String, Vec<Multiaddr>)> = if let Ok(pb) = self.peerbook.lock() {
            pb.top_n(MAX_PEERBOOK_KAD_SEED_PEERS)
        } else {
            return;
        };

        for (pid_str, addrs) in top.into_iter().take(MAX_AUTODIAL_PEERS_PER_TICK) {
            let peer_id = match pid_str.parse::<PeerId>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if swarm.is_connected(&peer_id) {
                continue;
            }

            if let Some(last_ms) = self.last_peer_dial_attempt_ms.get(&peer_id)
                && now_ms.saturating_sub(*last_ms) < AUTODIAL_RETRY_PEER_MS
            {
                continue;
            }

            self.last_peer_dial_attempt_ms.insert(peer_id, now_ms);

            let candidate_addrs: Vec<Multiaddr> = self
                .filter_multiaddr_bounds(addrs)
                .into_iter()
                .take(MAX_AUTODIAL_ADDRS_PER_PEER)
                .collect();

            for base in kad_ready_addrs_bounded(&candidate_addrs) {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, base);
            }

            for addr in candidate_addrs {
                _ = swarm.dial(addr);
            }
        }

        self.maintenance_housekeeping();
    }

    pub fn kad_periodic_bootstrap(&mut self, swarm: &mut Swarm<RemzarBehaviour>) {
        let now_ms = now_millis();

        if now_ms.saturating_sub(self.last_kad_bootstrap_ms) < KAD_BOOTSTRAP_PERIOD_MS {
            return;
        }

        self.last_kad_bootstrap_ms = now_ms;
        _ = swarm.behaviour_mut().kademlia.bootstrap();
    }

    pub fn kad_random_walk(&mut self, swarm: &mut Swarm<RemzarBehaviour>) {
        let now_ms = now_millis();

        if now_ms.saturating_sub(self.last_kad_random_walk_ms) < KAD_RANDOM_WALK_PERIOD_MS {
            return;
        }

        self.last_kad_random_walk_ms = now_ms;

        let tmp_kp = identity::Keypair::generate_ed25519();
        let rand_peer_id = PeerId::from(tmp_kp.public());

        swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(rand_peer_id);
    }

    #[inline(always)]
    fn genesis_is_ready(&self) -> bool {
        let Some(block0) = self.db.get_block_by_index(0).ok().flatten() else {
            return false;
        };

        if let Some(expected) = &self.expected_genesis_hash {
            block0.hash_hex() == *expected
        } else {
            true
        }
    }

    #[inline(always)]
    fn has_pending_sync_backlog(&self) -> bool {
        !self.block_queue.is_empty()
            || !self.pending_blocks.is_empty()
            || !self.batch_queue.is_empty()
            || !self.pending_batches.is_empty()
            || !self.reserved_block_indices.is_empty()
            || !self.reserved_batch_indices.is_empty()
    }

    /// Background sync bookkeeping still exists and is useful, but it must not
    /// be conflated with participation readiness.
    #[inline(always)]
    pub fn has_background_sync_work(&self) -> bool {
        self.has_pending_sync_backlog()
    }

    pub fn has_synced(&self) -> bool {
        self.has_synced
    }

    pub fn is_syncing(&self) -> bool {
        self.syncing
    }

    pub fn last_synced_index(&self) -> Option<u64> {
        self.last_synced_index
    }

    pub fn last_synced_hash(&self) -> Option<RemzarHashBytes> {
        self.last_synced_hash
    }

    pub fn sync_percent(&self) -> f64 {
        if self.total_to_download == 0 {
            return if self.has_synced { 100.0 } else { 0.0 };
        }

        let bps = u128::from(self.downloaded)
            .saturating_mul(10_000)
            .checked_div(u128::from(self.total_to_download))
            .unwrap_or(0)
            .min(10_000);

        let bps_for_percent = u16::try_from(bps).unwrap_or(10_000);

        std::ops::Div::div(f64::from(bps_for_percent), 100.0)
    }

    pub(super) fn expected_prev(&self) -> std::result::Result<RemzarHashBytes, &'static str> {
        self.last_synced_hash
            .ok_or("last_synced_hash not initialised")
    }

    pub fn update_sync_pointers(&mut self) {
        let local_height = self.db.get_tip_height().unwrap_or(0);

        if let Some(hash) = self.canonical_hash_at_height(local_height) {
            self.last_synced_hash = Some(hash);
            self.last_synced_index = Some(local_height);
            self.downloaded = local_height;
        } else {
            self.last_synced_hash = None;
            self.last_synced_index = None;
            self.downloaded = 0;
        }
    }

    pub fn update_sync_state(&mut self) {
        self.maintenance_housekeeping();

        let block0_ok = self.genesis_is_ready();

        let local_tip = self.db.get_tip_height().unwrap_or(0);
        let has_background_sync_work = self.has_pending_sync_backlog();

        // Preserve externally visible progress counters while active sync work is
        // being queued, pending, reserved, or retried.
        let visible_total_before = self.total_to_download;
        let visible_downloaded_before = self.downloaded;

        let target = if has_background_sync_work {
            self.effective_sync_target()
                .max(visible_total_before)
                .max(local_tip)
        } else {
            self.effective_sync_target().max(local_tip)
        };

        self.sync_target = target;

        if has_background_sync_work {
            self.total_to_download = visible_total_before.max(target);
            self.downloaded = visible_downloaded_before
                .max(local_tip)
                .min(self.total_to_download);
        } else {
            self.total_to_download = target;
            self.downloaded = local_tip.min(self.total_to_download);
        }

        if local_tip >= target {
            self.queued_sync_target = None;
        } else {
            self.queued_sync_target = Some(target);
        }

        let at_tip = local_tip >= target;

        // Participation-readiness:
        self.has_synced = block0_ok && at_tip;

        // Transport / scheduler activity:
        self.syncing = !block0_ok || !at_tip || has_background_sync_work;
    }
}

pub(super) fn now_millis() -> u128 {
    match TimePolicy::now_unix_millis_runtime() {
        Ok(ms) => u128::from(ms),
        Err(_) => 0,
    }
}
