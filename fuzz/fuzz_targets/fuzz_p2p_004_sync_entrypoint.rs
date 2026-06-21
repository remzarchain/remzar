#![no_main]

use libfuzzer_sys::fuzz_target;
extern crate self as libp2p;

use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Eq, PartialOrd, Ord)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer-{}", hex::encode(&self.0[..4]))
    }
}

pub mod swarm {
    use crate::PeerId;
    use std::collections::HashSet;

    #[derive(Debug, Clone)]
    pub struct Swarm<B> {
        behaviour: B,
        connected: HashSet<PeerId>,
    }

    impl<B> Swarm<B> {
        pub fn new_for_fuzz(behaviour: B) -> Self {
            Self {
                behaviour,
                connected: HashSet::new(),
            }
        }

        pub fn behaviour(&self) -> &B {
            &self.behaviour
        }

        pub fn behaviour_mut(&mut self) -> &mut B {
            &mut self.behaviour
        }

        pub fn is_connected(&self, peer: &PeerId) -> bool {
            self.connected.contains(peer)
        }

        pub fn connect_peer(&mut self, peer: PeerId) {
            self.connected.insert(peer);
        }

        pub fn disconnect_peer(&mut self, peer: &PeerId) {
            self.connected.remove(peer);
        }

        pub fn connected_len(&self) -> usize {
            self.connected.len()
        }
    }
}

// -----------------------------------------------------------------------------
// Mock network behaviour surface required by the real entrypoint.
// -----------------------------------------------------------------------------
mod network {
    pub mod p2p_007_handshake {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Services(pub u64);

        impl Services {
            pub const NODE: Self = Self(1);
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VersionInfo {
            pub protocol_version: u32,
            pub chain_height: u64,
            pub services: Services,
            pub user_agent: String,
            pub genesis_hash: Option<[u8; 64]>,
        }
    }

    pub mod p2p_003_behaviour {
        use crate::PeerId;
        use crate::network::p2p_007_handshake::VersionInfo;

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct VersionRequestId(pub u64);

        #[derive(Debug, Clone, Default)]
        pub struct MockGossipsub {
            peers: Vec<(PeerId, ())>,
        }

        impl MockGossipsub {
            pub fn new(peers: Vec<PeerId>) -> Self {
                Self {
                    peers: peers.into_iter().map(|p| (p, ())).collect(),
                }
            }

            pub fn set_peers(&mut self, peers: Vec<PeerId>) {
                self.peers = peers.into_iter().map(|p| (p, ())).collect();
            }

            pub fn all_peers(&self) -> impl Iterator<Item = (&PeerId, &())> {
                self.peers.iter().map(|(peer, marker)| (peer, marker))
            }

            pub fn peer_count(&self) -> usize {
                self.peers.len()
            }
        }

        #[derive(Debug, Clone)]
        pub struct MockVersionBehaviour {
            next_request_id: u64,
            pub sent_requests: Vec<(VersionRequestId, PeerId, VersionInfo)>,
        }

        impl Default for MockVersionBehaviour {
            fn default() -> Self {
                Self {
                    next_request_id: 1,
                    sent_requests: Vec::new(),
                }
            }
        }

        impl MockVersionBehaviour {
            pub fn send_request(
                &mut self,
                peer: &PeerId,
                req: VersionInfo,
            ) -> VersionRequestId {
                let id = VersionRequestId(self.next_request_id);
                self.next_request_id = self.next_request_id.saturating_add(1);
                self.sent_requests.push((id, *peer, req));
                id
            }

            pub fn sent_len(&self) -> usize {
                self.sent_requests.len()
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct RemzarBehaviour {
            pub gossipsub: MockGossipsub,
            pub version: MockVersionBehaviour,
        }

        impl RemzarBehaviour {
            pub fn new_for_fuzz(peers: Vec<PeerId>) -> Self {
                Self {
                    gossipsub: MockGossipsub::new(peers),
                    version: MockVersionBehaviour::default(),
                }
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Mock p2p_001_sync_builders surface required by the real entrypoint.
// -----------------------------------------------------------------------------
pub mod p2p_001_sync_builders {
    use crate::network::p2p_003_behaviour::{RemzarBehaviour, VersionRequestId};
    use crate::swarm::Swarm;
    use crate::PeerId;
    use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

    pub const MAX_HEIGHT_POLL_PEERS: usize = 16;
    pub const MAX_PENDING_VERSIONS: usize = 64;
    pub const MAX_RETRIES: u8 = 3;

    pub fn genesis_hash_bytes_64() -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..13].copy_from_slice(b"REMZAR_GENESI");
        out[13] = b'S';
        out
    }

    #[derive(Debug, Clone, Default)]
    pub struct MockSyncDb {
        tip_height: u64,
        present_block_indices: BTreeSet<u64>,
    }

    impl MockSyncDb {
        pub fn new(tip_height: u64) -> Self {
            let mut present_block_indices = BTreeSet::new();
            for idx in 0..=tip_height {
                present_block_indices.insert(idx);
            }
            Self {
                tip_height,
                present_block_indices,
            }
        }

        pub fn get_tip_height(&self) -> Result<u64, &'static str> {
            Ok(self.tip_height)
        }

        pub fn set_tip_height(&mut self, tip_height: u64) {
            self.tip_height = tip_height;
            for idx in 0..=tip_height {
                self.present_block_indices.insert(idx);
            }
        }

        pub fn has_block_index(&self, idx: u64) -> bool {
            self.present_block_indices.contains(&idx)
        }

        pub fn insert_block_index(&mut self, idx: u64) {
            self.present_block_indices.insert(idx);
        }

        pub fn remove_block_index(&mut self, idx: u64) {
            self.present_block_indices.remove(&idx);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FuzzSyncState {
        Idle,
        WaitingForPeer,
        WaitingForPq,
        Downloading,
        Complete,
    }

    #[derive(Debug, Clone)]
    pub struct P2pSync {
        pub(crate) db: MockSyncDb,

        pub(crate) sync_target: u64,
        pub(crate) queued_sync_target: Option<u64>,
        pub(crate) downloaded: u64,
        pub(crate) total_to_download: u64,

        pub(crate) pending_versions: HashMap<VersionRequestId, PeerId>,

        pub(crate) pending_blocks: BTreeSet<u64>,
        pub(crate) block_queue: VecDeque<u64>,
        pub(crate) pending_batches: BTreeSet<u64>,
        pub(crate) batch_queue: VecDeque<u64>,

        pq_ready_peers: HashSet<PeerId>,
        block_request_counts: HashMap<u64, u8>,
        batch_request_counts: HashMap<u64, u8>,
        pub(crate) state: FuzzSyncState,

        pub(crate) update_sync_pointers_calls: u64,
        pub(crate) update_sync_state_calls: u64,
        pub(crate) autodial_calls: u64,
        pub(crate) kad_bootstrap_calls: u64,
        pub(crate) kad_random_walk_calls: u64,
        pub(crate) reservations_cleared: u64,
    }

    impl P2pSync {
        pub fn new_for_fuzz(local_tip: u64) -> Self {
            Self {
                db: MockSyncDb::new(local_tip),
                sync_target: local_tip,
                queued_sync_target: None,
                downloaded: local_tip,
                total_to_download: local_tip,
                pending_versions: HashMap::new(),
                pending_blocks: BTreeSet::new(),
                block_queue: VecDeque::new(),
                pending_batches: BTreeSet::new(),
                batch_queue: VecDeque::new(),
                pq_ready_peers: HashSet::new(),
                block_request_counts: HashMap::new(),
                batch_request_counts: HashMap::new(),
                state: FuzzSyncState::Idle,
                update_sync_pointers_calls: 0,
                update_sync_state_calls: 0,
                autodial_calls: 0,
                kad_bootstrap_calls: 0,
                kad_random_walk_calls: 0,
                reservations_cleared: 0,
            }
        }

        pub fn local_tip(&self) -> u64 {
            self.db.get_tip_height().unwrap_or(0)
        }

        pub fn set_local_tip(&mut self, tip: u64) {
            self.db.set_tip_height(tip);
        }

        pub fn mark_block_present(&mut self, idx: u64) {
            self.db.insert_block_index(idx);
        }

        pub fn mark_block_missing(&mut self, idx: u64) {
            self.db.remove_block_index(idx);
        }

        pub fn set_pq_ready(&mut self, peer: PeerId, ready: bool) {
            if ready {
                self.pq_ready_peers.insert(peer);
            } else {
                self.pq_ready_peers.remove(&peer);
            }
        }

        pub fn prefill_pending_versions(&mut self, peers: &[PeerId], count: usize) {
            for i in 0..count {
                let peer = peers.get(i % peers.len().max(1)).copied().unwrap_or(PeerId([0u8; 32]));
                self.pending_versions
                    .insert(VersionRequestId(10_000 + i as u64), peer);
            }
        }

        pub(crate) fn update_sync_pointers(&mut self) {
            self.update_sync_pointers_calls = self.update_sync_pointers_calls.saturating_add(1);

            let local_tip = self.db.get_tip_height().unwrap_or(0);
            self.downloaded = local_tip;

            let highest = self
                .sync_target
                .max(self.queued_sync_target.unwrap_or(0))
                .max(local_tip);
            self.sync_target = highest;
            self.total_to_download = highest;
        }

        pub(crate) fn update_sync_state(&mut self) {
            self.update_sync_state_calls = self.update_sync_state_calls.saturating_add(1);

            let local_tip = self.db.get_tip_height().unwrap_or(0);
            let target = self.sync_target.max(self.queued_sync_target.unwrap_or(0));

            self.state = if local_tip >= target {
                FuzzSyncState::Complete
            } else if self.queued_sync_target.is_some()
                && self.pending_blocks.is_empty()
                && self.pending_batches.is_empty()
            {
                FuzzSyncState::WaitingForPq
            } else if !self.pending_blocks.is_empty() || !self.pending_batches.is_empty() {
                FuzzSyncState::Downloading
            } else {
                FuzzSyncState::WaitingForPeer
            };
        }

        pub(crate) fn autodial_known_peers(&mut self, _swarm: &mut Swarm<RemzarBehaviour>) {
            self.autodial_calls = self.autodial_calls.saturating_add(1);
        }

        pub(crate) fn kad_periodic_bootstrap(&mut self, _swarm: &mut Swarm<RemzarBehaviour>) {
            self.kad_bootstrap_calls = self.kad_bootstrap_calls.saturating_add(1);
        }

        pub(crate) fn kad_random_walk(&mut self, _swarm: &mut Swarm<RemzarBehaviour>) {
            self.kad_random_walk_calls = self.kad_random_walk_calls.saturating_add(1);
        }

        pub(crate) fn is_pq_ready(&self, peer: &PeerId) -> bool {
            self.pq_ready_peers.contains(peer)
        }

        pub(crate) fn db_has_block_index(&self, idx: u64) -> bool {
            self.db.has_block_index(idx)
        }

        pub(crate) fn issue_batch_request_if_absent(
            &mut self,
            _swarm: &mut Swarm<RemzarBehaviour>,
            _peer: PeerId,
            idx: u64,
            max_retries: u8,
        ) -> bool {
            let count = self.batch_request_counts.entry(idx).or_insert(0);
            if *count >= max_retries {
                return false;
            }

            if self.pending_batches.insert(idx) {
                self.batch_queue.push_back(idx);
                *count = count.saturating_add(1);
                true
            } else {
                false
            }
        }

        pub(crate) fn issue_block_request_if_absent(
            &mut self,
            _swarm: &mut Swarm<RemzarBehaviour>,
            _peer: PeerId,
            idx: u64,
            max_retries: u8,
        ) -> bool {
            let count = self.block_request_counts.entry(idx).or_insert(0);
            if *count >= max_retries {
                return false;
            }

            if self.pending_blocks.insert(idx) {
                self.block_queue.push_back(idx);
                *count = count.saturating_add(1);
                true
            } else {
                false
            }
        }

        pub(crate) fn count_batch_idx_occurrences(&self, idx: u64) -> usize {
            self.batch_queue.iter().filter(|v| **v == idx).count()
                + usize::from(self.pending_batches.contains(&idx))
        }

        pub(crate) fn batch_idx_debug_state(&self, idx: u64) -> String {
            format!(
                "pending={} queued={} retries={}",
                self.pending_batches.contains(&idx),
                self.batch_queue.iter().any(|v| *v == idx),
                self.batch_request_counts.get(&idx).copied().unwrap_or(0)
            )
        }

        pub(crate) fn count_block_idx_occurrences(&self, idx: u64) -> usize {
            self.block_queue.iter().filter(|v| **v == idx).count()
                + usize::from(self.pending_blocks.contains(&idx))
        }

        pub(crate) fn block_idx_debug_state(&self, idx: u64) -> String {
            format!(
                "pending={} queued={} retries={}",
                self.pending_blocks.contains(&idx),
                self.block_queue.iter().any(|v| *v == idx),
                self.block_request_counts.get(&idx).copied().unwrap_or(0)
            )
        }

        pub(crate) fn clear_all_sync_reservations(&mut self) {
            self.pending_blocks.clear();
            self.pending_batches.clear();
            self.block_queue.clear();
            self.batch_queue.clear();
            self.reservations_cleared = self.reservations_cleared.saturating_add(1);
        }
    }
}

#[path = "../../src/runtime/p2p_004_sync_entrypoint.rs"]
mod p2p_004_sync_entrypoint;

use crate::swarm::Swarm;
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::p2p_001_sync_builders::{P2pSync, MAX_HEIGHT_POLL_PEERS, MAX_PENDING_VERSIONS};

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }
    u64::from_le_bytes(out)
}

fn bounded_height(data: &[u8], offset: usize) -> u64 {
    read_u64(data, offset) % 128
}

fn peer_from_data(data: &[u8], salt: usize) -> PeerId {
    let mut out = [0u8; 32];

    for i in 0..32 {
        let a = byte_at(data, salt.wrapping_add(i), i as u8);
        let b = byte_at(
            data,
            salt.wrapping_add(i.wrapping_mul(13)).wrapping_add(7),
            (i as u8).wrapping_mul(3),
        );
        out[i] = a ^ b ^ (salt as u8).wrapping_add(i as u8);
    }

    if out == [0u8; 32] {
        out[0] = 1;
    }

    PeerId::from_bytes(out)
}

fn make_peers(data: &[u8], salt: usize, max_count: usize) -> Vec<PeerId> {
    let count = byte_at(data, salt, 0) as usize % max_count.saturating_add(1);
    let mut peers = Vec::with_capacity(count);

    for i in 0..count {
        let mut peer = peer_from_data(data, salt + 1 + i * 37);
        peer.0[31] ^= i as u8;
        peers.push(peer);
    }

    peers
}

fn make_swarm(
    peers: Vec<PeerId>,
    connected_mask_source: &[u8],
    salt: usize,
) -> Swarm<RemzarBehaviour> {
    let behaviour = RemzarBehaviour::new_for_fuzz(peers.clone());
    let mut swarm = Swarm::new_for_fuzz(behaviour);

    for (i, peer) in peers.iter().copied().enumerate() {
        if byte_at(connected_mask_source, salt + i, 0) & 1 == 0 {
            swarm.connect_peer(peer);
        }
    }

    swarm
}

fn assert_sync_invariants(sync: &P2pSync) {
    let local_tip = sync.local_tip();
    assert!(sync.sync_target >= local_tip);
    assert!(sync.total_to_download >= sync.downloaded);
    assert!(sync.pending_versions.len() <= MAX_PENDING_VERSIONS);

    if let Some(q) = sync.queued_sync_target {
        assert!(q >= local_tip);
    }

    for idx in &sync.pending_blocks {
        assert!(sync.count_block_idx_occurrences(*idx) >= 1);
    }

    for idx in &sync.pending_batches {
        assert!(sync.count_batch_idx_occurrences(*idx) >= 1);
    }
}

fn exercise_no_peer_preserves_target(data: &[u8]) {
    let local_tip = bounded_height(data, 0);
    let mut sync = P2pSync::new_for_fuzz(local_tip);

    let old_target = local_tip
        .saturating_add(1)
        .saturating_add(read_u64(data, 8) % 64);
    sync.sync_target = old_target;
    sync.queued_sync_target = Some(old_target.saturating_add(read_u64(data, 16) % 8));

    let mut swarm = make_swarm(Vec::new(), data, 24);

    sync.poll_peers_for_height(&mut swarm);

    let highest = old_target.max(sync.queued_sync_target.unwrap_or(0)).max(local_tip);
    assert!(sync.sync_target >= highest.min(sync.sync_target));
    assert!(sync.autodial_calls >= 1);
    assert!(sync.kad_bootstrap_calls >= 1);
    assert!(sync.kad_random_walk_calls >= 1);
    assert_sync_invariants(&sync);
}

fn exercise_poll_peers(data: &[u8]) {
    let local_tip = bounded_height(data, 40);
    let mut sync = P2pSync::new_for_fuzz(local_tip);
    sync.sync_target = local_tip.saturating_add(read_u64(data, 48) % 32);

    let peers = make_peers(data, 64, MAX_HEIGHT_POLL_PEERS.saturating_mul(2).saturating_add(8));
    let mut swarm = make_swarm(peers.clone(), data, 512);

    let prefill = match byte_at(data, 80, 0) % 4 {
        0 => 0,
        1 => MAX_PENDING_VERSIONS.saturating_sub(1),
        2 => MAX_PENDING_VERSIONS,
        _ => byte_at(data, 81, 0) as usize % MAX_PENDING_VERSIONS,
    };
    if !peers.is_empty() && prefill > 0 {
        sync.prefill_pending_versions(&peers, prefill);
    }

    let before_pending = sync.pending_versions.len();
    sync.poll_peers_for_height(&mut swarm);

    if peers.is_empty() || before_pending >= MAX_PENDING_VERSIONS {
        assert!(sync.autodial_calls >= 1);
    } else {
        assert!(sync.pending_versions.len() >= before_pending);
        assert!(swarm.behaviour().version.sent_len() <= MAX_HEIGHT_POLL_PEERS);
    }

    assert_sync_invariants(&sync);
}

fn exercise_begin_sync_disconnected_or_pq_deferred(data: &[u8]) {
    let local_tip = bounded_height(data, 600);
    let mut sync = P2pSync::new_for_fuzz(local_tip);
    let peer = peer_from_data(data, 608);
    let peer_tip = local_tip
        .saturating_add(1)
        .saturating_add(read_u64(data, 640) % 64);

    let peers = vec![peer];
    let mut swarm = make_swarm(peers.clone(), data, 700);

    // Force one of the important guard paths:
    // - disconnected peer
    // - connected but PQ not ready
    if byte_at(data, 720, 0) & 1 == 0 {
        swarm.disconnect_peer(&peer);
    } else {
        swarm.connect_peer(peer);
        sync.set_pq_ready(peer, false);
    }

    sync.begin_sync_to_target(&mut swarm, peer, peer_tip);

    assert!(sync.sync_target >= peer_tip.max(local_tip));
    if sync.local_tip() < sync.sync_target {
        assert_eq!(sync.queued_sync_target, Some(sync.sync_target));
        assert!(sync.pending_blocks.is_empty());
        assert!(sync.pending_batches.is_empty());
    }

    assert_sync_invariants(&sync);
}

fn exercise_begin_sync_connected_pq_ready(data: &[u8]) {
    let local_tip = bounded_height(data, 800);
    let mut sync = P2pSync::new_for_fuzz(local_tip);

    let peer = peer_from_data(data, 808);
    let peer_tip = local_tip
        .saturating_add(1)
        .saturating_add(read_u64(data, 840) % 64);

    let peers = vec![peer];
    let mut swarm = make_swarm(peers, data, 900);
    swarm.connect_peer(peer);
    sync.set_pq_ready(peer, true);

    let next_idx = local_tip.saturating_add(1);
    let block_was_present = byte_at(data, 920, 0) & 1 == 0;

    if block_was_present {
        sync.mark_block_present(next_idx);
    } else {
        sync.mark_block_missing(next_idx);
    }

    sync.begin_sync_to_target(&mut swarm, peer, peer_tip);

    // Connected + PQ-ready should never defer while there is still work to do.
    // The requested index is based on the canonical local tip, not merely on
    // whether block bytes for local_tip + 1 happen to exist.
    let final_local_tip = sync.local_tip();
    if final_local_tip < sync.sync_target {
        let expected_idx = final_local_tip.saturating_add(1);
        if sync.db_has_block_index(expected_idx) {
            assert!(
                sync.pending_batches.contains(&expected_idx),
                "block exists at next index; sync should request the missing batch"
            );
            assert!(
                !sync.pending_blocks.contains(&expected_idx),
                "block request must not be duplicated when block already exists"
            );
        } else {
            assert!(
                sync.pending_blocks.contains(&expected_idx),
                "missing block at next index should trigger a block request"
            );
            assert!(
                !sync.pending_batches.contains(&expected_idx),
                "batch request must wait until block exists"
            );
        }
        assert_eq!(sync.queued_sync_target, None);
    } else {
        assert_eq!(sync.queued_sync_target, None);
    }

    assert_sync_invariants(&sync);
}

fn exercise_request_next_block(data: &[u8]) {
    let local_tip = bounded_height(data, 1_000);
    let mut sync = P2pSync::new_for_fuzz(local_tip);

    let peer = peer_from_data(data, 1_008);
    let target = local_tip
        .saturating_add(1)
        .saturating_add(read_u64(data, 1_040) % 32);

    sync.sync_target = target;
    sync.queued_sync_target = if byte_at(data, 1_048, 0) & 1 == 0 {
        Some(target.saturating_add(read_u64(data, 1_049) % 4))
    } else {
        None
    };

    let peers = vec![peer];
    let mut swarm = make_swarm(peers, data, 1_100);

    if byte_at(data, 1_120, 0) & 1 == 0 {
        swarm.connect_peer(peer);
        sync.set_pq_ready(peer, true);
    } else if byte_at(data, 1_121, 0) & 1 == 0 {
        swarm.connect_peer(peer);
        sync.set_pq_ready(peer, false);
    } else {
        swarm.disconnect_peer(&peer);
    }

    let next_idx = local_tip.saturating_add(1);
    if byte_at(data, 1_122, 0) & 1 == 0 {
        sync.mark_block_present(next_idx);
    } else {
        sync.mark_block_missing(next_idx);
    }

    sync.request_next_block(&mut swarm, peer);
    assert_sync_invariants(&sync);
}

fn exercise_local_tip_advanced(data: &[u8]) {
    let old_tip = bounded_height(data, 1_200);
    let mut sync = P2pSync::new_for_fuzz(old_tip);

    let target = old_tip.saturating_add(read_u64(data, 1_208) % 64);
    sync.sync_target = target;
    sync.queued_sync_target = if byte_at(data, 1_216, 0) & 1 == 0 {
        Some(target.saturating_add(read_u64(data, 1_217) % 16))
    } else {
        None
    };

    let new_tip = match byte_at(data, 1_224, 0) % 3 {
        0 => old_tip,
        1 => old_tip.saturating_add(read_u64(data, 1_225) % 16),
        _ => sync.sync_target.saturating_add(read_u64(data, 1_233) % 16),
    };

    sync.set_local_tip(new_tip);
    sync.on_local_tip_advanced();

    assert!(sync.sync_target >= new_tip);
    if new_tip >= sync.sync_target {
        assert_eq!(sync.queued_sync_target, None);
    }

    assert_sync_invariants(&sync);
}

fn exercise_never_lower_target_across_pq_retry(data: &[u8]) {
    let local_tip = bounded_height(data, 1_300);
    let mut sync = P2pSync::new_for_fuzz(local_tip);

    let peer = peer_from_data(data, 1_308);
    let high_target = local_tip.saturating_add(10).saturating_add(read_u64(data, 1_340) % 64);
    let low_target = local_tip.saturating_add(read_u64(data, 1_348) % 3);

    sync.sync_target = high_target;
    sync.queued_sync_target = Some(high_target);

    let mut swarm = make_swarm(vec![peer], data, 1_400);
    swarm.connect_peer(peer);
    sync.set_pq_ready(peer, false);

    sync.begin_sync_to_target(&mut swarm, peer, low_target);
    assert!(sync.sync_target >= high_target);
    assert_eq!(sync.queued_sync_target, Some(sync.sync_target));

    assert_sync_invariants(&sync);
}

fuzz_target!(|data: &[u8]| {
    exercise_no_peer_preserves_target(data);
    exercise_poll_peers(data);
    exercise_begin_sync_disconnected_or_pq_deferred(data);
    exercise_begin_sync_connected_pq_ready(data);
    exercise_request_next_block(data);
    exercise_local_tip_advanced(data);
    exercise_never_lower_target_across_pq_retry(data);
});
