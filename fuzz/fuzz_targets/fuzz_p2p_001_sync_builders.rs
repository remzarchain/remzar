// fuzz/fuzz_targets/fuzz_p2p_001_sync_builders.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

use libp2p::{identity, multiaddr::Protocol, Multiaddr, PeerId};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

type Hash64 = [u8; 64];

// Mirrors p2p_001_sync_builders.rs.
const REMZAR_HASH_BYTES_LEN: usize = 64;
const ZERO_HASH_64: Hash64 = [0u8; 64];

const GENESIS_HASH_BYTES_64: Hash64 = [
    0x48, 0xca, 0x1f, 0x06, 0x5d, 0xeb, 0xb4, 0xf4,
    0x29, 0x1f, 0x14, 0x23, 0xc3, 0xe9, 0xda, 0x44,
    0x66, 0x35, 0xe6, 0xfb, 0xc3, 0x9e, 0x16, 0x9c,
    0x2c, 0x7b, 0x4d, 0xfb, 0x25, 0xb3, 0x10, 0xc9,
    0x51, 0x43, 0xbc, 0x31, 0xab, 0x6a, 0xfb, 0x7e,
    0x63, 0xa8, 0x61, 0xab, 0xb4, 0x80, 0x7d, 0xfc,
    0x50, 0x61, 0x17, 0x65, 0x33, 0x7a, 0xa4, 0x59,
    0xe3, 0x47, 0x0f, 0x68, 0x2d, 0x21, 0x0e, 0x66,
];

const MAX_RETRIES: u8 = 3;

const AUTODIAL_PERIOD_MS: u128 = 10_000;
const AUTODIAL_RETRY_PEER_MS: u128 = 12_000;
const KAD_BOOTSTRAP_PERIOD_MS: u128 = 20_000;
const KAD_RANDOM_WALK_PERIOD_MS: u128 = 15_000;

const MAX_PENDING_VERSIONS: usize = 1024;
const MAX_PENDING_PQ: usize = 1024;
const MAX_PENDING_BLOCKS: usize = 1024;
const MAX_PENDING_BATCHES: usize = 1024;

const MAX_BLOCK_QUEUE: usize = 2048;
const MAX_BATCH_QUEUE: usize = 2048;

const MAX_HEIGHT_POLL_PEERS: usize = 256;
const MAX_AUTODIAL_PEERS_PER_TICK: usize = 64;
const MAX_AUTODIAL_ADDRS_PER_PEER: usize = 3;
const MAX_MULTIADDR_BYTES: usize = 256;

// Keep this model in sync with GlobalConfiguration::MAX_BLOCK_SIZE.
// The p2p_006_reqresp fuzz/proptest examples use a 2 MiB wire cap, and this
// builder helper models consensus payload-size enforcement.
const CONSENSUS_MAX_BYTES: usize = 2 * 1024 * 1024;

const MAX_MODEL_OPS: usize = 512;
const MAX_MODEL_QUEUE_LEN: usize = 4096;
const MAX_MODEL_MULTIADDRS: usize = 64;
const MAX_MODEL_PEERS: usize = 64;

fn genesis_hash_bytes_64() -> Hash64 {
    GENESIS_HASH_BYTES_64
}

fn consensus_max_bytes() -> usize {
    CONSENSUS_MAX_BYTES
}

fn exceeds_consensus_cap(n: usize) -> bool {
    n > consensus_max_bytes()
}

fn usize_to_u64_saturating(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[inline(always)]
fn sync_percent_from_counts(downloaded: u64, total_to_download: u64, has_synced: bool) -> f64 {
    if total_to_download == 0 {
        return if has_synced { 100.0 } else { 0.0 };
    }

    // This prevents u64 saturation from producing bogus low percentages.
    if downloaded >= total_to_download {
        return 100.0;
    }

    let bps = u128::from(downloaded)
        .saturating_mul(10_000)
        .checked_div(u128::from(total_to_download))
        .unwrap_or(0)
        .min(10_000);

    let whole = bps.div_euclid(100);
    let frac = bps.rem_euclid(100);
    let s = format!("{whole}.{frac:02}");

    s.parse::<f64>().unwrap_or(0.0)
}

fn ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }

    None
}

fn filter_multiaddr_bounds(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addrs
        .into_iter()
        .filter(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES)
        .collect()
}

fn fresh_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn hash_hex(hash: &Hash64) -> String {
    hex::encode(hash)
}

fn xor_hash(a: Hash64, b: Hash64) -> Hash64 {
    let mut out = [0u8; 64];

    for i in 0..64 {
        out[i] = a[i] ^ b[i];
    }

    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WireHash64(#[serde(with = "BigArray")] Hash64);

impl WireHash64 {
    #[inline]
    fn into_inner(self) -> Hash64 {
        self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WirePendingBatchRequest {
    peer_slot: u8,
    idx: u64,
    retries_left: u8,
    expected_block_hash: Option<WireHash64>,
}

#[derive(Debug, Clone)]
struct MemoryPendingBatchRequest {
    peer: PeerId,
    idx: u64,
    retries_left: u8,
    expected_block_hash: Option<Hash64>,
}

#[derive(Debug, Clone)]
struct MemoryBlock {
    index: u64,
    #[allow(dead_code)]
    previous_hash: Hash64,
    block_hash: Hash64,
}

#[derive(Debug)]
struct MemorySyncBuildersHarness {
    peers: Vec<PeerId>,

    pending_versions: HashMap<u64, PeerId>,
    pending_pq: HashMap<u64, PeerId>,
    pq_ready_peers: HashSet<PeerId>,

    pending_blocks: HashMap<u64, (PeerId, u64, u8)>,
    pending_batches: HashMap<u64, MemoryPendingBatchRequest>,

    block_queue: VecDeque<(PeerId, u64, u8)>,
    batch_queue: VecDeque<(PeerId, u64, u8)>,

    reserved_block_indices: HashSet<u64>,
    reserved_batch_indices: HashSet<u64>,

    canonical_blocks: HashMap<u64, MemoryBlock>,
    tip_height: u64,

    expected_genesis_hash: Option<String>,

    syncing: bool,
    has_synced: bool,
    total_to_download: u64,
    downloaded: u64,
    sync_target: u64,
    queued_sync_target: Option<u64>,
    last_synced_hash: Option<Hash64>,
    last_synced_index: Option<u64>,

    last_peer_dial_attempt_ms: HashMap<PeerId, u128>,
    last_autodial_ms: u128,
    last_kad_bootstrap_ms: u128,
    last_kad_random_walk_ms: u128,

    admitted_peers: HashSet<PeerId>,
    peer_ip: HashMap<PeerId, IpAddr>,
}

impl MemorySyncBuildersHarness {
    fn new() -> Self {
        let peers = (0..MAX_MODEL_PEERS).map(|_| fresh_peer_id()).collect();

        Self {
            peers,

            pending_versions: HashMap::new(),
            pending_pq: HashMap::new(),
            pq_ready_peers: HashSet::new(),

            pending_blocks: HashMap::new(),
            pending_batches: HashMap::new(),

            block_queue: VecDeque::new(),
            batch_queue: VecDeque::new(),

            reserved_block_indices: HashSet::new(),
            reserved_batch_indices: HashSet::new(),

            canonical_blocks: HashMap::new(),
            tip_height: 0,

            expected_genesis_hash: None,

            syncing: false,
            has_synced: false,
            total_to_download: 0,
            downloaded: 0,
            sync_target: 0,
            queued_sync_target: None,
            last_synced_hash: None,
            last_synced_index: None,

            last_peer_dial_attempt_ms: HashMap::new(),
            last_autodial_ms: 0,
            last_kad_bootstrap_ms: 0,
            last_kad_random_walk_ms: 0,

            admitted_peers: HashSet::new(),
            peer_ip: HashMap::new(),
        }
    }

    fn peer(&self, slot: u8) -> PeerId {
        let index = usize::from(slot) % self.peers.len();
        self.peers[index]
    }

    fn can_issue_more_pq_requests(&self) -> bool {
        self.pending_pq.len() < MAX_PENDING_PQ
    }

    fn mark_pq_ready(&mut self, peer: PeerId) {
        self.pq_ready_peers.insert(peer);
    }

    fn is_pq_ready(&self, peer: &PeerId) -> bool {
        self.pq_ready_peers.contains(peer)
    }

    fn clear_pq_peer_state(&mut self, peer: &PeerId) {
        self.pq_ready_peers.remove(peer);
        self.pending_pq.retain(|_, p| p != peer);
    }

    fn canonical_hash_at_height(&self, height: u64) -> Option<Hash64> {
        self.canonical_blocks.get(&height).map(|b| b.block_hash)
    }

    fn put_canonical_block(&mut self, index: u64, previous_hash: Hash64, block_hash: Hash64) {
        if self.canonical_blocks.len() >= MAX_MODEL_QUEUE_LEN {
            return;
        }

        self.canonical_blocks.insert(
            index,
            MemoryBlock {
                index,
                previous_hash,
                block_hash,
            },
        );

        if index > self.tip_height {
            self.tip_height = index;
        }
    }

    fn genesis_is_ready(&self) -> bool {
        let have_block0 = self.canonical_blocks.get(&0);

        match (&self.expected_genesis_hash, have_block0) {
            (Some(expected), Some(block0)) => block0_hash_matches_expected(block0, expected),
            (Some(_), None) => false,
            (None, Some(_)) => true,
            (None, None) => false,
        }
    }

    fn is_at_or_past_sync_target(&self) -> bool {
        self.tip_height >= self.sync_target
    }

    fn has_pending_sync_backlog(&self) -> bool {
        !self.block_queue.is_empty()
            || !self.pending_blocks.is_empty()
            || !self.batch_queue.is_empty()
            || !self.pending_batches.is_empty()
            || !self.reserved_block_indices.is_empty()
            || !self.reserved_batch_indices.is_empty()
    }

    fn has_background_sync_work(&self) -> bool {
        self.has_pending_sync_backlog()
    }

    fn update_sync_pointers(&mut self) {
        if let Some(hash) = self.canonical_hash_at_height(self.tip_height) {
            self.last_synced_hash = Some(hash);
            self.last_synced_index = Some(self.tip_height);
        } else {
            self.last_synced_hash = None;
            self.last_synced_index = None;
        }
    }

    fn update_sync_state(&mut self) {
        let block0_ok = self.genesis_is_ready();
        let at_tip = self.is_at_or_past_sync_target();
        let has_background_sync_work = self.has_pending_sync_backlog();

        self.has_synced = block0_ok && at_tip;
        self.syncing = !block0_ok || !at_tip || has_background_sync_work;
    }

    fn expected_prev(&self) -> Result<Hash64, &'static str> {
        self.last_synced_hash.ok_or("last_synced_hash not initialised")
    }

    fn sync_percent(&self) -> f64 {
        sync_percent_from_counts(
            self.downloaded,
            self.total_to_download,
            self.has_synced,
        )
    }

    fn push_pending_version(&mut self, request_id: u64, peer: PeerId) {
        if self.pending_versions.len() < MAX_PENDING_VERSIONS {
            self.pending_versions.insert(request_id, peer);
        }
    }

    fn push_pending_pq(&mut self, request_id: u64, peer: PeerId) {
        if self.pending_pq.len() < MAX_PENDING_PQ {
            self.pending_pq.insert(request_id, peer);
        }
    }

    fn push_pending_block(&mut self, request_id: u64, peer: PeerId, idx: u64, retries_left: u8) {
        if self.pending_blocks.len() < MAX_PENDING_BLOCKS {
            self.pending_blocks
                .insert(request_id, (peer, idx, retries_left));
        }
    }

    fn push_pending_batch(
        &mut self,
        request_id: u64,
        peer: PeerId,
        idx: u64,
        retries_left: u8,
        expected_block_hash: Option<Hash64>,
    ) {
        if self.pending_batches.len() < MAX_PENDING_BATCHES {
            self.pending_batches.insert(
                request_id,
                MemoryPendingBatchRequest {
                    peer,
                    idx,
                    retries_left,
                    expected_block_hash,
                },
            );
        }
    }

    fn push_block_queue(&mut self, peer: PeerId, idx: u64, retries_left: u8) {
        if self.block_queue.len() < MAX_BLOCK_QUEUE {
            self.block_queue.push_back((peer, idx, retries_left));
        }
    }

    fn push_batch_queue(&mut self, peer: PeerId, idx: u64, retries_left: u8) {
        if self.batch_queue.len() < MAX_BATCH_QUEUE {
            self.batch_queue.push_back((peer, idx, retries_left));
        }
    }

    fn reserve_block_idx(&mut self, idx: u64) {
        if self.reserved_block_indices.len() < MAX_BLOCK_QUEUE {
            self.reserved_block_indices.insert(idx);
        }
    }

    fn reserve_batch_idx(&mut self, idx: u64) {
        if self.reserved_batch_indices.len() < MAX_BATCH_QUEUE {
            self.reserved_batch_indices.insert(idx);
        }
    }

    fn clear_all_sync_reservations(&mut self) {
        self.reserved_block_indices.clear();
        self.reserved_batch_indices.clear();
    }

    fn filter_multiaddr_bounds_model(&self, addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
        let _ = self;
        filter_multiaddr_bounds(addrs)
    }

    fn autodial_tick_allowed(&self, now_ms: u128) -> bool {
        now_ms.saturating_sub(self.last_autodial_ms) >= AUTODIAL_PERIOD_MS
    }

    fn peer_redial_allowed(&self, peer: &PeerId, now_ms: u128) -> bool {
        match self.last_peer_dial_attempt_ms.get(peer) {
            Some(last) => now_ms.saturating_sub(*last) >= AUTODIAL_RETRY_PEER_MS,
            None => true,
        }
    }

    fn note_peer_dial_attempt(&mut self, peer: PeerId, now_ms: u128) {
        self.last_peer_dial_attempt_ms.insert(peer, now_ms);
    }

    fn kad_bootstrap_allowed(&self, now_ms: u128) -> bool {
        now_ms.saturating_sub(self.last_kad_bootstrap_ms) >= KAD_BOOTSTRAP_PERIOD_MS
    }

    fn kad_random_walk_allowed(&self, now_ms: u128) -> bool {
        now_ms.saturating_sub(self.last_kad_random_walk_ms) >= KAD_RANDOM_WALK_PERIOD_MS
    }

    fn cleanup_pending_for_peer_memory(&mut self, peer: PeerId) {
        self.pending_versions.retain(|_, p| *p != peer);
        self.pending_pq.retain(|_, p| *p != peer);
        self.pending_blocks.retain(|_, (p, _, _)| *p != peer);
        self.pending_batches.retain(|_, req| req.peer != peer);
        self.block_queue.retain(|(p, _, _)| *p != peer);
        self.batch_queue.retain(|(p, _, _)| *p != peer);
        self.admitted_peers.remove(&peer);
        self.peer_ip.remove(&peer);
        self.clear_pq_peer_state(&peer);
    }

    fn assert_invariants(&self) {
        assert_eq!(REMZAR_HASH_BYTES_LEN, 64);
        assert_eq!(ZERO_HASH_64, [0u8; 64]);
        assert_ne!(genesis_hash_bytes_64(), ZERO_HASH_64);

        assert!(MAX_RETRIES > 0);
        assert!(MAX_PENDING_VERSIONS > 0);
        assert!(MAX_PENDING_PQ > 0);
        assert!(MAX_PENDING_BLOCKS > 0);
        assert!(MAX_PENDING_BATCHES > 0);

        assert!(MAX_BLOCK_QUEUE >= MAX_PENDING_BLOCKS);
        assert!(MAX_BATCH_QUEUE >= MAX_PENDING_BATCHES);
        assert!(MAX_HEIGHT_POLL_PEERS >= MAX_AUTODIAL_PEERS_PER_TICK);
        assert!(MAX_AUTODIAL_ADDRS_PER_PEER <= MAX_AUTODIAL_PEERS_PER_TICK);

        assert!(AUTODIAL_RETRY_PEER_MS > AUTODIAL_PERIOD_MS);
        assert!(KAD_BOOTSTRAP_PERIOD_MS > KAD_RANDOM_WALK_PERIOD_MS);
        assert!(KAD_RANDOM_WALK_PERIOD_MS > AUTODIAL_PERIOD_MS);

        assert!(MAX_MULTIADDR_BYTES >= 64);
        assert!(MAX_MULTIADDR_BYTES <= 1024);

        assert!(self.pending_versions.len() <= MAX_PENDING_VERSIONS);
        assert!(self.pending_pq.len() <= MAX_PENDING_PQ);
        assert!(self.pending_blocks.len() <= MAX_PENDING_BLOCKS);
        assert!(self.pending_batches.len() <= MAX_PENDING_BATCHES);

        assert!(self.block_queue.len() <= MAX_BLOCK_QUEUE);
        assert!(self.batch_queue.len() <= MAX_BATCH_QUEUE);
        assert!(self.reserved_block_indices.len() <= MAX_BLOCK_QUEUE);
        assert!(self.reserved_batch_indices.len() <= MAX_BATCH_QUEUE);

        for peer in &self.pq_ready_peers {
            assert!(self.peers.contains(peer));
        }

        for peer in self.pending_pq.values() {
            assert!(self.peers.contains(peer));
        }

        for request in self.pending_batches.values() {
            if let Some(hash) = request.expected_block_hash {
                assert_eq!(hash.len(), REMZAR_HASH_BYTES_LEN);
            }

            assert!(request.retries_left <= u8::MAX);
        }

        if self.has_synced {
            assert!(self.genesis_is_ready());
            assert!(self.is_at_or_past_sync_target());
        }

        if self.has_background_sync_work() {
            assert!(self.syncing || self.has_synced);
        }

        let pct = self.sync_percent();
        assert!(pct.is_finite());
        assert!((0.0..=100.0).contains(&pct));

        if let Some(index) = self.last_synced_index {
            assert!(self.canonical_hash_at_height(index).is_some());
        }

        if self.last_synced_hash.is_some() {
            assert!(self.expected_prev().is_ok());
        }
    }
}

fn block0_hash_matches_expected(block0: &MemoryBlock, expected: &str) -> bool {
    hash_hex(&block0.block_hash) == expected
}

#[derive(Debug)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take_u8(&mut self) -> u8 {
        if self.pos >= self.data.len() {
            return 0;
        }

        let b = self.data[self.pos];
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn take_bool(&mut self) -> bool {
        self.take_u8() & 1 == 1
    }

    fn take_u16(&mut self) -> u16 {
        let mut out = [0u8; 2];
        self.fill(&mut out);
        u16::from_le_bytes(out)
    }

    fn take_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.fill(&mut out);
        u32::from_le_bytes(out)
    }

    fn take_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill(&mut out);
        u64::from_le_bytes(out)
    }

    fn take_u128(&mut self) -> u128 {
        let mut out = [0u8; 16];
        self.fill(&mut out);
        u128::from_le_bytes(out)
    }

    fn take_usize_mod(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        usize::try_from(self.take_u64()).unwrap_or(0) % max
    }

    fn take_hash(&mut self) -> Hash64 {
        let mut out = [0u8; 64];
        self.fill(&mut out);
        out
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }
}

fn make_multiaddr(cursor: &mut Cursor<'_>, harness: &MemorySyncBuildersHarness) -> Multiaddr {
    let component_count = cursor.take_usize_mod(24);
    let mut addr = Multiaddr::empty();

    for _ in 0..component_count {
        match cursor.take_u8() % 7 {
            0 => {
                let octets = [
                    cursor.take_u8(),
                    cursor.take_u8(),
                    cursor.take_u8(),
                    cursor.take_u8(),
                ];
                addr.push(Protocol::Ip4(Ipv4Addr::from(octets)));
            }
            1 => {
                let mut octets = [0u8; 16];
                cursor.fill(&mut octets);
                addr.push(Protocol::Ip6(Ipv6Addr::from(octets)));
            }
            2 => {
                addr.push(Protocol::Tcp(cursor.take_u16()));
            }
            3 => {
                addr.push(Protocol::Udp(cursor.take_u16()));
            }
            4 => {
                addr.push(Protocol::Memory(cursor.take_u64()));
            }
            5 => {
                let peer = harness.peer(cursor.take_u8());
                addr.push(Protocol::P2p(peer));
            }
            _ => {
                // Intentionally no-op to create empty / sparse addresses.
            }
        }
    }

    addr
}

fn first_ip_by_model(addr: &Multiaddr) -> Option<IpAddr> {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }

    None
}

fn fuzz_constants_and_pure_helpers(cursor: &mut Cursor<'_>, harness: &MemorySyncBuildersHarness) {
    let n = cursor.take_usize_mod(CONSENSUS_MAX_BYTES.saturating_add(7_500));

    assert_eq!(exceeds_consensus_cap(n), n > consensus_max_bytes());
    assert_eq!(
        exceeds_consensus_cap(consensus_max_bytes()),
        false,
        "exact consensus cap must be accepted"
    );
    assert_eq!(
        exceeds_consensus_cap(consensus_max_bytes().saturating_add(1)),
        true,
        "cap + 1 must be rejected"
    );

    let converted = usize_to_u64_saturating(n);
    assert_eq!(converted, u64::try_from(n).unwrap_or(u64::MAX));

    let hash = cursor.take_hash();
    assert_eq!(xor_hash(hash, ZERO_HASH_64), hash);

    let genesis = genesis_hash_bytes_64();
    assert_eq!(genesis.len(), REMZAR_HASH_BYTES_LEN);
    assert_ne!(genesis, ZERO_HASH_64);

    let addr = make_multiaddr(cursor, harness);
    assert_eq!(ip_from_multiaddr(&addr), first_ip_by_model(&addr));

    let result = std::panic::catch_unwind(|| {
        let _ = ip_from_multiaddr(&addr);
    });

    assert!(result.is_ok());
}

fn fuzz_multiaddr_filter(cursor: &mut Cursor<'_>, harness: &MemorySyncBuildersHarness) {
    let count = cursor.take_usize_mod(MAX_MODEL_MULTIADDRS);
    let mut addrs = Vec::with_capacity(count);

    for _ in 0..count {
        addrs.push(make_multiaddr(cursor, harness));
    }

    let filtered = harness.filter_multiaddr_bounds_model(addrs.clone());

    assert!(filtered
        .iter()
        .all(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES));

    let expected: Vec<_> = addrs
        .into_iter()
        .filter(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES)
        .collect();

    assert_eq!(filtered, expected);
}

fn fuzz_pending_batch_request(cursor: &mut Cursor<'_>, harness: &MemorySyncBuildersHarness) {
    let peer = harness.peer(cursor.take_u8());
    let idx = cursor.take_u64();
    let retries_left = cursor.take_u8();
    let expected_block_hash = cursor.take_bool().then(|| cursor.take_hash());

    let req = MemoryPendingBatchRequest {
        peer,
        idx,
        retries_left,
        expected_block_hash,
    };

    let cloned = req.clone();

    assert_eq!(cloned.peer, req.peer);
    assert_eq!(cloned.idx, req.idx);
    assert_eq!(cloned.retries_left, req.retries_left);
    assert_eq!(cloned.expected_block_hash, req.expected_block_hash);

    if let Some(hash) = cloned.expected_block_hash {
        assert_eq!(hash.len(), REMZAR_HASH_BYTES_LEN);
    }

    // Exercise postcard decoding on a lightweight wire shape so arbitrary input
    // cannot panic the fuzz target.
    let raw = cursor.take_vec(256);
    let decoded = std::panic::catch_unwind(|| from_bytes::<WirePendingBatchRequest>(&raw));
    assert!(decoded.is_ok());

    let encoded = to_allocvec(&WirePendingBatchRequest {
        peer_slot: cursor.take_u8(),
        idx,
        retries_left,
        expected_block_hash: expected_block_hash.map(WireHash64),
    });

    if let Ok(bytes) = encoded {
        let roundtrip = from_bytes::<WirePendingBatchRequest>(&bytes)
            .expect("freshly encoded pending batch request must decode");

        assert_eq!(roundtrip.idx, idx);
        assert_eq!(roundtrip.retries_left, retries_left);
        assert_eq!(
            roundtrip.expected_block_hash.map(WireHash64::into_inner),
            expected_block_hash
        );
    }
}

fn fuzz_pq_state(cursor: &mut Cursor<'_>, harness: &mut MemorySyncBuildersHarness) {
    let peer = harness.peer(cursor.take_u8());
    let request_id = cursor.take_u64();

    if cursor.take_bool() {
        harness.push_pending_pq(request_id, peer);
    }

    if cursor.take_bool() {
        harness.mark_pq_ready(peer);
        assert!(harness.is_pq_ready(&peer));
    }

    if cursor.take_bool() {
        harness.clear_pq_peer_state(&peer);

        assert!(!harness.is_pq_ready(&peer));
        assert!(harness.pending_pq.values().all(|p| *p != peer));
    }

    assert_eq!(
        harness.can_issue_more_pq_requests(),
        harness.pending_pq.len() < MAX_PENDING_PQ
    );
}

fn fuzz_pending_maps_and_queues(cursor: &mut Cursor<'_>, harness: &mut MemorySyncBuildersHarness) {
    let peer = harness.peer(cursor.take_u8());
    let request_id = cursor.take_u64();
    let idx = cursor.take_u64();
    let retries_left = cursor.take_u8().min(MAX_RETRIES);
    let expected_hash = cursor.take_bool().then(|| cursor.take_hash());

    match cursor.take_u8() % 8 {
        0 => harness.push_pending_version(request_id, peer),
        1 => harness.push_pending_pq(request_id, peer),
        2 => harness.push_pending_block(request_id, peer, idx, retries_left),
        3 => harness.push_pending_batch(request_id, peer, idx, retries_left, expected_hash),
        4 => harness.push_block_queue(peer, idx, retries_left),
        5 => harness.push_batch_queue(peer, idx, retries_left),
        6 => harness.reserve_block_idx(idx),
        _ => harness.reserve_batch_idx(idx),
    }

    if cursor.take_bool() {
        harness.clear_all_sync_reservations();
        assert!(harness.reserved_block_indices.is_empty());
        assert!(harness.reserved_batch_indices.is_empty());
    }
}

fn fuzz_sync_state(cursor: &mut Cursor<'_>, harness: &mut MemorySyncBuildersHarness) {
    let index = cursor.take_u64() % 1_000_000;
    let prev = if index == 0 {
        ZERO_HASH_64
    } else {
        cursor.take_hash()
    };
    let block_hash = if cursor.take_bool() && index == 0 {
        genesis_hash_bytes_64()
    } else {
        cursor.take_hash()
    };

    if cursor.take_bool() {
        harness.put_canonical_block(index, prev, block_hash);
    }

    if cursor.take_bool() {
        harness.expected_genesis_hash = Some(hash_hex(&genesis_hash_bytes_64()));
    } else if cursor.take_bool() {
        harness.expected_genesis_hash = None;
    } else {
        harness.expected_genesis_hash = Some(hash_hex(&cursor.take_hash()));
    }

    harness.sync_target = cursor.take_u64() % 1_000_000;
    harness.downloaded = cursor.take_u64() % 1_000_000;
    harness.total_to_download = cursor.take_u64() % 1_000_000;
    harness.queued_sync_target = cursor.take_bool().then(|| cursor.take_u64() % 1_000_000);

    harness.update_sync_pointers();
    harness.update_sync_state();

    assert_eq!(
        harness.has_synced,
        harness.genesis_is_ready() && harness.is_at_or_past_sync_target()
    );

    assert_eq!(
        harness.syncing,
        !harness.genesis_is_ready()
            || !harness.is_at_or_past_sync_target()
            || harness.has_pending_sync_backlog()
    );

    if harness.tip_height > 0 && harness.canonical_hash_at_height(harness.tip_height).is_none() {
        assert!(harness.last_synced_hash.is_none() || harness.last_synced_index != Some(harness.tip_height));
    }
}

fn regression_sync_percent_handles_completion_and_overflow_edges() {
    let pct = sync_percent_from_counts(u64::MAX, u64::MAX - 1, false);
    assert_eq!(pct, 100.0);

    let pct = sync_percent_from_counts(u64::MAX, u64::MAX, false);
    assert_eq!(pct, 100.0);

    let pct = sync_percent_from_counts(u64::MAX / 2, u64::MAX, false);
    assert!(pct.is_finite());
    assert!((0.0..100.0).contains(&pct));

    let pct = sync_percent_from_counts(0, 0, false);
    assert_eq!(pct, 0.0);

    let pct = sync_percent_from_counts(0, 0, true);
    assert_eq!(pct, 100.0);

    let pct = sync_percent_from_counts(1, 4, false);
    assert_eq!(pct, 25.0);

    let pct = sync_percent_from_counts(3, 4, false);
    assert_eq!(pct, 75.0);

    let pct = sync_percent_from_counts(4, 4, false);
    assert_eq!(pct, 100.0);

    let pct = sync_percent_from_counts(5, 4, false);
    assert_eq!(pct, 100.0);
}

fn fuzz_sync_percent(cursor: &mut Cursor<'_>, harness: &mut MemorySyncBuildersHarness) {
    harness.downloaded = cursor.take_u64();
    harness.total_to_download = cursor.take_u64();
    harness.has_synced = cursor.take_bool();

    let pct = harness.sync_percent();

    assert!(pct.is_finite());
    assert!((0.0..=100.0).contains(&pct));

    if harness.total_to_download == 0 && harness.has_synced {
        assert_eq!(pct, 100.0);
    }

    if harness.total_to_download == 0 && !harness.has_synced {
        assert_eq!(pct, 0.0);
    }

    if harness.total_to_download > 0 && harness.downloaded >= harness.total_to_download {
        assert_eq!(pct, 100.0);
    }

    if harness.total_to_download > 0 && harness.downloaded < harness.total_to_download {
        assert!(pct < 100.0);
    }
}

fn fuzz_throttles(cursor: &mut Cursor<'_>, harness: &mut MemorySyncBuildersHarness) {
    let peer = harness.peer(cursor.take_u8());
    let now_ms = cursor.take_u128();

    let previous_autodial = harness.last_autodial_ms;
    let allowed = harness.autodial_tick_allowed(now_ms);

    assert_eq!(
        allowed,
        now_ms.saturating_sub(previous_autodial) >= AUTODIAL_PERIOD_MS
    );

    if allowed {
        harness.last_autodial_ms = now_ms;
    }

    let peer_allowed_before = harness.peer_redial_allowed(&peer, now_ms);
    let prev_peer_last = harness.last_peer_dial_attempt_ms.get(&peer).copied();

    assert_eq!(
        peer_allowed_before,
        prev_peer_last
            .map(|last| now_ms.saturating_sub(last) >= AUTODIAL_RETRY_PEER_MS)
            .unwrap_or(true)
    );

    harness.note_peer_dial_attempt(peer, now_ms);

    // Immediately after noting a dial attempt at `now_ms`, another dial at
    // the same timestamp must be rejected.
    assert!(!harness.peer_redial_allowed(&peer, now_ms));

    // A timestamp that advances by less than the cooldown must still be rejected.
    //
    // Use saturating_add here only for the "not enough time has passed" case:
    // even if `now_ms` is close to u128::MAX, the saturated timestamp cannot
    // represent a full AUTODIAL_RETRY_PEER_MS elapsed interval unless the model
    // says so through saturating_sub below.
    let soon_delta = AUTODIAL_RETRY_PEER_MS.saturating_sub(1);
    let soon = now_ms.saturating_add(soon_delta);
    let soon_expected = soon.saturating_sub(now_ms) >= AUTODIAL_RETRY_PEER_MS;

    assert_eq!(harness.peer_redial_allowed(&peer, soon), soon_expected);
    assert!(!soon_expected);

    // A timestamp exactly one cooldown later is allowed only when that timestamp
    // can be represented without overflowing u128. The previous version used
    // saturating_add and unconditionally expected success, which is false for
    // arbitrary fuzzed `now_ms` values near u128::MAX.
    if let Some(later) = now_ms.checked_add(AUTODIAL_RETRY_PEER_MS) {
        assert!(harness.peer_redial_allowed(&peer, later));
    } else {
        let saturated_later = u128::MAX;
        let expected = saturated_later.saturating_sub(now_ms) >= AUTODIAL_RETRY_PEER_MS;

        assert_eq!(
            harness.peer_redial_allowed(&peer, saturated_later),
            expected
        );
        assert!(!expected);
    }

    let kad_bootstrap = harness.kad_bootstrap_allowed(now_ms);
    assert_eq!(
        kad_bootstrap,
        now_ms.saturating_sub(harness.last_kad_bootstrap_ms) >= KAD_BOOTSTRAP_PERIOD_MS
    );

    if kad_bootstrap {
        harness.last_kad_bootstrap_ms = now_ms;
    }

    let kad_walk = harness.kad_random_walk_allowed(now_ms);
    assert_eq!(
        kad_walk,
        now_ms.saturating_sub(harness.last_kad_random_walk_ms) >= KAD_RANDOM_WALK_PERIOD_MS
    );

    if kad_walk {
        harness.last_kad_random_walk_ms = now_ms;
    }
}

fn fuzz_peer_cleanup(cursor: &mut Cursor<'_>, harness: &mut MemorySyncBuildersHarness) {
    let peer = harness.peer(cursor.take_u8());
    let other = harness.peer(cursor.take_u8());

    harness.admitted_peers.insert(peer);
    harness.admitted_peers.insert(other);

    harness.peer_ip.insert(
        peer,
        IpAddr::V4(Ipv4Addr::new(
            cursor.take_u8(),
            cursor.take_u8(),
            cursor.take_u8(),
            cursor.take_u8(),
        )),
    );

    harness.mark_pq_ready(peer);
    harness.push_pending_pq(cursor.take_u64(), peer);
    harness.push_pending_version(cursor.take_u64(), peer);
    harness.push_pending_block(cursor.take_u64(), peer, cursor.take_u64(), MAX_RETRIES);
    harness.push_pending_batch(
        cursor.take_u64(),
        peer,
        cursor.take_u64(),
        MAX_RETRIES,
        cursor.take_bool().then(|| cursor.take_hash()),
    );
    harness.push_block_queue(peer, cursor.take_u64(), MAX_RETRIES);
    harness.push_batch_queue(peer, cursor.take_u64(), MAX_RETRIES);

    harness.cleanup_pending_for_peer_memory(peer);

    assert!(!harness.pq_ready_peers.contains(&peer));
    assert!(!harness.admitted_peers.contains(&peer));
    assert!(!harness.peer_ip.contains_key(&peer));
    assert!(harness.pending_pq.values().all(|p| *p != peer));
    assert!(harness.pending_versions.values().all(|p| *p != peer));
    assert!(harness.pending_blocks.values().all(|(p, _, _)| *p != peer));
    assert!(harness.pending_batches.values().all(|req| req.peer != peer));
    assert!(harness.block_queue.iter().all(|(p, _, _)| *p != peer));
    assert!(harness.batch_queue.iter().all(|(p, _, _)| *p != peer));
}

fn fuzz_autodial_candidate_bounds(cursor: &mut Cursor<'_>, harness: &MemorySyncBuildersHarness) {
    let peer_count = cursor.take_usize_mod(MAX_AUTODIAL_PEERS_PER_TICK.saturating_mul(4));
    let mut attempted_peers = 0usize;
    let mut total_candidate_addrs = 0usize;

    for _ in 0..peer_count {
        if attempted_peers >= MAX_AUTODIAL_PEERS_PER_TICK {
            break;
        }

        let addr_count = cursor.take_usize_mod(16);
        let mut addrs = Vec::new();

        for _ in 0..addr_count {
            addrs.push(make_multiaddr(cursor, harness));
        }

        let bounded = filter_multiaddr_bounds(addrs);
        let selected = bounded
            .into_iter()
            .take(MAX_AUTODIAL_ADDRS_PER_PEER)
            .collect::<Vec<_>>();

        assert!(selected.len() <= MAX_AUTODIAL_ADDRS_PER_PEER);
        assert!(selected
            .iter()
            .all(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES));

        total_candidate_addrs = total_candidate_addrs.saturating_add(selected.len());
        attempted_peers = attempted_peers.saturating_add(1);
    }

    assert!(attempted_peers <= MAX_AUTODIAL_PEERS_PER_TICK);
    assert!(
        total_candidate_addrs
            <= MAX_AUTODIAL_PEERS_PER_TICK.saturating_mul(MAX_AUTODIAL_ADDRS_PER_PEER)
    );
}

fn fuzz_postcard_and_arbitrary_bytes(cursor: &mut Cursor<'_>) {
    let data = cursor.take_vec(1024);

    let result = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WirePendingBatchRequest>(&data);
    });

    assert!(result.is_ok());

    let hash = cursor.take_hash();
    let wire = WirePendingBatchRequest {
        peer_slot: cursor.take_u8(),
        idx: cursor.take_u64(),
        retries_left: cursor.take_u8(),
        expected_block_hash: cursor.take_bool().then_some(WireHash64(hash)),
    };

    let encoded = to_allocvec(&wire).expect("wire pending batch should encode");
    let decoded: WirePendingBatchRequest =
        from_bytes(&encoded).expect("freshly encoded wire pending batch should decode");

    assert_eq!(decoded.peer_slot, wire.peer_slot);
    assert_eq!(decoded.idx, wire.idx);
    assert_eq!(decoded.retries_left, wire.retries_left);
    assert_eq!(decoded.expected_block_hash, wire.expected_block_hash);
}

fuzz_target!(|data: &[u8]| {
    regression_sync_percent_handles_completion_and_overflow_edges();

    let mut cursor = Cursor::new(data);
    let mut harness = MemorySyncBuildersHarness::new();

    let op_count = cursor
        .take_usize_mod(MAX_MODEL_OPS)
        .min(data.len().saturating_add(1));

    for _ in 0..op_count {
        match cursor.take_u8() % 11 {
            0 => fuzz_constants_and_pure_helpers(&mut cursor, &harness),
            1 => fuzz_multiaddr_filter(&mut cursor, &harness),
            2 => fuzz_pending_batch_request(&mut cursor, &harness),
            3 => fuzz_pq_state(&mut cursor, &mut harness),
            4 => fuzz_pending_maps_and_queues(&mut cursor, &mut harness),
            5 => fuzz_sync_state(&mut cursor, &mut harness),
            6 => fuzz_sync_percent(&mut cursor, &mut harness),
            7 => fuzz_throttles(&mut cursor, &mut harness),
            8 => fuzz_peer_cleanup(&mut cursor, &mut harness),
            9 => fuzz_autodial_candidate_bounds(&mut cursor, &harness),
            _ => fuzz_postcard_and_arbitrary_bytes(&mut cursor),
        }

        // Refresh cached sync/synced flags after arbitrary model mutations.
        // Several fuzz operations mutate pending queues/reservations directly.
        harness.update_sync_state();

        harness.assert_invariants();

        if cursor.remaining() == 0 {
            break;
        }
    }

    harness.update_sync_state();
    harness.assert_invariants();
});