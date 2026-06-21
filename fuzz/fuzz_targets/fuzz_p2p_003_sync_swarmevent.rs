// fuzz/fuzz_targets/fuzz_p2p_003_sync_swarmevent.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

use libp2p::{identity, multiaddr::Protocol, Multiaddr, PeerId};

use postcard::{from_bytes, to_allocvec};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use std::collections::{HashMap, HashSet, VecDeque};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_PENDING_BLOCKS: usize = 1024;
const MAX_PENDING_BATCHES: usize = 1024;
const MAX_PENDING_PQ: usize = 1024;
const MAX_PENDING_VERSIONS: usize = 1024;

const MAX_BLOCK_QUEUE: usize = 2048;
const MAX_BATCH_QUEUE: usize = 2048;

const MAX_MULTIADDR_BYTES: usize = 256;

const MAX_RETRIES: u8 = 3;

const MAX_EVENTS: usize = 512;

type Hash64 = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WireHash64(#[serde(with = "BigArray")] Hash64);

impl WireHash64 {
    #[inline]
    fn into_inner(self) -> Hash64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum EventKind {
    ConnectionEstablished,
    ConnectionClosed,
    IncomingVersion,
    IncomingPq,
    IncomingBlock,
    IncomingBatch,
    ResponseTimeout,
    DuplicateBlock,
    DuplicateBatch,
    QueueDrain,
    ReservationClear,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEvent {
    peer_slot: u8,
    request_id: u64,
    index: u64,
    retries_left: u8,
    event_kind: EventKind,
    wants_hash: bool,
    hash: WireHash64,
}

#[derive(Debug, Clone)]
struct PendingBatch {
    peer: PeerId,
    index: u64,
    retries_left: u8,
    expected_hash: Option<Hash64>,
}

#[derive(Debug)]
struct SwarmEventHarness {
    peers: Vec<PeerId>,

    connected: HashSet<PeerId>,
    pq_ready: HashSet<PeerId>,

    pending_versions: HashMap<u64, PeerId>,
    pending_pq: HashMap<u64, PeerId>,
    pending_blocks: HashMap<u64, (PeerId, u64, u8)>,
    pending_batches: HashMap<u64, PendingBatch>,

    block_queue: VecDeque<(PeerId, u64, u8)>,
    batch_queue: VecDeque<(PeerId, u64, u8)>,

    reserved_block_indices: HashSet<u64>,
    reserved_batch_indices: HashSet<u64>,

    seen_blocks: HashSet<Hash64>,
    seen_batches: HashSet<Hash64>,

    peer_ip: HashMap<PeerId, IpAddr>,
}

impl SwarmEventHarness {
    fn new() -> Self {
        Self {
            peers: (0..64)
                .map(|_| PeerId::from(identity::Keypair::generate_ed25519().public()))
                .collect(),

            connected: HashSet::new(),
            pq_ready: HashSet::new(),

            pending_versions: HashMap::new(),
            pending_pq: HashMap::new(),
            pending_blocks: HashMap::new(),
            pending_batches: HashMap::new(),

            block_queue: VecDeque::new(),
            batch_queue: VecDeque::new(),

            reserved_block_indices: HashSet::new(),
            reserved_batch_indices: HashSet::new(),

            seen_blocks: HashSet::new(),
            seen_batches: HashSet::new(),

            peer_ip: HashMap::new(),
        }
    }

    fn peer(&self, slot: u8) -> PeerId {
        self.peers[(slot as usize) % self.peers.len()]
    }

    fn connect_peer(&mut self, peer: PeerId) {
        self.connected.insert(peer);
    }

    fn disconnect_peer(&mut self, peer: PeerId) {
        self.connected.remove(&peer);
        self.pq_ready.remove(&peer);

        self.pending_versions.retain(|_, p| *p != peer);
        self.pending_pq.retain(|_, p| *p != peer);
        self.pending_blocks.retain(|_, (p, _, _)| *p != peer);
        self.pending_batches.retain(|_, req| req.peer != peer);

        self.block_queue.retain(|(p, _, _)| *p != peer);
        self.batch_queue.retain(|(p, _, _)| *p != peer);

        self.peer_ip.remove(&peer);
    }

    fn mark_pq_ready(&mut self, peer: PeerId) {
        self.connected.insert(peer);
        self.pq_ready.insert(peer);
    }

    fn push_pending_block(
        &mut self,
        request_id: u64,
        peer: PeerId,
        index: u64,
        retries_left: u8,
    ) {
        if self.pending_blocks.len() < MAX_PENDING_BLOCKS {
            self.pending_blocks
                .insert(request_id, (peer, index, retries_left.min(MAX_RETRIES)));
        }
    }

    fn push_pending_batch(
        &mut self,
        request_id: u64,
        peer: PeerId,
        index: u64,
        retries_left: u8,
        expected_hash: Option<Hash64>,
    ) {
        if self.pending_batches.len() < MAX_PENDING_BATCHES {
            self.pending_batches.insert(
                request_id,
                PendingBatch {
                    peer,
                    index,
                    retries_left: retries_left.min(MAX_RETRIES),
                    expected_hash,
                },
            );
        }
    }

    fn enqueue_block_retry(&mut self, peer: PeerId, index: u64, retries_left: u8) {
        if self.block_queue.len() < MAX_BLOCK_QUEUE {
            self.block_queue
                .push_back((peer, index, retries_left.min(MAX_RETRIES)));
        }
    }

    fn enqueue_batch_retry(&mut self, peer: PeerId, index: u64, retries_left: u8) {
        if self.batch_queue.len() < MAX_BATCH_QUEUE {
            self.batch_queue
                .push_back((peer, index, retries_left.min(MAX_RETRIES)));
        }
    }

    fn clear_reservations(&mut self) {
        self.reserved_block_indices.clear();
        self.reserved_batch_indices.clear();
    }

    fn classify_duplicate_block(&mut self, hash: Hash64) -> bool {
        !self.seen_blocks.insert(hash)
    }

    fn classify_duplicate_batch(&mut self, hash: Hash64) -> bool {
        !self.seen_batches.insert(hash)
    }

    fn drain_queues(&mut self) {
        while self.block_queue.len() > MAX_PENDING_BLOCKS {
            self.block_queue.pop_front();
        }

        while self.batch_queue.len() > MAX_PENDING_BATCHES {
            self.batch_queue.pop_front();
        }
    }

    fn assert_invariants(&self) {
        assert!(self.pending_versions.len() <= MAX_PENDING_VERSIONS);
        assert!(self.pending_pq.len() <= MAX_PENDING_PQ);
        assert!(self.pending_blocks.len() <= MAX_PENDING_BLOCKS);
        assert!(self.pending_batches.len() <= MAX_PENDING_BATCHES);

        assert!(self.block_queue.len() <= MAX_BLOCK_QUEUE);
        assert!(self.batch_queue.len() <= MAX_BATCH_QUEUE);

        for peer in &self.pq_ready {
            assert!(self.connected.contains(peer));
        }

        for (_, (_, _, retries)) in &self.pending_blocks {
            assert!(*retries <= MAX_RETRIES);
        }

        for (_, req) in &self.pending_batches {
            assert!(req.retries_left <= MAX_RETRIES);
            assert!(req.index <= u64::MAX);

            if let Some(hash) = req.expected_hash {
                assert_eq!(hash.len(), 64);
            }
        }

        for ip in self.peer_ip.values() {
            match ip {
                IpAddr::V4(_) | IpAddr::V6(_) => {}
            }
        }
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
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

    fn take_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for b in &mut out {
            *b = self.take_u8();
        }

        u64::from_le_bytes(out)
    }

    fn take_hash(&mut self) -> Hash64 {
        let mut out = [0u8; 64];

        for b in &mut out {
            *b = self.take_u8();
        }

        out
    }

    fn take_vec(&mut self, max: usize) -> Vec<u8> {
        let len = (self.take_u64() as usize) % max.saturating_add(1);

        let mut out = vec![0u8; len];

        for b in &mut out {
            *b = self.take_u8();
        }

        out
    }
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

fn make_multiaddr(cursor: &mut Cursor<'_>) -> Multiaddr {
    let mut addr = Multiaddr::empty();

    match cursor.take_u8() % 4 {
        0 => {
            addr.push(Protocol::Ip4(Ipv4Addr::new(
                cursor.take_u8(),
                cursor.take_u8(),
                cursor.take_u8(),
                cursor.take_u8(),
            )));
        }

        1 => {
            let mut octets = [0u8; 16];

            for b in &mut octets {
                *b = cursor.take_u8();
            }

            addr.push(Protocol::Ip6(Ipv6Addr::from(octets)));
        }

        2 => {
            addr.push(Protocol::Memory(cursor.take_u64()));
        }

        _ => {}
    }

    addr
}

fn fuzz_event_dispatch(cursor: &mut Cursor<'_>, harness: &mut SwarmEventHarness) {
    let peer = harness.peer(cursor.take_u8());

    let request_id = cursor.take_u64();
    let index = cursor.take_u64();

    let retries = cursor.take_u8();

    let hash = cursor.take_hash();

    let event = match cursor.take_u8() % 12 {
        0 => EventKind::ConnectionEstablished,
        1 => EventKind::ConnectionClosed,
        2 => EventKind::IncomingVersion,
        3 => EventKind::IncomingPq,
        4 => EventKind::IncomingBlock,
        5 => EventKind::IncomingBatch,
        6 => EventKind::ResponseTimeout,
        7 => EventKind::DuplicateBlock,
        8 => EventKind::DuplicateBatch,
        9 => EventKind::QueueDrain,
        10 => EventKind::ReservationClear,
        _ => EventKind::Unknown,
    };

    match event {
        EventKind::ConnectionEstablished => {
            harness.connect_peer(peer);

            assert!(harness.connected.contains(&peer));
        }

        EventKind::ConnectionClosed => {
            harness.disconnect_peer(peer);

            assert!(!harness.connected.contains(&peer));
            assert!(!harness.pq_ready.contains(&peer));
        }

        EventKind::IncomingVersion => {
            if harness.pending_versions.len() < MAX_PENDING_VERSIONS {
                harness.pending_versions.insert(request_id, peer);
            }
        }

        EventKind::IncomingPq => {
            if harness.pending_pq.len() < MAX_PENDING_PQ {
                harness.pending_pq.insert(request_id, peer);
            }

            harness.mark_pq_ready(peer);

            assert!(harness.pq_ready.contains(&peer));
            assert!(harness.connected.contains(&peer));
        }

        EventKind::IncomingBlock => {
            harness.push_pending_block(request_id, peer, index, retries);
        }

        EventKind::IncomingBatch => {
            harness.push_pending_batch(request_id, peer, index, retries, Some(hash));
        }

        EventKind::ResponseTimeout => {
            harness.enqueue_block_retry(peer, index, retries);
            harness.enqueue_batch_retry(peer, index, retries);
        }

        EventKind::DuplicateBlock => {
            let duplicate = harness.classify_duplicate_block(hash);
            if duplicate {
                assert!(harness.seen_blocks.contains(&hash));
            }
        }

        EventKind::DuplicateBatch => {
            let duplicate = harness.classify_duplicate_batch(hash);
            if duplicate {
                assert!(harness.seen_batches.contains(&hash));
            }
        }

        EventKind::QueueDrain => {
            harness.drain_queues();
        }

        EventKind::ReservationClear => {
            harness.clear_reservations();
        }

        EventKind::Unknown => {}
    }
}

fn fuzz_multiaddr_handling(cursor: &mut Cursor<'_>, harness: &mut SwarmEventHarness) {
    let peer = harness.peer(cursor.take_u8());

    let addr = make_multiaddr(cursor);

    if addr.to_vec().len() <= MAX_MULTIADDR_BYTES {
        if let Some(ip) = ip_from_multiaddr(&addr) {
            harness.peer_ip.insert(peer, ip);
        }
    }

    if let Some(ip) = harness.peer_ip.get(&peer) {
        match ip {
            IpAddr::V4(_) | IpAddr::V6(_) => {}
        }
    }
}

fn fuzz_wire_decoding(cursor: &mut Cursor<'_>) {
    let raw = cursor.take_vec(1024);

    let result = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireEvent>(&raw);
    });

    assert!(result.is_ok());

    let hash = cursor.take_hash();
    let wire = WireEvent {
        peer_slot: cursor.take_u8(),
        request_id: cursor.take_u64(),
        index: cursor.take_u64(),
        retries_left: cursor.take_u8(),
        event_kind: EventKind::IncomingBlock,
        wants_hash: cursor.take_bool(),
        hash: WireHash64(hash),
    };

    let encoded = to_allocvec(&wire).expect("wire encode must succeed");

    let decoded: WireEvent = from_bytes(&encoded).expect("freshly encoded wire must decode");

    assert_eq!(decoded.peer_slot, wire.peer_slot);
    assert_eq!(decoded.request_id, wire.request_id);
    assert_eq!(decoded.index, wire.index);
    assert_eq!(decoded.retries_left, wire.retries_left);
    assert_eq!(decoded.event_kind, wire.event_kind);
    assert_eq!(decoded.wants_hash, wire.wants_hash);
    assert_eq!(decoded.hash.into_inner(), hash);
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);

    let mut harness = SwarmEventHarness::new();

    let iterations = ((cursor.take_u64() as usize) % MAX_EVENTS).max(1);

    for _ in 0..iterations {
        match cursor.take_u8() % 3 {
            0 => fuzz_event_dispatch(&mut cursor, &mut harness),

            1 => fuzz_multiaddr_handling(&mut cursor, &mut harness),

            _ => fuzz_wire_decoding(&mut cursor),
        }

        harness.assert_invariants();
    }

    harness.assert_invariants();
});
