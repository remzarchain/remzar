// fuzz/fuzz_targets/fuzz_p2p_005_sync_gossipsub.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

use libp2p::{identity, PeerId};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

type Hash32 = [u8; 32];
type Hash64 = [u8; 64];

// Mirrors p2p_005_sync_gossipsub.rs defensive caps.
const MAX_GOSSIP_BYTES: usize = 1024 * 1024;
const MAX_CHAT_WIRE_BYTES: usize = 64 * 1024;
const MAX_FILE_WIRE_BYTES: usize = 256 * 1024;
const MAX_FILE_CHUNK_BYTES: usize = 192 * 1024;
const MAX_FILE_TOTAL_CHUNKS: u32 = 200_000;
const MAX_FILENAME_BYTES: usize = 255;
const MAX_WALLET_TEXT_BYTES: usize = 256;

// Keep this model aligned with the other p2p fuzz targets that model
// GlobalConfiguration::MAX_BLOCK_SIZE as a 2 MiB consensus payload cap.
const CONSENSUS_MAX_BYTES: usize = 2 * 1024 * 1024;

const MAX_EVENTS: usize = 512;
const MAX_MODEL_PEERS: usize = 64;
const MAX_MODEL_BYTES: usize = 4096;
const MAX_MODEL_TEXT: usize = 512;
const MAX_MODEL_LISTEN_ADDRS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WireHash64(#[serde(with = "BigArray")] Hash64);

impl WireHash64 {
    #[inline]
    fn into_inner(self) -> Hash64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopicKind {
    Chat,
    File,
    PeerMesh,
    Consensus,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum WireMessageKind {
    TxKind,
    Transaction,
    RegisterNode,
    Reward,
    TxBatch,
    Block,
    PorPuzzleProof,
    PeerMeshAnnounce,
    Malformed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireConsensusEnvelope {
    kind: WireMessageKind,
    wallet: String,
    peer_id: String,
    payload_len: u64,
    canonical_len: u64,
    height: u64,
    hash: WireHash64,
    direct_peer_mesh: bool,
    declares_local_peer: bool,
    listen_addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireChatEnvelope {
    from_wallet: String,
    to_wallet: String,
    timestamp_ms: u64,
    json: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireFileChunkEnvelope {
    file_id: Hash32,
    from_wallet: String,
    to_wallet: String,
    filename: String,
    file_size_bytes: u64,
    content_hash_hex: String,
    total_chunks: u32,
    chunk_index: u32,
    timestamp_ms: u64,
    chunk_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireAnyEnvelope {
    kind: WireMessageKind,
    chat: Option<WireChatEnvelope>,
    file: Option<WireFileChunkEnvelope>,
    consensus: Option<WireConsensusEnvelope>,
}

#[derive(Debug, Default)]
struct ModelMempool {
    tx_kind_count: usize,
    tx_count: usize,
}

#[derive(Debug, Default)]
struct ModelRegistry {
    registered_wallets: HashSet<String>,
    identity_map: HashMap<String, String>,
    first_seen_tip: HashMap<String, u64>,
    heartbeats: usize,
}

impl ModelRegistry {
    fn note_heartbeat_round(&mut self, wallet: &str, tip: u64) -> Result<(), &'static str> {
        let canonical = canon_wallet_id_checked_model(wallet)?;
        self.registered_wallets.insert(canonical.clone());
        self.first_seen_tip.entry(canonical.to_ascii_lowercase()).or_insert(tip);
        self.heartbeats = self.heartbeats.saturating_add(1);
        Ok(())
    }

    fn associate_identity(&mut self, peer: &str, wallet: &str) -> Result<(), &'static str> {
        let canonical = canon_wallet_id_checked_model(wallet)?;
        if peer.is_empty() || peer.len() > 256 {
            return Err("bad peer id text");
        }

        self.identity_map.insert(peer.to_string(), canonical);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ModelDb {
    tip_height: u64,
    metadata: HashMap<String, Vec<u8>>,
    stored_batches: usize,
}

impl ModelDb {
    fn get_tip_height(&self) -> u64 {
        self.tip_height
    }

    fn store_metadata(&mut self, key: &str, value: &[u8]) {
        self.metadata.insert(key.to_string(), value.to_vec());
    }
}

#[derive(Debug, Default)]
struct ModelSync {
    sync_targets: Vec<(PeerId, u64)>,
    peerbook: HashMap<PeerId, Vec<String>>,
    kad_addrs: HashMap<PeerId, Vec<String>>,
    autodial_calls: usize,
}

impl ModelSync {
    fn begin_sync_to_target(&mut self, peer: PeerId, height: u64) {
        self.sync_targets.push((peer, height));
    }

    fn upsert_peer_mesh(&mut self, peer: PeerId, full_addrs: Vec<String>, kad_base_addrs: Vec<String>) {
        self.peerbook.insert(peer, full_addrs);
        self.kad_addrs.insert(peer, kad_base_addrs);
        self.autodial_calls = self.autodial_calls.saturating_add(1);
    }
}

#[derive(Debug, Default)]
struct ModelStores {
    received_chats: Vec<WireChatEnvelope>,
    received_file_chunks: Vec<WireFileChunkEnvelope>,
}

#[derive(Debug)]
struct GossipHarness {
    peers: Vec<PeerId>,
    local_peer: PeerId,
    local_wallet: String,
    data_dir: String,

    mempool: ModelMempool,
    registry: ModelRegistry,
    db: ModelDb,
    sync: ModelSync,
    stores: ModelStores,

    dropped_oversized_gossip: usize,
    dropped_oversized_chat: usize,
    dropped_oversized_file: usize,
    dropped_invalid_wallet: usize,
    dropped_invalid_file_chunk: usize,
    dropped_consensus_cap: usize,
    malformed_consensus: usize,
    ignored_self_echo: usize,
    decoded_chat_topics: usize,
    decoded_file_topics: usize,
    decoded_consensus_topics: usize,
}

impl GossipHarness {
    fn new(cursor: &mut Cursor<'_>) -> Self {
        let peers: Vec<_> = (0..MAX_MODEL_PEERS)
            .map(|_| PeerId::from(identity::Keypair::generate_ed25519().public()))
            .collect();

        let local_peer = peers[0];
        let local_wallet = if cursor.take_bool() {
            valid_wallet_from_byte(cursor.take_u8())
        } else {
            String::new()
        };

        let data_dir = if cursor.take_bool() {
            "data".to_string()
        } else {
            cursor.take_ascii_string(64)
        };

        Self {
            peers,
            local_peer,
            local_wallet,
            data_dir,

            mempool: ModelMempool::default(),
            registry: ModelRegistry::default(),
            db: ModelDb::default(),
            sync: ModelSync::default(),
            stores: ModelStores::default(),

            dropped_oversized_gossip: 0,
            dropped_oversized_chat: 0,
            dropped_oversized_file: 0,
            dropped_invalid_wallet: 0,
            dropped_invalid_file_chunk: 0,
            dropped_consensus_cap: 0,
            malformed_consensus: 0,
            ignored_self_echo: 0,
            decoded_chat_topics: 0,
            decoded_file_topics: 0,
            decoded_consensus_topics: 0,
        }
    }

    fn peer(&self, slot: u8) -> PeerId {
        self.peers[usize::from(slot) % self.peers.len()]
    }

    fn source_peer(&self, cursor: &mut Cursor<'_>) -> PeerId {
        if cursor.take_bool() {
            self.local_peer
        } else {
            self.peer(cursor.take_u8())
        }
    }

    fn handle_gossip_model(
        &mut self,
        topic: TopicKind,
        propagation_source: PeerId,
        reported_len: usize,
        raw: &[u8],
        fallback: WireAnyEnvelope,
    ) {
        // Self-echo guard comes first in the real handler.
        if propagation_source == self.local_peer {
            self.ignored_self_echo = self.ignored_self_echo.saturating_add(1);
            return;
        }

        // Shared gossipsub payload guard before any topic-specific decode/action.
        if reported_len > MAX_GOSSIP_BYTES {
            self.dropped_oversized_gossip = self.dropped_oversized_gossip.saturating_add(1);
            return;
        }

        match topic {
            TopicKind::Chat => {
                self.decoded_chat_topics = self.decoded_chat_topics.saturating_add(1);

                if reported_len > MAX_CHAT_WIRE_BYTES {
                    self.dropped_oversized_chat = self.dropped_oversized_chat.saturating_add(1);
                    return;
                }

                let decoded = from_bytes::<WireChatEnvelope>(raw)
                    .ok()
                    .or(fallback.chat);

                if let Some(chat) = decoded {
                    self.handle_chat(chat);
                }

                // Important invariant: chat topic never falls through to consensus decode.
            }

            TopicKind::File => {
                self.decoded_file_topics = self.decoded_file_topics.saturating_add(1);

                if reported_len > MAX_FILE_WIRE_BYTES {
                    self.dropped_oversized_file = self.dropped_oversized_file.saturating_add(1);
                    return;
                }

                let decoded = from_bytes::<WireFileChunkEnvelope>(raw)
                    .ok()
                    .or(fallback.file);

                if let Some(chunk) = decoded {
                    self.handle_file_chunk(chunk);
                }

                // Important invariant: file topic never falls through to consensus decode.
            }

            TopicKind::PeerMesh | TopicKind::Consensus | TopicKind::Unknown => {
                self.decoded_consensus_topics = self.decoded_consensus_topics.saturating_add(1);

                let decoded = from_bytes::<WireConsensusEnvelope>(raw)
                    .ok()
                    .or(fallback.consensus);

                match decoded {
                    Some(env) => self.handle_consensus(env, propagation_source),
                    None => {
                        self.malformed_consensus = self.malformed_consensus.saturating_add(1);
                    }
                }
            }
        }
    }

    fn handle_chat(&mut self, chat: WireChatEnvelope) {
        if chat.from_wallet.len() > MAX_WALLET_TEXT_BYTES
            || chat.to_wallet.len() > MAX_WALLET_TEXT_BYTES
        {
            self.dropped_invalid_wallet = self.dropped_invalid_wallet.saturating_add(1);
            return;
        }

        if !self.local_wallet.is_empty() && chat.to_wallet.eq_ignore_ascii_case(&self.local_wallet) {
            if receiver_root_dir_model(&self.data_dir, "receiver.message").is_ok() {
                self.stores.received_chats.push(chat);
            }
        }
    }

    fn handle_file_chunk(&mut self, chunk: WireFileChunkEnvelope) {
        if chunk.filename.len() > MAX_FILENAME_BYTES
            || chunk.total_chunks > MAX_FILE_TOTAL_CHUNKS
            || chunk.chunk_bytes.len() > MAX_FILE_CHUNK_BYTES
            || chunk.total_chunks == 0
            || chunk.chunk_index >= chunk.total_chunks
            || chunk.from_wallet.len() > MAX_WALLET_TEXT_BYTES
            || chunk.to_wallet.len() > MAX_WALLET_TEXT_BYTES
        {
            self.dropped_invalid_file_chunk = self.dropped_invalid_file_chunk.saturating_add(1);
            return;
        }

        if !self.local_wallet.is_empty() && chunk.to_wallet.eq_ignore_ascii_case(&self.local_wallet) {
            if receiver_root_dir_model(&self.data_dir, "receiver.files").is_ok() {
                let _safe_name = if is_safe_leaf_name_model(&chunk.filename) {
                    chunk.filename.clone()
                } else {
                    "unsafe_filename_replaced.bin".to_string()
                };

                self.stores.received_file_chunks.push(chunk);
            }
        }
    }

    fn handle_consensus(&mut self, env: WireConsensusEnvelope, propagation_source: PeerId) {
        match env.kind {
            WireMessageKind::TxKind => {
                self.mempool.tx_kind_count = self.mempool.tx_kind_count.saturating_add(1);
            }

            WireMessageKind::Transaction => {
                self.mempool.tx_count = self.mempool.tx_count.saturating_add(1);
            }

            WireMessageKind::RegisterNode => {
                if env.wallet.len() > MAX_WALLET_TEXT_BYTES {
                    self.dropped_invalid_wallet = self.dropped_invalid_wallet.saturating_add(1);
                    return;
                }

                let wallet_canon = match canon_wallet_id_checked_model(&env.wallet) {
                    Ok(w) => w,
                    Err(_) => {
                        self.dropped_invalid_wallet = self.dropped_invalid_wallet.saturating_add(1);
                        return;
                    }
                };

                let tip = self.db.get_tip_height();
                if self.registry.note_heartbeat_round(&wallet_canon, tip).is_ok() {
                    let fs_tip_key = format!("first_seen_tip::{}", wallet_canon.to_ascii_lowercase());
                    if !self.db.metadata.contains_key(&fs_tip_key) {
                        self.db.store_metadata(&fs_tip_key, &tip.to_be_bytes());
                    }

                    let _ = self
                        .registry
                        .associate_identity(&propagation_source.to_base58(), &wallet_canon);
                }
            }

            WireMessageKind::Reward => {
                // Reward gossip is ignored by design; applied through batch/block.
            }

            WireMessageKind::TxBatch => {
                if usize_from_u64_saturating(env.canonical_len) > consensus_max_bytes() {
                    self.dropped_consensus_cap = self.dropped_consensus_cap.saturating_add(1);
                    return;
                }

                self.db.stored_batches = self.db.stored_batches.saturating_add(1);
            }

            WireMessageKind::Block => {
                if usize_from_u64_saturating(env.canonical_len) > consensus_max_bytes() {
                    self.dropped_consensus_cap = self.dropped_consensus_cap.saturating_add(1);
                    return;
                }

                self.sync.begin_sync_to_target(propagation_source, env.height);
            }

            WireMessageKind::PorPuzzleProof => {
                // Non-mining nodes may ignore gracefully. Mining-path validation belongs
                // to BlockchainBuilder; the memory model only asserts non-panicking routing.
            }

            WireMessageKind::PeerMeshAnnounce => {
                if env.declares_local_peer {
                    return;
                }

                let declared_peer = if env.direct_peer_mesh {
                    propagation_source
                } else {
                    self.peer(byte_from_hash(env.hash.into_inner()))
                };

                if env.direct_peer_mesh && !env.wallet.is_empty() {
                    let _ = self
                        .registry
                        .associate_identity(&declared_peer.to_base58(), &env.wallet);
                }

                let mut full_addrs = env.listen_addrs;
                full_addrs.truncate(MAX_MODEL_LISTEN_ADDRS);
                let kad_base_addrs = full_addrs
                    .iter()
                    .map(|a| strip_p2p_suffix_model(a))
                    .collect::<Vec<_>>();

                self.sync.upsert_peer_mesh(declared_peer, full_addrs, kad_base_addrs);
            }

            WireMessageKind::Malformed => {
                self.malformed_consensus = self.malformed_consensus.saturating_add(1);
            }
        }
    }

    fn assert_invariants(&self) {
        assert!(self.stores.received_chats.len() <= MAX_EVENTS);
        assert!(self.stores.received_file_chunks.len() <= MAX_EVENTS);

        for chat in &self.stores.received_chats {
            assert!(!self.local_wallet.is_empty());
            assert!(chat.to_wallet.eq_ignore_ascii_case(&self.local_wallet));
            assert!(chat.from_wallet.len() <= MAX_WALLET_TEXT_BYTES);
            assert!(chat.to_wallet.len() <= MAX_WALLET_TEXT_BYTES);
        }

        for chunk in &self.stores.received_file_chunks {
            assert!(!self.local_wallet.is_empty());
            assert!(chunk.to_wallet.eq_ignore_ascii_case(&self.local_wallet));
            assert!(chunk.filename.len() <= MAX_FILENAME_BYTES);
            assert!(chunk.chunk_bytes.len() <= MAX_FILE_CHUNK_BYTES);
            assert!(chunk.total_chunks <= MAX_FILE_TOTAL_CHUNKS);
            assert!(chunk.total_chunks > 0);
            assert!(chunk.chunk_index < chunk.total_chunks);
            assert!(chunk.from_wallet.len() <= MAX_WALLET_TEXT_BYTES);
            assert!(chunk.to_wallet.len() <= MAX_WALLET_TEXT_BYTES);
        }

        for wallet in &self.registry.registered_wallets {
            assert!(canon_wallet_id_checked_model(wallet).is_ok());
        }

        for wallet in self.registry.identity_map.values() {
            assert!(canon_wallet_id_checked_model(wallet).is_ok());
        }

        for key in self.db.metadata.keys() {
            assert!(key.starts_with("first_seen_tip::"));
        }

        for addrs in self.sync.kad_addrs.values() {
            for addr in addrs {
                assert!(!addr.ends_with("/p2p/"));
            }
        }
    }
}

fn consensus_max_bytes() -> usize {
    CONSENSUS_MAX_BYTES
}

fn usize_from_u64_saturating(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn receiver_root_dir_model(data_dir: &str, leaf: &str) -> Result<PathBuf, &'static str> {
    let base = data_dir.trim();

    if base.is_empty() {
        return Err("empty data_dir");
    }

    if leaf.is_empty() || leaf.contains('/') || leaf.contains('\\') {
        return Err("bad leaf");
    }

    let mut dir = PathBuf::from(base);
    dir.push(leaf);
    Ok(dir)
}

fn is_safe_leaf_name_model(name: &str) -> bool {
    let p = Path::new(name);

    if name.is_empty() || p.is_absolute() {
        return false;
    }

    let mut comps = p.components();

    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => {}
        _ => return false,
    }

    name != "." && name != ".."
}

// Model of canon_wallet_id_checked for the current "r" + hex wallet format used
// elsewhere in the runtime tests. It accepts mixed-case input and outputs lower-case.
fn canon_wallet_id_checked_model(input: &str) -> Result<String, &'static str> {
    let trimmed = input.trim();

    if trimmed.len() != 129 {
        return Err("bad wallet length");
    }

    let (prefix, rest) = trimmed.split_at(1);
    if prefix != "r" && prefix != "R" {
        return Err("bad wallet prefix");
    }

    if !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bad wallet hex");
    }

    Ok(format!("r{}", rest.to_ascii_lowercase()))
}

fn valid_wallet_from_byte(b: u8) -> String {
    let nibble = b & 0x0f;
    let c = char::from_digit(u32::from(nibble), 16).unwrap_or('0');
    let hex: String = std::iter::repeat(c).take(128).collect();
    format!("r{hex}")
}

fn strip_p2p_suffix_model(addr: &str) -> String {
    match addr.rfind("/p2p/") {
        Some(pos) => addr[..pos].to_string(),
        None => addr.to_string(),
    }
}

fn byte_from_hash(hash: Hash64) -> u8 {
    hash.iter().fold(0u8, |acc, b| acc ^ *b)
}

fn topic_from_byte(b: u8) -> TopicKind {
    match b % 5 {
        0 => TopicKind::Chat,
        1 => TopicKind::File,
        2 => TopicKind::PeerMesh,
        3 => TopicKind::Consensus,
        _ => TopicKind::Unknown,
    }
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

    fn take_usize_mod(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        usize::try_from(self.take_u64()).unwrap_or(0) % max
    }

    fn take_hash32(&mut self) -> Hash32 {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }

    fn take_hash64(&mut self) -> Hash64 {
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

    fn take_ascii_string(&mut self, max_len: usize) -> String {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut s = String::with_capacity(len);

        for _ in 0..len {
            let b = self.take_u8();
            let ch = match b % 72 {
                0..=9 => char::from(b'0' + (b % 10)),
                10..=35 => char::from(b'a' + ((b - 10) % 26)),
                36..=61 => char::from(b'A' + ((b - 36) % 26)),
                62 => '.',
                63 => '_',
                64 => '-',
                65 => '/',
                66 => '\\',
                67 => ':',
                68 => ' ',
                _ => 'x',
            };
            s.push(ch);
        }

        s
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }
}

fn make_chat(cursor: &mut Cursor<'_>, local_wallet: &str) -> WireChatEnvelope {
    let to_wallet = if cursor.take_bool() && !local_wallet.is_empty() {
        local_wallet.to_string()
    } else if cursor.take_bool() {
        valid_wallet_from_byte(cursor.take_u8())
    } else {
        cursor.take_ascii_string(MAX_MODEL_TEXT)
    };

    WireChatEnvelope {
        from_wallet: if cursor.take_bool() {
            valid_wallet_from_byte(cursor.take_u8())
        } else {
            cursor.take_ascii_string(MAX_MODEL_TEXT)
        },
        to_wallet,
        timestamp_ms: cursor.take_u64(),
        json: cursor.take_vec(MAX_MODEL_BYTES),
    }
}

fn make_file_chunk(cursor: &mut Cursor<'_>, local_wallet: &str) -> WireFileChunkEnvelope {
    let total_chunks = match cursor.take_u8() % 5 {
        0 => 0,
        1 => cursor.take_u32() % 8,
        2 => MAX_FILE_TOTAL_CHUNKS,
        3 => MAX_FILE_TOTAL_CHUNKS.saturating_add(1),
        _ => cursor.take_u32(),
    };

    let chunk_index = match cursor.take_u8() % 4 {
        0 => 0,
        1 => total_chunks.saturating_sub(1),
        2 => total_chunks,
        _ => cursor.take_u32(),
    };

    let to_wallet = if cursor.take_bool() && !local_wallet.is_empty() {
        local_wallet.to_string()
    } else if cursor.take_bool() {
        valid_wallet_from_byte(cursor.take_u8())
    } else {
        cursor.take_ascii_string(MAX_MODEL_TEXT)
    };

    let filename = match cursor.take_u8() % 6 {
        0 => "safe.bin".to_string(),
        1 => "../escape.bin".to_string(),
        2 => ".".to_string(),
        3 => "nested/name.bin".to_string(),
        4 => cursor.take_ascii_string(MAX_FILENAME_BYTES.saturating_add(32)),
        _ => String::new(),
    };

    let chunk_len = match cursor.take_u8() % 4 {
        0 => 0,
        1 => MAX_FILE_CHUNK_BYTES.min(MAX_MODEL_BYTES),
        2 => MAX_FILE_CHUNK_BYTES.saturating_add(1).min(MAX_MODEL_BYTES),
        _ => cursor.take_usize_mod(MAX_MODEL_BYTES),
    };

    let mut chunk_bytes = vec![0u8; chunk_len];
    cursor.fill(&mut chunk_bytes);

    WireFileChunkEnvelope {
        file_id: cursor.take_hash32(),
        from_wallet: if cursor.take_bool() {
            valid_wallet_from_byte(cursor.take_u8())
        } else {
            cursor.take_ascii_string(MAX_MODEL_TEXT)
        },
        to_wallet,
        filename,
        file_size_bytes: cursor.take_u64(),
        content_hash_hex: cursor.take_ascii_string(128),
        total_chunks,
        chunk_index,
        timestamp_ms: cursor.take_u64(),
        chunk_bytes,
    }
}

fn make_consensus(cursor: &mut Cursor<'_>) -> WireConsensusEnvelope {
    let kind = match cursor.take_u8() % 9 {
        0 => WireMessageKind::TxKind,
        1 => WireMessageKind::Transaction,
        2 => WireMessageKind::RegisterNode,
        3 => WireMessageKind::Reward,
        4 => WireMessageKind::TxBatch,
        5 => WireMessageKind::Block,
        6 => WireMessageKind::PorPuzzleProof,
        7 => WireMessageKind::PeerMeshAnnounce,
        _ => WireMessageKind::Malformed,
    };

    let wallet = if cursor.take_bool() {
        valid_wallet_from_byte(cursor.take_u8())
    } else {
        cursor.take_ascii_string(MAX_MODEL_TEXT)
    };

    let canonical_len = match cursor.take_u8() % 5 {
        0 => 0,
        1 => CONSENSUS_MAX_BYTES as u64,
        2 => CONSENSUS_MAX_BYTES.saturating_add(1) as u64,
        3 => u64::MAX,
        _ => cursor.take_u64(),
    };

    let addr_count = cursor.take_usize_mod(MAX_MODEL_LISTEN_ADDRS.saturating_add(8));
    let mut listen_addrs = Vec::with_capacity(addr_count);
    for _ in 0..addr_count {
        let base = match cursor.take_u8() % 4 {
            0 => format!("/ip4/127.0.0.1/tcp/{}", cursor.take_u32()),
            1 => format!("/memory/{}", cursor.take_u64()),
            2 => cursor.take_ascii_string(128),
            _ => "/ip6/::1/tcp/1".to_string(),
        };

        if cursor.take_bool() {
            listen_addrs.push(format!("{base}/p2p/{}", cursor.take_ascii_string(64)));
        } else {
            listen_addrs.push(base);
        }
    }

    WireConsensusEnvelope {
        kind,
        wallet,
        peer_id: cursor.take_ascii_string(128),
        payload_len: cursor.take_u64(),
        canonical_len,
        height: cursor.take_u64(),
        hash: WireHash64(cursor.take_hash64()),
        direct_peer_mesh: cursor.take_bool(),
        declares_local_peer: cursor.take_bool(),
        listen_addrs,
    }
}

fn make_fallback(cursor: &mut Cursor<'_>, local_wallet: &str) -> WireAnyEnvelope {
    WireAnyEnvelope {
        kind: WireMessageKind::Malformed,
        chat: cursor.take_bool().then(|| make_chat(cursor, local_wallet)),
        file: cursor.take_bool().then(|| make_file_chunk(cursor, local_wallet)),
        consensus: cursor.take_bool().then(|| make_consensus(cursor)),
    }
}

fn encode_some_wire(cursor: &mut Cursor<'_>, fallback: &WireAnyEnvelope) -> Vec<u8> {
    match cursor.take_u8() % 4 {
        0 => fallback
            .chat
            .as_ref()
            .and_then(|v| to_allocvec(v).ok())
            .unwrap_or_default(),
        1 => fallback
            .file
            .as_ref()
            .and_then(|v| to_allocvec(v).ok())
            .unwrap_or_default(),
        2 => fallback
            .consensus
            .as_ref()
            .and_then(|v| to_allocvec(v).ok())
            .unwrap_or_default(),
        _ => cursor.take_vec(MAX_MODEL_BYTES),
    }
}

fn fuzz_arbitrary_wire_decoding(cursor: &mut Cursor<'_>) {
    let raw = cursor.take_vec(MAX_MODEL_BYTES);

    let chat_decode = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireChatEnvelope>(&raw);
    });
    assert!(chat_decode.is_ok());

    let file_decode = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireFileChunkEnvelope>(&raw);
    });
    assert!(file_decode.is_ok());

    let consensus_decode = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireConsensusEnvelope>(&raw);
    });
    assert!(consensus_decode.is_ok());
}

fn regression_helpers() {
    assert_eq!(consensus_max_bytes(), CONSENSUS_MAX_BYTES);

    assert!(receiver_root_dir_model("data", "receiver.message").is_ok());
    assert!(receiver_root_dir_model("", "receiver.message").is_err());
    assert!(receiver_root_dir_model("data", "../bad").is_err());

    assert!(is_safe_leaf_name_model("file.txt"));
    assert!(!is_safe_leaf_name_model("../file.txt"));
    assert!(!is_safe_leaf_name_model("nested/file.txt"));
    assert!(!is_safe_leaf_name_model(""));
    assert!(!is_safe_leaf_name_model("."));
    assert!(!is_safe_leaf_name_model(".."));

    let w = valid_wallet_from_byte(10);
    assert!(canon_wallet_id_checked_model(&w).is_ok());
    assert!(canon_wallet_id_checked_model("bad").is_err());

    assert_eq!(
        strip_p2p_suffix_model("/ip4/127.0.0.1/tcp/1/p2p/peer"),
        "/ip4/127.0.0.1/tcp/1"
    );
}

fuzz_target!(|data: &[u8]| {
    regression_helpers();

    let mut cursor = Cursor::new(data);
    let mut harness = GossipHarness::new(&mut cursor);

    let events = cursor
        .take_usize_mod(MAX_EVENTS)
        .min(data.len().saturating_add(1))
        .max(1);

    for _ in 0..events {
        let source = harness.source_peer(&mut cursor);
        let topic = topic_from_byte(cursor.take_u8());

        let fallback = make_fallback(&mut cursor, &harness.local_wallet);
        let raw = encode_some_wire(&mut cursor, &fallback);

        let reported_len = match cursor.take_u8() % 9 {
            0 => raw.len(),
            1 => MAX_CHAT_WIRE_BYTES,
            2 => MAX_CHAT_WIRE_BYTES.saturating_add(1),
            3 => MAX_FILE_WIRE_BYTES,
            4 => MAX_FILE_WIRE_BYTES.saturating_add(1),
            5 => MAX_GOSSIP_BYTES,
            6 => MAX_GOSSIP_BYTES.saturating_add(1),
            7 => usize::MAX,
            _ => cursor.take_usize_mod(MAX_GOSSIP_BYTES.saturating_add(4096)),
        };

        harness.handle_gossip_model(topic, source, reported_len, &raw, fallback);

        if cursor.take_bool() {
            fuzz_arbitrary_wire_decoding(&mut cursor);
        }

        harness.assert_invariants();

        if cursor.remaining() == 0 {
            break;
        }
    }

    harness.assert_invariants();
});
