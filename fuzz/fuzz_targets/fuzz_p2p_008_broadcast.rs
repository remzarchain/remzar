// fuzz/fuzz_targets/fuzz_p2p_008_broadcast.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// ─────────────────────────────────────────────────────────────────────────────
// Production topic/cap model
// ─────────────────────────────────────────────────────────────────────────────

const TX_TOPIC_STR: &str = "/remzar/tx/1.0.0";
const TXBATCH_TOPIC_STR: &str = "/remzar/tx_batch/1.0.0";
const REWARD_TOPIC_STR: &str = "/remzar/reward/1.0.0";
const REGISTER_TOPIC_STR: &str = "/remzar/register_node/1.0.0";
const BLOCK_TOPIC_STR: &str = "/remzar/block/1.0.0";
const POR_PUZZLE_PROOF_TOPIC_STR: &str = "/remzar/por/puzzle_proof/1.0.0";
const PEER_MESH_TOPIC_STR: &str = "/remzar/peer_mesh/1.0.0";
const CHAT_TOPIC: &str = "remzar.chat.v1";
const FILE_TOPIC_STR: &str = "remzar.file.v1";

const REMZAR_MESSAGE_MAX_WIRE_BYTES: usize = 1024 * 1024;
const CHAT_MAX_WIRE_BYTES: usize = 64 * 1024;
const FILE_CHUNK_MAX_WIRE_BYTES: usize = 1024 * 1024;

const REMZAR_WALLET_LEN: usize = 129;
const MAX_REASONABLE_HEIGHT: u64 = 10_000_000;

type Hash64 = [u8; 64];

const ZERO_HASH_64: Hash64 = [0u8; 64];
const FF_HASH_64: Hash64 = [0xFFu8; 64];

// ─────────────────────────────────────────────────────────────────────────────
// Local error model
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum BroadcastError {
    Encode(String),
    Decode(String),
    TooLarge { got: usize, max: usize },
    Publish(String),
    Validation(String),
}

type Result<T> = std::result::Result<T, BroadcastError>;

// ─────────────────────────────────────────────────────────────────────────────
// Serde helper for [u8; 64]
// ─────────────────────────────────────────────────────────────────────────────

mod serde_u8_array_64 {
    use core::fmt;
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(64)?;
        for b in arr.iter() {
            tup.serialize_element(b)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Arr64Visitor;

        impl<'de> Visitor<'de> for Arr64Visitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a strict 64-byte array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = [0u8; 64];

                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| DeError::invalid_length(i, &self))?;
                }

                if seq.next_element::<u8>()?.is_some() {
                    return Err(DeError::invalid_length(65, &self));
                }

                Ok(out)
            }
        }

        deserializer.deserialize_tuple(64, Arr64Visitor)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal data models for broadcast payloads
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Transaction {
    #[serde(with = "serde_big_array::BigArray")]
    sender: [u8; REMZAR_WALLET_LEN],

    #[serde(with = "serde_big_array::BigArray")]
    receiver: [u8; REMZAR_WALLET_LEN],

    amount: u64,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RegisterNodeTx {
    #[serde(with = "serde_big_array::BigArray")]
    wallet_address: [u8; REMZAR_WALLET_LEN],

    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RewardTx {
    #[serde(with = "serde_big_array::BigArray")]
    receiver: [u8; REMZAR_WALLET_LEN],

    amount: u64,
    block_height: u64,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum TxKind {
    Transfer(Transaction),
    RegisterNode(RegisterNodeTx),
    Reward(RewardTx),

    // Keep lightweight placeholders for future/extensible transaction variants.
    NftMint(Vec<u8>),
    NftTransfer(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TransactionBatch {
    transactions: Vec<TxKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BlockMetadata {
    index: u64,

    #[serde(with = "serde_u8_array_64")]
    previous_hash: Hash64,

    #[serde(with = "serde_u8_array_64")]
    merkle_root: Hash64,

    timestamp: u64,
    nonce: u64,

    // The production metadata has a large guardian signature.
    // For this broadcast fuzz target, a bounded Vec is enough to exercise
    // postcard encoding and size-cap logic without pulling crypto types.
    guardian_signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Block {
    metadata: BlockMetadata,
    batch_key: Option<String>,
    miner: String,

    #[serde(with = "serde_u8_array_64")]
    block_hash: Hash64,

    reward: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PorPuzzleProof {
    height: u64,
    validator: String,

    #[serde(with = "serde_u8_array_64")]
    prev_block_hash: Hash64,

    output: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PeerMeshAnnounce {
    peer_id: String,
    listen_addrs: Vec<String>,
    wallet: Option<String>,
    timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ChatMessage {
    from_peer: String,
    text: String,
    timestamp_unix: u64,
}

impl ChatMessage {
    fn encode_wire(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| BroadcastError::Encode(format!("chat encode: {e}")))
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self> {
        from_bytes(bytes).map_err(|e| BroadcastError::Decode(format!("chat decode: {e}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FileChunkMessage {
    file_id: Vec<u8>,
    chunk_index: u64,
    total_chunks: u64,
    data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// RemzarMessage protocol model
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum RemzarMessage {
    Transaction(Transaction),
    TxKind(TxKind),
    RegisterNode(RegisterNodeTx),
    Reward(RewardTx),
    TxBatch(TransactionBatch),
    Block(Box<Block>),
    PorPuzzleProof(PorPuzzleProof),
    PeerMeshAnnounce(PeerMeshAnnounce),
}

impl RemzarMessage {
    fn encode_to_wire(&self) -> Result<Vec<u8>> {
        let bytes = to_allocvec(self)
            .map_err(|e| BroadcastError::Encode(format!("RemzarMessage encode: {e}")))?;

        if bytes.len() > REMZAR_MESSAGE_MAX_WIRE_BYTES {
            return Err(BroadcastError::TooLarge {
                got: bytes.len(),
                max: REMZAR_MESSAGE_MAX_WIRE_BYTES,
            });
        }

        Ok(bytes)
    }

    fn decode_from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > REMZAR_MESSAGE_MAX_WIRE_BYTES {
            return Err(BroadcastError::TooLarge {
                got: bytes.len(),
                max: REMZAR_MESSAGE_MAX_WIRE_BYTES,
            });
        }

        from_bytes(bytes).map_err(|e| BroadcastError::Decode(format!("RemzarMessage decode: {e}")))
    }

    fn variant_name(&self) -> &'static str {
        match self {
            Self::Transaction(_) => "Transaction",
            Self::TxKind(_) => "TxKind",
            Self::RegisterNode(_) => "RegisterNode",
            Self::Reward(_) => "Reward",
            Self::TxBatch(_) => "TxBatch",
            Self::Block(_) => "Block",
            Self::PorPuzzleProof(_) => "PorPuzzleProof",
            Self::PeerMeshAnnounce(_) => "PeerMeshAnnounce",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory-only broadcaster
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublishedKind {
    RemzarMessage,
    Chat,
    FileChunk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Published {
    topic: String,
    bytes: Vec<u8>,
    kind: PublishedKind,
}

#[derive(Debug, Default)]
struct MemoryBroadcaster {
    joined_topics: BTreeSet<String>,
    published: Vec<Published>,
}

impl MemoryBroadcaster {
    fn new() -> Self {
        Self {
            joined_topics: BTreeSet::new(),
            published: Vec::new(),
        }
    }

    fn join_all_topics(&mut self) -> Result<()> {
        for id in [
            TX_TOPIC_STR,
            TXBATCH_TOPIC_STR,
            REWARD_TOPIC_STR,
            REGISTER_TOPIC_STR,
            BLOCK_TOPIC_STR,
            POR_PUZZLE_PROOF_TOPIC_STR,
            PEER_MESH_TOPIC_STR,
            CHAT_TOPIC,
            FILE_TOPIC_STR,
        ] {
            self.joined_topics.insert(id.to_string());
        }

        Ok(())
    }

    fn send_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.publish(
            TX_TOPIC_STR,
            RemzarMessage::Transaction(tx.clone()),
        )
    }

    fn send_tx_kind(&mut self, kind: &TxKind) -> Result<()> {
        self.publish(
            TX_TOPIC_STR,
            RemzarMessage::TxKind(kind.clone()),
        )
    }

    fn send_register_node(&mut self, reg: &RegisterNodeTx) -> Result<()> {
        self.publish(
            REGISTER_TOPIC_STR,
            RemzarMessage::RegisterNode(reg.clone()),
        )
    }

    fn send_reward_tx(&mut self, rew: &RewardTx) -> Result<()> {
        self.publish(
            REWARD_TOPIC_STR,
            RemzarMessage::Reward(rew.clone()),
        )
    }

    fn send_tx_batch(&mut self, batch: &TransactionBatch) -> Result<()> {
        self.publish(
            TXBATCH_TOPIC_STR,
            RemzarMessage::TxBatch(batch.clone()),
        )
    }

    fn send_block(&mut self, block: &Block) -> Result<()> {
        self.publish(
            BLOCK_TOPIC_STR,
            RemzarMessage::Block(Box::new(block.clone())),
        )
    }

    fn send_por_puzzle_proof(&mut self, proof: &PorPuzzleProof) -> Result<()> {
        self.publish(
            POR_PUZZLE_PROOF_TOPIC_STR,
            RemzarMessage::PorPuzzleProof(proof.clone()),
        )
    }

    fn send_peer_mesh_announce(&mut self, ann: &PeerMeshAnnounce) -> Result<()> {
        self.publish(
            PEER_MESH_TOPIC_STR,
            RemzarMessage::PeerMeshAnnounce(ann.clone()),
        )
    }

    fn send_chat(&mut self, chat: &ChatMessage) -> Result<()> {
        let bytes = chat.encode_wire()?;

        if bytes.len() > CHAT_MAX_WIRE_BYTES {
            return Err(BroadcastError::TooLarge {
                got: bytes.len(),
                max: CHAT_MAX_WIRE_BYTES,
            });
        }

        self.published.push(Published {
            topic: CHAT_TOPIC.to_string(),
            bytes,
            kind: PublishedKind::Chat,
        });

        Ok(())
    }

    fn send_file_chunk(&mut self, chunk: &FileChunkMessage) -> Result<()> {
        let bytes = to_allocvec(chunk)
            .map_err(|e| BroadcastError::Encode(format!("FileChunkMessage encode: {e}")))?;

        if bytes.len() > FILE_CHUNK_MAX_WIRE_BYTES {
            return Err(BroadcastError::TooLarge {
                got: bytes.len(),
                max: FILE_CHUNK_MAX_WIRE_BYTES,
            });
        }

        self.published.push(Published {
            topic: FILE_TOPIC_STR.to_string(),
            bytes,
            kind: PublishedKind::FileChunk,
        });

        Ok(())
    }

    fn publish(&mut self, topic: &str, msg: RemzarMessage) -> Result<()> {
        let bytes = msg.encode_to_wire()?;

        // Belt + suspenders, matching production p2p_008_broadcast.rs.
        if bytes.len() > REMZAR_MESSAGE_MAX_WIRE_BYTES {
            return Err(BroadcastError::TooLarge {
                got: bytes.len(),
                max: REMZAR_MESSAGE_MAX_WIRE_BYTES,
            });
        }

        self.published.push(Published {
            topic: topic.to_string(),
            bytes,
            kind: PublishedKind::RemzarMessage,
        });

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input helpers
// ─────────────────────────────────────────────────────────────────────────────

fn selector(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    if let Some(slice) = data.get(offset..offset.saturating_add(8)) {
        let len = slice.len().min(8);
        out[..len].copy_from_slice(&slice[..len]);
    }

    u64::from_le_bytes(out)
}

fn read_u128(data: &[u8], offset: usize) -> u128 {
    let mut out = [0u8; 16];

    if let Some(slice) = data.get(offset..offset.saturating_add(16)) {
        let len = slice.len().min(16);
        out[..len].copy_from_slice(&slice[..len]);
    }

    u128::from_le_bytes(out)
}

fn bounded_vec(data: &[u8], start: usize, max_len: usize) -> Vec<u8> {
    let requested = usize::from(selector(data, start)) % max_len.saturating_add(1);
    let available = data.get(start.saturating_add(1)..).unwrap_or_default();

    let mut out = Vec::with_capacity(requested);
    for i in 0..requested {
        let b = available
            .get(i % available.len().max(1))
            .copied()
            .unwrap_or(selector(data, start));
        out.push(b);
    }

    out
}

fn bounded_ascii(data: &[u8], start: usize, max_len: usize) -> String {
    let bytes = bounded_vec(data, start, max_len);
    bytes
        .into_iter()
        .map(|b| {
            let c = 32u8.saturating_add(b % 95);
            char::from(c)
        })
        .collect()
}

fn hash64(domain: &[u8], data: &[u8]) -> Hash64 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(data);

    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

fn non_sentinel_hash64(domain: &[u8], data: &[u8]) -> Hash64 {
    let mut out = hash64(domain, data);

    if out == ZERO_HASH_64 || out == FF_HASH_64 {
        out[0] ^= 0x01;
    }

    out
}

fn wallet_string_from_bytes(data: &[u8], domain: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(data);

    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn wallet_array_from_bytes(data: &[u8], domain: &[u8]) -> [u8; REMZAR_WALLET_LEN] {
    let wallet = wallet_string_from_bytes(data, domain);
    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(wallet.as_bytes());
    out
}

fn make_transaction(data: &[u8]) -> Transaction {
    Transaction {
        sender: wallet_array_from_bytes(data, b"tx-sender"),
        receiver: wallet_array_from_bytes(data, b"tx-receiver"),
        amount: read_u64(data, 0).max(1),
        timestamp: read_u64(data, 8),
    }
}

fn make_register_node(data: &[u8]) -> RegisterNodeTx {
    RegisterNodeTx {
        wallet_address: wallet_array_from_bytes(data, b"register-wallet"),
        timestamp: read_u64(data, 16),
    }
}

fn make_reward(data: &[u8]) -> RewardTx {
    RewardTx {
        receiver: wallet_array_from_bytes(data, b"reward-receiver"),
        amount: read_u64(data, 24).max(1),
        block_height: read_u64(data, 32).max(1),
        timestamp: read_u64(data, 40),
    }
}

fn make_tx_kind(data: &[u8]) -> TxKind {
    match selector(data, 48) % 5 {
        0 => TxKind::Transfer(make_transaction(data)),
        1 => TxKind::RegisterNode(make_register_node(data)),
        2 => TxKind::Reward(make_reward(data)),
        3 => TxKind::NftMint(bounded_vec(data, 49, 512)),
        _ => TxKind::NftTransfer(bounded_vec(data, 50, 512)),
    }
}

fn make_batch(data: &[u8]) -> TransactionBatch {
    let count = usize::from(selector(data, 51) % 8);
    let mut transactions = Vec::with_capacity(count);

    for i in 0..count {
        let offset = 52usize.saturating_add(i);
        let mut rotated = data.to_vec();

        // Fix E0502:
        // Do not call rotated.len() inside rotate_left(...), because rotate_left
        // mutably borrows rotated while rotated.len() tries to immutably borrow it.
        let len = rotated.len();
        if len != 0 {
            let shift = offset % len;
            rotated.rotate_left(shift);
        }

        transactions.push(make_tx_kind(&rotated));
    }

    TransactionBatch { transactions }
}

fn make_block(data: &[u8]) -> Block {
    let metadata = BlockMetadata {
        index: read_u64(data, 64) % (MAX_REASONABLE_HEIGHT + 1),
        previous_hash: non_sentinel_hash64(b"block-prev", data),
        merkle_root: non_sentinel_hash64(b"block-merkle", data),
        timestamp: read_u64(data, 72),
        nonce: read_u64(data, 80),
        guardian_signature: bounded_vec(data, 88, 512),
    };

    let miner = if selector(data, 89) % 7 == 0 && metadata.index == 0 {
        String::new()
    } else {
        wallet_string_from_bytes(data, b"block-miner")
    };

    Block {
        metadata,
        batch_key: match selector(data, 90) % 4 {
            0 => None,
            _ => Some(bounded_ascii(data, 91, 256)),
        },
        miner,
        block_hash: non_sentinel_hash64(b"block-hash", data),
        reward: read_u64(data, 96),
    }
}

fn make_por_puzzle_proof(data: &[u8]) -> PorPuzzleProof {
    PorPuzzleProof {
        height: read_u64(data, 104) % (MAX_REASONABLE_HEIGHT + 1),
        validator: wallet_string_from_bytes(data, b"por-validator"),
        prev_block_hash: non_sentinel_hash64(b"por-prev", data),
        output: read_u128(data, 112).max(1),
    }
}

fn make_peer_mesh_announce(data: &[u8]) -> PeerMeshAnnounce {
    let addr_count = usize::from(selector(data, 128) % 8);
    let mut listen_addrs = Vec::with_capacity(addr_count);

    for i in 0..addr_count {
        let port = 10000u16.saturating_add(u16::from(selector(data, 129 + i)));
        listen_addrs.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    PeerMeshAnnounce {
        peer_id: format!("peer-{}", hex::encode(hash64(b"peer-id", data).get(..8).unwrap_or(&[]))),
        listen_addrs,
        wallet: match selector(data, 140) % 3 {
            0 => None,
            _ => Some(wallet_string_from_bytes(data, b"peer-wallet")),
        },
        timestamp_unix: read_u64(data, 144),
    }
}

fn make_chat(data: &[u8]) -> ChatMessage {
    ChatMessage {
        from_peer: format!("peer-{}", selector(data, 152)),
        text: bounded_ascii(data, 153, 4096),
        timestamp_unix: read_u64(data, 160),
    }
}

fn make_file_chunk(data: &[u8]) -> FileChunkMessage {
    let total = read_u64(data, 168).max(1);
    let idx = read_u64(data, 176) % total;

    FileChunkMessage {
        file_id: bounded_vec(data, 184, 64),
        chunk_index: idx,
        total_chunks: total,
        data: bounded_vec(data, 185, 16 * 1024),
    }
}

fn make_message(data: &[u8]) -> RemzarMessage {
    match selector(data, 192) % 8 {
        0 => RemzarMessage::Transaction(make_transaction(data)),
        1 => RemzarMessage::TxKind(make_tx_kind(data)),
        2 => RemzarMessage::RegisterNode(make_register_node(data)),
        3 => RemzarMessage::Reward(make_reward(data)),
        4 => RemzarMessage::TxBatch(make_batch(data)),
        5 => RemzarMessage::Block(Box::new(make_block(data))),
        6 => RemzarMessage::PorPuzzleProof(make_por_puzzle_proof(data)),
        _ => RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(data)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertions / invariants
// ─────────────────────────────────────────────────────────────────────────────

fn expected_topic_for_message(msg: &RemzarMessage) -> &'static str {
    match msg {
        RemzarMessage::Transaction(_) => TX_TOPIC_STR,
        RemzarMessage::TxKind(_) => TX_TOPIC_STR,
        RemzarMessage::RegisterNode(_) => REGISTER_TOPIC_STR,
        RemzarMessage::Reward(_) => REWARD_TOPIC_STR,
        RemzarMessage::TxBatch(_) => TXBATCH_TOPIC_STR,
        RemzarMessage::Block(_) => BLOCK_TOPIC_STR,
        RemzarMessage::PorPuzzleProof(_) => POR_PUZZLE_PROOF_TOPIC_STR,
        RemzarMessage::PeerMeshAnnounce(_) => PEER_MESH_TOPIC_STR,
    }
}

fn assert_all_topics_joined(b: &MemoryBroadcaster) {
    for topic in [
        TX_TOPIC_STR,
        TXBATCH_TOPIC_STR,
        REWARD_TOPIC_STR,
        REGISTER_TOPIC_STR,
        BLOCK_TOPIC_STR,
        POR_PUZZLE_PROOF_TOPIC_STR,
        PEER_MESH_TOPIC_STR,
        CHAT_TOPIC,
        FILE_TOPIC_STR,
    ] {
        assert!(
            b.joined_topics.contains(topic),
            "missing joined topic {topic}"
        );
    }

    assert_eq!(b.joined_topics.len(), 9);
}

fn assert_successful_remzar_publish(
    before_len: usize,
    b: &MemoryBroadcaster,
    expected_topic: &str,
    expected_variant: &str,
) {
    assert_eq!(b.published.len(), before_len.saturating_add(1));

    let last = b.published.last().expect("publish must append one item");
    assert_eq!(last.topic, expected_topic);
    assert_eq!(last.kind, PublishedKind::RemzarMessage);
    assert!(last.bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    let decoded = RemzarMessage::decode_from_wire(&last.bytes)
        .expect("published RemzarMessage bytes must decode");
    assert_eq!(decoded.variant_name(), expected_variant);
    assert_eq!(expected_topic_for_message(&decoded), expected_topic);
}

fn fuzz_join_topics() {
    let mut b = MemoryBroadcaster::new();

    b.join_all_topics().expect("join_all_topics must not fail");
    assert_all_topics_joined(&b);

    let once = b.joined_topics.clone();

    b.join_all_topics()
        .expect("join_all_topics must be idempotent");
    assert_eq!(b.joined_topics, once);
    assert_all_topics_joined(&b);
}

fn fuzz_remzar_message_codec(data: &[u8]) {
    let msg = make_message(data);

    if let Ok(bytes) = msg.encode_to_wire() {
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        let decoded = RemzarMessage::decode_from_wire(&bytes)
            .expect("encoded RemzarMessage should decode");
        assert_eq!(decoded, msg);

        let encoded_again = decoded
            .encode_to_wire()
            .expect("decoded RemzarMessage should re-encode");
        assert_eq!(encoded_again, bytes);
    }

    // Untrusted arbitrary bytes must never panic.
    let _ = RemzarMessage::decode_from_wire(data);
}

fn fuzz_individual_send_helpers(data: &[u8]) {
    let mut b = MemoryBroadcaster::new();
    b.join_all_topics().unwrap();

    match selector(data, 193) % 8 {
        0 => {
            let payload = make_transaction(data);
            let before = b.published.len();
            let res = b.send_transaction(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    TX_TOPIC_STR,
                    "Transaction",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        1 => {
            let payload = make_tx_kind(data);
            let before = b.published.len();
            let res = b.send_tx_kind(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    TX_TOPIC_STR,
                    "TxKind",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        2 => {
            let payload = make_register_node(data);
            let before = b.published.len();
            let res = b.send_register_node(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    REGISTER_TOPIC_STR,
                    "RegisterNode",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        3 => {
            let payload = make_reward(data);
            let before = b.published.len();
            let res = b.send_reward_tx(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    REWARD_TOPIC_STR,
                    "Reward",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        4 => {
            let payload = make_batch(data);
            let before = b.published.len();
            let res = b.send_tx_batch(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    TXBATCH_TOPIC_STR,
                    "TxBatch",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        5 => {
            let payload = make_block(data);
            let before = b.published.len();
            let res = b.send_block(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    BLOCK_TOPIC_STR,
                    "Block",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        6 => {
            let payload = make_por_puzzle_proof(data);
            let before = b.published.len();
            let res = b.send_por_puzzle_proof(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    POR_PUZZLE_PROOF_TOPIC_STR,
                    "PorPuzzleProof",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
        _ => {
            let payload = make_peer_mesh_announce(data);
            let before = b.published.len();
            let res = b.send_peer_mesh_announce(&payload);
            if res.is_ok() {
                assert_successful_remzar_publish(
                    before,
                    &b,
                    PEER_MESH_TOPIC_STR,
                    "PeerMeshAnnounce",
                );
            } else {
                assert_eq!(b.published.len(), before);
            }
        }
    }
}

fn fuzz_direct_publish_route(data: &[u8]) {
    let msg = make_message(data);
    let expected_topic = expected_topic_for_message(&msg);
    let expected_variant = msg.variant_name();

    let mut b = MemoryBroadcaster::new();
    let before = b.published.len();

    let res = b.publish(expected_topic, msg);

    if res.is_ok() {
        assert_successful_remzar_publish(before, &b, expected_topic, expected_variant);
    } else {
        assert_eq!(b.published.len(), before);
    }
}

fn fuzz_chat_send(data: &[u8]) {
    let mut b = MemoryBroadcaster::new();
    let chat = make_chat(data);

    let before = b.published.len();
    let res = b.send_chat(&chat);

    if res.is_ok() {
        assert_eq!(b.published.len(), before.saturating_add(1));

        let last = b.published.last().unwrap();
        assert_eq!(last.topic, CHAT_TOPIC);
        assert_eq!(last.kind, PublishedKind::Chat);
        assert!(last.bytes.len() <= CHAT_MAX_WIRE_BYTES);

        let decoded = ChatMessage::decode_wire(&last.bytes)
            .expect("published chat bytes must decode");
        assert_eq!(decoded, chat);
    } else {
        assert_eq!(b.published.len(), before);
    }

    // Explicit oversized chat payload check.
    // Conditional to keep normal fuzz iterations cheap.
    if selector(data, 194) % 16 == 0 {
        let huge_chat = ChatMessage {
            from_peer: "peer-huge".to_string(),
            text: "x".repeat(CHAT_MAX_WIRE_BYTES.saturating_add(1)),
            timestamp_unix: read_u64(data, 200),
        };

        let before_huge = b.published.len();
        let huge_res = b.send_chat(&huge_chat);

        assert!(huge_res.is_err());
        assert_eq!(b.published.len(), before_huge);
    }
}

fn fuzz_file_chunk_send(data: &[u8]) {
    let mut b = MemoryBroadcaster::new();
    let chunk = make_file_chunk(data);

    let before = b.published.len();
    let res = b.send_file_chunk(&chunk);

    if res.is_ok() {
        assert_eq!(b.published.len(), before.saturating_add(1));

        let last = b.published.last().unwrap();
        assert_eq!(last.topic, FILE_TOPIC_STR);
        assert_eq!(last.kind, PublishedKind::FileChunk);
        assert!(last.bytes.len() <= FILE_CHUNK_MAX_WIRE_BYTES);

        let decoded: FileChunkMessage = from_bytes(&last.bytes)
            .expect("published file chunk bytes must decode");
        assert_eq!(decoded, chunk);
    } else {
        assert_eq!(b.published.len(), before);
    }

    // Explicit oversized file payload check.
    // Conditional because this allocates about 1 MiB.
    if selector(data, 195) % 32 == 0 {
        let huge_chunk = FileChunkMessage {
            file_id: vec![1, 2, 3, 4],
            chunk_index: 0,
            total_chunks: 1,
            data: vec![selector(data, 196); FILE_CHUNK_MAX_WIRE_BYTES.saturating_add(1)],
        };

        let before_huge = b.published.len();
        let huge_res = b.send_file_chunk(&huge_chunk);

        assert!(huge_res.is_err());
        assert_eq!(b.published.len(), before_huge);
    }
}

fn fuzz_mixed_sequence(data: &[u8]) {
    let mut b = MemoryBroadcaster::new();
    b.join_all_topics().unwrap();

    let steps = usize::from(selector(data, 197) % 16);

    for step in 0..steps {
        let choice = selector(data, 198usize.saturating_add(step)) % 10;
        let before = b.published.len();

        let res = match choice {
            0 => b.send_transaction(&make_transaction(data)),
            1 => b.send_tx_kind(&make_tx_kind(data)),
            2 => b.send_register_node(&make_register_node(data)),
            3 => b.send_reward_tx(&make_reward(data)),
            4 => b.send_tx_batch(&make_batch(data)),
            5 => b.send_block(&make_block(data)),
            6 => b.send_por_puzzle_proof(&make_por_puzzle_proof(data)),
            7 => b.send_peer_mesh_announce(&make_peer_mesh_announce(data)),
            8 => b.send_chat(&make_chat(data)),
            _ => b.send_file_chunk(&make_file_chunk(data)),
        };

        if res.is_ok() {
            assert_eq!(b.published.len(), before.saturating_add(1));

            let last = b.published.last().unwrap();
            match last.kind {
                PublishedKind::RemzarMessage => {
                    assert!(last.bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);
                    let decoded = RemzarMessage::decode_from_wire(&last.bytes)
                        .expect("mixed RemzarMessage publish must decode");
                    assert_eq!(expected_topic_for_message(&decoded), last.topic.as_str());
                }
                PublishedKind::Chat => {
                    assert_eq!(last.topic, CHAT_TOPIC);
                    assert!(last.bytes.len() <= CHAT_MAX_WIRE_BYTES);
                    let _ = ChatMessage::decode_wire(&last.bytes)
                        .expect("mixed chat publish must decode");
                }
                PublishedKind::FileChunk => {
                    assert_eq!(last.topic, FILE_TOPIC_STR);
                    assert!(last.bytes.len() <= FILE_CHUNK_MAX_WIRE_BYTES);
                    let _: FileChunkMessage = from_bytes(&last.bytes)
                        .expect("mixed file chunk publish must decode");
                }
            }
        } else {
            assert_eq!(b.published.len(), before);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_join_topics();
    fuzz_remzar_message_codec(data);
    fuzz_individual_send_helpers(data);
    fuzz_direct_publish_route(data);
    fuzz_chat_send(data);
    fuzz_file_chunk_send(data);
    fuzz_mixed_sequence(data);
});