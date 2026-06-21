use anyhow::{Result, anyhow};
use libp2p::{Swarm, gossipsub::IdentTopic};

use crate::{
    blockchain::{
        block_002_blocks::Block, transaction_001_tx::Transaction,
        transaction_002_tx_register::RegisterNodeTx, transaction_003_tx_reward::RewardTx,
        transaction_004_tx_kind::TxKind, transaction_005_tx_batch::TransactionBatch,
    },
    consensus::por_004_puzzle_proof::PorPuzzleProof,
    network::{
        p2p_002_protocal::{REMZAR_MESSAGE_MAX_WIRE_BYTES, RemzarMessage},
        p2p_003_behaviour::RemzarBehaviour,
        p2p_013_peer_mesh::{PEER_MESH_TOPIC_STR, PeerMeshAnnounce},
        p2p_014_chat::{CHAT_TOPIC, ChatMessage},
    },
    utility::send_file::FileChunkMessage,
};

/* ───────────── constants ───────────── */

pub const TX_TOPIC_STR: &str = "/remzar/tx/1.0.0";
pub const TXBATCH_TOPIC_STR: &str = "/remzar/tx_batch/1.0.0";
pub const REWARD_TOPIC_STR: &str = "/remzar/reward/1.0.0";
pub const REGISTER_TOPIC_STR: &str = "/remzar/register_node/1.0.0";
pub const BLOCK_TOPIC_STR: &str = "/remzar/block/1.0.0";

/// POR puzzle proof gossip topic.
/// Carries `RemzarMessage::PorPuzzleProof` payloads.
pub const POR_PUZZLE_PROOF_TOPIC_STR: &str = "/remzar/por/puzzle_proof/1.0.0";

/// Off-chain file-sharing topic (chunks).
/// Carries postcard-encoded `FileChunkMessage` payloads (not RemzarMessage).
pub const FILE_TOPIC_STR: &str = "remzar.file.v1";

/// Defensive cap for chat payloads (bytes) on the wire.
/// Chat should be small; keep a separate limit from consensus messages.
const CHAT_MAX_WIRE_BYTES: usize = 64 * 1024;

/// Defensive cap for file chunk payloads (bytes) on the wire.
/// This should align with chunking strategy in send_file / assembler.
const FILE_CHUNK_MAX_WIRE_BYTES: usize = 1024 * 1024;

#[inline(always)]
fn make_topic(id: &str) -> IdentTopic {
    IdentTopic::new(id)
}

/* ───────────── broadcaster ───────────── */

pub type BroadcastError = anyhow::Error;

pub struct Broadcaster<'a> {
    swarm: &'a mut Swarm<RemzarBehaviour>,
}

impl<'a> Broadcaster<'a> {
    pub fn new(swarm: &'a mut Swarm<RemzarBehaviour>) -> Self {
        Self { swarm }
    }

    /// Join all topics we may publish to.
    pub fn join_all_topics(&mut self) -> Result<()> {
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
            _ = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&make_topic(id));
        }
        Ok(())
    }

    /* ─── public send helpers ─── */

    /// Broadcast a simple balance-transfer `Transaction`.
    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.publish(
            make_topic(TX_TOPIC_STR),
            RemzarMessage::Transaction(tx.clone()),
        )
    }

    /// Broadcast a generic `TxKind` (including NFT mints).
    pub fn send_tx_kind(&mut self, kind: &TxKind) -> Result<()> {
        self.publish(
            make_topic(TX_TOPIC_STR),
            RemzarMessage::TxKind(kind.clone()),
        )
    }

    pub fn send_register_node(&mut self, reg: &RegisterNodeTx) -> Result<()> {
        self.publish(
            make_topic(REGISTER_TOPIC_STR),
            RemzarMessage::RegisterNode(reg.clone()),
        )
    }

    pub fn send_reward_tx(&mut self, rew: &RewardTx) -> Result<()> {
        self.publish(
            make_topic(REWARD_TOPIC_STR),
            RemzarMessage::Reward(rew.clone()),
        )
    }

    pub fn send_tx_batch(&mut self, batch: &TransactionBatch) -> Result<()> {
        self.publish(
            make_topic(TXBATCH_TOPIC_STR),
            RemzarMessage::TxBatch(batch.clone()),
        )
    }

    pub fn send_block(&mut self, block: &Block) -> Result<()> {
        self.publish(
            make_topic(BLOCK_TOPIC_STR),
            RemzarMessage::Block(Box::new(block.clone())),
        )
    }

    /// Broadcast a POR puzzle proof (single puzzle success).
    pub fn send_por_puzzle_proof(&mut self, proof: &PorPuzzleProof) -> Result<()> {
        self.publish(
            make_topic(POR_PUZZLE_PROOF_TOPIC_STR),
            RemzarMessage::PorPuzzleProof(proof.clone()),
        )
    }

    /// Broadcast a runtime peer-mesh announcement.
    pub fn send_peer_mesh_announce(&mut self, ann: &PeerMeshAnnounce) -> Result<()> {
        self.publish(
            make_topic(PEER_MESH_TOPIC_STR),
            RemzarMessage::PeerMeshAnnounce(ann.clone()),
        )
    }

    /// Send an off-chain chat message over gossipsub.
    pub fn send_chat(&mut self, chat: &ChatMessage) -> Result<()> {
        let bytes = chat
            .encode_wire()
            .map_err(|e| anyhow!("serialising ChatMessage for chat broadcast: {:?}", e))?;

        // Defensive bound: do not publish absurd chat payloads.
        if bytes.len() > CHAT_MAX_WIRE_BYTES {
            return Err(anyhow!(
                "chat payload too large: {} bytes (max {})",
                bytes.len(),
                CHAT_MAX_WIRE_BYTES
            ));
        }

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(make_topic(CHAT_TOPIC).hash(), bytes)
            .map(|_| ()) // discard MessageId
            .map_err(|e| anyhow!("gossipsub publish error (chat): {:?}", e))
    }

    /// Send an off-chain file chunk over gossipsub.
    pub fn send_file_chunk(&mut self, chunk: &FileChunkMessage) -> Result<()> {
        let bytes = postcard::to_allocvec(chunk)
            .map_err(|e| anyhow!("serialising FileChunkMessage for file broadcast: {:?}", e))?;

        // Defensive bound: ensure chunking code cannot accidentally produce huge chunks.
        if bytes.len() > FILE_CHUNK_MAX_WIRE_BYTES {
            return Err(anyhow!(
                "file chunk payload too large: {} bytes (max {})",
                bytes.len(),
                FILE_CHUNK_MAX_WIRE_BYTES
            ));
        }

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(make_topic(FILE_TOPIC_STR).hash(), bytes)
            .map(|_| ()) // discard MessageId
            .map_err(|e| anyhow!("gossipsub publish error (file): {:?}", e))
    }

    /* ─── internal ─── */

    fn publish(&mut self, topic: IdentTopic, msg: RemzarMessage) -> Result<()> {
        // Use protocol-level encoding helper so the same size cap is enforced everywhere.
        let bytes = msg.encode_to_wire().map_err(|e| anyhow!("{e}"))?;

        // Double-check (belt + suspenders) — protects against future changes inside encode_to_wire.
        if bytes.len() > REMZAR_MESSAGE_MAX_WIRE_BYTES {
            return Err(anyhow!(
                "RemzarMessage too large to publish: {} bytes (max {})",
                bytes.len(),
                REMZAR_MESSAGE_MAX_WIRE_BYTES
            ));
        }

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.hash(), bytes)
            .map(|_| ()) // discard MessageId
            .map_err(|e| anyhow!("gossipsub publish error: {:?}", e))
    }
}

/// Re-export so other modules can name the topic type without importing libp2p directly.
pub use libp2p::gossipsub::IdentTopic as BroadcastTopic;
