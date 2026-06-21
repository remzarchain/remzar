use serde::{Deserialize, Serialize};

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::transaction_003_tx_reward::RewardTx;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
use crate::network::p2p_013_peer_mesh::PeerMeshAnnounce;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RemzarMessage {
    /// Single-value transfer
    Transaction(Transaction),

    /// Generic transaction envelope (supports NFT and future variants).
    TxKind(TxKind),

    /// Node-registration request
    RegisterNode(RegisterNodeTx),

    /// Per-node reward
    Reward(RewardTx),

    /// A full batch of transactions
    TxBatch(TransactionBatch),

    /// A mined block (metadata + signature)
    Block(Box<Block>),

    /// Por puzzle proof for a specific (height, validator, prev_hash).
    PorPuzzleProof(PorPuzzleProof),

    /// Runtime peer-mesh announcement.
    PeerMeshAnnounce(PeerMeshAnnounce),
}

/// Hard safety limits for untrusted network payloads.
pub const REMZAR_MESSAGE_MAX_WIRE_BYTES: usize = 1024 * 1024;

#[derive(thiserror::Error, Debug)]
pub enum RemzarMessageCodecError {
    #[error("wire message too large: {got} bytes (max {max})")]
    TooLarge { got: usize, max: usize },

    #[error("postcard encode failed: {0}")]
    Encode(postcard::Error),

    #[error("postcard decode failed: {0}")]
    Decode(#[from] postcard::Error),
}

pub type RemzarMessageCodecResult<T> = Result<T, RemzarMessageCodecError>;

impl RemzarMessage {
    /// Encode to postcard bytes with a hard maximum size.
    pub fn encode_to_wire(&self) -> RemzarMessageCodecResult<Vec<u8>> {
        let bytes = postcard::to_stdvec(self).map_err(RemzarMessageCodecError::Encode)?;

        if bytes.len() > REMZAR_MESSAGE_MAX_WIRE_BYTES {
            return Err(RemzarMessageCodecError::TooLarge {
                got: bytes.len(),
                max: REMZAR_MESSAGE_MAX_WIRE_BYTES,
            });
        }

        Ok(bytes)
    }

    /// Decode from postcard bytes with a hard maximum size.
    pub fn decode_from_wire(bytes: &[u8]) -> RemzarMessageCodecResult<Self> {
        if bytes.len() > REMZAR_MESSAGE_MAX_WIRE_BYTES {
            return Err(RemzarMessageCodecError::TooLarge {
                got: bytes.len(),
                max: REMZAR_MESSAGE_MAX_WIRE_BYTES,
            });
        }

        let msg = postcard::from_bytes(bytes).map_err(RemzarMessageCodecError::Decode)?;
        Ok(msg)
    }

    /// Fast classification hook for metrics/routing without heavy processing.
    pub fn kind_str(&self) -> &'static str {
        match self {
            RemzarMessage::Transaction(_) => "Transaction",
            RemzarMessage::TxKind(_) => "TxKind",
            RemzarMessage::RegisterNode(_) => "RegisterNode",
            RemzarMessage::Reward(_) => "Reward",
            RemzarMessage::TxBatch(_) => "TxBatch",
            RemzarMessage::Block(_) => "Block",
            RemzarMessage::PorPuzzleProof(_) => "PorPuzzleProof",
            RemzarMessage::PeerMeshAnnounce(_) => "PeerMeshAnnounce",
        }
    }
}
