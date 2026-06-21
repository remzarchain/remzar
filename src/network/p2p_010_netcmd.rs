use crate::{
    blockchain::{
        block_002_blocks::Block, transaction_001_tx::Transaction,
        transaction_002_tx_register::RegisterNodeTx, transaction_004_tx_kind::TxKind,
    },
    consensus::por_004_puzzle_proof::PorPuzzleProof,
    network::{p2p_013_peer_mesh::PeerMeshAnnounce, p2p_014_chat::ChatMessage},
    utility::send_file::FileChunkMessage,
};

#[derive(Debug, Clone)]
pub enum NetCmd {
    SendTx(Transaction),

    SendTxKind(TxKind),

    SendBlock(Box<Block>),

    SendRegister(RegisterNodeTx),

    SendPeerMeshAnnounce(PeerMeshAnnounce),

    SendAosPuzzleProof(PorPuzzleProof),

    SendChat(ChatMessage),

    SendFileChunk(FileChunkMessage),
}
