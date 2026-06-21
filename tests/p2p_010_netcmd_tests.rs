#![cfg(test)]
#![deny(unsafe_code)]

use chrono::Utc;
use fips204::ml_dsa_65;
use libp2p::{Multiaddr, PeerId, identity};
use remzar::{
    blockchain::{
        block_001_metadata::BlockMetadata, block_002_blocks::Block,
        transaction_001_tx::Transaction, transaction_002_tx_register::RegisterNodeTx,
        transaction_003_tx_reward::RewardTx, transaction_004_tx_kind::TxKind,
    },
    consensus::por_004_puzzle_proof::PorPuzzleProof,
    network::{
        p2p_010_netcmd::NetCmd,
        p2p_013_peer_mesh::PeerMeshAnnounce,
        p2p_014_chat::{CHAT_TOPIC, ChatMessage},
    },
    utility::{
        alpha_001_global_configuration::GlobalConfiguration, helper::UNIT_DIVISOR,
        send_file::FileChunkMessage,
    },
};

type TestResult<T = ()> = Result<T, String>;

const TEST_TIMESTAMP: u64 = 1_700_000_000;
const TEST_FILE_TOPIC: &str = "remzar.file.v1";
const TEST_TX_TOPIC: &str = "/remzar/tx/1.0.0";
const TEST_REGISTER_TOPIC: &str = "/remzar/register_node/1.0.0";
const TEST_BLOCK_TOPIC: &str = "/remzar/block/1.0.0";
const TEST_PEER_MESH_TOPIC: &str = "/remzar/peer_mesh/1.0.0";
const TEST_POR_TOPIC: &str = "/remzar/por/puzzle_proof/1.0.0";

fn p2p_010_is_consensus_cmd(cmd: &NetCmd) -> bool {
    matches!(
        cmd,
        NetCmd::SendTx(_)
            | NetCmd::SendTxKind(_)
            | NetCmd::SendBlock(_)
            | NetCmd::SendRegister(_)
            | NetCmd::SendPeerMeshAnnounce(_)
            | NetCmd::SendAosPuzzleProof(_)
    )
}

fn p2p_010_is_offchain_cmd(cmd: &NetCmd) -> bool {
    matches!(cmd, NetCmd::SendChat(_) | NetCmd::SendFileChunk(_))
}

fn p2p_010_invalid_register_node() -> TestResult<RegisterNodeTx> {
    let mut reg = make_register_node()?;
    let first = reg
        .wallet_address
        .get_mut(0usize)
        .ok_or_else(|| "missing first wallet byte".to_string())?;
    *first = b'x';
    Ok(reg)
}

fn p2p_010_invalid_reward_kind_zero_amount() -> TestResult<TxKind> {
    let mut reward = make_reward(41u64)?;
    reward.amount = 0u64;
    Ok(TxKind::Reward(reward))
}

fn p2p_010_invalid_transfer_kind_zero_amount() -> TestResult<TxKind> {
    let mut tx = make_transaction(42u64)?;
    tx.amount = 0u64;
    Ok(TxKind::Transfer(tx))
}

fn p2p_010_chat_with_text(text: &str) -> TestResult<ChatMessage> {
    let json = serde_json::to_vec(&serde_json::json!({ "m": text })).map_err(fmt_err)?;

    Ok(ChatMessage {
        from_wallet: sender_wallet(),
        to_wallet: receiver_wallet(),
        timestamp_ms: now_millis()?,
        json,
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn p2p_010_chat_with_bad_signature() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: sender_wallet(),
        to_wallet: receiver_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":"bad signature"}"#.to_vec(),
        signature: vec![0u8; 3usize],
    })
}

fn p2p_010_file_chunk_with_index(
    bytes: Vec<u8>,
    chunk_index: u32,
    total_chunks: u32,
) -> TestResult<FileChunkMessage> {
    let digest = blake3::hash(&bytes);
    let file_id = *digest.as_bytes();

    Ok(FileChunkMessage {
        file_id,
        from_wallet: sender_wallet(),
        to_wallet: receiver_wallet(),
        chunk_index,
        total_chunks,
        filename: "indexed.bin".to_string(),
        file_size_bytes: u64::try_from(bytes.len()).map_err(fmt_err)?,
        content_hash_hex: hex::encode(file_id),
        chunk_bytes: bytes,
        timestamp_ms: now_millis()?,
    })
}

fn p2p_010_cmd_debug_contains_name(cmd: &NetCmd) -> TestResult {
    let name = netcmd_name(cmd);
    let debug = format!("{cmd:?}");

    assert!(debug.contains(name));
    Ok(())
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn now_millis() -> TestResult<u64> {
    u64::try_from(Utc::now().timestamp_millis()).map_err(fmt_err)
}

fn wallet(ch: char) -> String {
    format!("r{}", ch.to_string().repeat(128usize))
}

fn sender_wallet() -> String {
    wallet('1')
}

fn receiver_wallet() -> String {
    wallet('2')
}

fn third_wallet() -> String {
    wallet('3')
}

fn hash64(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn make_multiaddr(port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse::<Multiaddr>()
        .map_err(fmt_err)
}

fn make_transaction(amount: u64) -> TestResult<Transaction> {
    Transaction::new(sender_wallet(), receiver_wallet(), amount).map_err(fmt_err)
}

fn make_transaction_to_third(amount: u64) -> TestResult<Transaction> {
    Transaction::new(sender_wallet(), third_wallet(), amount).map_err(fmt_err)
}

fn make_register_node() -> TestResult<RegisterNodeTx> {
    RegisterNodeTx::new(sender_wallet()).map_err(fmt_err)
}

fn make_register_third() -> TestResult<RegisterNodeTx> {
    RegisterNodeTx::new(third_wallet()).map_err(fmt_err)
}

fn make_reward(height: u64) -> TestResult<RewardTx> {
    RewardTx::new(receiver_wallet(), UNIT_DIVISOR, height).map_err(fmt_err)
}

fn make_txkind_transfer(amount: u64) -> TestResult<TxKind> {
    Ok(TxKind::Transfer(make_transaction(amount)?))
}

fn make_txkind_register() -> TestResult<TxKind> {
    Ok(TxKind::RegisterNode(make_register_node()?))
}

fn make_txkind_reward(height: u64) -> TestResult<TxKind> {
    Ok(TxKind::Reward(make_reward(height)?))
}

fn make_block(index: u64) -> TestResult<Block> {
    let fill = u8::try_from(index.rem_euclid(251u64)).map_err(fmt_err)?;

    let previous_fill = fill.wrapping_add(17u8);
    let merkle_fill = fill.wrapping_add(1u8);

    let metadata = BlockMetadata::new(
        index,
        TEST_TIMESTAMP,
        hash64(previous_fill),
        hash64(merkle_fill),
        [merkle_fill; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_{index:010}")),
        sender_wallet(),
        0u64,
    )
    .map_err(fmt_err)
}

fn make_por_proof(height: u64, output: u128) -> PorPuzzleProof {
    PorPuzzleProof {
        height,
        validator: sender_wallet(),
        prev_block_hash: hash64(7u8),
        output,
    }
}

fn make_peer_mesh(port: u16) -> TestResult<PeerMeshAnnounce> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let addr = make_multiaddr(port)?;

    PeerMeshAnnounce::from_local(peer_id, &[addr], Some(&sender_wallet()), TEST_TIMESTAMP)
        .map_err(fmt_err)
}

fn make_chat_message(text: &str) -> TestResult<ChatMessage> {
    let json = serde_json::to_vec(&serde_json::json!({ "m": text })).map_err(fmt_err)?;

    Ok(ChatMessage {
        from_wallet: sender_wallet(),
        to_wallet: receiver_wallet(),
        timestamp_ms: now_millis()?,
        json,
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn make_chat_to_third(text: &str) -> TestResult<ChatMessage> {
    let json = serde_json::to_vec(&serde_json::json!({ "m": text })).map_err(fmt_err)?;

    Ok(ChatMessage {
        from_wallet: sender_wallet(),
        to_wallet: third_wallet(),
        timestamp_ms: now_millis()?,
        json,
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn make_file_chunk(bytes: Vec<u8>) -> TestResult<FileChunkMessage> {
    make_file_chunk_to_wallet(bytes, receiver_wallet(), "netcmd.txt".to_string())
}

fn make_file_chunk_to_wallet(
    bytes: Vec<u8>,
    to_wallet: String,
    filename: String,
) -> TestResult<FileChunkMessage> {
    let digest = blake3::hash(&bytes);
    let file_id = *digest.as_bytes();

    Ok(FileChunkMessage {
        file_id,
        from_wallet: sender_wallet(),
        to_wallet,
        chunk_index: 0u32,
        total_chunks: 1u32,
        filename,
        file_size_bytes: u64::try_from(bytes.len()).map_err(fmt_err)?,
        content_hash_hex: hex::encode(file_id),
        chunk_bytes: bytes,
        timestamp_ms: now_millis()?,
    })
}

fn netcmd_route(cmd: &NetCmd) -> &'static str {
    match cmd {
        NetCmd::SendTx(_) => TEST_TX_TOPIC,
        NetCmd::SendTxKind(_) => TEST_TX_TOPIC,
        NetCmd::SendBlock(_) => TEST_BLOCK_TOPIC,
        NetCmd::SendRegister(_) => TEST_REGISTER_TOPIC,
        NetCmd::SendPeerMeshAnnounce(_) => TEST_PEER_MESH_TOPIC,
        NetCmd::SendAosPuzzleProof(_) => TEST_POR_TOPIC,
        NetCmd::SendChat(_) => CHAT_TOPIC,
        NetCmd::SendFileChunk(_) => TEST_FILE_TOPIC,
    }
}

fn netcmd_name(cmd: &NetCmd) -> &'static str {
    match cmd {
        NetCmd::SendTx(_) => "SendTx",
        NetCmd::SendTxKind(_) => "SendTxKind",
        NetCmd::SendBlock(_) => "SendBlock",
        NetCmd::SendRegister(_) => "SendRegister",
        NetCmd::SendPeerMeshAnnounce(_) => "SendPeerMeshAnnounce",
        NetCmd::SendAosPuzzleProof(_) => "SendAosPuzzleProof",
        NetCmd::SendChat(_) => "SendChat",
        NetCmd::SendFileChunk(_) => "SendFileChunk",
    }
}

fn all_netcmd_variants() -> TestResult<Vec<NetCmd>> {
    Ok(vec![
        NetCmd::SendTx(make_transaction(1u64)?),
        NetCmd::SendTxKind(make_txkind_transfer(2u64)?),
        NetCmd::SendBlock(Box::new(make_block(3u64)?)),
        NetCmd::SendRegister(make_register_node()?),
        NetCmd::SendPeerMeshAnnounce(make_peer_mesh(4010u16)?),
        NetCmd::SendAosPuzzleProof(make_por_proof(4u64, 144u128)),
        NetCmd::SendChat(make_chat_message("hello")?),
        NetCmd::SendFileChunk(make_file_chunk(b"hello".to_vec())?),
    ])
}

#[test]
fn p2p_01_010_netcmd_send_tx_wraps_transaction() -> TestResult {
    let cmd = NetCmd::SendTx(make_transaction(11u64)?);

    match cmd {
        NetCmd::SendTx(tx) => {
            assert_eq!(tx.amount, 11u64);
            tx.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_02_010_netcmd_send_txkind_wraps_transfer() -> TestResult {
    let cmd = NetCmd::SendTxKind(make_txkind_transfer(12u64)?);

    match cmd {
        NetCmd::SendTxKind(kind) => {
            assert_eq!(kind.tag(), "transfer");
            kind.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_03_010_netcmd_send_block_wraps_boxed_block() -> TestResult {
    let cmd = NetCmd::SendBlock(Box::new(make_block(13u64)?));

    match cmd {
        NetCmd::SendBlock(block) => {
            assert_eq!(block.metadata.index, 13u64);
            assert!(block.verify_block_hash().map_err(fmt_err)?);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_04_010_netcmd_send_register_wraps_register_node() -> TestResult {
    let cmd = NetCmd::SendRegister(make_register_node()?);

    match cmd {
        NetCmd::SendRegister(reg) => {
            reg.validate().map_err(fmt_err)?;
            assert_eq!(reg.wallet_address.as_slice(), sender_wallet().as_bytes());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_05_010_netcmd_send_peer_mesh_wraps_announce() -> TestResult {
    let cmd = NetCmd::SendPeerMeshAnnounce(make_peer_mesh(4015u16)?);

    match cmd {
        NetCmd::SendPeerMeshAnnounce(ann) => {
            let normalized = ann.normalize().map_err(fmt_err)?;
            assert_eq!(normalized.full_dial_addrs.len(), 1usize);
            assert_eq!(normalized.wallet, Some(sender_wallet()));
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_06_010_netcmd_send_aos_puzzle_proof_wraps_proof() -> TestResult {
    let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(16u64, 144u128));

    match cmd {
        NetCmd::SendAosPuzzleProof(proof) => {
            assert_eq!(proof.height, 16u64);
            assert_eq!(proof.output, 144u128);
            proof.validate_structural().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_07_010_netcmd_send_chat_wraps_chat_message() -> TestResult {
    let cmd = NetCmd::SendChat(make_chat_message("netcmd chat")?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert_eq!(chat.plaintext().map_err(fmt_err)?, "netcmd chat");
            assert!(!chat.encode_wire().map_err(fmt_err)?.is_empty());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_08_010_netcmd_send_file_chunk_wraps_file_chunk() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk(b"netcmd-file".to_vec())?);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.filename, "netcmd.txt");
            assert_eq!(chunk.chunk_bytes, b"netcmd-file".to_vec());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_09_010_netcmd_send_tx_clone_preserves_transaction_amount() -> TestResult {
    let cmd = NetCmd::SendTx(make_transaction(19u64)?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendTx(tx) => {
            assert_eq!(tx.amount, 19u64);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_10_010_netcmd_send_txkind_clone_preserves_tag() -> TestResult {
    let cmd = NetCmd::SendTxKind(make_txkind_register()?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendTxKind(kind) => {
            assert_eq!(kind.tag(), "register_node");
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_11_010_netcmd_send_block_clone_preserves_index() -> TestResult {
    let cmd = NetCmd::SendBlock(Box::new(make_block(21u64)?));
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendBlock(block) => {
            assert_eq!(block.metadata.index, 21u64);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_12_010_netcmd_send_register_clone_preserves_wallet() -> TestResult {
    let cmd = NetCmd::SendRegister(make_register_node()?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendRegister(reg) => {
            assert_eq!(reg.wallet_address.as_slice(), sender_wallet().as_bytes());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_13_010_netcmd_send_peer_mesh_clone_preserves_wallet() -> TestResult {
    let cmd = NetCmd::SendPeerMeshAnnounce(make_peer_mesh(4023u16)?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendPeerMeshAnnounce(ann) => {
            let normalized = ann.normalize().map_err(fmt_err)?;
            assert_eq!(normalized.wallet, Some(sender_wallet()));
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_14_010_netcmd_send_aos_puzzle_clone_preserves_output() -> TestResult {
    let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(24u64, 987u128));
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendAosPuzzleProof(proof) => {
            assert_eq!(proof.height, 24u64);
            assert_eq!(proof.output, 987u128);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_15_010_netcmd_send_chat_clone_preserves_plaintext() -> TestResult {
    let cmd = NetCmd::SendChat(make_chat_message("clone me")?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendChat(chat) => {
            assert_eq!(chat.plaintext().map_err(fmt_err)?, "clone me");
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_16_010_netcmd_send_file_chunk_clone_preserves_bytes() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk(b"clone-bytes".to_vec())?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.chunk_bytes, b"clone-bytes".to_vec());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_17_010_netcmd_debug_send_tx_contains_variant_name() -> TestResult {
    let cmd = NetCmd::SendTx(make_transaction(27u64)?);
    let debug = format!("{cmd:?}");

    assert!(debug.contains("SendTx"));
    Ok(())
}

#[test]
fn p2p_18_010_netcmd_debug_send_txkind_contains_variant_name() -> TestResult {
    let cmd = NetCmd::SendTxKind(make_txkind_transfer(28u64)?);
    let debug = format!("{cmd:?}");

    assert!(debug.contains("SendTxKind"));
    Ok(())
}

#[test]
fn p2p_19_010_netcmd_debug_send_block_contains_variant_name() -> TestResult {
    let cmd = NetCmd::SendBlock(Box::new(make_block(29u64)?));
    let debug = format!("{cmd:?}");

    assert!(debug.contains("SendBlock"));
    Ok(())
}

#[test]
fn p2p_20_010_netcmd_debug_all_variants_contains_variant_names() -> TestResult {
    for cmd in all_netcmd_variants()? {
        let name = netcmd_name(&cmd);
        let debug = format!("{cmd:?}");

        assert!(debug.contains(name));
    }

    Ok(())
}

#[test]
fn p2p_21_010_netcmd_route_send_tx_is_tx_topic() -> TestResult {
    let cmd = NetCmd::SendTx(make_transaction(31u64)?);

    assert_eq!(netcmd_route(&cmd), TEST_TX_TOPIC);
    Ok(())
}

#[test]
fn p2p_22_010_netcmd_route_send_txkind_is_tx_topic() -> TestResult {
    let cmd = NetCmd::SendTxKind(make_txkind_reward(32u64)?);

    assert_eq!(netcmd_route(&cmd), TEST_TX_TOPIC);
    Ok(())
}

#[test]
fn p2p_23_010_netcmd_route_send_block_is_block_topic() -> TestResult {
    let cmd = NetCmd::SendBlock(Box::new(make_block(33u64)?));

    assert_eq!(netcmd_route(&cmd), TEST_BLOCK_TOPIC);
    Ok(())
}

#[test]
fn p2p_24_010_netcmd_route_send_register_is_register_topic() -> TestResult {
    let cmd = NetCmd::SendRegister(make_register_node()?);

    assert_eq!(netcmd_route(&cmd), TEST_REGISTER_TOPIC);
    Ok(())
}

#[test]
fn p2p_25_010_netcmd_route_send_peer_mesh_is_peer_mesh_topic() -> TestResult {
    let cmd = NetCmd::SendPeerMeshAnnounce(make_peer_mesh(4035u16)?);

    assert_eq!(netcmd_route(&cmd), TEST_PEER_MESH_TOPIC);
    Ok(())
}

#[test]
fn p2p_26_010_netcmd_route_send_aos_puzzle_is_por_topic() -> TestResult {
    let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(36u64, 144u128));

    assert_eq!(netcmd_route(&cmd), TEST_POR_TOPIC);
    Ok(())
}

#[test]
fn p2p_27_010_netcmd_route_send_chat_is_chat_topic() -> TestResult {
    let cmd = NetCmd::SendChat(make_chat_message("route chat")?);

    assert_eq!(netcmd_route(&cmd), CHAT_TOPIC);
    Ok(())
}

#[test]
fn p2p_28_010_netcmd_route_send_file_chunk_is_file_topic() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk(b"route-file".to_vec())?);

    assert_eq!(netcmd_route(&cmd), TEST_FILE_TOPIC);
    Ok(())
}

#[test]
fn p2p_29_010_netcmd_all_variants_have_non_empty_routes() -> TestResult {
    for cmd in all_netcmd_variants()? {
        assert!(!netcmd_route(&cmd).is_empty());
    }

    Ok(())
}

#[test]
fn p2p_30_010_netcmd_all_variants_have_non_empty_names() -> TestResult {
    for cmd in all_netcmd_variants()? {
        assert!(!netcmd_name(&cmd).is_empty());
    }

    Ok(())
}

#[test]
fn p2p_31_010_netcmd_vector_txkind_transfer_touched_addresses_preserved() -> TestResult {
    let cmd = NetCmd::SendTxKind(TxKind::Transfer(make_transaction_to_third(41u64)?));

    match cmd {
        NetCmd::SendTxKind(kind) => {
            let touched = kind.touched_addresses();

            assert!(touched.contains(&sender_wallet()));
            assert!(touched.contains(&third_wallet()));
            assert_eq!(kind.normalized_receiver(), Some(third_wallet()));
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_32_010_netcmd_vector_register_third_wallet_preserved() -> TestResult {
    let cmd = NetCmd::SendRegister(make_register_third()?);

    match cmd {
        NetCmd::SendRegister(reg) => {
            assert_eq!(reg.wallet_address.as_slice(), third_wallet().as_bytes());
            reg.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_33_010_netcmd_vector_chat_to_third_wallet_preserved() -> TestResult {
    let cmd = NetCmd::SendChat(make_chat_to_third("hello third")?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert_eq!(chat.to_wallet, third_wallet());
            assert_eq!(chat.plaintext().map_err(fmt_err)?, "hello third");
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_34_010_netcmd_vector_file_to_third_wallet_preserved() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk_to_wallet(
        b"third file".to_vec(),
        third_wallet(),
        "third.txt".to_string(),
    )?);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.to_wallet, third_wallet());
            assert_eq!(chunk.filename, "third.txt");
            assert_eq!(chunk.chunk_bytes, b"third file".to_vec());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_35_010_netcmd_edge_invalid_zero_amount_transaction_can_be_wrapped() -> TestResult {
    let mut tx = make_transaction(35u64)?;
    tx.amount = 0u64;

    let cmd = NetCmd::SendTx(tx);

    match cmd {
        NetCmd::SendTx(wrapped) => {
            assert_eq!(wrapped.amount, 0u64);
            assert!(wrapped.validate().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_36_010_netcmd_edge_invalid_zero_output_puzzle_can_be_wrapped() -> TestResult {
    let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(36u64, 0u128));

    match cmd {
        NetCmd::SendAosPuzzleProof(proof) => {
            assert_eq!(proof.output, 0u128);
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_37_010_netcmd_edge_invalid_chat_can_be_wrapped_but_encode_fails() -> TestResult {
    let cmd = NetCmd::SendChat(ChatMessage {
        from_wallet: sender_wallet(),
        to_wallet: receiver_wallet(),
        timestamp_ms: now_millis()?,
        json: b"not-json".to_vec(),
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    });

    match cmd {
        NetCmd::SendChat(chat) => {
            assert!(chat.encode_wire().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_38_010_netcmd_edge_empty_file_chunk_can_be_wrapped() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk(Vec::new())?);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert!(chunk.chunk_bytes.is_empty());
            assert_eq!(chunk.file_size_bytes, 0u64);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_39_010_netcmd_load_build_and_clone_128_tx_commands() -> TestResult {
    let mut checked = 0usize;

    for amount in 1u64..=128u64 {
        let cmd = NetCmd::SendTx(make_transaction(amount)?);
        let cloned = cmd.clone();

        match cloned {
            NetCmd::SendTx(tx) => assert_eq!(tx.amount, amount),
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "load counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_40_010_netcmd_full_variant_matrix_routes_and_clones() -> TestResult {
    let commands = all_netcmd_variants()?;
    let expected_names = [
        "SendTx",
        "SendTxKind",
        "SendBlock",
        "SendRegister",
        "SendPeerMeshAnnounce",
        "SendAosPuzzleProof",
        "SendChat",
        "SendFileChunk",
    ];

    let mut checked = 0usize;

    for (index, cmd) in commands.iter().enumerate() {
        let expected = expected_names
            .get(index)
            .ok_or_else(|| "missing expected command name".to_string())?;

        let cloned = cmd.clone();

        assert_eq!(netcmd_name(cmd), *expected);
        assert_eq!(netcmd_name(&cloned), *expected);
        assert_eq!(netcmd_route(cmd), netcmd_route(&cloned));
        assert!(format!("{cloned:?}").contains(expected));

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "variant matrix counter overflow".to_string())?;
    }

    assert_eq!(checked, expected_names.len());
    Ok(())
}

#[test]
fn p2p_41_010_netcmd_route_matrix_has_expected_topic_distribution() -> TestResult {
    let commands = all_netcmd_variants()?;
    let mut tx_topic_count = 0usize;
    let mut offchain_count = 0usize;

    for cmd in &commands {
        if netcmd_route(cmd) == TEST_TX_TOPIC {
            tx_topic_count = tx_topic_count
                .checked_add(1usize)
                .ok_or_else(|| "tx topic counter overflow".to_string())?;
        }

        if p2p_010_is_offchain_cmd(cmd) {
            offchain_count = offchain_count
                .checked_add(1usize)
                .ok_or_else(|| "offchain counter overflow".to_string())?;
        }
    }

    assert_eq!(tx_topic_count, 2usize);
    assert_eq!(offchain_count, 2usize);
    assert_eq!(commands.len(), 8usize);
    Ok(())
}

#[test]
fn p2p_42_010_netcmd_send_tx_and_send_txkind_share_tx_topic() -> TestResult {
    let send_tx = NetCmd::SendTx(make_transaction(42u64)?);
    let send_kind = NetCmd::SendTxKind(make_txkind_transfer(42u64)?);

    assert_eq!(netcmd_route(&send_tx), TEST_TX_TOPIC);
    assert_eq!(netcmd_route(&send_kind), TEST_TX_TOPIC);
    assert_eq!(netcmd_route(&send_tx), netcmd_route(&send_kind));
    Ok(())
}

#[test]
fn p2p_43_010_netcmd_consensus_and_offchain_classification_is_complete() -> TestResult {
    let commands = all_netcmd_variants()?;
    let mut classified = 0usize;

    for cmd in &commands {
        let consensus = p2p_010_is_consensus_cmd(cmd);
        let offchain = p2p_010_is_offchain_cmd(cmd);

        assert_ne!(consensus, offchain);

        classified = classified
            .checked_add(1usize)
            .ok_or_else(|| "classification counter overflow".to_string())?;
    }

    assert_eq!(classified, 8usize);
    Ok(())
}

#[test]
fn p2p_44_010_netcmd_consensus_commands_do_not_route_to_chat_or_file() -> TestResult {
    for cmd in all_netcmd_variants()? {
        if p2p_010_is_consensus_cmd(&cmd) {
            assert_ne!(netcmd_route(&cmd), CHAT_TOPIC);
            assert_ne!(netcmd_route(&cmd), TEST_FILE_TOPIC);
        }
    }

    Ok(())
}

#[test]
fn p2p_45_010_netcmd_offchain_commands_route_to_chat_or_file_only() -> TestResult {
    for cmd in all_netcmd_variants()? {
        if p2p_010_is_offchain_cmd(&cmd) {
            assert!(matches!(netcmd_route(&cmd), CHAT_TOPIC | TEST_FILE_TOPIC));
        }
    }

    Ok(())
}

#[test]
fn p2p_46_010_netcmd_send_tx_to_third_wallet_clone_preserves_receiver() -> TestResult {
    let cmd = NetCmd::SendTx(make_transaction_to_third(46u64)?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendTx(tx) => {
            assert_eq!(tx.receiver.as_slice(), third_wallet().as_bytes());
            assert_eq!(tx.amount, 46u64);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_47_010_netcmd_send_txkind_transfer_to_third_clone_preserves_receiver() -> TestResult {
    let cmd = NetCmd::SendTxKind(TxKind::Transfer(make_transaction_to_third(47u64)?));
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendTxKind(kind) => {
            assert_eq!(kind.normalized_receiver(), Some(third_wallet()));
            assert!(kind.touched_addresses().contains(&third_wallet()));
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_48_010_netcmd_send_register_third_clone_preserves_wallet() -> TestResult {
    let cmd = NetCmd::SendRegister(make_register_third()?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendRegister(reg) => {
            assert_eq!(reg.wallet_address.as_slice(), third_wallet().as_bytes());
            reg.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_49_010_netcmd_send_chat_to_third_clone_preserves_recipient() -> TestResult {
    let cmd = NetCmd::SendChat(make_chat_to_third("clone third")?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendChat(chat) => {
            assert_eq!(chat.to_wallet, third_wallet());
            assert_eq!(chat.plaintext().map_err(fmt_err)?, "clone third");
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_50_010_netcmd_send_file_to_third_clone_preserves_recipient() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk_to_wallet(
        b"clone third file".to_vec(),
        third_wallet(),
        "clone-third.txt".to_string(),
    )?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.to_wallet, third_wallet());
            assert_eq!(chunk.filename, "clone-third.txt");
            assert_eq!(chunk.chunk_bytes, b"clone third file".to_vec());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_51_010_netcmd_invalid_register_can_be_wrapped_but_validate_fails() -> TestResult {
    let cmd = NetCmd::SendRegister(p2p_010_invalid_register_node()?);

    match cmd {
        NetCmd::SendRegister(reg) => {
            assert!(reg.validate().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_52_010_netcmd_invalid_txkind_reward_zero_amount_can_be_wrapped() -> TestResult {
    let cmd = NetCmd::SendTxKind(p2p_010_invalid_reward_kind_zero_amount()?);

    match cmd {
        NetCmd::SendTxKind(kind) => {
            assert_eq!(kind.tag(), "reward");
            assert!(kind.validate().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_53_010_netcmd_invalid_txkind_transfer_zero_amount_can_be_wrapped() -> TestResult {
    let cmd = NetCmd::SendTxKind(p2p_010_invalid_transfer_kind_zero_amount()?);

    match cmd {
        NetCmd::SendTxKind(kind) => {
            assert_eq!(kind.tag(), "transfer");
            assert!(kind.validate().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_54_010_netcmd_invalid_chat_bad_signature_can_be_wrapped_but_encode_fails() -> TestResult {
    let cmd = NetCmd::SendChat(p2p_010_chat_with_bad_signature()?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert!(chat.encode_wire().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_55_010_netcmd_invalid_chat_empty_plaintext_can_be_wrapped_but_encode_fails() -> TestResult {
    let cmd = NetCmd::SendChat(p2p_010_chat_with_text("")?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert!(chat.encode_wire().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_56_010_netcmd_invalid_chat_whitespace_plaintext_can_be_wrapped_but_encode_fails()
-> TestResult {
    let cmd = NetCmd::SendChat(p2p_010_chat_with_text("     ")?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert!(chat.encode_wire().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_57_010_netcmd_chat_500_ascii_chars_can_be_wrapped_and_encoded() -> TestResult {
    let plaintext = "a".repeat(500usize);
    let cmd = NetCmd::SendChat(p2p_010_chat_with_text(&plaintext)?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert_eq!(chat.plaintext().map_err(fmt_err)?, plaintext);
            assert!(chat.encode_wire().is_ok());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_58_010_netcmd_chat_501_ascii_chars_can_be_wrapped_but_encode_fails() -> TestResult {
    let plaintext = "a".repeat(501usize);
    let cmd = NetCmd::SendChat(p2p_010_chat_with_text(&plaintext)?);

    match cmd {
        NetCmd::SendChat(chat) => {
            assert!(chat.encode_wire().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_59_010_netcmd_empty_file_chunk_clone_preserves_empty_bytes() -> TestResult {
    let cmd = NetCmd::SendFileChunk(make_file_chunk(Vec::new())?);
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendFileChunk(chunk) => {
            assert!(chunk.chunk_bytes.is_empty());
            assert_eq!(chunk.file_size_bytes, 0u64);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_60_010_netcmd_file_chunk_index_metadata_preserved() -> TestResult {
    let cmd = NetCmd::SendFileChunk(p2p_010_file_chunk_with_index(
        b"part-two".to_vec(),
        1u32,
        3u32,
    )?);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.chunk_index, 1u32);
            assert_eq!(chunk.total_chunks, 3u32);
            assert_eq!(chunk.chunk_bytes, b"part-two".to_vec());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_61_010_netcmd_file_chunk_hash_matches_payload() -> TestResult {
    let bytes = b"hash-check".to_vec();
    let cmd = NetCmd::SendFileChunk(make_file_chunk(bytes.clone())?);
    let expected = blake3::hash(&bytes);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.file_id, *expected.as_bytes());
            assert_eq!(chunk.content_hash_hex, hex::encode(expected.as_bytes()));
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_62_010_netcmd_peer_mesh_without_wallet_can_be_wrapped_and_normalized() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let addr = make_multiaddr(4062u16)?;
    let announce =
        PeerMeshAnnounce::from_local(peer_id, &[addr], None, TEST_TIMESTAMP).map_err(fmt_err)?;

    let cmd = NetCmd::SendPeerMeshAnnounce(announce);

    match cmd {
        NetCmd::SendPeerMeshAnnounce(ann) => {
            let normalized = ann.normalize().map_err(fmt_err)?;
            assert!(normalized.wallet.is_none());
            assert_eq!(normalized.full_dial_addrs.len(), 1usize);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_63_010_netcmd_peer_mesh_invalid_wallet_can_be_wrapped_but_normalize_fails() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());

    let announce = PeerMeshAnnounce {
        peer_id: peer_id.to_base58(),
        listen_addrs: vec![make_multiaddr(4063u16)?.to_string()],
        wallet: Some("not-a-wallet".to_string()),
        timestamp_unix: TEST_TIMESTAMP,
    };

    let cmd = NetCmd::SendPeerMeshAnnounce(announce);

    match cmd {
        NetCmd::SendPeerMeshAnnounce(ann) => {
            assert!(ann.normalize().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_64_010_netcmd_peer_mesh_empty_addrs_can_be_wrapped_but_normalize_fails() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());

    let announce = PeerMeshAnnounce {
        peer_id: peer_id.to_base58(),
        listen_addrs: Vec::new(),
        wallet: None,
        timestamp_unix: TEST_TIMESTAMP,
    };

    let cmd = NetCmd::SendPeerMeshAnnounce(announce);

    match cmd {
        NetCmd::SendPeerMeshAnnounce(ann) => {
            assert!(ann.normalize().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_65_010_netcmd_puzzle_max_structural_height_is_valid() -> TestResult {
    let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(10_000_000u64, 65u128));

    match cmd {
        NetCmd::SendAosPuzzleProof(proof) => {
            proof.validate_structural().map_err(fmt_err)?;
            assert_eq!(proof.height, 10_000_000u64);
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_66_010_netcmd_puzzle_too_high_height_can_be_wrapped_but_validation_fails() -> TestResult {
    let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(10_000_001u64, 66u128));

    match cmd {
        NetCmd::SendAosPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_67_010_netcmd_puzzle_zero_prev_hash_can_be_wrapped_but_validation_fails() -> TestResult {
    let proof = PorPuzzleProof {
        height: 67u64,
        validator: sender_wallet(),
        prev_block_hash: [0u8; 64],
        output: 67u128,
    };

    let cmd = NetCmd::SendAosPuzzleProof(proof);

    match cmd {
        NetCmd::SendAosPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_68_010_netcmd_puzzle_ff_prev_hash_can_be_wrapped_but_validation_fails() -> TestResult {
    let proof = PorPuzzleProof {
        height: 68u64,
        validator: sender_wallet(),
        prev_block_hash: [0xFFu8; 64],
        output: 68u128,
    };

    let cmd = NetCmd::SendAosPuzzleProof(proof);

    match cmd {
        NetCmd::SendAosPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_69_010_netcmd_block_clone_preserves_batch_key() -> TestResult {
    let cmd = NetCmd::SendBlock(Box::new(make_block(69u64)?));
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendBlock(block) => {
            assert_eq!(block.batch_key, Some("tx_batch_0000000069".to_string()));
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_70_010_netcmd_block_clone_preserves_miner_wallet() -> TestResult {
    let cmd = NetCmd::SendBlock(Box::new(make_block(70u64)?));
    let cloned = cmd.clone();

    match cloned {
        NetCmd::SendBlock(block) => {
            assert_eq!(block.miner_wallet(), sender_wallet());
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_71_010_netcmd_all_variant_debug_strings_are_nonempty() -> TestResult {
    for cmd in all_netcmd_variants()? {
        let debug = format!("{cmd:?}");

        assert!(!debug.trim().is_empty());
    }

    Ok(())
}

#[test]
fn p2p_72_010_netcmd_all_variant_debug_strings_contain_names() -> TestResult {
    for cmd in all_netcmd_variants()? {
        p2p_010_cmd_debug_contains_name(&cmd)?;
    }

    Ok(())
}

#[test]
fn p2p_73_010_netcmd_all_variant_clones_keep_names() -> TestResult {
    for cmd in all_netcmd_variants()? {
        let cloned = cmd.clone();

        assert_eq!(netcmd_name(&cmd), netcmd_name(&cloned));
    }

    Ok(())
}

#[test]
fn p2p_74_010_netcmd_all_variant_clones_keep_routes() -> TestResult {
    for cmd in all_netcmd_variants()? {
        let cloned = cmd.clone();

        assert_eq!(netcmd_route(&cmd), netcmd_route(&cloned));
    }

    Ok(())
}

#[test]
fn p2p_75_010_netcmd_route_set_has_seven_unique_topics_for_eight_variants() -> TestResult {
    let mut routes = std::collections::BTreeSet::new();

    for cmd in all_netcmd_variants()? {
        routes.insert(netcmd_route(&cmd).to_string());
    }

    assert_eq!(routes.len(), 7usize);
    assert!(routes.contains(TEST_TX_TOPIC));
    assert!(routes.contains(CHAT_TOPIC));
    assert!(routes.contains(TEST_FILE_TOPIC));
    Ok(())
}

#[test]
fn p2p_76_010_netcmd_name_set_has_eight_unique_variant_names() -> TestResult {
    let mut names = std::collections::BTreeSet::new();

    for cmd in all_netcmd_variants()? {
        names.insert(netcmd_name(&cmd).to_string());
    }

    assert_eq!(names.len(), 8usize);
    Ok(())
}

#[test]
fn p2p_77_010_netcmd_load_build_128_txkind_transfer_commands() -> TestResult {
    let mut checked = 0usize;

    for amount in 1u64..=128u64 {
        let cmd = NetCmd::SendTxKind(make_txkind_transfer(amount)?);

        match cmd {
            NetCmd::SendTxKind(kind) => {
                assert_eq!(kind.tag(), "transfer");
                kind.validate().map_err(fmt_err)?;
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "txkind load counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_78_010_netcmd_load_build_64_chat_commands() -> TestResult {
    let mut checked = 0usize;

    for index in 0usize..64usize {
        let cmd = NetCmd::SendChat(p2p_010_chat_with_text(&format!("chat-{index}"))?);

        match cmd {
            NetCmd::SendChat(chat) => {
                assert_eq!(chat.plaintext().map_err(fmt_err)?, format!("chat-{index}"));
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "chat load counter overflow".to_string())?;
    }

    assert_eq!(checked, 64usize);
    Ok(())
}

#[test]
fn p2p_79_010_netcmd_load_build_64_file_chunk_commands() -> TestResult {
    let mut checked = 0usize;

    for index in 0usize..64usize {
        let byte = u8::try_from(index).map_err(fmt_err)?;
        let cmd = NetCmd::SendFileChunk(make_file_chunk(vec![byte; 16usize])?);

        match cmd {
            NetCmd::SendFileChunk(chunk) => {
                assert_eq!(chunk.chunk_bytes.len(), 16usize);
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "file load counter overflow".to_string())?;
    }

    assert_eq!(checked, 64usize);
    Ok(())
}

#[test]
fn p2p_80_010_netcmd_vector_tx_amounts_are_preserved() -> TestResult {
    let amounts = [1u64, 2u64, 10u64, UNIT_DIVISOR, u64::from(u32::MAX)];

    for amount in amounts {
        let cmd = NetCmd::SendTx(make_transaction(amount)?);

        match cmd {
            NetCmd::SendTx(tx) => assert_eq!(tx.amount, amount),
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    Ok(())
}

#[test]
fn p2p_81_010_netcmd_vector_reward_heights_are_preserved_inside_txkind() -> TestResult {
    let heights = [1u64, 2u64, 10u64, 100u64, 10_000u64];

    for height in heights {
        let cmd = NetCmd::SendTxKind(make_txkind_reward(height)?);

        match cmd {
            NetCmd::SendTxKind(TxKind::Reward(reward)) => {
                assert_eq!(reward.block_height, height);
            }
            NetCmd::SendTxKind(other) => {
                return Err(format!("unexpected txkind {}", other.tag()));
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    Ok(())
}

#[test]
fn p2p_82_010_netcmd_vector_block_indices_are_preserved() -> TestResult {
    let indices = [1u64, 2u64, 10u64, 100u64, 1_000u64];

    for index in indices {
        let cmd = NetCmd::SendBlock(Box::new(make_block(index)?));

        match cmd {
            NetCmd::SendBlock(block) => assert_eq!(block.metadata.index, index),
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    Ok(())
}

#[test]
fn p2p_83_010_netcmd_vector_puzzle_outputs_are_preserved() -> TestResult {
    let outputs = [1u128, 2u128, 144u128, u128::from(u64::MAX), u128::MAX];

    for output in outputs {
        let cmd = NetCmd::SendAosPuzzleProof(make_por_proof(83u64, output));

        match cmd {
            NetCmd::SendAosPuzzleProof(proof) => assert_eq!(proof.output, output),
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    Ok(())
}

#[test]
fn p2p_84_010_netcmd_vector_chat_unicode_plaintexts_are_preserved() -> TestResult {
    let texts = ["hello", "remzar 🚀", "こんにちは", "مرحبا", "γειά"];

    for text in texts {
        let cmd = NetCmd::SendChat(p2p_010_chat_with_text(text)?);

        match cmd {
            NetCmd::SendChat(chat) => assert_eq!(chat.plaintext().map_err(fmt_err)?, text),
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    Ok(())
}

#[test]
fn p2p_85_010_netcmd_vector_file_payloads_are_preserved() -> TestResult {
    let payloads = [
        Vec::new(),
        b"a".to_vec(),
        b"hello".to_vec(),
        vec![0xFFu8; 32usize],
        vec![0x11u8; 1024usize],
    ];

    for payload in payloads {
        let cmd = NetCmd::SendFileChunk(make_file_chunk(payload.clone())?);

        match cmd {
            NetCmd::SendFileChunk(chunk) => assert_eq!(chunk.chunk_bytes, payload),
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    Ok(())
}

#[test]
fn p2p_86_010_netcmd_adversarial_sequence_valid_invalid_valid_tx_payloads() -> TestResult {
    let valid_a = NetCmd::SendTx(make_transaction(86u64)?);

    let mut bad_tx = make_transaction(87u64)?;
    bad_tx.amount = 0u64;
    let invalid = NetCmd::SendTx(bad_tx);

    let valid_b = NetCmd::SendTx(make_transaction(88u64)?);

    let commands = [valid_a, invalid, valid_b];
    let mut invalid_count = 0usize;
    let mut valid_count = 0usize;

    for cmd in commands {
        match cmd {
            NetCmd::SendTx(tx) => {
                if tx.validate().is_ok() {
                    valid_count = valid_count
                        .checked_add(1usize)
                        .ok_or_else(|| "valid tx counter overflow".to_string())?;
                } else {
                    invalid_count = invalid_count
                        .checked_add(1usize)
                        .ok_or_else(|| "invalid tx counter overflow".to_string())?;
                }
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    assert_eq!(valid_count, 2usize);
    assert_eq!(invalid_count, 1usize);
    Ok(())
}

#[test]
fn p2p_87_010_netcmd_adversarial_sequence_invalid_valid_chat_payloads() -> TestResult {
    let invalid = NetCmd::SendChat(p2p_010_chat_with_bad_signature()?);
    let valid = NetCmd::SendChat(p2p_010_chat_with_text("valid chat")?);

    let commands = [invalid, valid];
    let mut encodable = 0usize;
    let mut rejected = 0usize;

    for cmd in commands {
        match cmd {
            NetCmd::SendChat(chat) => {
                if chat.encode_wire().is_ok() {
                    encodable = encodable
                        .checked_add(1usize)
                        .ok_or_else(|| "encodable chat counter overflow".to_string())?;
                } else {
                    rejected = rejected
                        .checked_add(1usize)
                        .ok_or_else(|| "rejected chat counter overflow".to_string())?;
                }
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    assert_eq!(encodable, 1usize);
    assert_eq!(rejected, 1usize);
    Ok(())
}

#[test]
fn p2p_88_010_netcmd_adversarial_invalid_valid_peer_mesh_payloads() -> TestResult {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());

    let invalid = NetCmd::SendPeerMeshAnnounce(PeerMeshAnnounce {
        peer_id: peer_id.to_base58(),
        listen_addrs: Vec::new(),
        wallet: None,
        timestamp_unix: TEST_TIMESTAMP,
    });

    let valid = NetCmd::SendPeerMeshAnnounce(make_peer_mesh(4088u16)?);

    let commands = [invalid, valid];
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;

    for cmd in commands {
        match cmd {
            NetCmd::SendPeerMeshAnnounce(ann) => {
                if ann.normalize().is_ok() {
                    valid_count = valid_count
                        .checked_add(1usize)
                        .ok_or_else(|| "valid peer mesh counter overflow".to_string())?;
                } else {
                    invalid_count = invalid_count
                        .checked_add(1usize)
                        .ok_or_else(|| "invalid peer mesh counter overflow".to_string())?;
                }
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    assert_eq!(valid_count, 1usize);
    assert_eq!(invalid_count, 1usize);
    Ok(())
}

#[test]
fn p2p_89_010_netcmd_adversarial_invalid_valid_puzzle_payloads() -> TestResult {
    let invalid = NetCmd::SendAosPuzzleProof(make_por_proof(89u64, 0u128));
    let valid = NetCmd::SendAosPuzzleProof(make_por_proof(90u64, 90u128));

    let commands = [invalid, valid];
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;

    for cmd in commands {
        match cmd {
            NetCmd::SendAosPuzzleProof(proof) => {
                if proof.validate_structural().is_ok() {
                    valid_count = valid_count
                        .checked_add(1usize)
                        .ok_or_else(|| "valid puzzle counter overflow".to_string())?;
                } else {
                    invalid_count = invalid_count
                        .checked_add(1usize)
                        .ok_or_else(|| "invalid puzzle counter overflow".to_string())?;
                }
            }
            other => return Err(format!("unexpected command {}", netcmd_name(&other))),
        }
    }

    assert_eq!(valid_count, 1usize);
    assert_eq!(invalid_count, 1usize);
    Ok(())
}

#[test]
fn p2p_90_010_netcmd_property_cloned_debug_equals_original_debug_for_stable_payloads() -> TestResult
{
    for cmd in all_netcmd_variants()? {
        let cloned = cmd.clone();

        assert_eq!(format!("{cmd:?}"), format!("{cloned:?}"));
    }

    Ok(())
}

#[test]
fn p2p_91_010_netcmd_property_cloning_twice_preserves_route_and_name() -> TestResult {
    for cmd in all_netcmd_variants()? {
        let cloned_once = cmd.clone();
        let cloned_twice = cloned_once.clone();

        assert_eq!(netcmd_name(&cmd), netcmd_name(&cloned_twice));
        assert_eq!(netcmd_route(&cmd), netcmd_route(&cloned_twice));
    }

    Ok(())
}

#[test]
fn p2p_92_010_netcmd_property_every_route_has_topic_like_shape() -> TestResult {
    for cmd in all_netcmd_variants()? {
        let route = netcmd_route(&cmd);

        assert!(
            route.starts_with("/remzar/") || route.starts_with("remzar.") || route == CHAT_TOPIC
        );
    }

    Ok(())
}

#[test]
fn p2p_93_010_netcmd_property_every_debug_string_includes_payload_debug() -> TestResult {
    let commands = all_netcmd_variants()?;

    for cmd in commands {
        let debug = format!("{cmd:?}");

        assert!(debug.len() > netcmd_name(&cmd).len());
    }

    Ok(())
}

#[test]
fn p2p_94_010_netcmd_load_clone_full_variant_matrix_64_times() -> TestResult {
    let mut checked = 0usize;

    for _ in 0usize..64usize {
        for cmd in all_netcmd_variants()? {
            let cloned = cmd.clone();

            assert_eq!(netcmd_name(&cmd), netcmd_name(&cloned));
            assert_eq!(netcmd_route(&cmd), netcmd_route(&cloned));

            checked = checked
                .checked_add(1usize)
                .ok_or_else(|| "full matrix clone counter overflow".to_string())?;
        }
    }

    assert_eq!(checked, 64usize * 8usize);
    Ok(())
}

#[test]
fn p2p_95_010_netcmd_load_debug_full_variant_matrix_64_times() -> TestResult {
    let mut checked = 0usize;

    for _ in 0usize..64usize {
        for cmd in all_netcmd_variants()? {
            p2p_010_cmd_debug_contains_name(&cmd)?;

            checked = checked
                .checked_add(1usize)
                .ok_or_else(|| "full matrix debug counter overflow".to_string())?;
        }
    }

    assert_eq!(checked, 64usize * 8usize);
    Ok(())
}

#[test]
fn p2p_96_010_netcmd_vector_file_chunk_large_64k_payload_can_be_wrapped() -> TestResult {
    let data = vec![0xA5u8; 64usize * 1024usize];
    let cmd = NetCmd::SendFileChunk(make_file_chunk(data.clone())?);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.chunk_bytes.len(), data.len());
            assert_eq!(
                chunk.file_size_bytes,
                u64::try_from(data.len()).map_err(fmt_err)?
            );
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_97_010_netcmd_vector_file_chunk_large_256k_payload_can_be_wrapped() -> TestResult {
    let data = vec![0x5Au8; 256usize * 1024usize];
    let cmd = NetCmd::SendFileChunk(make_file_chunk(data.clone())?);

    match cmd {
        NetCmd::SendFileChunk(chunk) => {
            assert_eq!(chunk.chunk_bytes.len(), data.len());
            assert_eq!(
                chunk.file_size_bytes,
                u64::try_from(data.len()).map_err(fmt_err)?
            );
            Ok(())
        }
        other => Err(format!("unexpected command {}", netcmd_name(&other))),
    }
}

#[test]
fn p2p_98_010_netcmd_final_all_consensus_commands_are_not_offchain() -> TestResult {
    for cmd in all_netcmd_variants()? {
        if p2p_010_is_consensus_cmd(&cmd) {
            assert!(!p2p_010_is_offchain_cmd(&cmd));
            assert_ne!(netcmd_route(&cmd), CHAT_TOPIC);
            assert_ne!(netcmd_route(&cmd), TEST_FILE_TOPIC);
        }
    }

    Ok(())
}

#[test]
fn p2p_99_010_netcmd_final_all_offchain_commands_are_not_consensus() -> TestResult {
    for cmd in all_netcmd_variants()? {
        if p2p_010_is_offchain_cmd(&cmd) {
            assert!(!p2p_010_is_consensus_cmd(&cmd));
            assert!(matches!(netcmd_route(&cmd), CHAT_TOPIC | TEST_FILE_TOPIC));
        }
    }

    Ok(())
}

#[test]
fn p2p_100_010_netcmd_final_full_variant_matrix_names_routes_debug_and_clone() -> TestResult {
    let commands = all_netcmd_variants()?;
    let expected = [
        ("SendTx", TEST_TX_TOPIC),
        ("SendTxKind", TEST_TX_TOPIC),
        ("SendBlock", TEST_BLOCK_TOPIC),
        ("SendRegister", TEST_REGISTER_TOPIC),
        ("SendPeerMeshAnnounce", TEST_PEER_MESH_TOPIC),
        ("SendAosPuzzleProof", TEST_POR_TOPIC),
        ("SendChat", CHAT_TOPIC),
        ("SendFileChunk", TEST_FILE_TOPIC),
    ];

    let mut checked = 0usize;

    for (index, cmd) in commands.iter().enumerate() {
        let (expected_name, expected_route) = expected
            .get(index)
            .copied()
            .ok_or_else(|| "missing expected netcmd matrix entry".to_string())?;

        let cloned = cmd.clone();

        assert_eq!(netcmd_name(cmd), expected_name);
        assert_eq!(netcmd_route(cmd), expected_route);
        assert_eq!(netcmd_name(&cloned), expected_name);
        assert_eq!(netcmd_route(&cloned), expected_route);
        assert!(format!("{cmd:?}").contains(expected_name));
        assert!(format!("{cloned:?}").contains(expected_name));

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "final matrix counter overflow".to_string())?;
    }

    assert_eq!(checked, expected.len());
    Ok(())
}
