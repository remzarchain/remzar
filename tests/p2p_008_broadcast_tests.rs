#![cfg(test)]
#![deny(unsafe_code)]

use chrono::Utc;
use fips204::ml_dsa_65;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    gossipsub::{Event as GossipsubEvent, IdentTopic},
    identity,
    swarm::{Config as SwarmConfig, SwarmEvent},
};
use remzar::{
    blockchain::{
        block_001_metadata::BlockMetadata, block_002_blocks::Block,
        transaction_001_tx::Transaction, transaction_002_tx_register::RegisterNodeTx,
        transaction_003_tx_reward::RewardTx, transaction_004_tx_kind::TxKind,
        transaction_005_tx_batch::TransactionBatch,
    },
    consensus::por_004_puzzle_proof::PorPuzzleProof,
    network::{
        p2p_001_transport::build_transport,
        p2p_002_protocal::{REMZAR_MESSAGE_MAX_WIRE_BYTES, RemzarMessage},
        p2p_003_behaviour::{OutEvent, RemzarBehaviour},
        p2p_008_broadcast::{
            BLOCK_TOPIC_STR, BroadcastTopic, Broadcaster, FILE_TOPIC_STR,
            POR_PUZZLE_PROOF_TOPIC_STR, REGISTER_TOPIC_STR, REWARD_TOPIC_STR, TX_TOPIC_STR,
            TXBATCH_TOPIC_STR,
        },
        p2p_013_peer_mesh::{PEER_MESH_TOPIC_STR, PeerMeshAnnounce},
        p2p_014_chat::{CHAT_TOPIC, ChatMessage},
    },
    utility::send_file::FileChunkMessage,
    utility::{alpha_001_global_configuration::GlobalConfiguration, helper::UNIT_DIVISOR},
};
use std::{future::Future, time::Duration};

type TestResult<T = ()> = Result<T, String>;

const TEST_TIMEOUT: Duration = Duration::from_secs(12);
const TEST_TIMESTAMP: u64 = 1_700_000_000;
const FUZZ_SEED: u64 = 0x0BAD_CAFE_0080_0001;

struct TestNode {
    peer_id: PeerId,
    swarm: Swarm<RemzarBehaviour>,
}

fn p2p_008_chat_message_to_wallet(plaintext: &str, to_wallet: String) -> TestResult<ChatMessage> {
    let json = serde_json::to_vec(&serde_json::json!({ "m": plaintext })).map_err(fmt_err)?;

    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet,
        timestamp_ms: now_millis()?,
        json,
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn p2p_008_file_chunk_to_wallet(
    bytes: Vec<u8>,
    to_wallet: String,
    filename: String,
    chunk_index: u32,
    total_chunks: u32,
) -> TestResult<FileChunkMessage> {
    let digest = blake3::hash(&bytes);
    let file_id = *digest.as_bytes();

    Ok(FileChunkMessage {
        file_id,
        from_wallet: genesis_wallet(),
        to_wallet,
        chunk_index,
        total_chunks,
        filename,
        file_size_bytes: u64::try_from(bytes.len()).map_err(fmt_err)?,
        content_hash_hex: hex::encode(file_id),
        chunk_bytes: bytes,
        timestamp_ms: now_millis()?,
    })
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn run_async<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(fmt_err)?;

    runtime.block_on(future)
}

fn now_millis() -> TestResult<u64> {
    u64::try_from(Utc::now().timestamp_millis()).map_err(fmt_err)
}

fn wallet(ch: char) -> String {
    format!("r{}", ch.to_string().repeat(128usize))
}

fn p2p_008_chat_message_with_plaintext(plaintext: &str) -> TestResult<ChatMessage> {
    let json = serde_json::to_vec(&serde_json::json!({ "m": plaintext })).map_err(fmt_err)?;

    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json,
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn p2p_008_invalid_chat_empty_plaintext() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":""}"#.to_vec(),
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn p2p_008_invalid_chat_malformed_json() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: b"not-json".to_vec(),
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn p2p_008_transfer_batch_with_count(count: usize) -> TestResult<TransactionBatch> {
    let mut transactions = Vec::new();

    for amount in 1u64..=u64::try_from(count).map_err(fmt_err)? {
        transactions.push(transfer_kind(amount)?);
    }

    TransactionBatch::new(80u64, TEST_TIMESTAMP, transactions).map_err(fmt_err)
}

fn p2p_008_all_consensus_topics() -> [&'static str; 7] {
    [
        TX_TOPIC_STR,
        TXBATCH_TOPIC_STR,
        REWARD_TOPIC_STR,
        REGISTER_TOPIC_STR,
        BLOCK_TOPIC_STR,
        POR_PUZZLE_PROOF_TOPIC_STR,
        PEER_MESH_TOPIC_STR,
    ]
}

fn p2p_008_all_publish_topics() -> [&'static str; 9] {
    [
        TX_TOPIC_STR,
        TXBATCH_TOPIC_STR,
        REWARD_TOPIC_STR,
        REGISTER_TOPIC_STR,
        BLOCK_TOPIC_STR,
        POR_PUZZLE_PROOF_TOPIC_STR,
        PEER_MESH_TOPIC_STR,
        CHAT_TOPIC,
        FILE_TOPIC_STR,
    ]
}

fn genesis_wallet() -> String {
    wallet('1')
}

fn peer_wallet() -> String {
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

fn make_test_node() -> TestResult<TestNode> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let behaviour = RemzarBehaviour::new(keypair.clone()).map_err(fmt_err)?;
    let transport = build_transport(keypair).map_err(fmt_err)?;

    let swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        SwarmConfig::with_tokio_executor(),
    );

    Ok(TestNode { peer_id, swarm })
}

fn join_all(node: &mut TestNode) -> TestResult {
    Broadcaster::new(&mut node.swarm)
        .join_all_topics()
        .map_err(fmt_err)
}

async fn listen_on_loopback(node: &mut TestNode) -> TestResult<Multiaddr> {
    let addr = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .map_err(fmt_err)?;

    let _listener_id = node.swarm.listen_on(addr).map_err(fmt_err)?;

    let wait = async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.swarm.select_next_some().await {
                return Ok(address);
            }
        }
    };

    tokio::time::timeout(TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

async fn wait_for_connection_and_subscription(
    sender: &mut TestNode,
    receiver: &mut TestNode,
    topic_str: &str,
) -> TestResult {
    let expected_topic = IdentTopic::new(topic_str).hash();
    let sender_peer = sender.peer_id;
    let receiver_peer = receiver.peer_id;

    let wait = async {
        let mut sender_connected = false;
        let mut receiver_connected = false;
        let mut sender_saw_receiver_subscription = false;

        loop {
            tokio::select! {
                event = sender.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == receiver_peer =>
                        {
                            sender_connected = true;
                        }
                        SwarmEvent::Behaviour(OutEvent::Gossip(event)) => {
                            if let GossipsubEvent::Subscribed { peer_id, topic } = *event
                                && peer_id == receiver_peer
                                && topic == expected_topic
                            {
                                sender_saw_receiver_subscription = true;
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { error, .. } => {
                            return Err(format!("sender outgoing connection error: {error:?}"));
                        }
                        _ => {}
                    }
                }
                event = receiver.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == sender_peer =>
                        {
                            receiver_connected = true;
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            return Err(format!("receiver incoming connection error: {error:?}"));
                        }
                        _ => {}
                    }
                }
            }

            if sender_connected && receiver_connected && sender_saw_receiver_subscription {
                return Ok(());
            }
        }
    };

    tokio::time::timeout(TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

async fn setup_live_pair(topic_str: &str) -> TestResult<(TestNode, TestNode)> {
    let mut sender = make_test_node()?;
    let mut receiver = make_test_node()?;

    join_all(&mut sender)?;
    join_all(&mut receiver)?;

    let addr = listen_on_loopback(&mut receiver).await?;
    sender.swarm.dial(addr).map_err(fmt_err)?;

    wait_for_connection_and_subscription(&mut sender, &mut receiver, topic_str).await?;

    Ok((sender, receiver))
}

async fn wait_for_raw_gossip(
    sender: &mut TestNode,
    receiver: &mut TestNode,
    topic_str: &str,
) -> TestResult<Vec<u8>> {
    let expected_topic = IdentTopic::new(topic_str).hash();

    let wait = async {
        loop {
            tokio::select! {
                _event = sender.swarm.select_next_some() => {}
                event = receiver.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(OutEvent::Gossip(event)) = event
                        && let GossipsubEvent::Message { message, .. } = *event
                        && message.topic == expected_topic
                    {
                        return Ok(message.data);
                    }
                }
            }
        }
    };

    tokio::time::timeout(TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

async fn wait_for_remzar_message(
    sender: &mut TestNode,
    receiver: &mut TestNode,
    topic_str: &str,
) -> TestResult<RemzarMessage> {
    let bytes = wait_for_raw_gossip(sender, receiver, topic_str).await?;
    RemzarMessage::decode_from_wire(&bytes).map_err(fmt_err)
}

fn transfer_tx(amount: u64) -> TestResult<Transaction> {
    Transaction::new(genesis_wallet(), peer_wallet(), amount).map_err(fmt_err)
}

fn register_tx() -> TestResult<RegisterNodeTx> {
    RegisterNodeTx::new(genesis_wallet()).map_err(fmt_err)
}

fn reward_tx(height: u64) -> TestResult<RewardTx> {
    RewardTx::new(peer_wallet(), UNIT_DIVISOR, height).map_err(fmt_err)
}

fn transfer_kind(amount: u64) -> TestResult<TxKind> {
    Ok(TxKind::Transfer(transfer_tx(amount)?))
}

fn register_kind() -> TestResult<TxKind> {
    Ok(TxKind::RegisterNode(register_tx()?))
}

fn reward_kind(height: u64) -> TestResult<TxKind> {
    Ok(TxKind::Reward(reward_tx(height)?))
}

fn tx_batch() -> TestResult<TransactionBatch> {
    TransactionBatch::new(
        8u64,
        TEST_TIMESTAMP,
        vec![transfer_kind(1u64)?, register_kind()?, reward_kind(1u64)?],
    )
    .map_err(fmt_err)
}

fn block(index: u64) -> TestResult<Block> {
    let fill = u8::try_from(index.rem_euclid(251u64)).map_err(fmt_err)?;
    let merkle_fill = fill
        .checked_add(1u8)
        .ok_or_else(|| "merkle fill overflow".to_string())?;

    let metadata = BlockMetadata::new(
        index,
        TEST_TIMESTAMP,
        hash64(3u8),
        hash64(merkle_fill),
        [merkle_fill; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_{index:010}")),
        genesis_wallet(),
        0u64,
    )
    .map_err(fmt_err)
}

fn por_proof(height: u64) -> PorPuzzleProof {
    PorPuzzleProof {
        height,
        validator: genesis_wallet(),
        prev_block_hash: hash64(7u8),
        output: 144u128,
    }
}

fn peer_mesh_announce(port: u16) -> TestResult<PeerMeshAnnounce> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let addr = make_multiaddr(port)?;

    PeerMeshAnnounce::from_local(peer_id, &[addr], Some(&genesis_wallet()), TEST_TIMESTAMP)
        .map_err(fmt_err)
}

fn chat_message() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":"hello"}"#.to_vec(),
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn invalid_chat_short_signature() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":"hello"}"#.to_vec(),
        signature: vec![0u8; 4usize],
    })
}

fn invalid_chat_same_wallet() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: genesis_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":"hello"}"#.to_vec(),
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn oversized_chat() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: vec![b'a'; 4097usize],
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    })
}

fn file_chunk_with_bytes(bytes: Vec<u8>) -> TestResult<FileChunkMessage> {
    let digest = blake3::hash(&bytes);
    let file_id = *digest.as_bytes();

    Ok(FileChunkMessage {
        file_id,
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        chunk_index: 0u32,
        total_chunks: 1u32,
        filename: "hello.txt".to_string(),
        file_size_bytes: u64::try_from(bytes.len()).map_err(fmt_err)?,
        content_hash_hex: hex::encode(file_id),
        chunk_bytes: bytes,
        timestamp_ms: now_millis()?,
    })
}

fn file_chunk() -> TestResult<FileChunkMessage> {
    file_chunk_with_bytes(b"hello-remzar-file".to_vec())
}

fn oversized_file_chunk() -> TestResult<FileChunkMessage> {
    let len = 1024usize
        .checked_mul(1024usize)
        .and_then(|v| v.checked_add(1usize))
        .ok_or_else(|| "oversized file chunk length overflow".to_string())?;

    file_chunk_with_bytes(vec![0xABu8; len])
}

fn assert_no_peer_error(result: anyhow::Result<()>) -> TestResult {
    match result {
        Ok(()) => Err("expected publish to fail without subscribed peers".to_string()),
        Err(err) => {
            let text = err.to_string();
            assert!(!text.is_empty());
            Ok(())
        }
    }
}

fn next_xorshift64(seed: &mut u64) -> u64 {
    let mut x = *seed;
    x ^= x.wrapping_shl(13);
    x ^= x.wrapping_shr(7);
    x ^= x.wrapping_shl(17);
    *seed = x;
    x
}

#[test]
fn p2p_01_008_broadcast_topic_constants_match_expected_values() -> TestResult {
    assert_eq!(TX_TOPIC_STR, "/remzar/tx/1.0.0");
    assert_eq!(TXBATCH_TOPIC_STR, "/remzar/tx_batch/1.0.0");
    assert_eq!(REWARD_TOPIC_STR, "/remzar/reward/1.0.0");
    assert_eq!(REGISTER_TOPIC_STR, "/remzar/register_node/1.0.0");
    assert_eq!(BLOCK_TOPIC_STR, "/remzar/block/1.0.0");
    assert_eq!(POR_PUZZLE_PROOF_TOPIC_STR, "/remzar/por/puzzle_proof/1.0.0");
    assert_eq!(FILE_TOPIC_STR, "remzar.file.v1");
    Ok(())
}

#[test]
fn p2p_02_008_broadcast_offchain_topics_are_distinct_from_consensus_topics() -> TestResult {
    assert_ne!(CHAT_TOPIC, TX_TOPIC_STR);
    assert_ne!(CHAT_TOPIC, BLOCK_TOPIC_STR);
    assert_ne!(FILE_TOPIC_STR, TX_TOPIC_STR);
    assert_ne!(FILE_TOPIC_STR, BLOCK_TOPIC_STR);
    assert_ne!(PEER_MESH_TOPIC_STR, TX_TOPIC_STR);
    Ok(())
}

#[test]
fn p2p_03_008_broadcast_reexported_topic_type_hashes_like_ident_topic() -> TestResult {
    let a = BroadcastTopic::new(TX_TOPIC_STR);
    let b = IdentTopic::new(TX_TOPIC_STR);

    assert_eq!(a.hash(), b.hash());
    Ok(())
}

#[test]
fn p2p_04_008_broadcast_join_all_topics_succeeds_on_fresh_swarm() -> TestResult {
    let mut node = make_test_node()?;

    join_all(&mut node)
}

#[test]
fn p2p_05_008_broadcast_join_all_topics_is_idempotent() -> TestResult {
    let mut node = make_test_node()?;

    join_all(&mut node)?;
    join_all(&mut node)?;
    join_all(&mut node)?;

    Ok(())
}

#[test]
fn p2p_06_008_broadcast_no_peer_send_transaction_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let tx = transfer_tx(1u64)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_transaction(&tx))
}

#[test]
fn p2p_07_008_broadcast_no_peer_send_tx_kind_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let kind = transfer_kind(2u64)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_tx_kind(&kind))
}

#[test]
fn p2p_08_008_broadcast_no_peer_send_register_node_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let reg = register_tx()?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_register_node(&reg))
}

#[test]
fn p2p_09_008_broadcast_no_peer_send_reward_tx_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let reward = reward_tx(1u64)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_reward_tx(&reward))
}

#[test]
fn p2p_10_008_broadcast_no_peer_send_tx_batch_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let batch = tx_batch()?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_tx_batch(&batch))
}

#[test]
fn p2p_11_008_broadcast_no_peer_send_block_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let block = block(1u64)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_block(&block))
}

#[test]
fn p2p_12_008_broadcast_no_peer_send_por_puzzle_proof_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let proof = por_proof(1u64);
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_por_puzzle_proof(&proof))
}

#[test]
fn p2p_13_008_broadcast_no_peer_send_peer_mesh_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let announce = peer_mesh_announce(4013u16)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_peer_mesh_announce(&announce))
}

#[test]
fn p2p_14_008_broadcast_no_peer_send_chat_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = chat_message()?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_chat(&chat))
}

#[test]
fn p2p_15_008_broadcast_no_peer_send_file_chunk_returns_error() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chunk = file_chunk()?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_file_chunk(&chunk))
}

#[test]
fn p2p_16_008_broadcast_remzar_message_payloads_stay_under_wire_limit() -> TestResult {
    let messages = vec![
        RemzarMessage::Transaction(transfer_tx(1u64)?),
        RemzarMessage::TxKind(transfer_kind(2u64)?),
        RemzarMessage::RegisterNode(register_tx()?),
        RemzarMessage::Reward(reward_tx(1u64)?),
        RemzarMessage::TxBatch(tx_batch()?),
        RemzarMessage::Block(Box::new(block(1u64)?)),
        RemzarMessage::PorPuzzleProof(por_proof(1u64)),
        RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(4016u16)?),
    ];

    for message in messages {
        let bytes = message.encode_to_wire().map_err(fmt_err)?;
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);
    }

    Ok(())
}

#[test]
fn p2p_17_008_broadcast_live_send_transaction_delivers_transaction_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let tx = transfer_tx(17u64)?;

        Broadcaster::new(&mut sender.swarm)
            .send_transaction(&tx)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Transaction(received) => {
                assert_eq!(received.amount, 17u64);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_18_008_broadcast_live_send_tx_kind_delivers_txkind_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let kind = transfer_kind(18u64)?;

        Broadcaster::new(&mut sender.swarm)
            .send_tx_kind(&kind)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxKind(received) => {
                assert_eq!(received.tag(), "transfer");
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_19_008_broadcast_live_send_register_node_delivers_register_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REGISTER_TOPIC_STR).await?;
        let reg = register_tx()?;

        Broadcaster::new(&mut sender.swarm)
            .send_register_node(&reg)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, REGISTER_TOPIC_STR).await?;

        match msg {
            RemzarMessage::RegisterNode(received) => {
                received.validate().map_err(fmt_err)?;
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_20_008_broadcast_live_send_reward_delivers_reward_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REWARD_TOPIC_STR).await?;
        let reward = reward_tx(20u64)?;

        Broadcaster::new(&mut sender.swarm)
            .send_reward_tx(&reward)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, REWARD_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Reward(received) => {
                assert_eq!(received.block_height, 20u64);
                assert_eq!(received.amount, UNIT_DIVISOR);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_21_008_broadcast_live_send_tx_batch_delivers_batch_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TXBATCH_TOPIC_STR).await?;
        let batch = tx_batch()?;

        Broadcaster::new(&mut sender.swarm)
            .send_tx_batch(&batch)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TXBATCH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxBatch(received) => {
                assert_eq!(received.transactions.len(), 3usize);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_22_008_broadcast_live_send_block_delivers_block_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(BLOCK_TOPIC_STR).await?;
        let block = block(22u64)?;

        Broadcaster::new(&mut sender.swarm)
            .send_block(&block)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, BLOCK_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Block(received) => {
                assert_eq!(received.metadata.index, 22u64);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_23_008_broadcast_live_send_por_puzzle_delivers_proof_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(POR_PUZZLE_PROOF_TOPIC_STR).await?;
        let proof = por_proof(23u64);

        Broadcaster::new(&mut sender.swarm)
            .send_por_puzzle_proof(&proof)
            .map_err(fmt_err)?;

        let msg =
            wait_for_remzar_message(&mut sender, &mut receiver, POR_PUZZLE_PROOF_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PorPuzzleProof(received) => {
                assert_eq!(received.height, 23u64);
                assert_eq!(received.output, 144u128);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_24_008_broadcast_live_send_peer_mesh_delivers_announce_message() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(PEER_MESH_TOPIC_STR).await?;
        let announce = peer_mesh_announce(4024u16)?;

        Broadcaster::new(&mut sender.swarm)
            .send_peer_mesh_announce(&announce)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, PEER_MESH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PeerMeshAnnounce(received) => {
                assert_eq!(received.listen_addrs.len(), 1usize);
                assert!(!received.peer_id.is_empty());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_25_008_broadcast_live_send_chat_delivers_chat_wire_payload() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(CHAT_TOPIC).await?;
        let chat = chat_message()?;

        Broadcaster::new(&mut sender.swarm)
            .send_chat(&chat)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, CHAT_TOPIC).await?;
        let received = ChatMessage::decode_wire(&bytes).map_err(fmt_err)?;

        assert_eq!(received.from_wallet, genesis_wallet());
        assert_eq!(received.to_wallet, peer_wallet());
        assert_eq!(received.plaintext().map_err(fmt_err)?, "hello");
        Ok(())
    })
}

#[test]
fn p2p_26_008_broadcast_live_send_file_chunk_delivers_postcard_file_chunk() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = file_chunk()?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.filename, "hello.txt");
        assert_eq!(received.chunk_bytes, b"hello-remzar-file".to_vec());
        Ok(())
    })
}

#[test]
fn p2p_27_008_broadcast_oversized_chat_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = oversized_chat()?;
    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_28_008_broadcast_oversized_file_chunk_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chunk = oversized_file_chunk()?;
    assert!(
        Broadcaster::new(&mut node.swarm)
            .send_file_chunk(&chunk)
            .is_err()
    );
    Ok(())
}

#[test]
fn p2p_29_008_broadcast_invalid_chat_short_signature_is_rejected() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = invalid_chat_short_signature()?;
    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_30_008_broadcast_invalid_chat_same_wallet_is_rejected() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = invalid_chat_same_wallet()?;
    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_31_008_broadcast_adversarial_no_peer_sequence_all_fail_cleanly() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let tx = transfer_tx(31u64)?;
    let kind = transfer_kind(31u64)?;
    let reg = register_tx()?;
    let reward = reward_tx(31u64)?;
    let proof = por_proof(31u64);

    assert!(
        Broadcaster::new(&mut node.swarm)
            .send_transaction(&tx)
            .is_err()
    );
    assert!(
        Broadcaster::new(&mut node.swarm)
            .send_tx_kind(&kind)
            .is_err()
    );
    assert!(
        Broadcaster::new(&mut node.swarm)
            .send_register_node(&reg)
            .is_err()
    );
    assert!(
        Broadcaster::new(&mut node.swarm)
            .send_reward_tx(&reward)
            .is_err()
    );
    assert!(
        Broadcaster::new(&mut node.swarm)
            .send_por_puzzle_proof(&proof)
            .is_err()
    );

    Ok(())
}

#[test]
fn p2p_32_008_broadcast_load_join_all_topics_on_sixteen_swarms() -> TestResult {
    let mut nodes = Vec::new();

    for _ in 0usize..16usize {
        let mut node = make_test_node()?;
        join_all(&mut node)?;
        nodes.push(node);
    }

    assert_eq!(nodes.len(), 16usize);
    Ok(())
}

#[test]
fn p2p_33_008_broadcast_load_encode_128_transaction_messages_under_cap() -> TestResult {
    let mut checked = 0usize;

    for amount in 1u64..=128u64 {
        let msg = RemzarMessage::Transaction(transfer_tx(amount)?);
        let bytes = msg.encode_to_wire().map_err(fmt_err)?;

        assert!(!bytes.is_empty());
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "transaction encode counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_34_008_broadcast_live_repeated_transaction_broadcasts_deliver_all() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let mut received = 0usize;

        for amount in 1u64..=5u64 {
            let tx = transfer_tx(amount)?;

            Broadcaster::new(&mut sender.swarm)
                .send_transaction(&tx)
                .map_err(fmt_err)?;

            let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

            match msg {
                RemzarMessage::Transaction(received_tx) => {
                    assert_eq!(received_tx.amount, amount);
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }

            received = received
                .checked_add(1usize)
                .ok_or_else(|| "repeated tx receive counter overflow".to_string())?;
        }

        assert_eq!(received, 5usize);
        Ok(())
    })
}

#[test]
fn p2p_35_008_broadcast_live_mixed_consensus_messages_keep_expected_kinds() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;

        let tx = transfer_tx(35u64)?;
        Broadcaster::new(&mut sender.swarm)
            .send_transaction(&tx)
            .map_err(fmt_err)?;

        let first = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;
        assert_eq!(first.kind_str(), "Transaction");

        let kind = transfer_kind(36u64)?;
        Broadcaster::new(&mut sender.swarm)
            .send_tx_kind(&kind)
            .map_err(fmt_err)?;

        let second = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;
        assert_eq!(second.kind_str(), "TxKind");

        Ok(())
    })
}

#[test]
fn p2p_36_008_broadcast_property_topic_hashes_are_unique() -> TestResult {
    let topics = [
        TX_TOPIC_STR,
        TXBATCH_TOPIC_STR,
        REWARD_TOPIC_STR,
        REGISTER_TOPIC_STR,
        BLOCK_TOPIC_STR,
        POR_PUZZLE_PROOF_TOPIC_STR,
        PEER_MESH_TOPIC_STR,
        CHAT_TOPIC,
        FILE_TOPIC_STR,
    ];

    let mut hashes = std::collections::BTreeSet::new();

    for topic in topics {
        let hash = IdentTopic::new(topic).hash().to_string();
        assert!(hashes.insert(hash));
    }

    assert_eq!(hashes.len(), topics.len());
    Ok(())
}

#[test]
fn p2p_37_008_broadcast_fuzz_payload_selection_encodes_under_cap() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..64usize {
        let sample = next_xorshift64(&mut seed);
        let msg = match sample & 7u64 {
            0u64 => RemzarMessage::Transaction(transfer_tx(1u64)?),
            1u64 => RemzarMessage::TxKind(transfer_kind(2u64)?),
            2u64 => RemzarMessage::RegisterNode(register_tx()?),
            3u64 => RemzarMessage::Reward(reward_tx(1u64)?),
            4u64 => RemzarMessage::TxBatch(tx_batch()?),
            5u64 => RemzarMessage::Block(Box::new(block(5u64)?)),
            6u64 => RemzarMessage::PorPuzzleProof(por_proof(6u64)),
            _ => RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(4037u16)?),
        };

        let bytes = msg.encode_to_wire().map_err(fmt_err)?;
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "fuzz encode counter overflow".to_string())?;
    }

    assert_eq!(checked, 64usize);
    Ok(())
}

#[test]
fn p2p_38_008_broadcast_vector_tx_kind_register_and_reward_tags_are_preserved() -> TestResult {
    let register = register_kind()?;
    let reward = reward_kind(38u64)?;

    assert_eq!(register.tag(), "register_node");
    assert_eq!(reward.tag(), "reward");

    let reg_bytes = RemzarMessage::TxKind(register)
        .encode_to_wire()
        .map_err(fmt_err)?;
    let reward_bytes = RemzarMessage::TxKind(reward)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert_ne!(reg_bytes, reward_bytes);
    Ok(())
}

#[test]
fn p2p_39_008_broadcast_chat_and_file_wire_are_not_remzar_messages() -> TestResult {
    let chat = chat_message()?;
    let file = file_chunk()?;

    let chat_bytes = chat.encode_wire().map_err(fmt_err)?;
    let file_bytes = postcard::to_allocvec(&file).map_err(fmt_err)?;

    assert!(RemzarMessage::decode_from_wire(&chat_bytes).is_err());
    assert!(RemzarMessage::decode_from_wire(&file_bytes).is_err());

    Ok(())
}

#[test]
fn p2p_40_008_broadcast_live_file_and_chat_topics_do_not_cross_decode() -> TestResult {
    run_async(async {
        let (mut chat_sender, mut chat_receiver) = setup_live_pair(CHAT_TOPIC).await?;
        let chat = chat_message()?;

        Broadcaster::new(&mut chat_sender.swarm)
            .send_chat(&chat)
            .map_err(fmt_err)?;

        let chat_bytes =
            wait_for_raw_gossip(&mut chat_sender, &mut chat_receiver, CHAT_TOPIC).await?;
        assert!(ChatMessage::decode_wire(&chat_bytes).is_ok());
        assert!(postcard::from_bytes::<FileChunkMessage>(&chat_bytes).is_err());

        let (mut file_sender, mut file_receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = file_chunk()?;

        Broadcaster::new(&mut file_sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let file_bytes =
            wait_for_raw_gossip(&mut file_sender, &mut file_receiver, FILE_TOPIC_STR).await?;
        assert!(postcard::from_bytes::<FileChunkMessage>(&file_bytes).is_ok());
        assert!(ChatMessage::decode_wire(&file_bytes).is_err());

        Ok(())
    })
}

#[test]
fn p2p_41_008_broadcast_all_topic_strings_are_non_empty() -> TestResult {
    for topic in p2p_008_all_publish_topics() {
        assert!(!topic.trim().is_empty());
    }

    Ok(())
}

#[test]
fn p2p_42_008_broadcast_all_consensus_topic_hashes_are_stable() -> TestResult {
    for topic in p2p_008_all_consensus_topics() {
        let first = IdentTopic::new(topic).hash();
        let second = IdentTopic::new(topic).hash();

        assert_eq!(first, second);
    }

    Ok(())
}

#[test]
fn p2p_43_008_broadcast_no_peer_after_repeated_join_still_fails_cleanly() -> TestResult {
    let mut node = make_test_node()?;

    join_all(&mut node)?;
    join_all(&mut node)?;

    let tx = transfer_tx(43u64)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_transaction(&tx))
}

#[test]
fn p2p_44_008_broadcast_no_peer_txkind_register_fails_cleanly() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let kind = register_kind()?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_tx_kind(&kind))
}

#[test]
fn p2p_45_008_broadcast_no_peer_txkind_reward_fails_cleanly() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let kind = reward_kind(45u64)?;
    assert_no_peer_error(Broadcaster::new(&mut node.swarm).send_tx_kind(&kind))
}

#[test]
fn p2p_46_008_broadcast_live_txkind_register_delivers_on_tx_topic() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let kind = register_kind()?;

        Broadcaster::new(&mut sender.swarm)
            .send_tx_kind(&kind)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxKind(received) => {
                assert_eq!(received.tag(), "register_node");
                received.validate().map_err(fmt_err)?;
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_47_008_broadcast_live_txkind_reward_delivers_on_tx_topic() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let kind = reward_kind(47u64)?;

        Broadcaster::new(&mut sender.swarm)
            .send_tx_kind(&kind)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxKind(received) => {
                assert_eq!(received.tag(), "reward");
                received.validate().map_err(fmt_err)?;
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_48_008_broadcast_live_three_txkind_variants_keep_tags() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let kinds = [transfer_kind(48u64)?, register_kind()?, reward_kind(48u64)?];
        let expected_tags = ["transfer", "register_node", "reward"];

        for (index, kind) in kinds.iter().enumerate() {
            Broadcaster::new(&mut sender.swarm)
                .send_tx_kind(kind)
                .map_err(fmt_err)?;

            let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;
            let expected = expected_tags
                .get(index)
                .ok_or_else(|| "missing expected txkind tag".to_string())?;

            match msg {
                RemzarMessage::TxKind(received) => {
                    assert_eq!(received.tag(), *expected);
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_49_008_broadcast_live_batch_with_sixteen_transfers_delivers_count() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TXBATCH_TOPIC_STR).await?;
        let batch = p2p_008_transfer_batch_with_count(16usize)?;

        Broadcaster::new(&mut sender.swarm)
            .send_tx_batch(&batch)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TXBATCH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxBatch(received) => {
                assert_eq!(received.transactions.len(), 16usize);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_50_008_broadcast_live_peer_mesh_with_wallet_normalizes_after_delivery() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(PEER_MESH_TOPIC_STR).await?;
        let announce = peer_mesh_announce(4050u16)?;

        Broadcaster::new(&mut sender.swarm)
            .send_peer_mesh_announce(&announce)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, PEER_MESH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PeerMeshAnnounce(received) => {
                let normalized = received.normalize().map_err(fmt_err)?;
                assert_eq!(normalized.wallet, Some(genesis_wallet()));
                assert_eq!(normalized.full_dial_addrs.len(), 1usize);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_51_008_broadcast_live_invalid_por_zero_output_is_delivered_not_prevalidated() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(POR_PUZZLE_PROOF_TOPIC_STR).await?;
        let mut proof = por_proof(51u64);
        proof.output = 0u128;

        Broadcaster::new(&mut sender.swarm)
            .send_por_puzzle_proof(&proof)
            .map_err(fmt_err)?;

        let msg =
            wait_for_remzar_message(&mut sender, &mut receiver, POR_PUZZLE_PROOF_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PorPuzzleProof(received) => {
                assert_eq!(received.output, 0u128);
                assert!(received.validate_structural().is_err());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_52_008_broadcast_live_por_max_valid_height_is_delivered() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(POR_PUZZLE_PROOF_TOPIC_STR).await?;
        let proof = por_proof(10_000_000u64);

        Broadcaster::new(&mut sender.swarm)
            .send_por_puzzle_proof(&proof)
            .map_err(fmt_err)?;

        let msg =
            wait_for_remzar_message(&mut sender, &mut receiver, POR_PUZZLE_PROOF_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PorPuzzleProof(received) => {
                assert_eq!(received.height, 10_000_000u64);
                received.validate_structural().map_err(fmt_err)?;
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_53_008_broadcast_live_chat_unicode_plaintext_delivers() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(CHAT_TOPIC).await?;
        let chat = p2p_008_chat_message_with_plaintext("hello remzar 🚀")?;

        Broadcaster::new(&mut sender.swarm)
            .send_chat(&chat)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, CHAT_TOPIC).await?;
        let received = ChatMessage::decode_wire(&bytes).map_err(fmt_err)?;

        assert_eq!(received.plaintext().map_err(fmt_err)?, "hello remzar 🚀");
        Ok(())
    })
}

#[test]
fn p2p_54_008_broadcast_live_chat_500_ascii_chars_delivers() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(CHAT_TOPIC).await?;
        let plaintext = "a".repeat(500usize);
        let chat = p2p_008_chat_message_with_plaintext(&plaintext)?;

        Broadcaster::new(&mut sender.swarm)
            .send_chat(&chat)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, CHAT_TOPIC).await?;
        let received = ChatMessage::decode_wire(&bytes).map_err(fmt_err)?;

        assert_eq!(received.plaintext().map_err(fmt_err)?, plaintext);
        Ok(())
    })
}

#[test]
fn p2p_55_008_broadcast_invalid_chat_empty_plaintext_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = p2p_008_invalid_chat_empty_plaintext()?;
    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_56_008_broadcast_invalid_chat_malformed_json_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = p2p_008_invalid_chat_malformed_json()?;
    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_57_008_broadcast_file_empty_chunk_delivers_and_roundtrips() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = file_chunk_with_bytes(Vec::new())?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert!(received.chunk_bytes.is_empty());
        assert_eq!(received.file_size_bytes, 0u64);
        Ok(())
    })
}

#[test]
fn p2p_58_008_broadcast_file_64k_chunk_delivers_and_roundtrips() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let data = vec![0x5Au8; 64usize * 1024usize];
        let chunk = file_chunk_with_bytes(data.clone())?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.chunk_bytes, data);
        Ok(())
    })
}

#[test]
fn p2p_59_008_broadcast_file_256k_chunk_delivers_and_roundtrips() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let data = vec![0xBCu8; 256usize * 1024usize];
        let chunk = file_chunk_with_bytes(data.clone())?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.chunk_bytes.len(), data.len());
        assert_eq!(received.chunk_bytes, data);
        Ok(())
    })
}

#[test]
fn p2p_60_008_broadcast_file_chunk_metadata_survives_delivery() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = file_chunk()?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.from_wallet, genesis_wallet());
        assert_eq!(received.to_wallet, peer_wallet());
        assert_eq!(received.total_chunks, 1u32);
        assert_eq!(received.chunk_index, 0u32);
        assert_eq!(received.content_hash_hex.len(), 64usize);
        Ok(())
    })
}

#[test]
fn p2p_61_008_broadcast_live_repeated_rewards_deliver_distinct_heights() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REWARD_TOPIC_STR).await?;

        for height in 61u64..=63u64 {
            let reward = reward_tx(height)?;

            Broadcaster::new(&mut sender.swarm)
                .send_reward_tx(&reward)
                .map_err(fmt_err)?;

            let msg = wait_for_remzar_message(&mut sender, &mut receiver, REWARD_TOPIC_STR).await?;

            match msg {
                RemzarMessage::Reward(received) => {
                    assert_eq!(received.block_height, height);
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_62_008_broadcast_live_repeated_blocks_deliver_distinct_indices() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(BLOCK_TOPIC_STR).await?;

        for index in 62u64..=64u64 {
            let block = block(index)?;

            Broadcaster::new(&mut sender.swarm)
                .send_block(&block)
                .map_err(fmt_err)?;

            let msg = wait_for_remzar_message(&mut sender, &mut receiver, BLOCK_TOPIC_STR).await?;

            match msg {
                RemzarMessage::Block(received) => {
                    assert_eq!(received.metadata.index, index);
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_63_008_broadcast_live_repeated_por_proofs_deliver_distinct_heights() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(POR_PUZZLE_PROOF_TOPIC_STR).await?;

        for height in 63u64..=65u64 {
            let proof = por_proof(height);

            Broadcaster::new(&mut sender.swarm)
                .send_por_puzzle_proof(&proof)
                .map_err(fmt_err)?;

            let msg =
                wait_for_remzar_message(&mut sender, &mut receiver, POR_PUZZLE_PROOF_TOPIC_STR)
                    .await?;

            match msg {
                RemzarMessage::PorPuzzleProof(received) => {
                    assert_eq!(received.height, height);
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_64_008_broadcast_live_repeated_peer_mesh_announces_deliver_distinct_ports() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(PEER_MESH_TOPIC_STR).await?;

        for port in 4064u16..=4066u16 {
            let announce = peer_mesh_announce(port)?;

            Broadcaster::new(&mut sender.swarm)
                .send_peer_mesh_announce(&announce)
                .map_err(fmt_err)?;

            let msg =
                wait_for_remzar_message(&mut sender, &mut receiver, PEER_MESH_TOPIC_STR).await?;

            match msg {
                RemzarMessage::PeerMeshAnnounce(received) => {
                    let normalized = received.normalize().map_err(fmt_err)?;
                    let addr_text = normalized
                        .full_dial_addrs
                        .first()
                        .ok_or_else(|| "missing normalized peer mesh addr".to_string())?
                        .to_string();
                    assert!(addr_text.contains(&port.to_string()));
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_65_008_broadcast_property_consensus_payload_topic_mapping_vectors() -> TestResult {
    let vectors = [
        (
            TX_TOPIC_STR,
            RemzarMessage::Transaction(transfer_tx(65u64)?),
            "Transaction",
        ),
        (
            TX_TOPIC_STR,
            RemzarMessage::TxKind(transfer_kind(65u64)?),
            "TxKind",
        ),
        (
            REGISTER_TOPIC_STR,
            RemzarMessage::RegisterNode(register_tx()?),
            "RegisterNode",
        ),
        (
            REWARD_TOPIC_STR,
            RemzarMessage::Reward(reward_tx(65u64)?),
            "Reward",
        ),
        (
            TXBATCH_TOPIC_STR,
            RemzarMessage::TxBatch(tx_batch()?),
            "TxBatch",
        ),
        (
            BLOCK_TOPIC_STR,
            RemzarMessage::Block(Box::new(block(65u64)?)),
            "Block",
        ),
        (
            POR_PUZZLE_PROOF_TOPIC_STR,
            RemzarMessage::PorPuzzleProof(por_proof(65u64)),
            "PorPuzzleProof",
        ),
        (
            PEER_MESH_TOPIC_STR,
            RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(4065u16)?),
            "PeerMeshAnnounce",
        ),
    ];

    for (topic, message, expected_kind) in vectors {
        let topic_hash = IdentTopic::new(topic).hash();
        let bytes = message.encode_to_wire().map_err(fmt_err)?;
        let decoded = RemzarMessage::decode_from_wire(&bytes).map_err(fmt_err)?;

        assert!(!topic_hash.to_string().is_empty());
        assert_eq!(decoded.kind_str(), expected_kind);
    }

    Ok(())
}

#[test]
fn p2p_66_008_broadcast_load_create_32_broadcasters_and_join_topics() -> TestResult {
    let mut nodes = Vec::new();

    for _ in 0usize..32usize {
        let mut node = make_test_node()?;
        Broadcaster::new(&mut node.swarm)
            .join_all_topics()
            .map_err(fmt_err)?;
        nodes.push(node);
    }

    assert_eq!(nodes.len(), 32usize);
    Ok(())
}

#[test]
fn p2p_67_008_broadcast_load_encode_256_mixed_consensus_messages() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..256usize {
        let sample = next_xorshift64(&mut seed);

        let message = match sample & 7u64 {
            0u64 => RemzarMessage::Transaction(transfer_tx(67u64)?),
            1u64 => RemzarMessage::TxKind(transfer_kind(67u64)?),
            2u64 => RemzarMessage::RegisterNode(register_tx()?),
            3u64 => RemzarMessage::Reward(reward_tx(67u64)?),
            4u64 => RemzarMessage::TxBatch(tx_batch()?),
            5u64 => RemzarMessage::Block(Box::new(block(67u64)?)),
            6u64 => RemzarMessage::PorPuzzleProof(por_proof(67u64)),
            _ => RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(4067u16)?),
        };

        let bytes = message.encode_to_wire().map_err(fmt_err)?;
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "mixed encode load counter overflow".to_string())?;
    }

    assert_eq!(checked, 256usize);
    Ok(())
}

#[test]
fn p2p_68_008_broadcast_adversarial_invalid_chat_then_valid_chat_is_stateless() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(CHAT_TOPIC).await?;

        let invalid = p2p_008_invalid_chat_malformed_json()?;
        assert!(
            Broadcaster::new(&mut sender.swarm)
                .send_chat(&invalid)
                .is_err()
        );

        let valid = p2p_008_chat_message_with_plaintext("valid-after-invalid")?;
        Broadcaster::new(&mut sender.swarm)
            .send_chat(&valid)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, CHAT_TOPIC).await?;
        let received = ChatMessage::decode_wire(&bytes).map_err(fmt_err)?;

        assert_eq!(
            received.plaintext().map_err(fmt_err)?,
            "valid-after-invalid"
        );
        Ok(())
    })
}

#[test]
fn p2p_69_008_broadcast_adversarial_oversized_file_then_valid_file_is_stateless() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;

        let oversized = oversized_file_chunk()?;
        assert!(
            Broadcaster::new(&mut sender.swarm)
                .send_file_chunk(&oversized)
                .is_err()
        );

        let valid = file_chunk()?;
        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&valid)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.filename, "hello.txt");
        Ok(())
    })
}

#[test]
fn p2p_70_008_broadcast_chat_wire_does_not_decode_as_remzar_after_delivery() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(CHAT_TOPIC).await?;
        let chat = p2p_008_chat_message_with_plaintext("not consensus")?;

        Broadcaster::new(&mut sender.swarm)
            .send_chat(&chat)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, CHAT_TOPIC).await?;

        assert!(ChatMessage::decode_wire(&bytes).is_ok());
        assert!(RemzarMessage::decode_from_wire(&bytes).is_err());
        Ok(())
    })
}

#[test]
fn p2p_71_008_broadcast_file_wire_does_not_decode_as_remzar_after_delivery() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = file_chunk()?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;

        assert!(postcard::from_bytes::<FileChunkMessage>(&bytes).is_ok());
        assert!(RemzarMessage::decode_from_wire(&bytes).is_err());
        Ok(())
    })
}

#[test]
fn p2p_72_008_broadcast_consensus_wire_does_not_decode_as_chat_or_file() -> TestResult {
    let bytes = RemzarMessage::Transaction(transfer_tx(72u64)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert!(ChatMessage::decode_wire(&bytes).is_err());
    assert!(postcard::from_bytes::<FileChunkMessage>(&bytes).is_err());
    Ok(())
}

#[test]
fn p2p_73_008_broadcast_vector_file_chunk_hash_matches_bytes() -> TestResult {
    let data = b"hash-me".to_vec();
    let chunk = file_chunk_with_bytes(data.clone())?;
    let expected_hash = blake3::hash(&data);

    assert_eq!(chunk.file_id, *expected_hash.as_bytes());
    assert_eq!(
        chunk.content_hash_hex,
        hex::encode(expected_hash.as_bytes())
    );
    Ok(())
}

#[test]
fn p2p_74_008_broadcast_vector_file_chunk_empty_hash_matches_empty_bytes() -> TestResult {
    let data = Vec::new();
    let chunk = file_chunk_with_bytes(data.clone())?;
    let expected_hash = blake3::hash(&data);

    assert_eq!(chunk.file_id, *expected_hash.as_bytes());
    assert_eq!(
        chunk.content_hash_hex,
        hex::encode(expected_hash.as_bytes())
    );
    Ok(())
}

#[test]
fn p2p_75_008_broadcast_vector_chat_plaintext_roundtrips_locally_before_send() -> TestResult {
    let chat = p2p_008_chat_message_with_plaintext("local plaintext vector")?;

    assert_eq!(chat.plaintext().map_err(fmt_err)?, "local plaintext vector");
    assert!(!chat.encode_wire().map_err(fmt_err)?.is_empty());
    Ok(())
}

#[test]
fn p2p_76_008_broadcast_property_chat_wire_len_stable_for_same_message() -> TestResult {
    let chat = p2p_008_chat_message_with_plaintext("stable chat wire")?;
    let first = chat.encode_wire().map_err(fmt_err)?;
    let second = chat.encode_wire().map_err(fmt_err)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_77_008_broadcast_property_file_wire_len_stable_for_same_chunk() -> TestResult {
    let chunk = file_chunk()?;
    let first = postcard::to_allocvec(&chunk).map_err(fmt_err)?;
    let second = postcard::to_allocvec(&chunk).map_err(fmt_err)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_78_008_broadcast_property_remzar_wire_len_stable_for_same_tx() -> TestResult {
    let message = RemzarMessage::Transaction(transfer_tx(78u64)?);
    let first = message.encode_to_wire().map_err(fmt_err)?;
    let second = message.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_79_008_broadcast_live_large_batch_still_under_cap_and_delivers() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TXBATCH_TOPIC_STR).await?;
        let batch = p2p_008_transfer_batch_with_count(32usize)?;
        let msg = RemzarMessage::TxBatch(batch.clone());
        let bytes = msg.encode_to_wire().map_err(fmt_err)?;

        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        Broadcaster::new(&mut sender.swarm)
            .send_tx_batch(&batch)
            .map_err(fmt_err)?;

        let received =
            wait_for_remzar_message(&mut sender, &mut receiver, TXBATCH_TOPIC_STR).await?;

        match received {
            RemzarMessage::TxBatch(received_batch) => {
                assert_eq!(received_batch.transactions.len(), 32usize);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_80_008_broadcast_live_end_to_end_all_core_consensus_topics_once() -> TestResult {
    run_async(async {
        let cases = [
            TX_TOPIC_STR,
            TXBATCH_TOPIC_STR,
            REWARD_TOPIC_STR,
            REGISTER_TOPIC_STR,
            BLOCK_TOPIC_STR,
            POR_PUZZLE_PROOF_TOPIC_STR,
            PEER_MESH_TOPIC_STR,
        ];

        for topic in cases {
            let (mut sender, mut receiver) = setup_live_pair(topic).await?;

            match topic {
                TX_TOPIC_STR => {
                    let tx = transfer_tx(80u64)?;
                    Broadcaster::new(&mut sender.swarm)
                        .send_transaction(&tx)
                        .map_err(fmt_err)?;
                }
                TXBATCH_TOPIC_STR => {
                    let batch = tx_batch()?;
                    Broadcaster::new(&mut sender.swarm)
                        .send_tx_batch(&batch)
                        .map_err(fmt_err)?;
                }
                REWARD_TOPIC_STR => {
                    let reward = reward_tx(80u64)?;
                    Broadcaster::new(&mut sender.swarm)
                        .send_reward_tx(&reward)
                        .map_err(fmt_err)?;
                }
                REGISTER_TOPIC_STR => {
                    let reg = register_tx()?;
                    Broadcaster::new(&mut sender.swarm)
                        .send_register_node(&reg)
                        .map_err(fmt_err)?;
                }
                BLOCK_TOPIC_STR => {
                    let b = block(80u64)?;
                    Broadcaster::new(&mut sender.swarm)
                        .send_block(&b)
                        .map_err(fmt_err)?;
                }
                POR_PUZZLE_PROOF_TOPIC_STR => {
                    let proof = por_proof(80u64);
                    Broadcaster::new(&mut sender.swarm)
                        .send_por_puzzle_proof(&proof)
                        .map_err(fmt_err)?;
                }
                PEER_MESH_TOPIC_STR => {
                    let ann = peer_mesh_announce(4080u16)?;
                    Broadcaster::new(&mut sender.swarm)
                        .send_peer_mesh_announce(&ann)
                        .map_err(fmt_err)?;
                }
                _ => return Err("unexpected topic in core consensus vector".to_string()),
            }

            let message = wait_for_remzar_message(&mut sender, &mut receiver, topic).await?;
            assert!(!message.kind_str().is_empty());
        }

        Ok(())
    })
}

#[test]
fn p2p_81_008_broadcast_live_transaction_to_third_wallet_delivers_receiver() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let tx = Transaction::new(genesis_wallet(), third_wallet(), 81u64).map_err(fmt_err)?;

        Broadcaster::new(&mut sender.swarm)
            .send_transaction(&tx)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Transaction(received) => {
                assert_eq!(received.receiver.as_slice(), third_wallet().as_bytes());
                assert_eq!(received.amount, 81u64);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_82_008_broadcast_live_txkind_transfer_to_third_wallet_touches_third() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let tx = Transaction::new(genesis_wallet(), third_wallet(), 82u64).map_err(fmt_err)?;
        let kind = TxKind::Transfer(tx);

        Broadcaster::new(&mut sender.swarm)
            .send_tx_kind(&kind)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxKind(received) => {
                let touched = received.touched_addresses();

                assert!(touched.contains(&genesis_wallet()));
                assert!(touched.contains(&third_wallet()));
                assert_eq!(received.normalized_receiver(), Some(third_wallet()));
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_83_008_broadcast_live_register_third_wallet_delivers_and_validates() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REGISTER_TOPIC_STR).await?;
        let reg = RegisterNodeTx::new(third_wallet()).map_err(fmt_err)?;

        Broadcaster::new(&mut sender.swarm)
            .send_register_node(&reg)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, REGISTER_TOPIC_STR).await?;

        match msg {
            RemzarMessage::RegisterNode(received) => {
                received.validate().map_err(fmt_err)?;
                assert_eq!(
                    received.wallet_address.as_slice(),
                    third_wallet().as_bytes()
                );
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_84_008_broadcast_live_reward_to_third_wallet_delivers_receiver() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REWARD_TOPIC_STR).await?;
        let reward = RewardTx::new(third_wallet(), UNIT_DIVISOR, 84u64).map_err(fmt_err)?;

        Broadcaster::new(&mut sender.swarm)
            .send_reward_tx(&reward)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, REWARD_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Reward(received) => {
                assert_eq!(received.receiver.as_slice(), third_wallet().as_bytes());
                assert_eq!(received.block_height, 84u64);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_85_008_broadcast_live_chat_to_third_wallet_delivers_to_wallet() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(CHAT_TOPIC).await?;
        let chat = p2p_008_chat_message_to_wallet("hello third", third_wallet())?;

        Broadcaster::new(&mut sender.swarm)
            .send_chat(&chat)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, CHAT_TOPIC).await?;
        let received = ChatMessage::decode_wire(&bytes).map_err(fmt_err)?;

        assert_eq!(received.to_wallet, third_wallet());
        assert_eq!(received.plaintext().map_err(fmt_err)?, "hello third");
        Ok(())
    })
}

#[test]
fn p2p_86_008_broadcast_live_file_chunk_to_third_wallet_delivers_to_wallet() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = p2p_008_file_chunk_to_wallet(
            b"third-wallet-file".to_vec(),
            third_wallet(),
            "third.txt".to_string(),
            0u32,
            1u32,
        )?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.to_wallet, third_wallet());
        assert_eq!(received.filename, "third.txt");
        assert_eq!(received.chunk_bytes, b"third-wallet-file".to_vec());
        Ok(())
    })
}

#[test]
fn p2p_87_008_broadcast_live_file_second_chunk_metadata_survives_delivery() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let chunk = p2p_008_file_chunk_to_wallet(
            b"second chunk".to_vec(),
            peer_wallet(),
            "multi.bin".to_string(),
            1u32,
            3u32,
        )?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.chunk_index, 1u32);
        assert_eq!(received.total_chunks, 3u32);
        assert_eq!(received.filename, "multi.bin");
        Ok(())
    })
}

#[test]
fn p2p_88_008_broadcast_live_file_long_filename_survives_delivery() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let filename = format!("{}.txt", "a".repeat(128usize));
        let chunk = p2p_008_file_chunk_to_wallet(
            b"long filename".to_vec(),
            peer_wallet(),
            filename.clone(),
            0u32,
            1u32,
        )?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.filename, filename);
        Ok(())
    })
}

#[test]
fn p2p_89_008_broadcast_chat_501_ascii_chars_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let plaintext = "a".repeat(501usize);
    let chat = p2p_008_chat_message_with_plaintext(&plaintext)?;

    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_90_008_broadcast_chat_whitespace_plaintext_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = p2p_008_chat_message_with_plaintext("     ")?;

    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_91_008_broadcast_chat_unknown_json_field_is_rejected_before_publish() -> TestResult {
    let mut node = make_test_node()?;
    join_all(&mut node)?;

    let chat = ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":"hello","extra":true}"#.to_vec(),
        signature: vec![0u8; ml_dsa_65::SIG_LEN],
    };

    assert!(Broadcaster::new(&mut node.swarm).send_chat(&chat).is_err());
    Ok(())
}

#[test]
fn p2p_92_008_broadcast_live_file_512k_chunk_delivers_and_roundtrips() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(FILE_TOPIC_STR).await?;
        let data = vec![0xC3u8; 512usize * 1024usize];
        let chunk = file_chunk_with_bytes(data.clone())?;

        Broadcaster::new(&mut sender.swarm)
            .send_file_chunk(&chunk)
            .map_err(fmt_err)?;

        let bytes = wait_for_raw_gossip(&mut sender, &mut receiver, FILE_TOPIC_STR).await?;
        let received: FileChunkMessage = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(received.chunk_bytes.len(), data.len());
        assert_eq!(received.chunk_bytes, data);
        Ok(())
    })
}

#[test]
fn p2p_93_008_broadcast_live_peer_mesh_without_wallet_delivers_and_normalizes_none() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(PEER_MESH_TOPIC_STR).await?;
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let addr = make_multiaddr(4093u16)?;
        let announce = PeerMeshAnnounce::from_local(peer_id, &[addr], None, TEST_TIMESTAMP)
            .map_err(fmt_err)?;

        Broadcaster::new(&mut sender.swarm)
            .send_peer_mesh_announce(&announce)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, PEER_MESH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PeerMeshAnnounce(received) => {
                let normalized = received.normalize().map_err(fmt_err)?;

                assert!(normalized.wallet.is_none());
                assert_eq!(normalized.full_dial_addrs.len(), 1usize);
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_94_008_broadcast_live_invalid_peer_mesh_wallet_is_delivered_not_prevalidated() -> TestResult
{
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(PEER_MESH_TOPIC_STR).await?;
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let announce = PeerMeshAnnounce {
            peer_id: peer_id.to_base58(),
            listen_addrs: vec![make_multiaddr(4094u16)?.to_string()],
            wallet: Some("not-a-wallet".to_string()),
            timestamp_unix: TEST_TIMESTAMP,
        };

        Broadcaster::new(&mut sender.swarm)
            .send_peer_mesh_announce(&announce)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, PEER_MESH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::PeerMeshAnnounce(received) => {
                assert!(received.normalize().is_err());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_95_008_broadcast_live_invalid_register_node_is_delivered_not_prevalidated() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REGISTER_TOPIC_STR).await?;
        let mut reg = register_tx()?;

        let first = reg
            .wallet_address
            .get_mut(0usize)
            .ok_or_else(|| "missing first wallet byte".to_string())?;
        *first = b'x';

        Broadcaster::new(&mut sender.swarm)
            .send_register_node(&reg)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, REGISTER_TOPIC_STR).await?;

        match msg {
            RemzarMessage::RegisterNode(received) => {
                assert!(received.validate().is_err());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_96_008_broadcast_live_invalid_reward_zero_amount_is_delivered_not_prevalidated() -> TestResult
{
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(REWARD_TOPIC_STR).await?;
        let mut reward = reward_tx(96u64)?;
        reward.amount = 0u64;

        Broadcaster::new(&mut sender.swarm)
            .send_reward_tx(&reward)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, REWARD_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Reward(received) => {
                assert_eq!(received.amount, 0u64);
                assert!(received.validate().is_err());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_97_008_broadcast_live_invalid_transaction_zero_amount_is_delivered_not_prevalidated()
-> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let mut tx = transfer_tx(97u64)?;
        tx.amount = 0u64;

        Broadcaster::new(&mut sender.swarm)
            .send_transaction(&tx)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

        match msg {
            RemzarMessage::Transaction(received) => {
                assert_eq!(received.amount, 0u64);
                assert!(received.validate().is_err());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_98_008_broadcast_live_batch_with_invalid_txkind_is_delivered_not_prevalidated() -> TestResult
{
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TXBATCH_TOPIC_STR).await?;
        let mut tx = transfer_tx(98u64)?;
        tx.amount = 0u64;

        let batch = TransactionBatch::new(98u64, TEST_TIMESTAMP, vec![TxKind::Transfer(tx)])
            .map_err(fmt_err)?;

        Broadcaster::new(&mut sender.swarm)
            .send_tx_batch(&batch)
            .map_err(fmt_err)?;

        let msg = wait_for_remzar_message(&mut sender, &mut receiver, TXBATCH_TOPIC_STR).await?;

        match msg {
            RemzarMessage::TxBatch(received) => {
                let first_kind = received
                    .transactions
                    .first()
                    .ok_or_else(|| "missing first txkind in received batch".to_string())?;

                assert!(first_kind.validate().is_err());
                Ok(())
            }
            other => Err(format!("unexpected message kind {}", other.kind_str())),
        }
    })
}

#[test]
fn p2p_99_008_broadcast_live_ten_transaction_broadcasts_deliver_in_order_amounts() -> TestResult {
    run_async(async {
        let (mut sender, mut receiver) = setup_live_pair(TX_TOPIC_STR).await?;
        let mut received_count = 0usize;

        for amount in 1u64..=10u64 {
            let tx = transfer_tx(amount)?;

            Broadcaster::new(&mut sender.swarm)
                .send_transaction(&tx)
                .map_err(fmt_err)?;

            let msg = wait_for_remzar_message(&mut sender, &mut receiver, TX_TOPIC_STR).await?;

            match msg {
                RemzarMessage::Transaction(received) => {
                    assert_eq!(received.amount, amount);
                }
                other => return Err(format!("unexpected message kind {}", other.kind_str())),
            }

            received_count = received_count
                .checked_add(1usize)
                .ok_or_else(|| "ten transaction receive counter overflow".to_string())?;
        }

        assert_eq!(received_count, 10usize);
        Ok(())
    })
}

#[test]
fn p2p_100_008_broadcast_final_vector_all_payload_encoders_are_stable_and_capped() -> TestResult {
    let chat = p2p_008_chat_message_to_wallet("final vector", third_wallet())?;
    let file = p2p_008_file_chunk_to_wallet(
        b"final vector file".to_vec(),
        third_wallet(),
        "final.txt".to_string(),
        0u32,
        1u32,
    )?;

    let remzar_messages = vec![
        RemzarMessage::Transaction(
            Transaction::new(genesis_wallet(), third_wallet(), 100u64).map_err(fmt_err)?,
        ),
        RemzarMessage::TxKind(TxKind::Transfer(
            Transaction::new(genesis_wallet(), third_wallet(), 101u64).map_err(fmt_err)?,
        )),
        RemzarMessage::RegisterNode(RegisterNodeTx::new(third_wallet()).map_err(fmt_err)?),
        RemzarMessage::Reward(
            RewardTx::new(third_wallet(), UNIT_DIVISOR, 100u64).map_err(fmt_err)?,
        ),
        RemzarMessage::TxBatch(tx_batch()?),
        RemzarMessage::Block(Box::new(block(100u64)?)),
        RemzarMessage::PorPuzzleProof(por_proof(100u64)),
        RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(4100u16)?),
    ];

    for message in remzar_messages {
        let first = message.encode_to_wire().map_err(fmt_err)?;
        let second = message.encode_to_wire().map_err(fmt_err)?;

        assert_eq!(first, second);
        assert!(!first.is_empty());
        assert!(first.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);
    }

    let chat_first = chat.encode_wire().map_err(fmt_err)?;
    let chat_second = chat.encode_wire().map_err(fmt_err)?;
    assert_eq!(chat_first, chat_second);
    assert!(ChatMessage::decode_wire(&chat_first).is_ok());

    let file_first = postcard::to_allocvec(&file).map_err(fmt_err)?;
    let file_second = postcard::to_allocvec(&file).map_err(fmt_err)?;
    assert_eq!(file_first, file_second);
    assert!(postcard::from_bytes::<FileChunkMessage>(&file_first).is_ok());

    Ok(())
}
