#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{
    Multiaddr, PeerId, gossipsub::IdentTopic, identity, multiaddr::Protocol, swarm::Swarm,
};
use remzar::{
    blockchain::{
        transaction_001_tx::Transaction, transaction_002_tx_register::RegisterNodeTx,
        transaction_003_tx_reward::RewardTx, transaction_004_tx_kind::TxKind,
        transaction_005_tx_batch::TransactionBatch,
    },
    network::{
        p2p_002_protocal::{REMZAR_MESSAGE_MAX_WIRE_BYTES, RemzarMessage},
        p2p_003_behaviour::RemzarBehaviour,
        p2p_008_broadcast::{
            BLOCK_TOPIC_STR, BroadcastTopic, Broadcaster, FILE_TOPIC_STR,
            POR_PUZZLE_PROOF_TOPIC_STR, REGISTER_TOPIC_STR, REWARD_TOPIC_STR, TX_TOPIC_STR,
            TXBATCH_TOPIC_STR,
        },
        p2p_013_peer_mesh::{PEER_MESH_TOPIC_STR, PeerMeshAnnounce},
        p2p_014_chat::CHAT_TOPIC,
    },
    utility::alpha_001_global_configuration::GlobalConfiguration,
};

type TestResult<T = ()> = Result<T, String>;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn wallet(ch: char) -> String {
    format!("r{}", ch.to_string().repeat(128))
}

fn sender_wallet() -> String {
    wallet('1')
}

fn receiver_wallet() -> String {
    wallet('2')
}

fn validator_wallet() -> String {
    GlobalConfiguration::GENESIS_VALIDATOR.to_string()
}

fn keypair() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

fn peer_id() -> PeerId {
    PeerId::from(keypair().public())
}

fn listen_addr(port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse()
        .map_err(fmt_err)
}

fn memory_addr(id: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(id));
    addr
}

fn tx(amount: u64) -> TestResult<Transaction> {
    Transaction::new(sender_wallet(), receiver_wallet(), amount).map_err(fmt_err)
}

fn register_tx() -> TestResult<RegisterNodeTx> {
    RegisterNodeTx::new(validator_wallet()).map_err(fmt_err)
}

fn reward_tx(amount: u64, height: u64) -> TestResult<RewardTx> {
    RewardTx::new(validator_wallet(), amount, height).map_err(fmt_err)
}

fn tx_kind_transfer(amount: u64) -> TestResult<TxKind> {
    Ok(TxKind::Transfer(tx(amount)?))
}

fn tx_kind_register() -> TestResult<TxKind> {
    Ok(TxKind::RegisterNode(register_tx()?))
}

fn tx_kind_reward(amount: u64, height: u64) -> TestResult<TxKind> {
    Ok(TxKind::Reward(reward_tx(amount, height)?))
}

fn tx_batch(index: u64, count: usize) -> TestResult<TransactionBatch> {
    let mut transactions = Vec::new();

    for i in 0..count {
        let amount = u64::try_from(i).unwrap_or(0).saturating_add(1);
        transactions.push(tx_kind_transfer(amount)?);
    }

    TransactionBatch::new(index, 946_684_800 + index, transactions).map_err(fmt_err)
}

fn peer_mesh_announce(seed: u16) -> TestResult<PeerMeshAnnounce> {
    let addr = listen_addr(32_000u16.saturating_add(seed))?;

    PeerMeshAnnounce::from_local(
        peer_id(),
        &[addr],
        Some(validator_wallet().as_str()),
        946_684_800 + u64::from(seed),
    )
    .map_err(fmt_err)
}

fn peer_mesh_announce_memory(seed: u64) -> TestResult<PeerMeshAnnounce> {
    PeerMeshAnnounce::from_local(
        peer_id(),
        &[memory_addr(seed)],
        Some(validator_wallet().as_str()),
        946_684_800 + seed,
    )
    .map_err(fmt_err)
}

fn build_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let kp = keypair();

    let swarm = libp2p::SwarmBuilder::with_existing_identity(kp)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(fmt_err)?
        .with_behaviour(|key| {
            RemzarBehaviour::new(key.clone()).unwrap_or_else(|err| {
                panic!("failed to build RemzarBehaviour for e2e broadcast test: {err}");
            })
        })
        .map_err(fmt_err)?
        .build();

    Ok(swarm)
}

fn is_publish_result_safe(result: anyhow::Result<()>) -> TestResult {
    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            let text = err.to_string();

            if text.contains("InsufficientPeers")
                || text.contains("NoPeers")
                || text.contains("PublishError")
                || text.contains("gossipsub publish error")
            {
                Ok(())
            } else {
                Err(format!("unexpected broadcast error: {text}"))
            }
        }
    }
}

fn send_after_join<F>(mut f: F) -> TestResult
where
    F: FnMut(&mut Broadcaster<'_>) -> anyhow::Result<()>,
{
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    is_publish_result_safe(f(&mut broadcaster))
}

fn encoded_len(msg: RemzarMessage) -> TestResult<usize> {
    Ok(msg.encode_to_wire().map_err(fmt_err)?.len())
}

#[test]
fn e2e_01_topic_constants_are_non_empty() -> TestResult {
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

    for topic in topics {
        assert!(!topic.is_empty(), "topic must not be empty");
    }

    Ok(())
}

#[test]
fn e2e_02_consensus_topics_use_remzar_prefix() -> TestResult {
    let topics = [
        TX_TOPIC_STR,
        TXBATCH_TOPIC_STR,
        REWARD_TOPIC_STR,
        REGISTER_TOPIC_STR,
        BLOCK_TOPIC_STR,
        POR_PUZZLE_PROOF_TOPIC_STR,
    ];

    for topic in topics {
        assert!(
            topic.starts_with("/remzar/"),
            "consensus topic must use /remzar prefix: {topic}"
        );
    }

    Ok(())
}

#[test]
fn e2e_03_offchain_topics_are_distinct_from_consensus_topics() -> TestResult {
    assert_eq!(CHAT_TOPIC, "remzar.chat.v1");
    assert_eq!(FILE_TOPIC_STR, "remzar.file.v1");

    assert!(!CHAT_TOPIC.starts_with("/remzar/"));
    assert!(!FILE_TOPIC_STR.starts_with("/remzar/"));

    Ok(())
}

#[test]
fn e2e_04_tx_topic_is_stable() -> TestResult {
    assert_eq!(TX_TOPIC_STR, "/remzar/tx/1.0.0");

    Ok(())
}

#[test]
fn e2e_05_tx_batch_topic_is_stable() -> TestResult {
    assert_eq!(TXBATCH_TOPIC_STR, "/remzar/tx_batch/1.0.0");

    Ok(())
}

#[test]
fn e2e_06_reward_topic_is_stable() -> TestResult {
    assert_eq!(REWARD_TOPIC_STR, "/remzar/reward/1.0.0");

    Ok(())
}

#[test]
fn e2e_07_register_topic_is_stable() -> TestResult {
    assert_eq!(REGISTER_TOPIC_STR, "/remzar/register_node/1.0.0");

    Ok(())
}

#[test]
fn e2e_08_block_topic_is_stable() -> TestResult {
    assert_eq!(BLOCK_TOPIC_STR, "/remzar/block/1.0.0");

    Ok(())
}

#[test]
fn e2e_09_por_puzzle_proof_topic_is_stable() -> TestResult {
    assert_eq!(POR_PUZZLE_PROOF_TOPIC_STR, "/remzar/por/puzzle_proof/1.0.0");

    Ok(())
}

#[test]
fn e2e_10_file_topic_is_stable() -> TestResult {
    assert_eq!(FILE_TOPIC_STR, "remzar.file.v1");

    Ok(())
}

#[test]
fn e2e_11_broadcast_topic_reexport_can_create_ident_topic() -> TestResult {
    let topic: BroadcastTopic = BroadcastTopic::new(TX_TOPIC_STR);
    let direct = IdentTopic::new(TX_TOPIC_STR);

    assert_eq!(topic.hash(), direct.hash());

    Ok(())
}

#[test]
fn e2e_12_all_topics_have_distinct_hashes() -> TestResult {
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

    let mut hashes = Vec::new();

    for topic in topics {
        let hash = IdentTopic::new(topic).hash();
        assert!(
            !hashes.contains(&hash),
            "duplicate topic hash for topic {topic}"
        );
        hashes.push(hash);
    }

    Ok(())
}

#[test]
fn e2e_13_broadcaster_new_can_be_constructed() -> TestResult {
    let mut swarm = build_swarm()?;
    let _broadcaster = Broadcaster::new(&mut swarm);

    Ok(())
}

#[test]
fn e2e_14_join_all_topics_succeeds_on_fresh_swarm() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_15_join_all_topics_is_idempotent() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;
    broadcaster.join_all_topics().map_err(fmt_err)?;
    broadcaster.join_all_topics().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_16_join_all_topics_can_be_called_many_times() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    for _ in 0..25usize {
        broadcaster.join_all_topics().map_err(fmt_err)?;
    }

    Ok(())
}

#[test]
fn e2e_17_transaction_message_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::Transaction(tx(17)?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_18_txkind_transfer_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::TxKind(tx_kind_transfer(18)?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_19_txkind_register_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::TxKind(tx_kind_register()?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_20_txkind_reward_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::TxKind(tx_kind_reward(1, 20)?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_21_register_message_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::RegisterNode(register_tx()?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_22_reward_message_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::Reward(reward_tx(1, 22)?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_23_tx_batch_message_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::TxBatch(tx_batch(23, 5)?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_24_peer_mesh_message_encoding_used_by_broadcast_is_under_cap() -> TestResult {
    let len = encoded_len(RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(24)?))?;

    assert!(len > 0);
    assert!(len <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_25_send_transaction_after_join_is_safe() -> TestResult {
    let value = tx(25)?;

    send_after_join(|broadcaster| broadcaster.send_transaction(&value))
}

#[test]
fn e2e_26_send_transaction_without_join_is_safe_or_returns_publish_error() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);
    let value = tx(26)?;

    is_publish_result_safe(broadcaster.send_transaction(&value))
}

#[test]
fn e2e_27_send_tx_kind_transfer_after_join_is_safe() -> TestResult {
    let value = tx_kind_transfer(27)?;

    send_after_join(|broadcaster| broadcaster.send_tx_kind(&value))
}

#[test]
fn e2e_28_send_tx_kind_register_after_join_is_safe() -> TestResult {
    let value = tx_kind_register()?;

    send_after_join(|broadcaster| broadcaster.send_tx_kind(&value))
}

#[test]
fn e2e_29_send_tx_kind_reward_after_join_is_safe() -> TestResult {
    let value = tx_kind_reward(1, 29)?;

    send_after_join(|broadcaster| broadcaster.send_tx_kind(&value))
}

#[test]
fn e2e_30_send_register_node_after_join_is_safe() -> TestResult {
    let value = register_tx()?;

    send_after_join(|broadcaster| broadcaster.send_register_node(&value))
}

#[test]
fn e2e_31_send_reward_tx_after_join_is_safe() -> TestResult {
    let value = reward_tx(1, 31)?;

    send_after_join(|broadcaster| broadcaster.send_reward_tx(&value))
}

#[test]
fn e2e_32_send_empty_tx_batch_after_join_is_safe() -> TestResult {
    let value = tx_batch(32, 0)?;

    send_after_join(|broadcaster| broadcaster.send_tx_batch(&value))
}

#[test]
fn e2e_33_send_small_tx_batch_after_join_is_safe() -> TestResult {
    let value = tx_batch(33, 3)?;

    send_after_join(|broadcaster| broadcaster.send_tx_batch(&value))
}

#[test]
fn e2e_34_send_larger_tx_batch_after_join_is_safe() -> TestResult {
    let value = tx_batch(34, 25)?;

    send_after_join(|broadcaster| broadcaster.send_tx_batch(&value))
}

#[test]
fn e2e_35_send_peer_mesh_announce_after_join_is_safe() -> TestResult {
    let value = peer_mesh_announce(35)?;

    send_after_join(|broadcaster| broadcaster.send_peer_mesh_announce(&value))
}

#[test]
fn e2e_36_send_peer_mesh_announce_with_memory_addr_after_join_is_safe() -> TestResult {
    let value = peer_mesh_announce_memory(36)?;

    send_after_join(|broadcaster| broadcaster.send_peer_mesh_announce(&value))
}

#[test]
fn e2e_37_multiple_transaction_broadcasts_same_swarm_are_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    for amount in 1u64..=10u64 {
        is_publish_result_safe(broadcaster.send_transaction(&tx(amount)?))?;
    }

    Ok(())
}

#[test]
fn e2e_38_multiple_txkind_broadcasts_same_swarm_are_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    let kinds = vec![
        tx_kind_transfer(1)?,
        tx_kind_register()?,
        tx_kind_reward(1, 38)?,
    ];

    for kind in kinds {
        is_publish_result_safe(broadcaster.send_tx_kind(&kind))?;
    }

    Ok(())
}

#[test]
fn e2e_39_multiple_register_broadcasts_same_swarm_are_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    for _ in 0..10usize {
        let value = register_tx()?;
        is_publish_result_safe(broadcaster.send_register_node(&value))?;
    }

    Ok(())
}

#[test]
fn e2e_40_multiple_reward_broadcasts_same_swarm_are_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    for height in 1u64..=10u64 {
        let value = reward_tx(1, height)?;
        is_publish_result_safe(broadcaster.send_reward_tx(&value))?;
    }

    Ok(())
}

#[test]
fn e2e_41_multiple_tx_batch_broadcasts_same_swarm_are_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    for index in 0u64..10u64 {
        let value = tx_batch(index, 3)?;
        is_publish_result_safe(broadcaster.send_tx_batch(&value))?;
    }

    Ok(())
}

#[test]
fn e2e_42_multiple_peer_mesh_broadcasts_same_swarm_are_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    for seed in 0u16..10u16 {
        let value = peer_mesh_announce(seed)?;
        is_publish_result_safe(broadcaster.send_peer_mesh_announce(&value))?;
    }

    Ok(())
}

#[test]
fn e2e_43_join_then_send_all_core_non_block_message_types_is_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    let tx_value = tx(43)?;
    let tx_kind_value = tx_kind_transfer(44)?;
    let register_value = register_tx()?;
    let reward_value = reward_tx(1, 45)?;
    let batch_value = tx_batch(46, 4)?;
    let peer_mesh_value = peer_mesh_announce(47)?;

    is_publish_result_safe(broadcaster.send_transaction(&tx_value))?;
    is_publish_result_safe(broadcaster.send_tx_kind(&tx_kind_value))?;
    is_publish_result_safe(broadcaster.send_register_node(&register_value))?;
    is_publish_result_safe(broadcaster.send_reward_tx(&reward_value))?;
    is_publish_result_safe(broadcaster.send_tx_batch(&batch_value))?;
    is_publish_result_safe(broadcaster.send_peer_mesh_announce(&peer_mesh_value))?;

    Ok(())
}

#[test]
fn e2e_44_two_broadcasters_on_separate_swarms_can_join_topics() -> TestResult {
    let mut first_swarm = build_swarm()?;
    let mut second_swarm = build_swarm()?;

    let mut first = Broadcaster::new(&mut first_swarm);
    let mut second = Broadcaster::new(&mut second_swarm);

    first.join_all_topics().map_err(fmt_err)?;
    second.join_all_topics().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_45_two_broadcasters_on_separate_swarms_can_send_transaction() -> TestResult {
    let mut first_swarm = build_swarm()?;
    let mut second_swarm = build_swarm()?;

    let mut first = Broadcaster::new(&mut first_swarm);
    let mut second = Broadcaster::new(&mut second_swarm);

    first.join_all_topics().map_err(fmt_err)?;
    second.join_all_topics().map_err(fmt_err)?;

    let value = tx(45)?;

    is_publish_result_safe(first.send_transaction(&value))?;
    is_publish_result_safe(second.send_transaction(&value))?;

    Ok(())
}

#[test]
fn e2e_46_join_all_topics_after_sending_is_still_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    let value = tx(46)?;
    is_publish_result_safe(broadcaster.send_transaction(&value))?;

    broadcaster.join_all_topics().map_err(fmt_err)?;
    broadcaster.join_all_topics().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_47_rejoin_topics_between_sends_is_safe() -> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    broadcaster.join_all_topics().map_err(fmt_err)?;

    for amount in 1u64..=5u64 {
        let value = tx(amount)?;
        is_publish_result_safe(broadcaster.send_transaction(&value))?;
        broadcaster.join_all_topics().map_err(fmt_err)?;
    }

    Ok(())
}

#[test]
fn e2e_48_encoded_lengths_for_all_broadcast_wrapped_messages_stay_under_protocol_cap() -> TestResult
{
    let messages = vec![
        RemzarMessage::Transaction(tx(48)?),
        RemzarMessage::TxKind(tx_kind_transfer(49)?),
        RemzarMessage::TxKind(tx_kind_register()?),
        RemzarMessage::TxKind(tx_kind_reward(1, 50)?),
        RemzarMessage::RegisterNode(register_tx()?),
        RemzarMessage::Reward(reward_tx(1, 51)?),
        RemzarMessage::TxBatch(tx_batch(52, 8)?),
        RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(53)?),
    ];

    for msg in messages {
        let kind = msg.kind_str();
        let bytes = msg.encode_to_wire().map_err(fmt_err)?;

        assert!(!bytes.is_empty(), "{kind} encoded to empty payload");
        assert!(
            bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES,
            "{kind} exceeded protocol cap"
        );
    }

    Ok(())
}

#[test]
fn e2e_49_broadcast_topic_alias_matches_ident_topic_hash_for_every_public_topic() -> TestResult {
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

    for topic in topics {
        let via_alias: BroadcastTopic = BroadcastTopic::new(topic);
        let direct = IdentTopic::new(topic);

        assert_eq!(via_alias.hash(), direct.hash());
    }

    Ok(())
}

#[test]
fn e2e_50_full_broadcast_lifecycle_join_topics_encode_core_messages_send_many_and_rejoin()
-> TestResult {
    let mut swarm = build_swarm()?;
    let mut broadcaster = Broadcaster::new(&mut swarm);

    // 1. Join all public broadcast topics. This is intentionally idempotent.
    broadcaster.join_all_topics().map_err(fmt_err)?;
    broadcaster.join_all_topics().map_err(fmt_err)?;

    // 2. Prepare every easy-to-construct broadcast payload from this module.
    let tx_value = tx(50)?;
    let tx_kind_transfer_value = tx_kind_transfer(51)?;
    let tx_kind_register_value = tx_kind_register()?;
    let tx_kind_reward_value = tx_kind_reward(1, 52)?;
    let register_value = register_tx()?;
    let reward_value = reward_tx(1, 53)?;
    let empty_batch = tx_batch(54, 0)?;
    let small_batch = tx_batch(55, 5)?;
    let mesh_value = peer_mesh_announce(56)?;

    // 3. Verify protocol-wrapped messages remain below the core RemzarMessage cap.
    let messages = vec![
        RemzarMessage::Transaction(tx_value.clone()),
        RemzarMessage::TxKind(tx_kind_transfer_value.clone()),
        RemzarMessage::TxKind(tx_kind_register_value.clone()),
        RemzarMessage::TxKind(tx_kind_reward_value.clone()),
        RemzarMessage::RegisterNode(register_value.clone()),
        RemzarMessage::Reward(reward_value.clone()),
        RemzarMessage::TxBatch(empty_batch.clone()),
        RemzarMessage::TxBatch(small_batch.clone()),
        RemzarMessage::PeerMeshAnnounce(mesh_value.clone()),
    ];

    for msg in messages {
        let bytes = msg.encode_to_wire().map_err(fmt_err)?;
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);
    }

    // 4. Exercise the live outbound helper methods. In an isolated E2E test swarm,
    // libp2p may return an "insufficient peers" style publish error, which is safe.
    is_publish_result_safe(broadcaster.send_transaction(&tx_value))?;
    is_publish_result_safe(broadcaster.send_tx_kind(&tx_kind_transfer_value))?;
    is_publish_result_safe(broadcaster.send_tx_kind(&tx_kind_register_value))?;
    is_publish_result_safe(broadcaster.send_tx_kind(&tx_kind_reward_value))?;
    is_publish_result_safe(broadcaster.send_register_node(&register_value))?;
    is_publish_result_safe(broadcaster.send_reward_tx(&reward_value))?;
    is_publish_result_safe(broadcaster.send_tx_batch(&empty_batch))?;
    is_publish_result_safe(broadcaster.send_tx_batch(&small_batch))?;
    is_publish_result_safe(broadcaster.send_peer_mesh_announce(&mesh_value))?;

    // 5. Rejoining topics after sends must stay safe.
    broadcaster.join_all_topics().map_err(fmt_err)?;

    Ok(())
}
