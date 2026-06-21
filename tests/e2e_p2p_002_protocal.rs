#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{Multiaddr, PeerId, identity};
use remzar::{
    blockchain::{
        transaction_001_tx::Transaction, transaction_002_tx_register::RegisterNodeTx,
        transaction_003_tx_reward::RewardTx, transaction_004_tx_kind::TxKind,
        transaction_005_tx_batch::TransactionBatch,
    },
    network::{
        p2p_002_protocal::{REMZAR_MESSAGE_MAX_WIRE_BYTES, RemzarMessage, RemzarMessageCodecError},
        p2p_013_peer_mesh::PeerMeshAnnounce,
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

fn peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn listen_addr(port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse()
        .map_err(fmt_err)
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

fn encode_decode(msg: RemzarMessage) -> TestResult<RemzarMessage> {
    let bytes = msg.encode_to_wire().map_err(fmt_err)?;
    RemzarMessage::decode_from_wire(&bytes).map_err(fmt_err)
}

fn assert_same_kind_after_roundtrip(msg: RemzarMessage) -> TestResult {
    let expected_kind = msg.kind_str();
    let decoded = encode_decode(msg)?;

    assert_eq!(decoded.kind_str(), expected_kind);

    Ok(())
}

fn assert_too_large(err: RemzarMessageCodecError, got: usize) {
    match err {
        RemzarMessageCodecError::TooLarge { got: actual, max } => {
            assert_eq!(actual, got);
            assert_eq!(max, REMZAR_MESSAGE_MAX_WIRE_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

fn malformed_payload(seed: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for idx in 0..len {
        let i = u8::try_from(idx % 251).unwrap_or(0);
        out.push(seed.wrapping_add(i.rotate_left(u32::from(seed % 7))));
    }

    out
}

#[test]
fn e2e_01_wire_limit_is_exactly_one_mib() -> TestResult {
    assert_eq!(REMZAR_MESSAGE_MAX_WIRE_BYTES, 1024 * 1024);

    Ok(())
}

#[test]
fn e2e_02_transaction_kind_str_is_stable() -> TestResult {
    let msg = RemzarMessage::Transaction(tx(2)?);

    assert_eq!(msg.kind_str(), "Transaction");

    Ok(())
}

#[test]
fn e2e_03_txkind_kind_str_is_stable() -> TestResult {
    let msg = RemzarMessage::TxKind(tx_kind_transfer(3)?);

    assert_eq!(msg.kind_str(), "TxKind");

    Ok(())
}

#[test]
fn e2e_04_register_node_kind_str_is_stable() -> TestResult {
    let msg = RemzarMessage::RegisterNode(register_tx()?);

    assert_eq!(msg.kind_str(), "RegisterNode");

    Ok(())
}

#[test]
fn e2e_05_reward_kind_str_is_stable() -> TestResult {
    let msg = RemzarMessage::Reward(reward_tx(1, 5)?);

    assert_eq!(msg.kind_str(), "Reward");

    Ok(())
}

#[test]
fn e2e_06_txbatch_kind_str_is_stable() -> TestResult {
    let msg = RemzarMessage::TxBatch(tx_batch(6, 2)?);

    assert_eq!(msg.kind_str(), "TxBatch");

    Ok(())
}

#[test]
fn e2e_07_peer_mesh_kind_str_is_stable() -> TestResult {
    let msg = RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(7)?);

    assert_eq!(msg.kind_str(), "PeerMeshAnnounce");

    Ok(())
}

#[test]
fn e2e_08_transaction_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::Transaction(tx(8)?))
}

#[test]
fn e2e_09_txkind_transfer_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::TxKind(tx_kind_transfer(9)?))
}

#[test]
fn e2e_10_txkind_register_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::TxKind(tx_kind_register()?))
}

#[test]
fn e2e_11_txkind_reward_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::TxKind(tx_kind_reward(1, 11)?))
}

#[test]
fn e2e_12_register_node_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::RegisterNode(register_tx()?))
}

#[test]
fn e2e_13_reward_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::Reward(reward_tx(1, 13)?))
}

#[test]
fn e2e_14_empty_txbatch_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::TxBatch(tx_batch(14, 0)?))
}

#[test]
fn e2e_15_small_txbatch_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::TxBatch(tx_batch(15, 3)?))
}

#[test]
fn e2e_16_peer_mesh_roundtrip_preserves_kind() -> TestResult {
    assert_same_kind_after_roundtrip(RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(16)?))
}

#[test]
fn e2e_17_transaction_roundtrip_preserves_wire_bytes_canonically() -> TestResult {
    let msg = RemzarMessage::Transaction(tx(17)?);

    let first = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&first).map_err(fmt_err)?;
    let second = decoded.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn e2e_18_register_roundtrip_preserves_wire_bytes_canonically() -> TestResult {
    let msg = RemzarMessage::RegisterNode(register_tx()?);

    let first = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&first).map_err(fmt_err)?;
    let second = decoded.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn e2e_19_reward_roundtrip_preserves_wire_bytes_canonically() -> TestResult {
    let msg = RemzarMessage::Reward(reward_tx(1, 19)?);

    let first = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&first).map_err(fmt_err)?;
    let second = decoded.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn e2e_20_txbatch_roundtrip_preserves_wire_bytes_canonically() -> TestResult {
    let msg = RemzarMessage::TxBatch(tx_batch(20, 5)?);

    let first = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&first).map_err(fmt_err)?;
    let second = decoded.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn e2e_21_peer_mesh_roundtrip_preserves_wire_bytes_canonically() -> TestResult {
    let msg = RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(21)?);

    let first = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&first).map_err(fmt_err)?;
    let second = decoded.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn e2e_22_encode_transaction_is_non_empty_and_under_limit() -> TestResult {
    let bytes = RemzarMessage::Transaction(tx(22)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());
    assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_23_encode_register_is_non_empty_and_under_limit() -> TestResult {
    let bytes = RemzarMessage::RegisterNode(register_tx()?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());
    assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_24_encode_reward_is_non_empty_and_under_limit() -> TestResult {
    let bytes = RemzarMessage::Reward(reward_tx(1, 24)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());
    assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_25_encode_txbatch_is_non_empty_and_under_limit() -> TestResult {
    let bytes = RemzarMessage::TxBatch(tx_batch(25, 8)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());
    assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_26_encode_peer_mesh_is_non_empty_and_under_limit() -> TestResult {
    let bytes = RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(26)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());
    assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_27_decode_empty_payload_returns_decode_error() -> TestResult {
    let err = RemzarMessage::decode_from_wire(&[]).expect_err("empty payload must fail");

    match err {
        RemzarMessageCodecError::Decode(_) => {}
        other => return Err(format!("expected Decode error, got {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_28_decode_single_invalid_byte_returns_decode_error() -> TestResult {
    let err = RemzarMessage::decode_from_wire(&[0xff]).expect_err("invalid payload must fail");

    match err {
        RemzarMessageCodecError::Decode(_) => {}
        other => return Err(format!("expected Decode error, got {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_29_decode_random_small_payload_returns_decode_error() -> TestResult {
    let bytes = malformed_payload(29, 64);

    let err =
        RemzarMessage::decode_from_wire(&bytes).expect_err("random malformed payload must fail");

    match err {
        RemzarMessageCodecError::Decode(_) => {}
        other => return Err(format!("expected Decode error, got {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_30_decode_random_medium_payload_returns_decode_error() -> TestResult {
    let bytes = malformed_payload(30, 4096);

    let err =
        RemzarMessage::decode_from_wire(&bytes).expect_err("random malformed payload must fail");

    match err {
        RemzarMessageCodecError::Decode(_) => {}
        other => return Err(format!("expected Decode error, got {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_31_decode_oversized_payload_is_rejected_before_decode() -> TestResult {
    let bytes = vec![0u8; REMZAR_MESSAGE_MAX_WIRE_BYTES + 1];

    let err = RemzarMessage::decode_from_wire(&bytes)
        .expect_err("oversized payload must fail before decode");

    assert_too_large(err, REMZAR_MESSAGE_MAX_WIRE_BYTES + 1);

    Ok(())
}

#[test]
fn e2e_32_decode_exact_limit_payload_reaches_decode_path() -> TestResult {
    let mut bytes = vec![0u8; REMZAR_MESSAGE_MAX_WIRE_BYTES];

    bytes[0] = 8;

    let err = RemzarMessage::decode_from_wire(&bytes)
        .expect_err("exact-limit invalid enum tag should fail as Decode, not TooLarge");

    match err {
        RemzarMessageCodecError::Decode(_) => {}
        other => {
            return Err(format!(
                "expected Decode error at exact limit, got {other:?}"
            ));
        }
    }

    Ok(())
}

#[test]
fn e2e_33_decode_one_byte_under_limit_reaches_decode_path() -> TestResult {
    let mut bytes = vec![0u8; REMZAR_MESSAGE_MAX_WIRE_BYTES - 1];

    bytes[0] = 8;

    let err = RemzarMessage::decode_from_wire(&bytes)
        .expect_err("under-limit invalid enum tag should fail as Decode, not TooLarge");

    match err {
        RemzarMessageCodecError::Decode(_) => {}
        other => return Err(format!("expected Decode error under limit, got {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_34_codec_error_display_too_large_is_stable() -> TestResult {
    let err = RemzarMessageCodecError::TooLarge {
        got: REMZAR_MESSAGE_MAX_WIRE_BYTES + 99,
        max: REMZAR_MESSAGE_MAX_WIRE_BYTES,
    };

    let text = err.to_string();

    assert!(text.contains("wire message too large"));
    assert!(text.contains(&(REMZAR_MESSAGE_MAX_WIRE_BYTES + 99).to_string()));
    assert!(text.contains(&REMZAR_MESSAGE_MAX_WIRE_BYTES.to_string()));

    Ok(())
}

#[test]
fn e2e_35_codec_error_debug_too_large_mentions_variant() -> TestResult {
    let err = RemzarMessageCodecError::TooLarge { got: 123, max: 100 };

    let text = format!("{err:?}");

    assert!(text.contains("TooLarge"));
    assert!(text.contains("got"));
    assert!(text.contains("max"));

    Ok(())
}

#[test]
fn e2e_36_decode_error_display_mentions_postcard() -> TestResult {
    let err = RemzarMessage::decode_from_wire(&[0xfe, 0xed, 0xfa, 0xce])
        .expect_err("malformed payload must fail");

    let text = err.to_string();

    assert!(text.contains("postcard decode failed"));

    Ok(())
}

#[test]
fn e2e_37_clone_transaction_message_preserves_kind() -> TestResult {
    let msg = RemzarMessage::Transaction(tx(37)?);
    let cloned = msg.clone();

    assert_eq!(cloned.kind_str(), msg.kind_str());

    Ok(())
}

#[test]
fn e2e_38_clone_register_message_preserves_kind() -> TestResult {
    let msg = RemzarMessage::RegisterNode(register_tx()?);
    let cloned = msg.clone();

    assert_eq!(cloned.kind_str(), msg.kind_str());

    Ok(())
}

#[test]
fn e2e_39_clone_reward_message_preserves_kind() -> TestResult {
    let msg = RemzarMessage::Reward(reward_tx(1, 39)?);
    let cloned = msg.clone();

    assert_eq!(cloned.kind_str(), msg.kind_str());

    Ok(())
}

#[test]
fn e2e_40_clone_txbatch_message_preserves_kind() -> TestResult {
    let msg = RemzarMessage::TxBatch(tx_batch(40, 4)?);
    let cloned = msg.clone();

    assert_eq!(cloned.kind_str(), msg.kind_str());

    Ok(())
}

#[test]
fn e2e_41_clone_peer_mesh_message_preserves_kind() -> TestResult {
    let msg = RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(41)?);
    let cloned = msg.clone();

    assert_eq!(cloned.kind_str(), msg.kind_str());

    Ok(())
}

#[test]
fn e2e_42_debug_transaction_message_mentions_variant() -> TestResult {
    let msg = RemzarMessage::Transaction(tx(42)?);
    let text = format!("{msg:?}");

    assert!(text.contains("Transaction"));

    Ok(())
}

#[test]
fn e2e_43_debug_register_message_mentions_variant() -> TestResult {
    let msg = RemzarMessage::RegisterNode(register_tx()?);
    let text = format!("{msg:?}");

    assert!(text.contains("RegisterNode"));

    Ok(())
}

#[test]
fn e2e_44_debug_reward_message_mentions_variant() -> TestResult {
    let msg = RemzarMessage::Reward(reward_tx(1, 44)?);
    let text = format!("{msg:?}");

    assert!(text.contains("Reward"));

    Ok(())
}

#[test]
fn e2e_45_debug_txbatch_message_mentions_variant() -> TestResult {
    let msg = RemzarMessage::TxBatch(tx_batch(45, 2)?);
    let text = format!("{msg:?}");

    assert!(text.contains("TxBatch"));

    Ok(())
}

#[test]
fn e2e_46_debug_peer_mesh_message_mentions_variant() -> TestResult {
    let msg = RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(46)?);
    let text = format!("{msg:?}");

    assert!(text.contains("PeerMeshAnnounce"));

    Ok(())
}

#[test]
fn e2e_47_many_transaction_messages_roundtrip_without_kind_drift() -> TestResult {
    for amount in 1u64..=25u64 {
        let decoded = encode_decode(RemzarMessage::Transaction(tx(amount)?))?;
        assert_eq!(decoded.kind_str(), "Transaction");
    }

    Ok(())
}

#[test]
fn e2e_48_many_reward_messages_roundtrip_without_kind_drift() -> TestResult {
    for height in 1u64..=25u64 {
        let decoded = encode_decode(RemzarMessage::Reward(reward_tx(1, height)?))?;
        assert_eq!(decoded.kind_str(), "Reward");
    }

    Ok(())
}

#[test]
fn e2e_49_many_txbatches_roundtrip_without_kind_drift() -> TestResult {
    for index in 0u64..10u64 {
        let decoded = encode_decode(RemzarMessage::TxBatch(tx_batch(index, 3)?))?;
        assert_eq!(decoded.kind_str(), "TxBatch");
    }

    Ok(())
}

#[test]
fn e2e_50_full_protocol_lifecycle_encode_decode_limit_malformed_and_kind_classification()
-> TestResult {
    let messages = vec![
        RemzarMessage::Transaction(tx(50)?),
        RemzarMessage::TxKind(tx_kind_transfer(51)?),
        RemzarMessage::TxKind(tx_kind_register()?),
        RemzarMessage::TxKind(tx_kind_reward(1, 52)?),
        RemzarMessage::RegisterNode(register_tx()?),
        RemzarMessage::Reward(reward_tx(1, 53)?),
        RemzarMessage::TxBatch(tx_batch(54, 4)?),
        RemzarMessage::PeerMeshAnnounce(peer_mesh_announce(55)?),
    ];

    for msg in messages {
        let expected_kind = msg.kind_str();
        let bytes = msg.encode_to_wire().map_err(fmt_err)?;

        assert!(!bytes.is_empty());
        assert!(bytes.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        let decoded = RemzarMessage::decode_from_wire(&bytes).map_err(fmt_err)?;
        assert_eq!(decoded.kind_str(), expected_kind);

        let canonical = decoded.encode_to_wire().map_err(fmt_err)?;
        assert_eq!(canonical, bytes);
    }

    let malformed = malformed_payload(50, 128);
    let malformed_err =
        RemzarMessage::decode_from_wire(&malformed).expect_err("malformed payload must fail");

    match malformed_err {
        RemzarMessageCodecError::Decode(_) => {}
        other => return Err(format!("expected Decode error, got {other:?}")),
    }

    let oversized = vec![0u8; REMZAR_MESSAGE_MAX_WIRE_BYTES + 1];
    let oversized_err =
        RemzarMessage::decode_from_wire(&oversized).expect_err("oversized payload must fail");

    assert_too_large(oversized_err, REMZAR_MESSAGE_MAX_WIRE_BYTES + 1);

    Ok(())
}
