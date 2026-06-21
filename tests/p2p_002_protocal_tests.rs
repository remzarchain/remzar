#![cfg(test)]
#![deny(unsafe_code)]

use fips204::ml_dsa_65;
use libp2p::{Multiaddr, PeerId, identity};
use remzar::{
    blockchain::{
        block_001_metadata::BlockMetadata, block_002_blocks::Block,
        transaction_001_tx::Transaction, transaction_002_tx_register::RegisterNodeTx,
        transaction_003_tx_reward::RewardTx, transaction_004_tx_kind::TxKind,
        transaction_005_tx_batch::TransactionBatch,
    },
    consensus::por_004_puzzle_proof::PorPuzzleProof,
    network::{
        p2p_002_protocal::{REMZAR_MESSAGE_MAX_WIRE_BYTES, RemzarMessage, RemzarMessageCodecError},
        p2p_013_peer_mesh::PeerMeshAnnounce,
    },
    utility::{
        alpha_001_global_configuration::GlobalConfiguration,
        helper::{REMZAR_WALLET_LEN, UNIT_DIVISOR},
    },
};

type TestResult<T = ()> = Result<T, String>;

const TEST_TIMESTAMP: u64 = 1_700_000_000;
const FUZZ_SEED: u64 = 0xA5A5_5A5A_1234_5678;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn p2p_002_protocal_assert_trailing_garbage_decodes_same_kind(
    message: RemzarMessage,
) -> TestResult {
    let expected_kind = message.kind_str().to_string();
    let wire = message.encode_to_wire().map_err(fmt_err)?;
    let original_len = wire.len();

    let mut with_trailing = wire;
    with_trailing.push(0xAAu8);

    let decoded = RemzarMessage::decode_from_wire(&with_trailing).map_err(fmt_err)?;

    assert!(with_trailing.len() > original_len);
    assert_eq!(decoded.kind_str(), expected_kind);

    Ok(())
}

fn make_wallet(ch: char) -> String {
    let body = ch.to_string().repeat(128usize);
    format!("r{body}")
}

fn sender_wallet() -> String {
    make_wallet('1')
}

fn receiver_wallet() -> String {
    make_wallet('2')
}

fn validator_wallet() -> String {
    make_wallet('a')
}

fn alternate_wallet() -> String {
    make_wallet('b')
}

fn p2p_002_protocal_make_transfer_batch(count: usize) -> TestResult<TransactionBatch> {
    let mut transactions = Vec::new();

    for amount in 1u64..=u64::try_from(count).map_err(fmt_err)? {
        transactions.push(make_transfer_kind(amount)?);
    }

    TransactionBatch::new(10u64, TEST_TIMESTAMP, transactions).map_err(fmt_err)
}

fn p2p_002_protocal_wire_first_byte(message: &RemzarMessage) -> TestResult<u8> {
    let wire = message.encode_to_wire().map_err(fmt_err)?;
    let first = wire
        .first()
        .copied()
        .ok_or_else(|| "wire unexpectedly empty".to_string())?;

    Ok(first)
}

fn p2p_002_protocal_roundtrip(message: RemzarMessage) -> TestResult<RemzarMessage> {
    let wire = message.encode_to_wire().map_err(fmt_err)?;
    RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)
}

fn next_xorshift64(seed: &mut u64) -> u64 {
    let mut x = *seed;
    x ^= x.wrapping_shl(13);
    x ^= x.wrapping_shr(7);
    x ^= x.wrapping_shl(17);
    *seed = x;
    x
}

fn hash64(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn make_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
}

fn make_multiaddr(port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse::<Multiaddr>()
        .map_err(fmt_err)
}

fn make_transaction(amount: u64) -> TestResult<Transaction> {
    Transaction::new(sender_wallet(), receiver_wallet(), amount).map_err(fmt_err)
}

fn make_register_node() -> TestResult<RegisterNodeTx> {
    RegisterNodeTx::new(validator_wallet()).map_err(fmt_err)
}

fn make_reward(amount: u64, block_height: u64) -> TestResult<RewardTx> {
    RewardTx::new(receiver_wallet(), amount, block_height).map_err(fmt_err)
}

fn make_transfer_kind(amount: u64) -> TestResult<TxKind> {
    Ok(TxKind::Transfer(make_transaction(amount)?))
}

fn make_register_kind() -> TestResult<TxKind> {
    Ok(TxKind::RegisterNode(make_register_node()?))
}

fn make_reward_kind(amount: u64, block_height: u64) -> TestResult<TxKind> {
    Ok(TxKind::Reward(make_reward(amount, block_height)?))
}

fn make_empty_batch() -> TestResult<TransactionBatch> {
    TransactionBatch::new(7u64, TEST_TIMESTAMP, Vec::new()).map_err(fmt_err)
}

fn make_mixed_batch() -> TestResult<TransactionBatch> {
    TransactionBatch::new(
        8u64,
        TEST_TIMESTAMP,
        vec![
            make_transfer_kind(10u64)?,
            make_register_kind()?,
            make_reward_kind(UNIT_DIVISOR, 1u64)?,
        ],
    )
    .map_err(fmt_err)
}

fn make_por_proof(height: u64, output: u128) -> PorPuzzleProof {
    PorPuzzleProof {
        height,
        validator: validator_wallet(),
        prev_block_hash: hash64(7u8),
        output,
    }
}

fn make_peer_mesh_announce(port: u16, wallet: Option<String>) -> TestResult<PeerMeshAnnounce> {
    let peer_id = make_peer_id();
    let addr = make_multiaddr(port)?;

    Ok(PeerMeshAnnounce {
        peer_id: peer_id.to_base58(),
        listen_addrs: vec![addr.to_string()],
        wallet,
        timestamp_unix: TEST_TIMESTAMP,
    })
}

fn make_block() -> TestResult<Block> {
    let guardian_signature = [0u8; ml_dsa_65::SIG_LEN];

    let metadata = BlockMetadata::new(
        0u64,
        TEST_TIMESTAMP,
        hash64(3u8),
        hash64(4u8),
        guardian_signature,
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(metadata, None, String::new(), 0u64).map_err(fmt_err)
}

fn make_all_messages() -> TestResult<Vec<RemzarMessage>> {
    Ok(vec![
        RemzarMessage::Transaction(make_transaction(1u64)?),
        RemzarMessage::TxKind(make_transfer_kind(2u64)?),
        RemzarMessage::RegisterNode(make_register_node()?),
        RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 1u64)?),
        RemzarMessage::TxBatch(make_mixed_batch()?),
        RemzarMessage::Block(Box::new(make_block()?)),
        RemzarMessage::PorPuzzleProof(make_por_proof(9u64, 123u128)),
        RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4001u16, None)?),
    ])
}

fn make_message_from_sample(sample: u64) -> TestResult<RemzarMessage> {
    match sample & 7u64 {
        0u64 => Ok(RemzarMessage::Transaction(make_transaction(1u64)?)),
        1u64 => Ok(RemzarMessage::TxKind(make_transfer_kind(2u64)?)),
        2u64 => Ok(RemzarMessage::RegisterNode(make_register_node()?)),
        3u64 => Ok(RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 1u64)?)),
        4u64 => Ok(RemzarMessage::TxBatch(make_mixed_batch()?)),
        5u64 => Ok(RemzarMessage::Block(Box::new(make_block()?))),
        6u64 => Ok(RemzarMessage::PorPuzzleProof(make_por_proof(
            10u64, 456u128,
        ))),
        _ => Ok(RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(
            4002u16, None,
        )?)),
    }
}

fn assert_roundtrip_kind(message: RemzarMessage, expected_kind: &str) -> TestResult {
    let wire = message.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    assert_eq!(decoded.kind_str(), expected_kind);
    assert!(!wire.is_empty());
    assert!(wire.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

    Ok(())
}

fn assert_decode_error(bytes: &[u8]) -> TestResult {
    match RemzarMessage::decode_from_wire(bytes) {
        Err(RemzarMessageCodecError::Decode(_)) => Ok(()),
        Err(other) => Err(format!("expected Decode error, got {other:?}")),
        Ok(message) => Err(format!(
            "expected Decode error, decoded kind {}",
            message.kind_str()
        )),
    }
}

fn assert_too_large_error(bytes: &[u8]) -> TestResult {
    match RemzarMessage::decode_from_wire(bytes) {
        Err(RemzarMessageCodecError::TooLarge { got, max }) => {
            assert_eq!(got, bytes.len());
            assert_eq!(max, REMZAR_MESSAGE_MAX_WIRE_BYTES);
            Ok(())
        }
        Err(other) => Err(format!("expected TooLarge error, got {other:?}")),
        Ok(message) => Err(format!(
            "expected TooLarge error, decoded kind {}",
            message.kind_str()
        )),
    }
}

fn is_known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Transaction"
            | "TxKind"
            | "RegisterNode"
            | "Reward"
            | "TxBatch"
            | "Block"
            | "PorPuzzleProof"
            | "PeerMeshAnnounce"
    )
}

#[test]
fn p2p_01_002_protocal_wire_limit_is_one_mib() -> TestResult {
    assert_eq!(REMZAR_MESSAGE_MAX_WIRE_BYTES, 1024usize * 1024usize);
    Ok(())
}

#[test]
fn p2p_02_002_protocal_transaction_kind_str() -> TestResult {
    let msg = RemzarMessage::Transaction(make_transaction(1u64)?);

    assert_eq!(msg.kind_str(), "Transaction");
    Ok(())
}

#[test]
fn p2p_03_002_protocal_txkind_kind_str() -> TestResult {
    let msg = RemzarMessage::TxKind(make_transfer_kind(2u64)?);

    assert_eq!(msg.kind_str(), "TxKind");
    Ok(())
}

#[test]
fn p2p_04_002_protocal_register_node_kind_str() -> TestResult {
    let msg = RemzarMessage::RegisterNode(make_register_node()?);

    assert_eq!(msg.kind_str(), "RegisterNode");
    Ok(())
}

#[test]
fn p2p_05_002_protocal_reward_kind_str() -> TestResult {
    let msg = RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 1u64)?);

    assert_eq!(msg.kind_str(), "Reward");
    Ok(())
}

#[test]
fn p2p_06_002_protocal_empty_tx_batch_kind_str() -> TestResult {
    let msg = RemzarMessage::TxBatch(make_empty_batch()?);

    assert_eq!(msg.kind_str(), "TxBatch");
    Ok(())
}

#[test]
fn p2p_07_002_protocal_mixed_tx_batch_kind_str() -> TestResult {
    let msg = RemzarMessage::TxBatch(make_mixed_batch()?);

    assert_eq!(msg.kind_str(), "TxBatch");
    Ok(())
}

#[test]
fn p2p_08_002_protocal_block_kind_str() -> TestResult {
    let msg = RemzarMessage::Block(Box::new(make_block()?));

    assert_eq!(msg.kind_str(), "Block");
    Ok(())
}

#[test]
fn p2p_09_002_protocal_por_puzzle_proof_kind_str() -> TestResult {
    let msg = RemzarMessage::PorPuzzleProof(make_por_proof(1u64, 1u128));

    assert_eq!(msg.kind_str(), "PorPuzzleProof");
    Ok(())
}

#[test]
fn p2p_10_002_protocal_peer_mesh_announce_kind_str() -> TestResult {
    let msg = RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4001u16, None)?);

    assert_eq!(msg.kind_str(), "PeerMeshAnnounce");
    Ok(())
}

#[test]
fn p2p_11_002_protocal_transaction_roundtrip_preserves_kind_and_amount() -> TestResult {
    let msg = RemzarMessage::Transaction(make_transaction(123u64)?);
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::Transaction(tx) => {
            assert_eq!(tx.amount, 123u64);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_12_002_protocal_txkind_transfer_roundtrip_preserves_kind() -> TestResult {
    assert_roundtrip_kind(RemzarMessage::TxKind(make_transfer_kind(456u64)?), "TxKind")
}

#[test]
fn p2p_13_002_protocal_register_node_roundtrip_preserves_wallet_len() -> TestResult {
    let msg = RemzarMessage::RegisterNode(make_register_node()?);
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::RegisterNode(tx) => {
            assert_eq!(tx.wallet_address.len(), REMZAR_WALLET_LEN);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_14_002_protocal_reward_roundtrip_preserves_amount_and_height() -> TestResult {
    let msg = RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 55u64)?);
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::Reward(tx) => {
            assert_eq!(tx.amount, UNIT_DIVISOR);
            assert_eq!(tx.block_height, 55u64);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_15_002_protocal_empty_batch_roundtrip_preserves_empty_transactions() -> TestResult {
    let msg = RemzarMessage::TxBatch(make_empty_batch()?);
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert!(batch.transactions.is_empty());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_16_002_protocal_mixed_batch_roundtrip_preserves_transaction_count() -> TestResult {
    let msg = RemzarMessage::TxBatch(make_mixed_batch()?);
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert_eq!(batch.transactions.len(), 3usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_17_002_protocal_block_roundtrip_preserves_reward() -> TestResult {
    let msg = RemzarMessage::Block(Box::new(make_block()?));
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::Block(block) => {
            assert_eq!(block.reward, 0u64);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_18_002_protocal_por_puzzle_roundtrip_preserves_fields() -> TestResult {
    let msg = RemzarMessage::PorPuzzleProof(make_por_proof(42u64, 999u128));
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            assert_eq!(proof.height, 42u64);
            assert_eq!(proof.output, 999u128);
            assert_eq!(proof.prev_block_hash, hash64(7u8));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_19_002_protocal_peer_mesh_roundtrip_preserves_peer_and_addr() -> TestResult {
    let msg = RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4010u16, None)?);
    let wire = msg.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            assert_eq!(announce.listen_addrs.len(), 1usize);
            assert!(!announce.peer_id.is_empty());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_20_002_protocal_every_supported_variant_roundtrips_kind() -> TestResult {
    for message in make_all_messages()? {
        let expected = message.kind_str().to_string();
        assert_roundtrip_kind(message, &expected)?;
    }

    Ok(())
}

#[test]
fn p2p_21_002_protocal_decode_rejects_oversized_wire_before_postcard() -> TestResult {
    let oversized_len = REMZAR_MESSAGE_MAX_WIRE_BYTES
        .checked_add(1usize)
        .ok_or_else(|| "oversized len overflow".to_string())?;
    let bytes = vec![0u8; oversized_len];

    assert_too_large_error(&bytes)
}

#[test]
fn p2p_22_002_protocal_decode_exact_limit_is_not_too_large() -> TestResult {
    let bytes = vec![0u8; REMZAR_MESSAGE_MAX_WIRE_BYTES];

    match RemzarMessage::decode_from_wire(&bytes) {
        Err(RemzarMessageCodecError::TooLarge { got, max }) => Err(format!(
            "exact-limit frame must not be TooLarge: got {got}, max {max}"
        )),
        Err(RemzarMessageCodecError::Decode(_)) => Ok(()),
        Err(other) => Err(format!("unexpected codec error at exact limit: {other:?}")),
        Ok(message) => {
            assert!(is_known_kind(message.kind_str()));
            Ok(())
        }
    }
}

#[test]
fn p2p_23_002_protocal_empty_wire_returns_decode_error() -> TestResult {
    let bytes = Vec::new();

    assert_decode_error(&bytes)
}

#[test]
fn p2p_24_002_protocal_invalid_variant_tag_returns_decode_error() -> TestResult {
    let bytes = vec![8u8];

    assert_decode_error(&bytes)
}

#[test]
fn p2p_25_002_protocal_truncated_transaction_wire_returns_decode_error() -> TestResult {
    let msg = RemzarMessage::Transaction(make_transaction(1u64)?);
    let mut wire = msg.encode_to_wire().map_err(fmt_err)?;

    wire.pop()
        .ok_or_else(|| "cannot truncate empty wire".to_string())?;

    assert_decode_error(&wire)
}

#[test]
fn p2p_26_002_protocal_corrupted_variant_tag_returns_decode_error() -> TestResult {
    let msg = RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 1u64)?);
    let mut wire = msg.encode_to_wire().map_err(fmt_err)?;

    let first = wire
        .get_mut(0usize)
        .ok_or_else(|| "wire had no first byte".to_string())?;
    *first = 8u8;

    assert_decode_error(&wire)
}

#[test]
fn p2p_27_002_protocal_encoding_same_message_is_deterministic() -> TestResult {
    let msg = RemzarMessage::TxBatch(make_mixed_batch()?);

    let first = msg.encode_to_wire().map_err(fmt_err)?;
    let second = msg.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_28_002_protocal_kind_str_after_roundtrip_is_known_for_all_variants() -> TestResult {
    for message in make_all_messages()? {
        let wire = message.encode_to_wire().map_err(fmt_err)?;
        let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

        assert!(is_known_kind(decoded.kind_str()));
    }

    Ok(())
}

#[test]
fn p2p_29_002_protocal_fuzz_roundtrip_sixty_four_generated_messages() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..64usize {
        let sample = next_xorshift64(&mut seed);
        let message = make_message_from_sample(sample)?;
        let expected = message.kind_str().to_string();

        assert_roundtrip_kind(message, &expected)?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "fuzz roundtrip counter overflow".to_string())?;
    }

    assert_eq!(checked, 64usize);
    Ok(())
}

#[test]
fn p2p_30_002_protocal_fuzz_invalid_variant_tags_are_decode_errors() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut rejected = 0usize;

    for _ in 0usize..32usize {
        let sample = next_xorshift64(&mut seed);
        let tag_u64 = 8u64
            .checked_add(sample & 63u64)
            .ok_or_else(|| "invalid tag overflow".to_string())?;
        let tag = u8::try_from(tag_u64).map_err(fmt_err)?;
        let bytes = vec![tag];

        assert_decode_error(&bytes)?;

        rejected = rejected
            .checked_add(1usize)
            .ok_or_else(|| "invalid tag reject counter overflow".to_string())?;
    }

    assert_eq!(rejected, 32usize);
    Ok(())
}

#[test]
fn p2p_31_002_protocal_adversarial_stream_counts_valid_invalid_and_oversized() -> TestResult {
    let valid_a = RemzarMessage::Transaction(make_transaction(1u64)?)
        .encode_to_wire()
        .map_err(fmt_err)?;
    let valid_b = RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4020u16, None)?)
        .encode_to_wire()
        .map_err(fmt_err)?;
    let invalid = vec![8u8];
    let oversized = vec![
        0u8;
        REMZAR_MESSAGE_MAX_WIRE_BYTES
            .checked_add(1usize)
            .ok_or_else(|| "oversized stream frame len overflow".to_string())?
    ];

    let frames = vec![valid_a, invalid, oversized, valid_b];
    let mut valid_count = 0usize;
    let mut decode_error_count = 0usize;
    let mut too_large_count = 0usize;

    for frame in frames {
        match RemzarMessage::decode_from_wire(&frame) {
            Ok(_) => {
                valid_count = valid_count
                    .checked_add(1usize)
                    .ok_or_else(|| "valid frame counter overflow".to_string())?;
            }
            Err(RemzarMessageCodecError::Decode(_)) => {
                decode_error_count = decode_error_count
                    .checked_add(1usize)
                    .ok_or_else(|| "decode error counter overflow".to_string())?;
            }
            Err(RemzarMessageCodecError::TooLarge { .. }) => {
                too_large_count = too_large_count
                    .checked_add(1usize)
                    .ok_or_else(|| "too large counter overflow".to_string())?;
            }
            Err(other) => return Err(format!("unexpected codec error {other:?}")),
        }
    }

    assert_eq!(valid_count, 2usize);
    assert_eq!(decode_error_count, 1usize);
    assert_eq!(too_large_count, 1usize);
    Ok(())
}

#[test]
fn p2p_32_002_protocal_load_encode_256_transaction_messages() -> TestResult {
    let mut encoded = 0usize;

    for amount in 1u64..=256u64 {
        let message = RemzarMessage::Transaction(make_transaction(amount)?);
        let wire = message.encode_to_wire().map_err(fmt_err)?;

        assert!(!wire.is_empty());
        assert!(wire.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        encoded = encoded
            .checked_add(1usize)
            .ok_or_else(|| "encode load counter overflow".to_string())?;
    }

    assert_eq!(encoded, 256usize);
    Ok(())
}

#[test]
fn p2p_33_002_protocal_load_decode_256_transaction_messages() -> TestResult {
    let mut wires = Vec::new();

    for amount in 1u64..=256u64 {
        let message = RemzarMessage::Transaction(make_transaction(amount)?);
        wires.push(message.encode_to_wire().map_err(fmt_err)?);
    }

    let mut decoded = 0usize;

    for wire in wires {
        let message = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;
        assert_eq!(message.kind_str(), "Transaction");

        decoded = decoded
            .checked_add(1usize)
            .ok_or_else(|| "decode load counter overflow".to_string())?;
    }

    assert_eq!(decoded, 256usize);
    Ok(())
}

#[test]
fn p2p_34_002_protocal_property_roundtrip_preserves_kind_for_vector_set() -> TestResult {
    let messages = make_all_messages()?;
    let mut checked = 0usize;

    for message in messages {
        let expected = message.kind_str().to_string();
        let wire = message.encode_to_wire().map_err(fmt_err)?;
        let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

        assert_eq!(decoded.kind_str(), expected);

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "kind property counter overflow".to_string())?;
    }

    assert_eq!(checked, 8usize);
    Ok(())
}

#[test]
fn p2p_35_002_protocal_property_same_txkind_message_has_stable_wire_len() -> TestResult {
    let message = RemzarMessage::TxKind(make_transfer_kind(999u64)?);

    let first = message.encode_to_wire().map_err(fmt_err)?;
    let second = message.encode_to_wire().map_err(fmt_err)?;

    assert_eq!(first.len(), second.len());
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_36_002_protocal_edge_batch_with_32_transfers_stays_under_wire_limit() -> TestResult {
    let mut transactions = Vec::new();

    for amount in 1u64..=32u64 {
        transactions.push(make_transfer_kind(amount)?);
    }

    let batch = TransactionBatch::new(99u64, TEST_TIMESTAMP, transactions).map_err(fmt_err)?;
    let message = RemzarMessage::TxBatch(batch);
    let wire = message.encode_to_wire().map_err(fmt_err)?;

    assert!(!wire.is_empty());
    assert!(wire.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);
    assert_roundtrip_kind(message, "TxBatch")
}

#[test]
fn p2p_37_002_protocal_edge_peer_mesh_without_wallet_roundtrips_none_wallet() -> TestResult {
    let message = RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4030u16, None)?);
    let wire = message.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            assert!(announce.wallet.is_none());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_38_002_protocal_vector_peer_mesh_with_wallet_preserves_wallet() -> TestResult {
    let wallet = alternate_wallet();
    let message =
        RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4031u16, Some(wallet.clone()))?);
    let wire = message.encode_to_wire().map_err(fmt_err)?;
    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            assert_eq!(announce.wallet, Some(wallet));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_39_002_protocal_vector_por_puzzle_max_structural_height_is_valid() -> TestResult {
    let proof = make_por_proof(10_000_000u64, u128::MAX);

    proof.validate_structural().map_err(fmt_err)?;

    let message = RemzarMessage::PorPuzzleProof(proof);
    assert_roundtrip_kind(message, "PorPuzzleProof")
}

#[test]
fn p2p_40_002_protocal_edge_por_puzzle_invalid_zero_hash_rejects_structural_validation()
-> TestResult {
    let proof = PorPuzzleProof {
        height: 1u64,
        validator: validator_wallet(),
        prev_block_hash: [0u8; 64],
        output: 1u128,
    };

    assert!(proof.validate_structural().is_err());

    let message = RemzarMessage::PorPuzzleProof(proof);
    assert_roundtrip_kind(message, "PorPuzzleProof")
}

#[test]
fn p2p_41_002_protocal_all_variant_wires_are_nonempty_and_capped() -> TestResult {
    let messages = make_all_messages()?;
    let mut checked = 0usize;

    for message in messages {
        let wire = message.encode_to_wire().map_err(fmt_err)?;

        assert!(!wire.is_empty());
        assert!(wire.len() <= REMZAR_MESSAGE_MAX_WIRE_BYTES);

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "wire cap check counter overflow".to_string())?;
    }

    assert_eq!(checked, 8usize);
    Ok(())
}

#[test]
fn p2p_42_002_protocal_all_variant_first_tags_are_distinct() -> TestResult {
    let messages = make_all_messages()?;
    let mut tags = std::collections::BTreeSet::new();

    for message in &messages {
        let tag = p2p_002_protocal_wire_first_byte(message)?;
        let inserted = tags.insert(tag);

        assert!(inserted);
    }

    assert_eq!(tags.len(), messages.len());
    Ok(())
}

#[test]
fn p2p_43_002_protocal_variant_tag_vector_matches_declared_order() -> TestResult {
    let messages = make_all_messages()?;
    let mut expected = 0u8;

    for message in &messages {
        let tag = p2p_002_protocal_wire_first_byte(message)?;
        assert_eq!(tag, expected);

        expected = expected
            .checked_add(1u8)
            .ok_or_else(|| "expected variant tag overflow".to_string())?;
    }

    assert_eq!(expected, 8u8);
    Ok(())
}

#[test]
fn p2p_44_002_protocal_transaction_with_trailing_garbage_decodes_same_kind() -> TestResult {
    p2p_002_protocal_assert_trailing_garbage_decodes_same_kind(RemzarMessage::Transaction(
        make_transaction(1u64)?,
    ))
}

#[test]
fn p2p_45_002_protocal_txkind_with_trailing_garbage_decodes_same_kind() -> TestResult {
    p2p_002_protocal_assert_trailing_garbage_decodes_same_kind(RemzarMessage::TxKind(
        make_transfer_kind(1u64)?,
    ))
}

#[test]
fn p2p_46_002_protocal_peer_mesh_with_trailing_garbage_decodes_same_kind() -> TestResult {
    p2p_002_protocal_assert_trailing_garbage_decodes_same_kind(RemzarMessage::PeerMeshAnnounce(
        make_peer_mesh_announce(4046u16, None)?,
    ))
}

#[test]
fn p2p_47_002_protocal_block_with_trailing_garbage_decodes_same_kind() -> TestResult {
    p2p_002_protocal_assert_trailing_garbage_decodes_same_kind(RemzarMessage::Block(Box::new(
        make_block()?,
    )))
}

#[test]
fn p2p_48_002_protocal_empty_batch_wire_is_smaller_than_mixed_batch_wire() -> TestResult {
    let empty = RemzarMessage::TxBatch(make_empty_batch()?);
    let mixed = RemzarMessage::TxBatch(make_mixed_batch()?);

    let empty_wire = empty.encode_to_wire().map_err(fmt_err)?;
    let mixed_wire = mixed.encode_to_wire().map_err(fmt_err)?;

    assert!(empty_wire.len() < mixed_wire.len());
    Ok(())
}

#[test]
fn p2p_49_002_protocal_transfer_batch_1_roundtrips_count() -> TestResult {
    let message = RemzarMessage::TxBatch(p2p_002_protocal_make_transfer_batch(1usize)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert_eq!(batch.transactions.len(), 1usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_50_002_protocal_transfer_batch_2_roundtrips_count() -> TestResult {
    let message = RemzarMessage::TxBatch(p2p_002_protocal_make_transfer_batch(2usize)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert_eq!(batch.transactions.len(), 2usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_51_002_protocal_transfer_batch_8_roundtrips_count() -> TestResult {
    let message = RemzarMessage::TxBatch(p2p_002_protocal_make_transfer_batch(8usize)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert_eq!(batch.transactions.len(), 8usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_52_002_protocal_transfer_batch_16_roundtrips_count() -> TestResult {
    let message = RemzarMessage::TxBatch(p2p_002_protocal_make_transfer_batch(16usize)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert_eq!(batch.transactions.len(), 16usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_53_002_protocal_txkind_register_node_roundtrips_and_validates() -> TestResult {
    let message = RemzarMessage::TxKind(make_register_kind()?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            kind.validate().map_err(fmt_err)?;
            assert_eq!(kind.tag(), "register_node");
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_54_002_protocal_txkind_reward_roundtrips_and_validates() -> TestResult {
    let message = RemzarMessage::TxKind(make_reward_kind(UNIT_DIVISOR, 2u64)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            kind.validate().map_err(fmt_err)?;
            assert_eq!(kind.tag(), "reward");
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_55_002_protocal_txkind_transfer_roundtrips_and_validates() -> TestResult {
    let message = RemzarMessage::TxKind(make_transfer_kind(77u64)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            kind.validate().map_err(fmt_err)?;
            assert_eq!(kind.tag(), "transfer");
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_56_002_protocal_transaction_roundtrip_validate_passes() -> TestResult {
    let message = RemzarMessage::Transaction(make_transaction(999u64)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::Transaction(tx) => {
            tx.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_57_002_protocal_register_node_roundtrip_validate_passes() -> TestResult {
    let message = RemzarMessage::RegisterNode(make_register_node()?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::RegisterNode(tx) => {
            tx.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_58_002_protocal_reward_roundtrip_validate_passes() -> TestResult {
    let message = RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 3u64)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::Reward(tx) => {
            tx.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_59_002_protocal_peer_mesh_roundtrip_normalize_passes() -> TestResult {
    let message = RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4059u16, None)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            let normalized = announce.normalize().map_err(fmt_err)?;
            assert_eq!(normalized.full_dial_addrs.len(), 1usize);
            assert_eq!(normalized.kad_base_addrs.len(), 1usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_60_002_protocal_peer_mesh_with_wallet_roundtrip_normalize_preserves_wallet() -> TestResult {
    let wallet = alternate_wallet();
    let message =
        RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(4060u16, Some(wallet.clone()))?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            let normalized = announce.normalize().map_err(fmt_err)?;
            assert_eq!(normalized.wallet, Some(wallet));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_61_002_protocal_por_proof_roundtrip_structural_validation_passes() -> TestResult {
    let message = RemzarMessage::PorPuzzleProof(make_por_proof(61u64, 6100u128));
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            proof.validate_structural().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_62_002_protocal_por_proof_zero_output_roundtrips_but_structural_rejects() -> TestResult {
    let proof = make_por_proof(62u64, 0u128);
    let message = RemzarMessage::PorPuzzleProof(proof);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_63_002_protocal_por_proof_too_high_height_roundtrips_but_structural_rejects() -> TestResult {
    let proof = make_por_proof(10_000_001u64, 63u128);
    let message = RemzarMessage::PorPuzzleProof(proof);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_64_002_protocal_por_proof_ff_hash_roundtrips_but_structural_rejects() -> TestResult {
    let proof = PorPuzzleProof {
        height: 64u64,
        validator: validator_wallet(),
        prev_block_hash: [0xFFu8; 64],
        output: 64u128,
    };
    let message = RemzarMessage::PorPuzzleProof(proof);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_65_002_protocal_decode_rejects_all_ff_exact_limit_as_decode_not_too_large() -> TestResult {
    let bytes = vec![0xFFu8; REMZAR_MESSAGE_MAX_WIRE_BYTES];

    match RemzarMessage::decode_from_wire(&bytes) {
        Err(RemzarMessageCodecError::Decode(_)) => Ok(()),
        Err(other) => Err(format!("expected Decode at exact cap, got {other:?}")),
        Ok(message) => Err(format!(
            "expected Decode at exact cap, decoded kind {}",
            message.kind_str()
        )),
    }
}

#[test]
fn p2p_66_002_protocal_decode_rejects_all_ff_over_limit_as_too_large() -> TestResult {
    let over_limit = REMZAR_MESSAGE_MAX_WIRE_BYTES
        .checked_add(1usize)
        .ok_or_else(|| "over limit length overflow".to_string())?;
    let bytes = vec![0xFFu8; over_limit];

    assert_too_large_error(&bytes)
}

#[test]
fn p2p_67_002_protocal_load_encode_decode_128_mixed_messages() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..128usize {
        let sample = next_xorshift64(&mut seed);
        let message = make_message_from_sample(sample)?;
        let expected = message.kind_str().to_string();
        let decoded = p2p_002_protocal_roundtrip(message)?;

        assert_eq!(decoded.kind_str(), expected);

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "mixed load counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_68_002_protocal_load_repeated_block_roundtrip_32() -> TestResult {
    let mut checked = 0usize;

    for _ in 0usize..32usize {
        let decoded = p2p_002_protocal_roundtrip(RemzarMessage::Block(Box::new(make_block()?)))?;

        assert_eq!(decoded.kind_str(), "Block");

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "block load counter overflow".to_string())?;
    }

    assert_eq!(checked, 32usize);
    Ok(())
}

#[test]
fn p2p_69_002_protocal_load_repeated_peer_mesh_roundtrip_32() -> TestResult {
    let mut checked = 0usize;

    for offset in 0u16..32u16 {
        let port = 4100u16
            .checked_add(offset)
            .ok_or_else(|| "peer mesh port overflow".to_string())?;
        let message = RemzarMessage::PeerMeshAnnounce(make_peer_mesh_announce(port, None)?);
        let decoded = p2p_002_protocal_roundtrip(message)?;

        assert_eq!(decoded.kind_str(), "PeerMeshAnnounce");

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "peer mesh load counter overflow".to_string())?;
    }

    assert_eq!(checked, 32usize);
    Ok(())
}

#[test]
fn p2p_70_002_protocal_adversarial_truncated_each_variant_rejected() -> TestResult {
    let messages = make_all_messages()?;
    let mut rejected = 0usize;

    for message in messages {
        let mut wire = message.encode_to_wire().map_err(fmt_err)?;
        wire.pop()
            .ok_or_else(|| "cannot truncate empty variant wire".to_string())?;

        assert_decode_error(&wire)?;

        rejected = rejected
            .checked_add(1usize)
            .ok_or_else(|| "truncated reject counter overflow".to_string())?;
    }

    assert_eq!(rejected, 8usize);
    Ok(())
}

#[test]
fn p2p_71_002_protocal_adversarial_invalid_tag_plus_valid_payload_rejected() -> TestResult {
    let message = RemzarMessage::Transaction(make_transaction(71u64)?);
    let mut wire = message.encode_to_wire().map_err(fmt_err)?;

    let first = wire
        .get_mut(0usize)
        .ok_or_else(|| "wire unexpectedly empty".to_string())?;
    *first = 200u8;

    assert_decode_error(&wire)
}

#[test]
fn p2p_72_002_protocal_adversarial_empty_then_valid_message_still_decodes() -> TestResult {
    assert_decode_error(&[])?;

    let message = RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 72u64)?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    assert_eq!(decoded.kind_str(), "Reward");
    Ok(())
}

#[test]
fn p2p_73_002_protocal_adversarial_oversized_then_valid_message_still_decodes() -> TestResult {
    let over_limit = REMZAR_MESSAGE_MAX_WIRE_BYTES
        .checked_add(1usize)
        .ok_or_else(|| "over limit length overflow".to_string())?;
    let oversized = vec![0u8; over_limit];

    assert_too_large_error(&oversized)?;

    let message = RemzarMessage::RegisterNode(make_register_node()?);
    let decoded = p2p_002_protocal_roundtrip(message)?;

    assert_eq!(decoded.kind_str(), "RegisterNode");
    Ok(())
}

#[test]
fn p2p_74_002_protocal_property_encoding_len_stable_for_all_variants() -> TestResult {
    let messages = make_all_messages()?;

    for message in messages {
        let first = message.encode_to_wire().map_err(fmt_err)?;
        let second = message.encode_to_wire().map_err(fmt_err)?;
        let third = message.encode_to_wire().map_err(fmt_err)?;

        assert_eq!(first.len(), second.len());
        assert_eq!(second.len(), third.len());
        assert_eq!(first, second);
        assert_eq!(second, third);
    }

    Ok(())
}

#[test]
fn p2p_75_002_protocal_property_decode_encode_decode_preserves_kind() -> TestResult {
    for message in make_all_messages()? {
        let first_kind = message.kind_str().to_string();
        let first_wire = message.encode_to_wire().map_err(fmt_err)?;
        let decoded = RemzarMessage::decode_from_wire(&first_wire).map_err(fmt_err)?;
        let second_wire = decoded.encode_to_wire().map_err(fmt_err)?;
        let decoded_again = RemzarMessage::decode_from_wire(&second_wire).map_err(fmt_err)?;

        assert_eq!(decoded_again.kind_str(), first_kind);
        assert_eq!(first_wire, second_wire);
    }

    Ok(())
}

#[test]
fn p2p_76_002_protocal_property_wire_lengths_are_nonzero_for_all_variants() -> TestResult {
    let mut lengths = Vec::new();

    for message in make_all_messages()? {
        let wire = message.encode_to_wire().map_err(fmt_err)?;
        lengths.push(wire.len());
    }

    assert_eq!(lengths.len(), 8usize);

    for len in lengths {
        assert_ne!(len, 0usize);
    }

    Ok(())
}

#[test]
fn p2p_77_002_protocal_vector_transaction_amounts_roundtrip() -> TestResult {
    let amounts = [1u64, 2u64, 10u64, UNIT_DIVISOR, u64::from(u32::MAX)];
    let mut checked = 0usize;

    for amount in amounts {
        let decoded =
            p2p_002_protocal_roundtrip(RemzarMessage::Transaction(make_transaction(amount)?))?;

        match decoded {
            RemzarMessage::Transaction(tx) => {
                assert_eq!(tx.amount, amount);
            }
            other => return Err(format!("decoded wrong kind {}", other.kind_str())),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "amount vector counter overflow".to_string())?;
    }

    assert_eq!(checked, amounts.len());
    Ok(())
}

#[test]
fn p2p_78_002_protocal_vector_reward_heights_roundtrip() -> TestResult {
    let heights = [1u64, 2u64, 100u64, 10_000u64, 1_000_000u64];
    let mut checked = 0usize;

    for height in heights {
        let decoded =
            p2p_002_protocal_roundtrip(RemzarMessage::Reward(make_reward(UNIT_DIVISOR, height)?))?;

        match decoded {
            RemzarMessage::Reward(tx) => {
                assert_eq!(tx.block_height, height);
            }
            other => return Err(format!("decoded wrong kind {}", other.kind_str())),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "height vector counter overflow".to_string())?;
    }

    assert_eq!(checked, heights.len());
    Ok(())
}

#[test]
fn p2p_79_002_protocal_vector_por_outputs_roundtrip() -> TestResult {
    let outputs = [1u128, 2u128, 999u128, u128::from(u64::MAX), u128::MAX];
    let mut checked = 0usize;

    for output in outputs {
        let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PorPuzzleProof(make_por_proof(
            79u64, output,
        )))?;

        match decoded {
            RemzarMessage::PorPuzzleProof(proof) => {
                assert_eq!(proof.output, output);
            }
            other => return Err(format!("decoded wrong kind {}", other.kind_str())),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "por output vector counter overflow".to_string())?;
    }

    assert_eq!(checked, outputs.len());
    Ok(())
}

#[test]
fn p2p_80_002_protocal_stress_encode_decode_512_small_transactions() -> TestResult {
    let mut checked = 0usize;

    for amount in 1u64..=512u64 {
        let message = RemzarMessage::Transaction(make_transaction(amount)?);
        let wire = message.encode_to_wire().map_err(fmt_err)?;
        let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;

        match decoded {
            RemzarMessage::Transaction(tx) => {
                assert_eq!(tx.amount, amount);
            }
            other => return Err(format!("decoded wrong kind {}", other.kind_str())),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "512 transaction stress counter overflow".to_string())?;
    }

    assert_eq!(checked, 512usize);
    Ok(())
}

#[test]
fn p2p_81_002_protocal_transaction_roundtrip_preserves_wallet_bytes() -> TestResult {
    let expected_sender = sender_wallet();
    let expected_receiver = receiver_wallet();

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::Transaction(make_transaction(81u64)?))?;

    match decoded {
        RemzarMessage::Transaction(tx) => {
            assert_eq!(tx.sender.as_slice(), expected_sender.as_bytes());
            assert_eq!(tx.receiver.as_slice(), expected_receiver.as_bytes());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_82_002_protocal_txkind_transfer_normalized_sender_receiver_survive_roundtrip() -> TestResult
{
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::TxKind(make_transfer_kind(82u64)?))?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            assert_eq!(kind.normalized_sender(), Some(sender_wallet()));
            assert_eq!(kind.normalized_receiver(), Some(receiver_wallet()));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_83_002_protocal_txkind_transfer_touched_addresses_has_sender_and_receiver() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::TxKind(make_transfer_kind(83u64)?))?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            let touched = kind.touched_addresses();

            assert_eq!(touched.len(), 2usize);
            assert!(touched.contains(&sender_wallet()));
            assert!(touched.contains(&receiver_wallet()));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_84_002_protocal_txkind_reward_touched_addresses_has_receiver_only() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::TxKind(make_reward_kind(
        UNIT_DIVISOR,
        84u64,
    )?))?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            let touched = kind.touched_addresses();

            assert_eq!(kind.normalized_sender(), None);
            assert_eq!(kind.normalized_receiver(), Some(receiver_wallet()));
            assert_eq!(touched.len(), 1usize);
            assert!(touched.contains(&receiver_wallet()));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_85_002_protocal_txkind_register_node_touches_no_balance_addresses() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::TxKind(make_register_kind()?))?;

    match decoded {
        RemzarMessage::TxKind(kind) => {
            assert_eq!(kind.normalized_sender(), None);
            assert_eq!(kind.normalized_receiver(), None);
            assert!(kind.touched_addresses().is_empty());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_86_002_protocal_batch_roundtrip_preserves_index_and_timestamp() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::TxBatch(make_mixed_batch()?))?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert_eq!(batch.index, 8u64);
            assert_eq!(batch.timestamp, TEST_TIMESTAMP);
            assert_eq!(batch.transactions.len(), 3usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_87_002_protocal_batch_roundtrip_preserves_none_guardian_signature() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::TxBatch(make_empty_batch()?))?;

    match decoded {
        RemzarMessage::TxBatch(batch) => {
            assert!(batch.guardian_signature.is_none());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_88_002_protocal_block_roundtrip_verify_block_hash_passes() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::Block(Box::new(make_block()?)))?;

    match decoded {
        RemzarMessage::Block(block) => {
            let verified = block.verify_block_hash().map_err(fmt_err)?;
            assert!(verified);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_89_002_protocal_genesis_block_roundtrip_preserves_empty_miner() -> TestResult {
    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::Block(Box::new(make_block()?)))?;

    match decoded {
        RemzarMessage::Block(block) => {
            assert_eq!(block.miner_wallet(), "");
            assert_eq!(block.reward, 0u64);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_90_002_protocal_por_proof_uppercase_validator_roundtrips_but_structural_rejects()
-> TestResult {
    let proof = PorPuzzleProof {
        height: 90u64,
        validator: format!("r{}", "A".repeat(128usize)),
        prev_block_hash: hash64(9u8),
        output: 90u128,
    };

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PorPuzzleProof(proof))?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_91_002_protocal_por_proof_too_long_validator_roundtrips_but_structural_rejects() -> TestResult
{
    let proof = PorPuzzleProof {
        height: 91u64,
        validator: format!("r{}", "a".repeat(300usize)),
        prev_block_hash: hash64(9u8),
        output: 91u128,
    };

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PorPuzzleProof(proof))?;

    match decoded {
        RemzarMessage::PorPuzzleProof(proof) => {
            assert!(proof.validate_structural().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_92_002_protocal_peer_mesh_duplicate_addrs_roundtrip_normalizes_to_one_addr() -> TestResult {
    let peer_id = make_peer_id();
    let addr = make_multiaddr(4092u16)?.to_string();

    let announce = PeerMeshAnnounce {
        peer_id: peer_id.to_base58(),
        listen_addrs: vec![addr.clone(), addr],
        wallet: None,
        timestamp_unix: TEST_TIMESTAMP,
    };

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PeerMeshAnnounce(announce))?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            let normalized = announce.normalize().map_err(fmt_err)?;

            assert_eq!(normalized.full_dial_addrs.len(), 1usize);
            assert_eq!(normalized.kad_base_addrs.len(), 1usize);
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_93_002_protocal_peer_mesh_mismatched_trailing_peer_is_rebound_to_announced_peer()
-> TestResult {
    let announced_peer = make_peer_id();
    let wrong_peer = make_peer_id();

    let raw_addr = format!("{}/p2p/{wrong_peer}", make_multiaddr(4093u16)?.to_string());

    let announce = PeerMeshAnnounce {
        peer_id: announced_peer.to_base58(),
        listen_addrs: vec![raw_addr],
        wallet: None,
        timestamp_unix: TEST_TIMESTAMP,
    };

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PeerMeshAnnounce(announce))?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            let normalized = announce.normalize().map_err(fmt_err)?;
            let full_addr = normalized
                .full_dial_addrs
                .first()
                .ok_or_else(|| "missing normalized full dial addr".to_string())?
                .to_string();

            assert!(full_addr.contains(&announced_peer.to_string()));
            assert!(!full_addr.contains(&wrong_peer.to_string()));
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_94_002_protocal_peer_mesh_empty_listen_addrs_roundtrips_but_normalize_rejects() -> TestResult
{
    let announce = PeerMeshAnnounce {
        peer_id: make_peer_id().to_base58(),
        listen_addrs: Vec::new(),
        wallet: None,
        timestamp_unix: TEST_TIMESTAMP,
    };

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PeerMeshAnnounce(announce))?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            assert!(announce.normalize().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_95_002_protocal_peer_mesh_invalid_wallet_roundtrips_but_normalize_rejects() -> TestResult {
    let announce = PeerMeshAnnounce {
        peer_id: make_peer_id().to_base58(),
        listen_addrs: vec![make_multiaddr(4095u16)?.to_string()],
        wallet: Some("not-a-wallet".to_string()),
        timestamp_unix: TEST_TIMESTAMP,
    };

    let decoded = p2p_002_protocal_roundtrip(RemzarMessage::PeerMeshAnnounce(announce))?;

    match decoded {
        RemzarMessage::PeerMeshAnnounce(announce) => {
            assert!(announce.normalize().is_err());
            Ok(())
        }
        other => Err(format!("decoded wrong kind {}", other.kind_str())),
    }
}

#[test]
fn p2p_96_002_protocal_all_prefixes_of_transaction_wire_are_rejected_until_complete() -> TestResult
{
    let wire = RemzarMessage::Transaction(make_transaction(96u64)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    let mut rejected = 0usize;

    for len in 0usize..wire.len() {
        let prefix: Vec<u8> = wire.iter().take(len).copied().collect();

        assert_decode_error(&prefix)?;

        rejected = rejected
            .checked_add(1usize)
            .ok_or_else(|| "prefix rejection counter overflow".to_string())?;
    }

    let decoded = RemzarMessage::decode_from_wire(&wire).map_err(fmt_err)?;
    assert_eq!(decoded.kind_str(), "Transaction");
    assert_eq!(rejected, wire.len());

    Ok(())
}

#[test]
fn p2p_97_002_protocal_random_small_frames_never_panic_and_return_valid_kind_or_decode_error()
-> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for frame_len in 0usize..128usize {
        let mut frame = Vec::new();

        for _ in 0usize..frame_len {
            let sample = next_xorshift64(&mut seed);
            let byte = u8::try_from(sample & 0xFFu64).map_err(fmt_err)?;
            frame.push(byte);
        }

        match RemzarMessage::decode_from_wire(&frame) {
            Ok(message) => assert!(is_known_kind(message.kind_str())),
            Err(RemzarMessageCodecError::Decode(_)) => {}
            Err(other) => return Err(format!("unexpected codec error {other:?}")),
        }

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "random frame counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_98_002_protocal_valid_prefix_padded_over_limit_is_rejected_as_too_large() -> TestResult {
    let mut wire = RemzarMessage::Reward(make_reward(UNIT_DIVISOR, 98u64)?)
        .encode_to_wire()
        .map_err(fmt_err)?;

    let over_limit = REMZAR_MESSAGE_MAX_WIRE_BYTES
        .checked_add(1usize)
        .ok_or_else(|| "over limit resize overflow".to_string())?;
    wire.resize(over_limit, 0u8);

    assert_too_large_error(&wire)
}

#[test]
fn p2p_99_002_protocal_adversarial_decode_sequence_is_stateless() -> TestResult {
    let valid_a = RemzarMessage::Transaction(make_transaction(99u64)?)
        .encode_to_wire()
        .map_err(fmt_err)?;
    let valid_b = RemzarMessage::PorPuzzleProof(make_por_proof(99u64, 99u128))
        .encode_to_wire()
        .map_err(fmt_err)?;
    let invalid_empty = Vec::new();
    let invalid_tag = vec![250u8];

    let oversized =
        vec![
            0u8;
            REMZAR_MESSAGE_MAX_WIRE_BYTES
                .checked_add(1usize)
                .ok_or_else(|| "oversized adversarial sequence len overflow".to_string())?
        ];

    let frames = vec![invalid_empty, valid_a, invalid_tag, oversized, valid_b];

    let mut valid_count = 0usize;
    let mut decode_error_count = 0usize;
    let mut too_large_count = 0usize;

    for frame in frames {
        match RemzarMessage::decode_from_wire(&frame) {
            Ok(message) => {
                assert!(is_known_kind(message.kind_str()));
                valid_count = valid_count
                    .checked_add(1usize)
                    .ok_or_else(|| "valid count overflow".to_string())?;
            }
            Err(RemzarMessageCodecError::Decode(_)) => {
                decode_error_count = decode_error_count
                    .checked_add(1usize)
                    .ok_or_else(|| "decode error count overflow".to_string())?;
            }
            Err(RemzarMessageCodecError::TooLarge { .. }) => {
                too_large_count = too_large_count
                    .checked_add(1usize)
                    .ok_or_else(|| "too large count overflow".to_string())?;
            }
            Err(other) => return Err(format!("unexpected codec error {other:?}")),
        }
    }

    assert_eq!(valid_count, 2usize);
    assert_eq!(decode_error_count, 2usize);
    assert_eq!(too_large_count, 1usize);
    Ok(())
}

#[test]
fn p2p_100_002_protocal_complete_variant_matrix_tags_kinds_and_stable_wire() -> TestResult {
    let messages = make_all_messages()?;
    let expected_kinds = [
        "Transaction",
        "TxKind",
        "RegisterNode",
        "Reward",
        "TxBatch",
        "Block",
        "PorPuzzleProof",
        "PeerMeshAnnounce",
    ];

    let mut seen_tags = std::collections::BTreeSet::new();

    for (index, message) in messages.iter().enumerate() {
        let expected_tag = u8::try_from(index).map_err(fmt_err)?;
        let expected_kind = expected_kinds
            .get(index)
            .ok_or_else(|| "missing expected kind".to_string())?;

        let first_wire = message.encode_to_wire().map_err(fmt_err)?;
        let second_wire = message.encode_to_wire().map_err(fmt_err)?;

        let first_tag = first_wire
            .first()
            .copied()
            .ok_or_else(|| "variant wire unexpectedly empty".to_string())?;

        assert_eq!(first_tag, expected_tag);
        assert_eq!(message.kind_str(), *expected_kind);
        assert_eq!(first_wire, second_wire);
        assert!(seen_tags.insert(first_tag));

        let decoded = RemzarMessage::decode_from_wire(&first_wire).map_err(fmt_err)?;
        assert_eq!(decoded.kind_str(), *expected_kind);
    }

    assert_eq!(seen_tags.len(), expected_kinds.len());
    Ok(())
}
