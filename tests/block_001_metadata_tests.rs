// tests/block_001_metadata_tests.rs

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use std::collections::BTreeSet;
use std::error::Error as StdError;

type TestResult = Result<(), Box<dyn StdError>>;

fn fail(message: impl Into<String>) -> Box<dyn StdError> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(fail(message))
    }
}

fn ensure_eq<T>(left: &T, right: &T, message: &str) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(fail(format!("{message}: left={left:?}, right={right:?}")))
    }
}

fn ensure_ne<T>(left: &T, right: &T, message: &str) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left != right {
        Ok(())
    } else {
        Err(fail(format!("{message}: both={left:?}")))
    }
}

fn require_validation_error<T>(result: Result<T, ErrorDetection>, needle: &str) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => ensure(
            message.contains(needle),
            format!("ValidationError did not contain `{needle}`: {message}"),
        ),
        Err(other) => Err(fail(format!(
            "expected ValidationError containing `{needle}`, got {other:?}"
        ))),
        Ok(_) => Err(fail(format!(
            "expected ValidationError containing `{needle}`, got Ok"
        ))),
    }
}

fn require_serialization_error<T>(result: Result<T, ErrorDetection>, needle: &str) -> TestResult {
    match result {
        Err(ErrorDetection::SerializationError { details }) => ensure(
            details.contains(needle),
            format!("SerializationError did not contain `{needle}`: {details}"),
        ),
        Err(other) => Err(fail(format!(
            "expected SerializationError containing `{needle}`, got {other:?}"
        ))),
        Ok(_) => Err(fail(format!(
            "expected SerializationError containing `{needle}`, got Ok"
        ))),
    }
}

fn canonical_validator() -> String {
    let mut validator = String::from("r");
    for _ in 0..128 {
        validator.push('1');
    }
    validator
}

fn patterned_hash(seed: u8) -> [u8; 64] {
    let mut out = [0_u8; 64];
    let mut value = seed;
    for byte in &mut out {
        value = value.wrapping_mul(31).wrapping_add(17);
        *byte = value;
    }
    out
}

fn nonzero_signature(seed: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let mut sig = [0_u8; ml_dsa_65::SIG_LEN];
    let mut value = seed;
    for byte in &mut sig {
        value = value.wrapping_add(1);
        *byte = value;
    }
    sig
}

fn timestamp_for_height(height: u64) -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS
        .saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS)
        .saturating_add(height)
}

fn valid_metadata(index: u64, seed: u8) -> BlockMetadata {
    BlockMetadata::new(
        index,
        timestamp_for_height(index),
        patterned_hash(seed),
        patterned_hash(seed.wrapping_add(1)),
        nonzero_signature(seed.wrapping_add(2)),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    )
}

fn valid_proof_for(
    index: u64,
    prev_block_hash: [u8; 64],
    output: u128,
) -> Result<BlockPuzzleProof, ErrorDetection> {
    BlockPuzzleProof::new(index, canonical_validator(), prev_block_hash, output)
}

fn is_all_zero_64(bytes: &[u8; 64]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
}

fn flip_first_byte(bytes: &mut [u8; 64]) {
    for byte in bytes.iter_mut().take(1) {
        *byte = byte.wrapping_add(1);
    }
}

#[test]
fn block_01_new_preserves_all_fields() -> TestResult {
    let index = 7_u64;
    let timestamp = timestamp_for_height(index);
    let previous_hash = patterned_hash(10);
    let merkle_root = patterned_hash(11);
    let guardian_signature = nonzero_signature(12);
    let proof = valid_proof_for(index, previous_hash, 123_u128)?;
    let size = GlobalConfiguration::MIN_BLOCK_SIZE;

    let meta = BlockMetadata::new(
        index,
        timestamp,
        previous_hash,
        merkle_root,
        guardian_signature,
        Some(proof.clone()),
        size,
    );

    ensure_eq(&meta.index, &index, "index should be preserved")?;
    ensure_eq(&meta.timestamp, &timestamp, "timestamp should be preserved")?;
    ensure_eq(
        &meta.previous_hash,
        &previous_hash,
        "previous_hash should be preserved",
    )?;
    ensure_eq(
        &meta.merkle_root,
        &merkle_root,
        "merkle_root should be preserved",
    )?;
    ensure_eq(
        &meta.guardian_signature,
        &guardian_signature,
        "guardian_signature should be preserved",
    )?;
    ensure_eq(
        &meta.puzzle_proof,
        &Some(proof),
        "puzzle_proof should be preserved",
    )?;
    ensure_eq(&meta.size, &size, "size should be preserved")
}

#[test]
fn block_02_from_genesis_builds_valid_metadata() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp(
        "Remzar block metadata genesis vector",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
    )?;
    let meta = BlockMetadata::from_genesis(genesis.clone())?;

    ensure_eq(&meta.index, &0_u64, "genesis metadata index must be zero")?;
    ensure_eq(
        &meta.timestamp,
        &genesis.timestamp,
        "timestamp should come from genesis block",
    )?;
    ensure_eq(
        &meta.previous_hash,
        &genesis.prev_hash,
        "previous_hash should come from genesis block",
    )?;
    ensure_eq(
        &meta.merkle_root,
        &genesis.merkle_root,
        "merkle_root should come from genesis block",
    )?;
    ensure(
        meta.guardian_signature.iter().all(|byte| *byte == 0),
        "genesis metadata guardian signature should be all zeros",
    )?;
    ensure(
        meta.puzzle_proof().is_none(),
        "genesis metadata must not include puzzle proof",
    )?;
    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_03_from_genesis_rejects_zero_merkle_root() -> TestResult {
    let mut genesis = GenesisBlock::new_with_timestamp(
        "Remzar block metadata bad genesis",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
    )?;

    genesis.merkle_root = [0_u8; 64];

    require_validation_error(
        BlockMetadata::from_genesis(genesis),
        "Merkle root is all zeros",
    )
}

#[test]
fn block_04_from_genesis_sets_nonzero_serialized_size() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp(
        "Remzar block metadata size genesis",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
    )?;
    let meta = BlockMetadata::from_genesis(genesis)?;

    ensure(
        meta.size >= GlobalConfiguration::MIN_BLOCK_SIZE,
        "from_genesis should set a plausible metadata size",
    )?;
    ensure(
        meta.size <= GlobalConfiguration::MAX_BLOCK_SIZE,
        "from_genesis size should not exceed max block size",
    )
}

#[test]
fn block_05_compute_hash_returns_128_lowercase_hex() -> TestResult {
    let meta = valid_metadata(1, 21);
    let hash = meta.compute_hash()?;

    ensure_eq(
        &hash.len(),
        &128_usize,
        "metadata hash must be 128 hex chars",
    )?;
    ensure(
        is_lowercase_hex(&hash),
        "metadata hash must be lowercase hex",
    )
}

#[test]
fn block_06_compute_hash_is_deterministic() -> TestResult {
    let meta = valid_metadata(1, 22);

    let first = meta.compute_hash()?;
    let second = meta.compute_hash()?;

    ensure_eq(&first, &second, "same metadata must hash deterministically")
}

#[test]
fn block_07_compute_hash_changes_when_index_changes() -> TestResult {
    let first = valid_metadata(1, 23);
    let second = valid_metadata(2, 23);

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;

    ensure_ne(
        &first_hash,
        &second_hash,
        "index should affect metadata hash",
    )
}

#[test]
fn block_08_compute_hash_changes_when_timestamp_changes() -> TestResult {
    let first = valid_metadata(1, 24);
    let mut second = first.clone();
    second.timestamp = second.timestamp.saturating_add(1);

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;

    ensure_ne(
        &first_hash,
        &second_hash,
        "timestamp should affect metadata hash",
    )
}

#[test]
fn block_09_compute_hash_changes_when_previous_hash_changes() -> TestResult {
    let first = valid_metadata(1, 25);
    let mut second = first.clone();
    second.previous_hash = patterned_hash(200);

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;

    ensure_ne(
        &first_hash,
        &second_hash,
        "previous_hash should affect metadata hash",
    )
}

#[test]
fn block_10_compute_hash_changes_when_merkle_root_changes() -> TestResult {
    let first = valid_metadata(1, 26);
    let mut second = first.clone();
    second.merkle_root = patterned_hash(201);

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;

    ensure_ne(
        &first_hash,
        &second_hash,
        "merkle_root should affect metadata hash",
    )
}

#[test]
fn block_11_compute_hash_changes_when_guardian_signature_changes() -> TestResult {
    let first = valid_metadata(1, 27);
    let mut second = first.clone();
    second.guardian_signature = nonzero_signature(99);

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;

    ensure_ne(
        &first_hash,
        &second_hash,
        "guardian_signature should affect metadata hash",
    )
}

#[test]
fn block_12_compute_hash_changes_when_size_changes() -> TestResult {
    let first = valid_metadata(1, 28);
    let mut second = first.clone();
    second.size = second.size.saturating_add(1);

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;

    ensure_ne(
        &first_hash,
        &second_hash,
        "size should affect metadata hash",
    )
}

#[test]
fn block_13_verify_hash_accepts_exact_hash() -> TestResult {
    let meta = valid_metadata(1, 29);
    let hash = meta.compute_hash()?;

    let verified = meta.verify_hash(&hash)?;

    ensure(verified, "verify_hash should accept exact computed hash")
}

#[test]
fn block_14_verify_hash_trims_surrounding_whitespace() -> TestResult {
    let meta = valid_metadata(1, 30);
    let hash = meta.compute_hash()?;
    let padded = format!("  {hash}\n");

    let verified = meta.verify_hash(&padded)?;

    ensure(verified, "verify_hash should trim whitespace")
}

#[test]
fn block_15_verify_hash_returns_false_for_wrong_valid_length_hash() -> TestResult {
    let meta = valid_metadata(1, 31);
    let hash = meta.compute_hash()?;
    let zero_hash = "0".repeat(128);
    let one_hash = "1".repeat(128);
    let wrong_hash = if hash == zero_hash {
        one_hash
    } else {
        zero_hash
    };

    let verified = meta.verify_hash(&wrong_hash)?;

    ensure(!verified, "wrong 128-char hash should return false")
}

#[test]
fn block_16_verify_hash_rejects_short_hash() -> TestResult {
    let meta = valid_metadata(1, 32);

    require_validation_error(
        meta.verify_hash("abcd"),
        "expected hash hex length mismatch",
    )
}

#[test]
fn block_17_verify_hash_rejects_long_hash() -> TestResult {
    let meta = valid_metadata(1, 33);
    let too_long = "a".repeat(129);

    require_validation_error(
        meta.verify_hash(&too_long),
        "expected hash hex length mismatch",
    )
}

#[test]
fn block_18_verify_hash_rejects_empty_hash() -> TestResult {
    let meta = valid_metadata(1, 34);

    require_validation_error(meta.verify_hash(""), "expected hash hex length mismatch")
}

#[test]
fn block_19_set_merkle_root_empty_uses_dummy_hash() -> TestResult {
    let mut meta = valid_metadata(1, 35);
    let transactions: [u64; 0] = [];

    meta.set_merkle_root(&transactions)?;

    let expected_hex = RemzarHash::compute_dummy_hash();
    let actual_hex = hex::encode(meta.merkle_root);

    ensure_eq(
        &actual_hex,
        &expected_hex,
        "empty transaction list should use dummy hash",
    )
}

#[test]
fn block_20_set_merkle_root_empty_is_nonzero() -> TestResult {
    let mut meta = valid_metadata(1, 36);
    let transactions: [String; 0] = [];

    meta.set_merkle_root(&transactions)?;

    ensure(
        !is_all_zero_64(&meta.merkle_root),
        "dummy merkle root must not be all zeros",
    )
}

#[test]
fn block_21_set_merkle_root_transactions_is_deterministic() -> TestResult {
    let transactions = vec![
        String::from("tx-alpha"),
        String::from("tx-beta"),
        String::from("tx-gamma"),
    ];
    let mut first = valid_metadata(1, 37);
    let mut second = valid_metadata(1, 38);

    first.set_merkle_root(&transactions)?;
    second.set_merkle_root(&transactions)?;

    ensure_eq(
        &first.merkle_root,
        &second.merkle_root,
        "same transactions should produce same merkle root",
    )
}

#[test]
fn block_22_set_merkle_root_changes_when_transactions_change() -> TestResult {
    let mut first = valid_metadata(1, 39);
    let mut second = valid_metadata(1, 40);

    first.set_merkle_root(&[String::from("tx-one")])?;
    second.set_merkle_root(&[String::from("tx-two")])?;

    ensure_ne(
        &first.merkle_root,
        &second.merkle_root,
        "different transactions should produce different roots",
    )
}

#[test]
fn block_23_set_merkle_root_order_is_consensus_relevant() -> TestResult {
    let mut first = valid_metadata(1, 41);
    let mut second = valid_metadata(1, 42);

    first.set_merkle_root(&[1_u64, 2_u64, 3_u64])?;
    second.set_merkle_root(&[3_u64, 2_u64, 1_u64])?;

    ensure_ne(
        &first.merkle_root,
        &second.merkle_root,
        "transaction order should affect merkle root",
    )
}

#[test]
fn block_24_set_guardian_signature_replaces_signature() -> TestResult {
    let mut meta = valid_metadata(1, 43);
    let replacement = nonzero_signature(100);

    meta.set_guardian_signature(replacement);

    ensure_eq(
        &meta.guardian_signature,
        &replacement,
        "set_guardian_signature should replace signature bytes",
    )
}

#[test]
fn block_25_set_guardian_signature_changes_metadata_hash() -> TestResult {
    let mut meta = valid_metadata(1, 44);
    let before = meta.compute_hash()?;

    meta.set_guardian_signature(nonzero_signature(101));
    let after = meta.compute_hash()?;

    ensure_ne(
        &before,
        &after,
        "changing guardian signature should change metadata hash",
    )
}

#[test]
fn block_26_to_bytes_from_bytes_roundtrip() -> TestResult {
    let meta = valid_metadata(2, 45);

    let bytes = meta.to_bytes()?;
    let decoded = BlockMetadata::from_bytes(&bytes)?;

    ensure_eq(
        &decoded,
        &meta,
        "postcard roundtrip should preserve metadata",
    )
}

#[test]
fn block_27_to_bytes_is_deterministic() -> TestResult {
    let meta = valid_metadata(2, 46);

    let first = meta.to_bytes()?;
    let second = meta.to_bytes()?;

    ensure_eq(&first, &second, "to_bytes should be deterministic")
}

#[test]
fn block_28_from_bytes_rejects_empty_payload() -> TestResult {
    require_serialization_error(
        BlockMetadata::from_bytes(&[]),
        "Deserialize BlockMetadata failed",
    )
}

#[test]
fn block_29_from_bytes_rejects_oversized_payload() -> TestResult {
    let oversized_len = GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES.saturating_add(1);
    let oversized = vec![0_u8; oversized_len];

    require_serialization_error(BlockMetadata::from_bytes(&oversized), "payload size")
}

#[test]
fn block_30_from_bytes_rejects_valid_payload_with_trailing_zero_byte() -> TestResult {
    let meta = valid_metadata(2, 47);
    let mut bytes = meta.to_bytes()?;
    bytes.push(0_u8);

    ensure(
        BlockMetadata::from_bytes(&bytes).is_err(),
        "BlockMetadata::from_bytes must reject trailing zero byte after valid postcard payload",
    )
}

#[test]
fn block_31_from_bytes_runs_structural_validation() -> TestResult {
    let mut meta = valid_metadata(2, 48);

    // Poison the structure after creating otherwise-valid metadata.
    meta.guardian_signature = [0_u8; ml_dsa_65::SIG_LEN];

    let bytes = postcard::to_allocvec(&meta)?;

    require_validation_error(BlockMetadata::from_bytes(&bytes), "guardian_signature")
}

#[test]
fn block_32_json_roundtrip_preserves_metadata() -> TestResult {
    let meta = valid_metadata(2, 49);

    let json = serde_json::to_string(&meta)?;
    let decoded: BlockMetadata = serde_json::from_str(&json)?;

    ensure_eq(&decoded, &meta, "JSON roundtrip should preserve metadata")
}

#[test]
fn block_33_json_rejects_unknown_fields() -> TestResult {
    let meta = valid_metadata(2, 50);
    let mut value = serde_json::to_value(meta)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("hostile_extra_field"),
                serde_json::Value::Bool(true),
            );
        }
        None => return Err(fail("BlockMetadata should serialize to a JSON object")),
    }

    let raw = serde_json::to_string(&value)?;
    let decoded = serde_json::from_str::<BlockMetadata>(&raw);

    ensure(
        decoded.is_err(),
        "deny_unknown_fields should reject hostile extra field",
    )
}

#[test]
fn block_34_validate_structural_accepts_valid_non_genesis() -> TestResult {
    let meta = valid_metadata(1, 51);

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_35_validate_structural_accepts_max_reasonable_index() -> TestResult {
    let meta = valid_metadata(10_000_000_u64, 52);

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_36_validate_structural_rejects_index_over_limit() -> TestResult {
    let meta = valid_metadata(10_000_001_u64, 53);

    require_validation_error(meta.validate_structural(), "fields out of bounds")
}

#[test]
fn block_37_validate_structural_accepts_min_size() -> TestResult {
    let mut meta = valid_metadata(1, 54);
    meta.size = GlobalConfiguration::MIN_BLOCK_SIZE;

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_38_validate_structural_rejects_size_below_minimum() -> TestResult {
    let mut meta = valid_metadata(1, 55);
    meta.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);

    require_validation_error(meta.validate_structural(), "implausibly small")
}

#[test]
fn block_39_validate_structural_accepts_max_block_size() -> TestResult {
    let mut meta = valid_metadata(1, 56);
    meta.size = GlobalConfiguration::MAX_BLOCK_SIZE;

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_40_validate_structural_rejects_size_above_max_block_size() -> TestResult {
    let mut meta = valid_metadata(1, 57);
    meta.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);

    require_validation_error(meta.validate_structural(), "fields out of bounds")
}

#[test]
fn block_41_validate_structural_accepts_min_timestamp() -> TestResult {
    let mut meta = valid_metadata(1, 58);
    meta.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS;

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_42_validate_structural_rejects_timestamp_below_minimum() -> TestResult {
    let mut meta = valid_metadata(1, 59);
    meta.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1);

    // Current TimePolicy wording is:
    // "BlockMetadata.timestamp: timestamp below UNIX_2000_SECS: ..."
    require_validation_error(meta.validate_structural(), "timestamp below")
}

#[test]
fn block_43_genesis_metadata_allows_zero_previous_hash_and_zero_signature() -> TestResult {
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        [0_u8; 64],
        patterned_hash(60),
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_44_genesis_metadata_rejects_zero_merkle_root() -> TestResult {
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        [0_u8; 64],
        [0_u8; 64],
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    require_validation_error(
        meta.validate_structural(),
        "genesis merkle_root is all zeros",
    )
}

#[test]
fn block_45_genesis_metadata_rejects_puzzle_proof() -> TestResult {
    let previous_hash = patterned_hash(61);
    let proof = valid_proof_for(0, previous_hash, 1_u128)?;
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        previous_hash,
        patterned_hash(62),
        [0_u8; ml_dsa_65::SIG_LEN],
        Some(proof),
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    require_validation_error(
        meta.validate_structural(),
        "genesis must not include puzzle_proof",
    )
}

#[test]
fn block_46_non_genesis_rejects_zero_merkle_root() -> TestResult {
    let meta = BlockMetadata::new(
        1,
        timestamp_for_height(1),
        patterned_hash(63),
        [0_u8; 64],
        nonzero_signature(64),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    require_validation_error(meta.validate_structural(), "merkle_root is all zeros")
}

#[test]
fn block_47_non_genesis_rejects_zero_previous_hash() -> TestResult {
    let meta = BlockMetadata::new(
        1,
        timestamp_for_height(1),
        [0_u8; 64],
        patterned_hash(65),
        nonzero_signature(66),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    require_validation_error(meta.validate_structural(), "previous_hash is all zeros")
}

#[test]
fn block_48_non_genesis_rejects_zero_guardian_signature() -> TestResult {
    let meta = BlockMetadata::new(
        1,
        timestamp_for_height(1),
        patterned_hash(67),
        patterned_hash(68),
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    require_validation_error(
        meta.validate_structural(),
        "guardian_signature is all zeros",
    )
}

#[test]
fn block_49_non_genesis_rejects_merkle_equal_previous_hash() -> TestResult {
    let same_hash = patterned_hash(69);
    let meta = BlockMetadata::new(
        1,
        timestamp_for_height(1),
        same_hash,
        same_hash,
        nonzero_signature(70),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    require_validation_error(meta.validate_structural(), "merkle_root == previous_hash")
}

#[test]
fn block_50_set_and_borrow_puzzle_proof() -> TestResult {
    let mut meta = valid_metadata(5, 71);
    let proof = valid_proof_for(meta.index, meta.previous_hash, 777_u128)?;

    meta.set_puzzle_proof(Some(proof.clone()));

    match meta.puzzle_proof() {
        Some(borrowed) => ensure_eq(
            borrowed,
            &proof,
            "borrowed proof should match inserted proof",
        ),
        None => Err(fail("expected puzzle proof after set_puzzle_proof(Some)")),
    }
}

#[test]
fn block_51_clear_puzzle_proof() -> TestResult {
    let mut meta = valid_metadata(5, 72);
    let proof = valid_proof_for(meta.index, meta.previous_hash, 888_u128)?;

    meta.set_puzzle_proof(Some(proof));
    meta.set_puzzle_proof(None);

    ensure(
        meta.puzzle_proof().is_none(),
        "set_puzzle_proof(None) should clear proof",
    )
}

#[test]
fn block_52_no_puzzle_commitment_bytes_are_zero() -> TestResult {
    let meta = valid_metadata(5, 73);

    let commitment = meta.puzzle_commitment_bytes()?;

    ensure(
        is_all_zero_64(&commitment),
        "missing puzzle proof should commit to zero bytes",
    )
}

#[test]
fn block_53_no_puzzle_commitment_hex_is_128_zero_chars() -> TestResult {
    let meta = valid_metadata(5, 74);

    let commitment_hex = meta.puzzle_commitment_hex()?;

    ensure_eq(
        &commitment_hex,
        &"0".repeat(128),
        "missing puzzle proof hex should be 128 zeros",
    )
}

#[test]
fn block_54_puzzle_commitment_is_nonzero_when_proof_present() -> TestResult {
    let mut meta = valid_metadata(5, 75);
    let proof = valid_proof_for(meta.index, meta.previous_hash, 999_u128)?;
    meta.set_puzzle_proof(Some(proof));

    let commitment = meta.puzzle_commitment_bytes()?;

    ensure(
        !is_all_zero_64(&commitment),
        "present puzzle proof should not commit to all zeros",
    )
}

#[test]
fn block_55_puzzle_commitment_is_deterministic() -> TestResult {
    let mut first = valid_metadata(5, 76);
    let mut second = valid_metadata(5, 76);
    let proof = valid_proof_for(first.index, first.previous_hash, 1000_u128)?;

    first.set_puzzle_proof(Some(proof.clone()));
    second.set_puzzle_proof(Some(proof));

    let first_commitment = first.puzzle_commitment_hex()?;
    let second_commitment = second.puzzle_commitment_hex()?;

    ensure_eq(
        &first_commitment,
        &second_commitment,
        "same proof should produce same commitment",
    )
}

#[test]
fn block_56_puzzle_commitment_changes_when_output_changes() -> TestResult {
    let mut first = valid_metadata(5, 77);
    let mut second = valid_metadata(5, 77);
    let first_proof = valid_proof_for(first.index, first.previous_hash, 1001_u128)?;
    let second_proof = valid_proof_for(second.index, second.previous_hash, 1002_u128)?;

    first.set_puzzle_proof(Some(first_proof));
    second.set_puzzle_proof(Some(second_proof));

    let first_commitment = first.puzzle_commitment_hex()?;
    let second_commitment = second.puzzle_commitment_hex()?;

    ensure_ne(
        &first_commitment,
        &second_commitment,
        "different proof output should change commitment",
    )
}

#[test]
fn block_57_validate_structural_accepts_aligned_puzzle_proof() -> TestResult {
    let mut meta = valid_metadata(6, 78);
    let proof = valid_proof_for(meta.index, meta.previous_hash, 1003_u128)?;
    meta.set_puzzle_proof(Some(proof));

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_58_validate_structural_rejects_puzzle_height_mismatch() -> TestResult {
    let mut meta = valid_metadata(6, 79);
    let proof = valid_proof_for(meta.index.saturating_add(1), meta.previous_hash, 1004_u128)?;
    meta.set_puzzle_proof(Some(proof));

    require_validation_error(meta.validate_structural(), "puzzle_proof.height")
}

#[test]
fn block_59_validate_structural_rejects_puzzle_previous_hash_mismatch() -> TestResult {
    let mut meta = valid_metadata(6, 80);
    let proof = valid_proof_for(meta.index, patterned_hash(210), 1005_u128)?;
    meta.set_puzzle_proof(Some(proof));

    require_validation_error(meta.validate_structural(), "puzzle_proof.prev_block_hash")
}

#[test]
fn block_60_metadata_hash_changes_when_puzzle_proof_added() -> TestResult {
    let mut meta = valid_metadata(6, 81);
    let before = meta.compute_hash()?;
    let proof = valid_proof_for(meta.index, meta.previous_hash, 1006_u128)?;
    meta.set_puzzle_proof(Some(proof));

    let after = meta.compute_hash()?;

    ensure_ne(
        &before,
        &after,
        "adding puzzle proof should change metadata hash",
    )
}

#[test]
fn block_61_from_bytes_rejects_packet_with_puzzle_height_mismatch() -> TestResult {
    let mut meta = valid_metadata(6, 82);

    let proof = valid_proof_for(meta.index.saturating_add(1), meta.previous_hash, 1007_u128)?;

    meta.set_puzzle_proof(Some(proof));

    // IMPORTANT:
    // Do NOT use meta.to_bytes(); it validates and returns the error before
    // from_bytes() is exercised. Encode directly to simulate hostile input.
    let bytes = postcard::to_allocvec(&meta)?;

    require_validation_error(BlockMetadata::from_bytes(&bytes), "puzzle_proof.height")
}

#[test]
fn block_62_from_bytes_rejects_packet_with_puzzle_prev_hash_mismatch() -> TestResult {
    let mut meta = valid_metadata(6, 83);

    let proof = valid_proof_for(meta.index, patterned_hash(211), 1008_u128)?;

    meta.set_puzzle_proof(Some(proof));

    let bytes = postcard::to_allocvec(&meta)?;

    require_validation_error(
        BlockMetadata::from_bytes(&bytes),
        "puzzle_proof.prev_block_hash",
    )
}

#[test]
fn block_63_validate_against_now_accepts_current_timestamp() -> TestResult {
    let now = timestamp_for_height(7);
    let mut meta = valid_metadata(7, 84);
    meta.timestamp = now;

    meta.validate_against_now(now)?;
    Ok(())
}

#[test]
fn block_64_validate_against_now_accepts_future_boundary() -> TestResult {
    let now = timestamp_for_height(7);
    let mut meta = valid_metadata(7, 85);
    meta.timestamp = now.saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS);

    meta.validate_against_now(now)?;
    Ok(())
}

#[test]
fn block_65_validate_against_now_rejects_too_far_future() -> TestResult {
    let now = timestamp_for_height(7);
    let mut meta = valid_metadata(7, 86);
    meta.timestamp = now
        .saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS)
        .saturating_add(1);

    require_validation_error(
        meta.validate_against_now(now),
        "timestamp too far in future",
    )
}

#[test]
fn block_66_validate_against_now_uses_saturating_add_at_u64_max() -> TestResult {
    let mut meta = valid_metadata(7, 87);
    meta.timestamp = u64::MAX;

    require_validation_error(
        meta.validate_against_now(u64::MAX),
        "timestamp above UNIX_9999_SECS",
    )
}

#[test]
fn block_67_validate_timestamp_accepts_exact_block_interval() -> TestResult {
    let previous_timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS;
    let mut meta = valid_metadata(8, 88);
    meta.timestamp =
        previous_timestamp.saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS);

    meta.validate_timestamp(previous_timestamp)?;
    Ok(())
}

#[test]
fn block_68_validate_timestamp_accepts_later_than_interval() -> TestResult {
    let previous_timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS;
    let mut meta = valid_metadata(8, 89);
    meta.timestamp = previous_timestamp
        .saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS)
        .saturating_add(1);

    meta.validate_timestamp(previous_timestamp)?;
    Ok(())
}

#[test]
fn block_69_validate_timestamp_rejects_too_soon() -> TestResult {
    let previous_timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS;

    let mut meta = valid_metadata(8, 90);
    meta.timestamp = previous_timestamp
        .saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS)
        .saturating_sub(1);

    // Current TimePolicy wording is:
    // "block.timestamp too early: block_ts=... parent_ts=... min_delta_secs=..."
    require_validation_error(
        meta.validate_timestamp(previous_timestamp),
        "block.timestamp too early",
    )
}

#[test]
fn block_70_validate_timestamp_rejects_checked_add_overflow() -> TestResult {
    let meta = valid_metadata(8, 91);

    // Current TimePolicy rejects the parent timestamp structurally first:
    // "parent_block.timestamp: timestamp above UNIX_9999_SECS: ..."
    require_validation_error(meta.validate_timestamp(u64::MAX), "parent_block.timestamp")
}

#[test]
fn block_71_validate_size_accepts_min_size() -> TestResult {
    let mut meta = valid_metadata(9, 92);
    meta.size = GlobalConfiguration::MIN_BLOCK_SIZE;

    meta.validate_size()?;
    Ok(())
}

#[test]
fn block_72_validate_size_accepts_max_size() -> TestResult {
    let mut meta = valid_metadata(9, 93);
    meta.size = GlobalConfiguration::MAX_BLOCK_SIZE;

    meta.validate_size()?;
    Ok(())
}

#[test]
fn block_73_validate_size_rejects_below_minimum() -> TestResult {
    let mut meta = valid_metadata(9, 94);
    meta.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);

    require_validation_error(meta.validate_size(), "below minimum")
}

#[test]
fn block_74_validate_size_rejects_above_maximum() -> TestResult {
    let mut meta = valid_metadata(9, 95);
    meta.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);

    require_validation_error(meta.validate_size(), "exceeds MAX_BLOCK_SIZE")
}

#[test]
fn block_75_fuzz_hash_and_roundtrip_many_valid_metadata_values() -> TestResult {
    let mut seed = 1_u8;

    for index in 1_u64..=128_u64 {
        let meta = valid_metadata(index, seed);

        meta.validate_structural()?;

        let first_hash = meta.compute_hash()?;
        let second_hash = meta.compute_hash()?;
        ensure_eq(
            &first_hash,
            &second_hash,
            "metadata hash should be deterministic during fuzz pass",
        )?;

        let bytes = meta.to_bytes()?;
        let decoded = BlockMetadata::from_bytes(&bytes)?;
        ensure_eq(
            &decoded,
            &meta,
            "metadata should roundtrip during fuzz pass",
        )?;

        seed = seed.wrapping_add(3);
    }

    Ok(())
}

#[test]
fn block_76_fuzz_rejects_structural_poison_variants() -> TestResult {
    let mut seed = 20_u8;

    for index in 1_u64..=64_u64 {
        let base = valid_metadata(index, seed);

        let mut zero_prev = base.clone();
        zero_prev.previous_hash = [0_u8; 64];
        require_validation_error(zero_prev.validate_structural(), "previous_hash")?;

        let mut zero_merkle = base.clone();
        zero_merkle.merkle_root = [0_u8; 64];
        require_validation_error(zero_merkle.validate_structural(), "merkle_root")?;

        let mut zero_signature = base.clone();
        zero_signature.guardian_signature = [0_u8; ml_dsa_65::SIG_LEN];
        require_validation_error(zero_signature.validate_structural(), "guardian_signature")?;

        let mut small_size = base;
        small_size.size = 0;
        require_validation_error(small_size.validate_structural(), "implausibly small")?;

        seed = seed.wrapping_add(5);
    }

    Ok(())
}

#[test]
fn block_77_property_unique_hashes_for_unique_metadata_vectors() -> TestResult {
    let mut hashes = BTreeSet::new();
    let mut seed = 40_u8;

    for index in 1_u64..=256_u64 {
        let meta = valid_metadata(index, seed);
        let hash = meta.compute_hash()?;
        let inserted = hashes.insert(hash);

        ensure(
            inserted,
            "unique metadata vectors should produce unique hashes",
        )?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &hashes.len(),
        &256_usize,
        "property pass should collect 256 unique hashes",
    )
}

#[test]
fn block_78_adversarial_network_sim_rejects_tampered_serialized_packets() -> TestResult {
    let mut seed = 60_u8;

    for index in 1_u64..=64_u64 {
        let valid = valid_metadata(index, seed);

        let valid_packet = valid.to_bytes()?;
        let valid_decoded = BlockMetadata::from_bytes(&valid_packet)?;

        ensure_eq(
            &valid_decoded,
            &valid,
            "valid network packet should decode before tamper checks",
        )?;

        // Tamper #1: zero guardian signature.
        let mut zero_signature = valid.clone();
        zero_signature.guardian_signature = [0_u8; ml_dsa_65::SIG_LEN];

        // Encode directly so from_bytes() is the validation boundary.
        let zero_signature_packet = postcard::to_allocvec(&zero_signature)?;

        require_validation_error(
            BlockMetadata::from_bytes(&zero_signature_packet),
            "guardian_signature",
        )?;

        // Tamper #2: merkle_root equals previous_hash.
        let mut equal_hashes = valid.clone();
        equal_hashes.merkle_root = equal_hashes.previous_hash;

        // Encode directly so from_bytes() is the validation boundary.
        let equal_hashes_packet = postcard::to_allocvec(&equal_hashes)?;

        require_validation_error(
            BlockMetadata::from_bytes(&equal_hashes_packet),
            "merkle_root == previous_hash",
        )?;

        seed = seed.wrapping_add(2);
    }

    Ok(())
}

#[test]
fn block_79_adversarial_network_sim_rejects_mutated_hash_commitments() -> TestResult {
    let mut seed = 80_u8;

    for index in 1_u64..=64_u64 {
        let mut meta = valid_metadata(index, seed);

        let proof = valid_proof_for(
            meta.index,
            meta.previous_hash,
            9000_u128.saturating_add(index as u128),
        )?;

        meta.set_puzzle_proof(Some(proof));

        let valid_packet = meta.to_bytes()?;
        let valid_decoded = BlockMetadata::from_bytes(&valid_packet)?;

        ensure_eq(
            &valid_decoded,
            &meta,
            "valid puzzle metadata packet should decode",
        )?;

        let mut bad_prev = meta.clone();
        flip_first_byte(&mut bad_prev.previous_hash);

        let bad_prev_packet = postcard::to_allocvec(&bad_prev)?;

        require_validation_error(
            BlockMetadata::from_bytes(&bad_prev_packet),
            "puzzle_proof.prev_block_hash",
        )?;

        seed = seed.wrapping_add(3);
    }

    Ok(())
}

#[test]
fn block_80_load_test_many_metadata_roundtrips_and_hashes() -> TestResult {
    let mut seen_hashes = BTreeSet::new();
    let mut total_encoded_bytes = 0_usize;
    let mut seed = 100_u8;

    for index in 1_u64..=512_u64 {
        let mut meta = valid_metadata(index, seed);

        if index % 2 == 0 {
            let proof = valid_proof_for(
                meta.index,
                meta.previous_hash,
                10_000_u128.saturating_add(index as u128),
            )?;
            meta.set_puzzle_proof(Some(proof));
        }

        meta.validate_structural()?;

        let hash = meta.compute_hash()?;
        let inserted = seen_hashes.insert(hash);
        ensure(
            inserted,
            "load test should not produce duplicate metadata hashes",
        )?;

        let bytes = meta.to_bytes()?;
        total_encoded_bytes = total_encoded_bytes.saturating_add(bytes.len());

        let decoded = BlockMetadata::from_bytes(&bytes)?;
        ensure_eq(
            &decoded,
            &meta,
            "load test encoded metadata should decode exactly",
        )?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &seen_hashes.len(),
        &512_usize,
        "load test should process 512 unique metadata hashes",
    )?;
    ensure(
        total_encoded_bytes > 0,
        "load test should account for encoded bytes",
    )
}

#[test]
fn block_81_compute_hash_matches_remzarhash_reference_vector() -> TestResult {
    let meta = valid_metadata(10, 120);

    let direct = meta.compute_hash()?;
    let reference = RemzarHash::compute_data_hash(&meta)?;

    ensure_eq(
        &direct,
        &reference,
        "BlockMetadata::compute_hash should match RemzarHash::compute_data_hash",
    )
}

#[test]
fn block_82_puzzle_commitment_hex_matches_hex_encoded_commitment_bytes() -> TestResult {
    let mut meta = valid_metadata(10, 121);
    let proof = valid_proof_for(meta.index, meta.previous_hash, 44_001_u128)?;
    meta.set_puzzle_proof(Some(proof));

    let commitment_bytes = meta.puzzle_commitment_bytes()?;
    let commitment_hex = meta.puzzle_commitment_hex()?;

    ensure_eq(
        &commitment_hex,
        &hex::encode(commitment_bytes),
        "puzzle_commitment_hex should be hex encoding of puzzle_commitment_bytes",
    )
}

#[test]
fn block_83_max_index_and_max_size_valid_metadata_roundtrips() -> TestResult {
    let mut meta = valid_metadata(10_000_000_u64, 122);
    meta.size = GlobalConfiguration::MAX_BLOCK_SIZE;

    meta.validate_structural()?;
    meta.validate_size()?;

    let bytes = meta.to_bytes()?;
    let decoded = BlockMetadata::from_bytes(&bytes)?;

    ensure_eq(
        &decoded,
        &meta,
        "max-bound valid metadata should roundtrip through postcard bytes",
    )
}

#[test]
fn block_84_genesis_metadata_allows_nonzero_previous_hash_equal_to_merkle_root() -> TestResult {
    let shared_hash = patterned_hash(123);
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        shared_hash,
        shared_hash,
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_85_genesis_metadata_rejects_size_below_minimum_before_genesis_rules() -> TestResult {
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        [0_u8; 64],
        patterned_hash(124),
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1),
    );

    require_validation_error(meta.validate_structural(), "implausibly small")
}

#[test]
fn block_86_genesis_metadata_rejects_size_above_maximum_before_genesis_rules() -> TestResult {
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        [0_u8; 64],
        patterned_hash(125),
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1),
    );

    require_validation_error(meta.validate_structural(), "fields out of bounds")
}

#[test]
fn block_87_genesis_metadata_rejects_timestamp_below_minimum_before_genesis_rules() -> TestResult {
    let meta = BlockMetadata::new(
        0,
        GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1),
        [0_u8; 64],
        patterned_hash(126),
        [0_u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    // Current TimePolicy wording is:
    // "BlockMetadata.timestamp: timestamp below UNIX_2000_SECS: ..."
    require_validation_error(meta.validate_structural(), "timestamp below")
}

#[test]
fn block_88_non_genesis_accepts_ff_previous_hash_when_other_fields_are_valid() -> TestResult {
    let meta = BlockMetadata::new(
        11,
        timestamp_for_height(11),
        [0xFF_u8; 64],
        patterned_hash(127),
        nonzero_signature(128),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_89_non_genesis_accepts_ff_merkle_root_when_other_fields_are_valid() -> TestResult {
    let meta = BlockMetadata::new(
        11,
        timestamp_for_height(11),
        patterned_hash(129),
        [0xFF_u8; 64],
        nonzero_signature(130),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    meta.validate_structural()?;
    Ok(())
}

#[test]
fn block_90_non_genesis_max_size_with_aligned_puzzle_proof_validates() -> TestResult {
    let mut meta = valid_metadata(12, 131);
    meta.size = GlobalConfiguration::MAX_BLOCK_SIZE;
    let proof = valid_proof_for(meta.index, meta.previous_hash, 44_002_u128)?;
    meta.set_puzzle_proof(Some(proof));

    meta.validate_structural()?;
    meta.validate_size()?;
    Ok(())
}

#[test]
fn block_91_metadata_rejects_manual_puzzle_proof_with_zero_output() -> TestResult {
    let mut meta = valid_metadata(12, 132);
    let proof = BlockPuzzleProof {
        height: meta.index,
        validator: canonical_validator(),
        prev_block_hash: meta.previous_hash,
        output: 0_u128,
    };
    meta.set_puzzle_proof(Some(proof));

    require_validation_error(meta.validate_structural(), "output cannot be 0")
}

#[test]
fn block_92_metadata_rejects_manual_puzzle_proof_with_empty_validator() -> TestResult {
    let mut meta = valid_metadata(12, 133);
    let proof = BlockPuzzleProof {
        height: meta.index,
        validator: String::new(),
        prev_block_hash: meta.previous_hash,
        output: 44_003_u128,
    };
    meta.set_puzzle_proof(Some(proof));

    require_validation_error(meta.validate_structural(), "validator is empty")
}

#[test]
fn block_93_metadata_rejects_manual_puzzle_proof_with_ff_prev_hash_sentinel() -> TestResult {
    let mut meta = BlockMetadata::new(
        12,
        timestamp_for_height(12),
        [0xFF_u8; 64],
        patterned_hash(134),
        nonzero_signature(135),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );
    let proof = BlockPuzzleProof {
        height: meta.index,
        validator: canonical_validator(),
        prev_block_hash: meta.previous_hash,
        output: 44_004_u128,
    };
    meta.set_puzzle_proof(Some(proof));

    require_validation_error(meta.validate_structural(), "invalid sentinel")
}

#[test]
fn block_94_metadata_rejects_manual_puzzle_proof_with_too_long_validator() -> TestResult {
    let mut meta = valid_metadata(12, 136);
    let proof = BlockPuzzleProof {
        height: meta.index,
        validator: "r".repeat(257),
        prev_block_hash: meta.previous_hash,
        output: 44_005_u128,
    };
    meta.set_puzzle_proof(Some(proof));

    require_validation_error(meta.validate_structural(), "validator too long")
}

#[test]
fn block_95_verify_hash_with_128_non_hex_chars_returns_false_not_error() -> TestResult {
    let meta = valid_metadata(13, 137);
    let invalid_hex_but_valid_len = "z".repeat(128);

    let verified = meta.verify_hash(&invalid_hex_but_valid_len)?;

    ensure(
        !verified,
        "verify_hash only length-checks expected hash and should return false for wrong 128-char input",
    )
}

#[test]
fn block_96_verify_hash_with_uppercase_real_hash_returns_false() -> TestResult {
    let meta = valid_metadata(13, 138);
    let uppercase_hash = meta.compute_hash()?.to_ascii_uppercase();

    let verified = meta.verify_hash(&uppercase_hash)?;

    ensure(
        !verified,
        "metadata hashes are lowercase hex, so uppercase expected hash should not verify",
    )
}

#[test]
fn block_97_set_merkle_root_with_structured_transaction_vectors_is_stable() -> TestResult {
    #[derive(serde::Serialize)]
    struct TestTransaction {
        from: String,
        to: String,
        amount: u64,
        nonce: u64,
    }

    let transactions = vec![
        TestTransaction {
            from: String::from("alice"),
            to: String::from("bob"),
            amount: 100,
            nonce: 1,
        },
        TestTransaction {
            from: String::from("bob"),
            to: String::from("carol"),
            amount: 50,
            nonce: 2,
        },
    ];

    let mut first = valid_metadata(13, 139);
    let mut second = valid_metadata(13, 140);

    first.set_merkle_root(&transactions)?;
    second.set_merkle_root(&transactions)?;

    ensure_eq(
        &first.merkle_root,
        &second.merkle_root,
        "structured transaction vector should produce stable merkle root",
    )?;
    ensure(
        !is_all_zero_64(&first.merkle_root),
        "structured transaction merkle root should not be all zeros",
    )
}

#[test]
fn block_98_from_bytes_rejects_truncated_valid_packets() -> TestResult {
    let meta = valid_metadata(14, 141);
    let bytes = meta.to_bytes()?;
    let truncation_limit = bytes.len().min(32);

    for prefix_len in 0..truncation_limit {
        let truncated = bytes
            .get(0..prefix_len)
            .ok_or_else(|| fail("prefix length should be in bounds"))?;

        require_serialization_error(
            BlockMetadata::from_bytes(truncated),
            "Deserialize BlockMetadata failed",
        )?;
    }

    Ok(())
}

#[test]
fn block_99_validate_size_accepts_in_range_claimed_size_without_requiring_exact_serialized_size()
-> TestResult {
    let mut meta = valid_metadata(14, 142);
    let encoded_len = meta.to_bytes()?.len();
    let claimed_size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_add(42);

    ensure_ne(
        &usize::try_from(claimed_size).map_err(|_| fail("claimed size should fit usize"))?,
        &encoded_len,
        "test setup should use a claimed size different from actual encoded length",
    )?;

    meta.size = claimed_size;
    meta.validate_size()?;
    Ok(())
}

#[test]
fn block_100_large_vector_merkle_root_hash_and_roundtrip_is_deterministic() -> TestResult {
    let transactions: Vec<String> = (0_u64..512_u64)
        .map(|index| format!("remzar-load-vector-transaction-{index}"))
        .collect();

    let mut first = valid_metadata(15, 143);
    let mut second = valid_metadata(15, 143);

    first.set_merkle_root(&transactions)?;
    second.set_merkle_root(&transactions)?;

    ensure_eq(
        &first.merkle_root,
        &second.merkle_root,
        "large vector merkle root should be deterministic",
    )?;

    let first_hash = first.compute_hash()?;
    let second_hash = second.compute_hash()?;
    ensure_eq(
        &first_hash,
        &second_hash,
        "large vector metadata hash should be deterministic",
    )?;

    let encoded = first.to_bytes()?;
    let decoded = BlockMetadata::from_bytes(&encoded)?;

    ensure_eq(
        &decoded,
        &first,
        "large vector metadata should roundtrip through to_bytes/from_bytes",
    )
}
