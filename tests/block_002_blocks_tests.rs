// tests/block_002_blocks_tests.rs

use fips204::ml_dsa_65;
use fips204::traits::KeyGen;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use std::collections::BTreeSet;
use std::error::Error as StdError;

type TestResult = Result<(), Box<dyn StdError>>;

fn alternate_wallet() -> String {
    let mut wallet = String::from("r");
    for _ in 0..128 {
        wallet.push('2');
    }
    wallet
}

fn serialize_block_without_prevalidation(block: &Block) -> Result<Vec<u8>, Box<dyn StdError>> {
    Ok(postcard::to_allocvec(block)?)
}

fn valid_puzzle_proof_for(
    index: u64,
    previous_hash: [u8; 64],
    output: u128,
) -> Result<BlockPuzzleProof, ErrorDetection> {
    BlockPuzzleProof::new(index, canonical_wallet(), previous_hash, output)
}

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

fn require_validation_error_any<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { .. }) => Ok(()),
        Err(other) => Err(fail(format!("expected ValidationError, got {other:?}"))),
        Ok(_) => Err(fail("expected ValidationError, got Ok")),
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

fn require_signature_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::SignatureVerificationFailed { .. }) => Ok(()),
        Err(other) => Err(fail(format!(
            "expected SignatureVerificationFailed, got {other:?}"
        ))),
        Ok(_) => Err(fail("expected SignatureVerificationFailed, got Ok")),
    }
}

fn canonical_wallet() -> String {
    let mut wallet = String::from("r");
    for _ in 0..128 {
        wallet.push('1');
    }
    wallet
}

fn uppercase_wallet() -> String {
    let mut wallet = String::from("R");
    for _ in 0..128 {
        wallet.push('A');
    }
    wallet
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

fn valid_block(index: u64, seed: u8) -> Result<Block, ErrorDetection> {
    Block::new(
        valid_metadata(index, seed),
        Some(format!("batch-key-{seed}")),
        canonical_wallet(),
        50_u64,
    )
}

fn valid_genesis_style_block(seed: u8) -> Result<Block, ErrorDetection> {
    Block::new(
        valid_metadata(0, seed),
        None,
        String::new(),
        GlobalConfiguration::GENESIS_REWARD,
    )
}

fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
}

fn decode_hash_hex(hex_hash: &str) -> Result<[u8; 64], Box<dyn StdError>> {
    let mut out = [0_u8; 64];
    hex::decode_to_slice(hex_hash, &mut out)?;
    Ok(out)
}

fn first_byte_plus_one(bytes: &mut [u8; 64]) {
    for byte in bytes.iter_mut().take(1) {
        *byte = byte.wrapping_add(1);
    }
}

#[test]
fn blocks_01_new_allows_genesis_empty_miner() -> TestResult {
    let block = valid_genesis_style_block(1)?;

    ensure_eq(
        &block.metadata.index,
        &0_u64,
        "genesis-style block should have index 0",
    )?;
    ensure_eq(
        &block.miner,
        &String::new(),
        "genesis-style block may have empty miner",
    )?;
    ensure_eq(
        &block.reward,
        &GlobalConfiguration::GENESIS_REWARD,
        "genesis reward should be preserved",
    )
}

#[test]
fn blocks_02_new_rejects_non_genesis_empty_miner() -> TestResult {
    require_validation_error(
        Block::new(valid_metadata(1, 2), None, String::new(), 1_u64),
        "Block.miner missing",
    )
}

#[test]
fn blocks_03_new_canonicalizes_uppercase_wallet_miner() -> TestResult {
    let block = Block::new(valid_metadata(1, 3), None, uppercase_wallet(), 1_u64)?;

    let expected = uppercase_wallet().to_ascii_lowercase();

    ensure_eq(
        &block.miner,
        &expected,
        "Block::new should canonicalize uppercase wallet input",
    )
}

#[test]
fn blocks_04_new_rejects_invalid_miner_wallet() -> TestResult {
    require_validation_error_any(Block::new(
        valid_metadata(1, 4),
        None,
        String::from("not-a-remzar-wallet"),
        1_u64,
    ))
}

#[test]
fn blocks_05_new_rejects_batch_key_over_4096_bytes() -> TestResult {
    let too_long = "x".repeat(4097);

    require_validation_error(
        Block::new(
            valid_metadata(1, 5),
            Some(too_long),
            canonical_wallet(),
            1_u64,
        ),
        "batch_key too long",
    )
}

#[test]
fn blocks_06_new_accepts_batch_key_exactly_4096_bytes() -> TestResult {
    let exact = "x".repeat(4096);

    let block = Block::new(
        valid_metadata(1, 6),
        Some(exact.clone()),
        canonical_wallet(),
        1_u64,
    )?;

    ensure_eq(
        &block.batch_key,
        &Some(exact),
        "4096-byte batch_key should be accepted",
    )
}

#[test]
fn blocks_07_miner_wallet_returns_stored_miner() -> TestResult {
    let block = valid_block(1, 7)?;
    let miner = canonical_wallet();

    ensure_eq(
        &block.miner_wallet(),
        &miner.as_str(),
        "miner_wallet should return stored canonical miner",
    )
}

#[test]
fn blocks_08_hash_hex_returns_128_lowercase_hex_chars() -> TestResult {
    let block = valid_block(1, 8)?;
    let hash_hex = block.hash_hex();

    ensure_eq(&hash_hex.len(), &128_usize, "hash_hex length should be 128")?;
    ensure(
        is_lowercase_hex(&hash_hex),
        "hash_hex should be lowercase hex",
    )
}

#[test]
fn blocks_09_block_hash_matches_compute_block_hash_on_new_block() -> TestResult {
    let block = valid_block(1, 9)?;
    let computed_hex = block.compute_block_hash()?;
    let computed_bytes = decode_hash_hex(&computed_hex)?;

    ensure_eq(
        &block.block_hash,
        &computed_bytes,
        "stored block_hash should match compute_block_hash output",
    )
}

#[test]
fn blocks_10_verify_block_hash_accepts_new_block() -> TestResult {
    let block = valid_block(1, 10)?;

    ensure(
        block.verify_block_hash()?,
        "new block should verify its stored hash",
    )
}

#[test]
fn blocks_11_verify_block_hash_detects_tampered_hash_bytes() -> TestResult {
    let mut block = valid_block(1, 11)?;
    first_byte_plus_one(&mut block.block_hash);

    ensure(
        !block.verify_block_hash()?,
        "verify_block_hash should return false for tampered block_hash",
    )
}

#[test]
fn blocks_12_compute_block_hash_is_deterministic() -> TestResult {
    let block = valid_block(1, 12)?;

    let first = block.compute_block_hash()?;
    let second = block.compute_block_hash()?;

    ensure_eq(
        &first,
        &second,
        "compute_block_hash should be deterministic",
    )
}

#[test]
fn blocks_13_none_batch_key_and_empty_batch_key_hash_the_same() -> TestResult {
    let metadata = valid_metadata(1, 13);

    let none_block = Block::new(metadata.clone(), None, canonical_wallet(), 1_u64)?;
    let empty_block = Block::new(metadata, Some(String::new()), canonical_wallet(), 1_u64)?;

    ensure_eq(
        &none_block.block_hash,
        &empty_block.block_hash,
        "None and Some(\"\") batch_key should have same consensus hash",
    )
}

#[test]
fn blocks_14_different_nonempty_batch_keys_change_hash() -> TestResult {
    let metadata = valid_metadata(1, 14);

    let first = Block::new(
        metadata.clone(),
        Some(String::from("batch-a")),
        canonical_wallet(),
        1_u64,
    )?;
    let second = Block::new(
        metadata,
        Some(String::from("batch-b")),
        canonical_wallet(),
        1_u64,
    )?;

    ensure_ne(
        &first.block_hash,
        &second.block_hash,
        "different nonempty batch keys should change block hash",
    )
}

#[test]
fn blocks_15_different_rewards_change_hash() -> TestResult {
    let metadata = valid_metadata(1, 15);

    let first = Block::new(metadata.clone(), None, canonical_wallet(), 1_u64)?;
    let second = Block::new(metadata, None, canonical_wallet(), 2_u64)?;

    ensure_ne(
        &first.block_hash,
        &second.block_hash,
        "reward is part of block hash preimage",
    )
}

#[test]
fn blocks_16_different_previous_hash_changes_hash() -> TestResult {
    let first = valid_block(1, 16)?;
    let second = valid_block(1, 17)?;

    ensure_ne(
        &first.block_hash,
        &second.block_hash,
        "metadata previous_hash should affect block hash",
    )
}

#[test]
fn blocks_17_different_merkle_root_changes_hash() -> TestResult {
    let mut metadata = valid_metadata(1, 18);
    let first = Block::new(metadata.clone(), None, canonical_wallet(), 1_u64)?;

    metadata.merkle_root = patterned_hash(200);
    let second = Block::new(metadata, None, canonical_wallet(), 1_u64)?;

    ensure_ne(
        &first.block_hash,
        &second.block_hash,
        "metadata merkle_root should affect block hash",
    )
}

#[test]
fn blocks_18_different_guardian_signature_changes_hash() -> TestResult {
    let mut metadata = valid_metadata(1, 19);
    let first = Block::new(metadata.clone(), None, canonical_wallet(), 1_u64)?;

    metadata.guardian_signature = nonzero_signature(201);
    let second = Block::new(metadata, None, canonical_wallet(), 1_u64)?;

    ensure_ne(
        &first.block_hash,
        &second.block_hash,
        "guardian_signature should affect block hash",
    )
}

#[test]
fn blocks_19_validate_accepts_valid_non_genesis_block() -> TestResult {
    let block = valid_block(1, 20)?;

    block.validate(None)?;
    Ok(())
}

#[test]
fn blocks_20_validate_rejects_invalid_metadata_zero_signature() -> TestResult {
    let mut block = valid_block(1, 21)?;
    block.metadata.guardian_signature = [0_u8; ml_dsa_65::SIG_LEN];

    require_validation_error(block.validate(None), "guardian_signature")
}

#[test]
fn blocks_21_validate_rejects_block_hash_mismatch() -> TestResult {
    let mut block = valid_block(1, 22)?;
    block.reward = block.reward.saturating_add(1);

    require_validation_error(block.validate(None), "Block hash mismatch")
}

#[test]
fn blocks_22_validate_accepts_genesis_empty_miner() -> TestResult {
    let block = valid_genesis_style_block(23)?;

    block.validate(None)?;
    Ok(())
}

#[test]
fn blocks_23_validate_rejects_non_genesis_empty_miner_after_manual_tamper() -> TestResult {
    let mut block = valid_block(1, 24)?;
    block.miner.clear();

    require_validation_error(block.validate(None), "Block.miner missing")
}

#[test]
fn blocks_24_validate_rejects_manual_batch_key_over_4096_bytes() -> TestResult {
    let mut block = valid_block(1, 25)?;
    block.batch_key = Some("x".repeat(4097));

    require_validation_error(block.validate(None), "batch_key too long")
}

#[test]
fn blocks_25_serialize_for_storage_roundtrips_through_deserialize_from_storage() -> TestResult {
    let block = valid_block(1, 26)?;
    let bytes = block.serialize_for_storage()?;
    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded,
        &block,
        "serialize_for_storage should roundtrip through deserialize_from_storage",
    )
}

#[test]
fn blocks_26_deserialize_from_storage_rejects_too_short_payload() -> TestResult {
    let min_len = usize::try_from(GlobalConfiguration::MIN_BLOCK_SIZE)
        .map_err(|_| fail("MIN_BLOCK_SIZE should fit usize"))?;
    let too_short_len = min_len.saturating_sub(1);
    let bytes = vec![0_u8; too_short_len];

    require_serialization_error(
        Block::deserialize_from_storage(&bytes),
        "Block data too short",
    )
}

#[test]
fn blocks_27_deserialize_from_storage_rejects_oversized_payload() -> TestResult {
    let max_len = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| fail("MAX_BLOCK_SIZE should fit usize"))?;
    let bytes = vec![0_u8; max_len.saturating_add(1)];

    require_serialization_error(
        Block::deserialize_from_storage(&bytes),
        "Block data too large",
    )
}

#[test]
fn blocks_28_deserialize_from_storage_accepts_trailing_zero_padding() -> TestResult {
    let block = valid_block(1, 28)?;
    let mut bytes = block.serialize_for_storage()?;
    bytes.extend_from_slice(&[0_u8, 0_u8, 0_u8, 0_u8]);

    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded,
        &block,
        "deserialize_from_storage should accept legacy trailing zero padding",
    )
}

#[test]
fn blocks_29_deserialize_with_sizes_reports_exact_sizes_for_canonical_payload() -> TestResult {
    let block = valid_block(1, 29)?;
    let bytes = block.serialize_for_storage()?;
    let expected_len = bytes.len();

    let (decoded, actual_size, stored_size) = Block::deserialize_with_sizes(&bytes)?;

    ensure_eq(&decoded, &block, "decoded block should match original")?;
    ensure_eq(
        &actual_size,
        &expected_len,
        "actual size should equal canonical payload length",
    )?;
    ensure_eq(
        &stored_size,
        &expected_len,
        "stored size should equal canonical payload length",
    )
}

#[test]
fn blocks_30_deserialize_with_sizes_accepts_padded_payload_and_reports_stored_len() -> TestResult {
    let block = valid_block(1, 30)?;
    let mut bytes = block.serialize_for_storage()?;
    bytes.extend_from_slice(&[0_u8, 0_u8, 0_u8]);

    let stored_len = bytes.len();
    let (decoded, actual_size, stored_size) = Block::deserialize_with_sizes(&bytes)?;

    ensure_eq(
        &decoded,
        &block,
        "decoded padded block should match original",
    )?;
    ensure(actual_size > 0, "actual decoded size should be nonzero")?;
    ensure_eq(
        &stored_size,
        &stored_len,
        "stored size should report raw input length",
    )
}

#[test]
fn blocks_31_deserialize_rejects_non_genesis_zero_block_hash() -> TestResult {
    let mut block = valid_block(1, 31)?;
    block.block_hash = [0_u8; 64];

    let bytes = serialize_block_without_prevalidation(&block)?;

    require_validation_error(
        Block::deserialize_from_storage(&bytes),
        "block_hash is all zeros",
    )
}

#[test]
fn blocks_32_deserialize_canonicalizes_uppercase_miner() -> TestResult {
    let mut block = valid_block(1, 32)?;
    block.miner = uppercase_wallet();

    let bytes = serialize_block_without_prevalidation(&block)?;
    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded.miner,
        &uppercase_wallet().to_ascii_lowercase(),
        "deserialize_from_storage should canonicalize miner wallet",
    )?;

    decoded.validate(None)?;
    Ok(())
}

#[test]
fn blocks_33_deserialize_rejects_non_genesis_missing_miner() -> TestResult {
    let mut block = valid_block(1, 33)?;
    block.miner.clear();

    let bytes = serialize_block_without_prevalidation(&block)?;

    require_validation_error(
        Block::deserialize_from_storage(&bytes),
        "Block.miner missing",
    )
}

#[test]
fn blocks_34_hash_hex_matches_hex_encode_block_hash() -> TestResult {
    let block = valid_block(1, 34)?;
    let expected = hex::encode(block.block_hash);

    ensure_eq(
        &block.hash_hex(),
        &expected,
        "hash_hex should be hex encoding of stored block_hash",
    )
}

#[test]
fn blocks_35_encoded_len_unpadded_matches_storage_serialized_len() -> TestResult {
    let block = valid_block(1, 35)?;
    let bytes = block.serialize_for_storage()?;
    let encoded_len = block.encoded_len_unpadded()?;

    ensure_eq(
        &encoded_len,
        &bytes.len(),
        "encoded_len_unpadded should match canonical storage bytes length",
    )
}

#[test]
fn blocks_36_encoded_len_padded_matches_current_variable_length_storage_len() -> TestResult {
    let block = valid_block(1, 36)?;
    let bytes = block.serialize_for_storage()?;

    ensure_eq(
        &block.encoded_len_padded(),
        &bytes.len(),
        "encoded_len_padded currently returns variable-length storage size",
    )
}

#[test]
fn blocks_37_sign_block_sets_nonzero_guardian_signature_and_updates_hash() -> TestResult {
    let seed = [37_u8; 32];
    let (_vk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let mut block = valid_block(1, 37)?;
    let old_hash = block.block_hash;
    let zero_sig = [0_u8; ml_dsa_65::SIG_LEN];

    block.sign_block(&sk)?;

    ensure_ne(
        &block.metadata.guardian_signature,
        &zero_sig,
        "sign_block should set nonzero guardian signature",
    )?;
    ensure_ne(
        &block.block_hash,
        &old_hash,
        "sign_block should recompute block_hash after embedding signature",
    )?;
    ensure(
        block.verify_block_hash()?,
        "signed block should verify updated block hash",
    )
}

#[test]
fn blocks_38_verify_block_signature_rejects_invalid_signature_bytes() -> TestResult {
    let seed = [38_u8; 32];
    let (vk, _sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let block = valid_block(1, 38)?;

    require_signature_error(block.verify_block_signature(&vk))
}

#[test]
fn blocks_39_property_unique_hashes_for_unique_block_vectors() -> TestResult {
    let mut hashes = BTreeSet::new();
    let mut seed = 39_u8;

    for index in 1_u64..=128_u64 {
        let block = valid_block(index, seed)?;
        let inserted = hashes.insert(block.hash_hex());

        ensure(
            inserted,
            "unique block vectors should produce unique block hashes",
        )?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &hashes.len(),
        &128_usize,
        "property test should collect 128 unique hashes",
    )
}

#[test]
fn blocks_40_adversarial_network_load_roundtrip_and_tamper_detection() -> TestResult {
    let mut seen_hashes = BTreeSet::new();
    let mut seed = 80_u8;
    let mut total_encoded_bytes = 0_usize;

    for index in 1_u64..=256_u64 {
        let mut block = valid_block(index, seed)?;

        if index % 2 == 0 {
            block.batch_key = Some(format!("network-load-batch-key-{index}"));
            let recomputed = block.compute_block_hash()?;
            block.block_hash = decode_hash_hex(&recomputed)?;
        }

        block.validate(None)?;

        let hash = block.hash_hex();
        ensure(
            seen_hashes.insert(hash),
            "network load should not produce duplicate block hashes",
        )?;

        let bytes = block.serialize_for_storage()?;
        total_encoded_bytes = total_encoded_bytes.saturating_add(bytes.len());

        let decoded = Block::deserialize_from_storage(&bytes)?;
        ensure_eq(
            &decoded,
            &block,
            "valid network block packet should roundtrip",
        )?;

        let mut tampered = block.clone();
        tampered.reward = tampered.reward.saturating_add(1);
        require_validation_error(tampered.validate(None), "Block hash mismatch")?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &seen_hashes.len(),
        &256_usize,
        "load simulation should process 256 unique block hashes",
    )?;
    ensure(
        total_encoded_bytes > 0,
        "load simulation should account for encoded bytes",
    )
}

#[test]
fn blocks_41_new_preserves_metadata_batch_miner_reward_and_hash() -> TestResult {
    let metadata = valid_metadata(2, 41);
    let batch_key = Some(String::from("blocks-41-batch"));
    let miner = canonical_wallet();
    let reward = 123_456_u64;

    let block = Block::new(metadata.clone(), batch_key.clone(), miner.clone(), reward)?;

    ensure_eq(&block.metadata, &metadata, "metadata should be preserved")?;
    ensure_eq(
        &block.batch_key,
        &batch_key,
        "batch_key should be preserved",
    )?;
    ensure_eq(&block.miner, &miner, "miner should be preserved")?;
    ensure_eq(&block.reward, &reward, "reward should be preserved")?;
    ensure(
        block.block_hash.iter().any(|byte| *byte != 0),
        "new block_hash should not be all zeros",
    )
}

#[test]
fn blocks_42_new_with_none_batch_key_preserves_none() -> TestResult {
    let block = Block::new(valid_metadata(2, 42), None, canonical_wallet(), 42_u64)?;

    ensure(
        block.batch_key.is_none(),
        "Block::new should preserve None batch_key",
    )
}

#[test]
fn blocks_43_new_with_empty_batch_key_preserves_some_empty_string() -> TestResult {
    let block = Block::new(
        valid_metadata(2, 43),
        Some(String::new()),
        canonical_wallet(),
        43_u64,
    )?;

    ensure_eq(
        &block.batch_key,
        &Some(String::new()),
        "Block::new should preserve Some(empty string)",
    )
}

#[test]
fn blocks_44_new_genesis_whitespace_miner_becomes_empty() -> TestResult {
    let block = Block::new(
        valid_metadata(0, 44),
        None,
        String::from("   \n\t   "),
        0_u64,
    )?;

    ensure_eq(
        &block.miner,
        &String::new(),
        "genesis whitespace miner should normalize to empty string",
    )
}

#[test]
fn blocks_45_new_non_genesis_whitespace_miner_is_rejected() -> TestResult {
    require_validation_error(
        Block::new(
            valid_metadata(2, 45),
            None,
            String::from("   \n\t   "),
            45_u64,
        ),
        "Block.miner missing",
    )
}

#[test]
fn blocks_46_new_trims_and_canonicalizes_padded_wallet_miner() -> TestResult {
    let wallet = uppercase_wallet();
    let padded = format!("  {wallet}\n");

    let block = Block::new(valid_metadata(2, 46), None, padded, 46_u64)?;

    ensure_eq(
        &block.miner,
        &wallet.to_ascii_lowercase(),
        "Block::new should trim and canonicalize padded wallet miner",
    )
}

#[test]
fn blocks_47_new_rejects_short_miner_wallet() -> TestResult {
    require_validation_error_any(Block::new(
        valid_metadata(2, 47),
        None,
        String::from("r1234"),
        47_u64,
    ))
}

#[test]
fn blocks_48_new_rejects_long_miner_wallet() -> TestResult {
    let mut miner = String::from("r");
    for _ in 0..129 {
        miner.push('1');
    }

    require_validation_error_any(Block::new(valid_metadata(2, 48), None, miner, 48_u64))
}

#[test]
fn blocks_49_new_rejects_wrong_wallet_prefix() -> TestResult {
    let mut miner = String::from("x");
    for _ in 0..128 {
        miner.push('1');
    }

    require_validation_error_any(Block::new(valid_metadata(2, 49), None, miner, 49_u64))
}

#[test]
fn blocks_50_new_rejects_non_hex_wallet_body() -> TestResult {
    let mut miner = String::from("r");
    for _ in 0..127 {
        miner.push('1');
    }
    miner.push('z');

    require_validation_error_any(Block::new(valid_metadata(2, 50), None, miner, 50_u64))
}

#[test]
fn blocks_51_new_accepts_zero_reward_for_non_genesis() -> TestResult {
    let block = Block::new(valid_metadata(2, 51), None, canonical_wallet(), 0_u64)?;

    ensure_eq(
        &block.reward,
        &0_u64,
        "Block::new currently allows zero reward for non-genesis blocks",
    )?;
    ensure(
        block.verify_block_hash()?,
        "zero-reward block hash should verify",
    )
}

#[test]
fn blocks_52_new_accepts_u64_max_reward() -> TestResult {
    let block = Block::new(valid_metadata(2, 52), None, canonical_wallet(), u64::MAX)?;

    ensure_eq(
        &block.reward,
        &u64::MAX,
        "Block::new should preserve u64::MAX reward",
    )?;
    ensure(
        block.verify_block_hash()?,
        "u64::MAX reward hash should verify",
    )
}

#[test]
fn blocks_53_reward_zero_and_reward_max_produce_different_hashes() -> TestResult {
    let metadata = valid_metadata(2, 53);

    let zero_reward = Block::new(metadata.clone(), None, canonical_wallet(), 0_u64)?;
    let max_reward = Block::new(metadata, None, canonical_wallet(), u64::MAX)?;

    ensure_ne(
        &zero_reward.block_hash,
        &max_reward.block_hash,
        "reward should be consensus-hash relevant",
    )
}

#[test]
fn blocks_54_block_hash_does_not_include_miner_field() -> TestResult {
    let metadata = valid_metadata(2, 54);

    let first = Block::new(
        metadata.clone(),
        Some(String::from("same-batch")),
        canonical_wallet(),
        54_u64,
    )?;
    let second = Block::new(
        metadata,
        Some(String::from("same-batch")),
        alternate_wallet(),
        54_u64,
    )?;

    ensure_eq(
        &first.block_hash,
        &second.block_hash,
        "current compute_block_hash domain does not include miner",
    )
}

#[test]
fn blocks_55_block_hash_does_not_include_metadata_index() -> TestResult {
    let mut first_metadata = valid_metadata(2, 55);
    let mut second_metadata = first_metadata.clone();
    second_metadata.index = first_metadata.index.saturating_add(1);
    first_metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE;
    second_metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE;

    let first = Block::new(first_metadata, None, canonical_wallet(), 55_u64)?;
    let second = Block::new(second_metadata, None, canonical_wallet(), 55_u64)?;

    ensure_eq(
        &first.block_hash,
        &second.block_hash,
        "current compute_block_hash domain does not include metadata.index",
    )
}

#[test]
fn blocks_56_block_hash_does_not_include_metadata_timestamp() -> TestResult {
    let first_metadata = valid_metadata(2, 56);
    let mut second_metadata = first_metadata.clone();
    second_metadata.timestamp = second_metadata.timestamp.saturating_add(10_000);

    let first = Block::new(first_metadata, None, canonical_wallet(), 56_u64)?;
    let second = Block::new(second_metadata, None, canonical_wallet(), 56_u64)?;

    ensure_eq(
        &first.block_hash,
        &second.block_hash,
        "current compute_block_hash domain does not include metadata.timestamp",
    )
}

#[test]
fn blocks_57_block_hash_does_not_include_metadata_size() -> TestResult {
    let first_metadata = valid_metadata(2, 57);
    let mut second_metadata = first_metadata.clone();
    second_metadata.size = second_metadata.size.saturating_add(1);

    let first = Block::new(first_metadata, None, canonical_wallet(), 57_u64)?;
    let second = Block::new(second_metadata, None, canonical_wallet(), 57_u64)?;

    ensure_eq(
        &first.block_hash,
        &second.block_hash,
        "current compute_block_hash domain does not include metadata.size",
    )
}

#[test]
fn blocks_58_nonempty_batch_key_differs_from_dummy_batch_key_hash() -> TestResult {
    let metadata = valid_metadata(2, 58);

    let none_block = Block::new(metadata.clone(), None, canonical_wallet(), 58_u64)?;
    let keyed_block = Block::new(
        metadata,
        Some(String::from("not-empty")),
        canonical_wallet(),
        58_u64,
    )?;

    ensure_ne(
        &none_block.block_hash,
        &keyed_block.block_hash,
        "nonempty batch_key should not hash like dummy/empty batch key",
    )
}

#[test]
fn blocks_59_none_batch_key_hash_matches_manual_dummy_key_vector() -> TestResult {
    let block = Block::new(valid_metadata(2, 59), None, canonical_wallet(), 59_u64)?;

    let dummy_hex = RemzarHash::compute_dummy_hash();
    let mut key_bytes = [0_u8; 64];
    hex::decode_to_slice(&dummy_hex, &mut key_bytes)?;

    let mut preimage = Vec::with_capacity(64 + 64 + ml_dsa_65::SIG_LEN + 8 + 64);
    preimage.extend_from_slice(&block.metadata.previous_hash);
    preimage.extend_from_slice(&block.metadata.merkle_root);
    preimage.extend_from_slice(&block.metadata.guardian_signature);
    preimage.extend_from_slice(&block.reward.to_be_bytes());
    preimage.extend_from_slice(&key_bytes);

    let expected = RemzarHash::compute_bytes_hash_hex(&preimage);

    ensure_eq(
        &block.compute_block_hash()?,
        &expected,
        "None batch_key should use Remzar dummy hash in block preimage",
    )
}

#[test]
fn blocks_60_nonempty_batch_key_hash_matches_manual_key_hash_vector() -> TestResult {
    let batch_key = String::from("blocks-60-key");
    let block = Block::new(
        valid_metadata(2, 60),
        Some(batch_key.clone()),
        canonical_wallet(),
        60_u64,
    )?;

    let key_hex = RemzarHash::compute_bytes_hash_hex(batch_key.as_bytes());
    let mut key_bytes = [0_u8; 64];
    hex::decode_to_slice(&key_hex, &mut key_bytes)?;

    let mut preimage = Vec::with_capacity(64 + 64 + ml_dsa_65::SIG_LEN + 8 + 64);
    preimage.extend_from_slice(&block.metadata.previous_hash);
    preimage.extend_from_slice(&block.metadata.merkle_root);
    preimage.extend_from_slice(&block.metadata.guardian_signature);
    preimage.extend_from_slice(&block.reward.to_be_bytes());
    preimage.extend_from_slice(&key_bytes);

    let expected = RemzarHash::compute_bytes_hash_hex(&preimage);

    ensure_eq(
        &block.compute_block_hash()?,
        &expected,
        "nonempty batch_key should use RemzarHash::compute_bytes_hash_hex(batch_key bytes)",
    )
}

#[test]
fn blocks_61_validate_rejects_manual_uppercase_miner() -> TestResult {
    let mut block = valid_block(2, 61)?;
    block.miner = uppercase_wallet();

    require_validation_error(block.validate(None), "canonical form")
}

#[test]
fn blocks_62_validate_rejects_manual_padded_miner() -> TestResult {
    let mut block = valid_block(2, 62)?;
    block.miner = format!("  {}\n", canonical_wallet());

    require_validation_error(block.validate(None), "canonical form")
}

#[test]
fn blocks_63_validate_rejects_manual_invalid_long_miner() -> TestResult {
    let mut block = valid_block(2, 63)?;
    block.miner = "r".repeat(257);

    require_validation_error_any(block.validate(None))
}

#[test]
fn blocks_64_validate_uses_prev_ts_argument() -> TestResult {
    let block = valid_block(2, 64)?;

    require_validation_error(block.validate(Some(u64::MAX)), "parent_block.timestamp")
}

#[test]
fn blocks_65_validate_rejects_metadata_size_below_minimum() -> TestResult {
    let mut block = valid_block(2, 65)?;
    block.metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);
    let recomputed = block.compute_block_hash()?;
    block.block_hash = decode_hash_hex(&recomputed)?;

    require_validation_error(block.validate(None), "implausibly small")
}

#[test]
fn blocks_66_validate_rejects_metadata_size_above_maximum() -> TestResult {
    let mut block = valid_block(2, 66)?;
    block.metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);
    let recomputed = block.compute_block_hash()?;
    block.block_hash = decode_hash_hex(&recomputed)?;

    require_validation_error(block.validate(None), "fields out of bounds")
}

#[test]
fn blocks_67_validate_rejects_metadata_timestamp_below_minimum() -> TestResult {
    let mut block = valid_block(2, 67)?;
    block.metadata.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1);

    require_validation_error(block.validate(None), "timestamp below")
}

#[test]
fn blocks_68_validate_rejects_metadata_zero_previous_hash() -> TestResult {
    let mut block = valid_block(2, 68)?;
    block.metadata.previous_hash = [0_u8; 64];
    let recomputed = block.compute_block_hash()?;
    block.block_hash = decode_hash_hex(&recomputed)?;

    require_validation_error(block.validate(None), "previous_hash is all zeros")
}

#[test]
fn blocks_69_validate_rejects_metadata_zero_merkle_root() -> TestResult {
    let mut block = valid_block(2, 69)?;
    block.metadata.merkle_root = [0_u8; 64];
    let recomputed = block.compute_block_hash()?;
    block.block_hash = decode_hash_hex(&recomputed)?;

    require_validation_error(block.validate(None), "merkle_root is all zeros")
}

#[test]
fn blocks_70_validate_rejects_metadata_merkle_equal_previous_hash() -> TestResult {
    let mut block = valid_block(2, 70)?;
    block.metadata.merkle_root = block.metadata.previous_hash;
    let recomputed = block.compute_block_hash()?;
    block.block_hash = decode_hash_hex(&recomputed)?;

    require_validation_error(block.validate(None), "merkle_root == previous_hash")
}

#[test]
fn blocks_71_validate_rejects_genesis_metadata_with_puzzle_proof() -> TestResult {
    let mut block = valid_genesis_style_block(71)?;
    let proof = valid_puzzle_proof_for(0, block.metadata.previous_hash, 71_000_u128)?;
    block.metadata.set_puzzle_proof(Some(proof));
    let recomputed = block.compute_block_hash()?;
    block.block_hash = decode_hash_hex(&recomputed)?;

    require_validation_error(
        block.validate(None),
        "genesis must not include puzzle_proof",
    )
}

#[test]
fn blocks_72_deserialize_from_storage_accepts_trailing_nonzero_padding() -> TestResult {
    let block = valid_block(2, 72)?;
    let mut bytes = block.serialize_for_storage()?;
    bytes.extend_from_slice(&[7_u8, 8_u8, 9_u8]);

    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded,
        &block,
        "deserialize_from_storage should accept legacy trailing nonzero padding via fallback",
    )
}

#[test]
fn blocks_73_deserialize_with_sizes_reports_stored_size_for_zero_padded_payload() -> TestResult {
    let block = valid_block(2, 73)?;
    let canonical = block.serialize_for_storage()?;
    let canonical_len = canonical.len();

    let mut padded = canonical;
    padded.extend_from_slice(&[0_u8, 0_u8, 0_u8, 0_u8, 0_u8]);

    let (decoded, actual_size, stored_size) = Block::deserialize_with_sizes(&padded)?;

    ensure_eq(&decoded, &block, "decoded block should match original")?;
    ensure_eq(
        &actual_size,
        &canonical_len,
        "actual_size should report the postcard payload length before legacy zero padding",
    )?;
    ensure_eq(
        &stored_size,
        &padded.len(),
        "stored_size should include trailing zero padding",
    )?;
    ensure(
        actual_size < stored_size,
        "zero-padded legacy payload should report actual_size < stored_size",
    )
}

#[test]
fn blocks_74_deserialize_with_sizes_reports_stored_size_for_nonzero_padded_payload() -> TestResult {
    let block = valid_block(2, 74)?;
    let canonical = block.serialize_for_storage()?;

    let mut padded = canonical;
    padded.extend_from_slice(&[1_u8, 2_u8, 3_u8, 4_u8]);

    require_serialization_error(
        Block::deserialize_with_sizes(&padded),
        "non-zero trailing bytes",
    )
}

#[test]
fn blocks_75_deserialize_with_sizes_rejects_too_short_payload() -> TestResult {
    let min_len = usize::try_from(GlobalConfiguration::MIN_BLOCK_SIZE)
        .map_err(|_| fail("MIN_BLOCK_SIZE should fit usize"))?;
    let data = vec![0_u8; min_len.saturating_sub(1)];

    require_serialization_error(Block::deserialize_with_sizes(&data), "Block data too short")
}

#[test]
fn blocks_76_deserialize_with_sizes_rejects_too_large_payload() -> TestResult {
    let max_len = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| fail("MAX_BLOCK_SIZE should fit usize"))?;
    let data = vec![0_u8; max_len.saturating_add(1)];

    require_serialization_error(Block::deserialize_with_sizes(&data), "Block data too large")
}

#[test]
fn blocks_77_deserialize_rejects_serialized_block_with_metadata_size_below_minimum() -> TestResult {
    let mut block = valid_block(2, 77)?;
    block.metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);

    let bytes = serialize_block_without_prevalidation(&block)?;

    require_validation_error(Block::deserialize_from_storage(&bytes), "implausibly small")
}

#[test]
fn blocks_78_deserialize_genesis_whitespace_miner_normalizes_to_empty() -> TestResult {
    let mut block = valid_genesis_style_block(78)?;
    block.miner = String::from("   \n\t   ");
    let bytes = block.serialize_for_storage()?;

    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded.miner,
        &String::new(),
        "genesis whitespace miner should normalize to empty after deserialize",
    )
}

#[test]
fn blocks_79_deserialize_rejects_invalid_miner_wallet() -> TestResult {
    let mut block = valid_block(2, 79)?;
    block.miner = String::from("bad-wallet");

    let bytes = serialize_block_without_prevalidation(&block)?;

    require_validation_error_any(Block::deserialize_from_storage(&bytes))
}

#[test]
fn blocks_80_deserialize_rejects_manual_batch_key_over_4096_bytes() -> TestResult {
    let mut block = valid_block(2, 80)?;
    block.batch_key = Some("x".repeat(4097));

    let bytes = serialize_block_without_prevalidation(&block)?;

    require_validation_error(
        Block::deserialize_from_storage(&bytes),
        "batch_key too long",
    )
}

#[test]
fn blocks_81_deserialize_accepts_batch_key_exactly_4096_bytes() -> TestResult {
    let block = Block::new(
        valid_metadata(2, 81),
        Some("x".repeat(4096)),
        canonical_wallet(),
        81_u64,
    )?;
    let bytes = block.serialize_for_storage()?;

    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded,
        &block,
        "deserialize should accept batch_key exactly at 4096-byte limit",
    )
}

#[test]
fn blocks_82_deserialize_accepts_none_batch_key() -> TestResult {
    let block = Block::new(valid_metadata(2, 82), None, canonical_wallet(), 82_u64)?;
    let bytes = block.serialize_for_storage()?;

    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure(
        decoded.batch_key.is_none(),
        "None batch_key should survive storage roundtrip",
    )
}

#[test]
fn blocks_83_encoded_len_unpadded_increases_with_batch_key_payload() -> TestResult {
    let metadata = valid_metadata(2, 83);
    let without_key = Block::new(metadata.clone(), None, canonical_wallet(), 83_u64)?;
    let with_key = Block::new(metadata, Some("x".repeat(128)), canonical_wallet(), 83_u64)?;

    ensure(
        with_key.encoded_len_unpadded()? > without_key.encoded_len_unpadded()?,
        "encoded length should increase when batch_key payload is stored",
    )
}

#[test]
fn blocks_84_encoded_len_padded_equals_unpadded_for_large_valid_batch_key() -> TestResult {
    let block = Block::new(
        valid_metadata(2, 84),
        Some("x".repeat(4096)),
        canonical_wallet(),
        84_u64,
    )?;

    ensure_eq(
        &block.encoded_len_padded(),
        &block.encoded_len_unpadded()?,
        "current encoded_len_padded returns canonical variable-length size",
    )
}

#[test]
fn blocks_85_json_roundtrip_preserves_block() -> TestResult {
    let block = valid_block(2, 85)?;

    let json = serde_json::to_string(&block)?;
    let decoded: Block = serde_json::from_str(&json)?;

    ensure_eq(&decoded, &block, "JSON roundtrip should preserve block")
}

#[test]
fn blocks_86_json_rejects_unknown_block_field() -> TestResult {
    let block = valid_block(2, 86)?;
    let mut value = serde_json::to_value(block)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("hostile_extra_block_field"),
                serde_json::Value::Bool(true),
            );
        }
        None => return Err(fail("Block should serialize as a JSON object")),
    }

    let result = serde_json::from_value::<Block>(value);

    ensure(
        result.is_err(),
        "Block serde deny_unknown_fields should reject extra block fields",
    )
}

#[test]
fn blocks_87_json_rejects_block_hash_with_65_elements() -> TestResult {
    let block = valid_block(2, 87)?;
    let mut value = serde_json::to_value(block)?;
    let oversized_hash = serde_json::Value::Array(
        (0_u8..65_u8)
            .map(|_| serde_json::Value::from(0_u8))
            .collect(),
    );

    match value.as_object_mut() {
        Some(object) => {
            object.insert(String::from("block_hash"), oversized_hash);
        }
        None => return Err(fail("Block should serialize as a JSON object")),
    }

    let result = serde_json::from_value::<Block>(value);

    ensure(
        result.is_err(),
        "serde_u8_array_64 should reject block_hash arrays longer than 64",
    )
}

#[test]
fn blocks_88_json_rejects_unknown_metadata_field_inside_block() -> TestResult {
    let block = valid_block(2, 88)?;
    let mut value = serde_json::to_value(block)?;

    let metadata_object = value
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("metadata should serialize as an object"))?;

    metadata_object.insert(
        String::from("hostile_extra_metadata_field"),
        serde_json::Value::String(String::from("reject me")),
    );

    let result = serde_json::from_value::<Block>(value);

    ensure(
        result.is_err(),
        "nested BlockMetadata deny_unknown_fields should reject extra metadata fields",
    )
}

#[test]
fn blocks_89_verify_block_hash_detects_metadata_tampering_after_construction() -> TestResult {
    let mut block = valid_block(2, 89)?;
    block.metadata.merkle_root = patterned_hash(222);

    ensure(
        !block.verify_block_hash()?,
        "verify_block_hash should return false after metadata merkle_root tampering",
    )
}

#[test]
fn blocks_90_validate_rejects_metadata_tampering_as_hash_mismatch_when_structurally_valid()
-> TestResult {
    let mut block = valid_block(2, 90)?;
    block.metadata.merkle_root = patterned_hash(223);

    require_validation_error(block.validate(None), "Block hash mismatch")
}

#[test]
fn blocks_91_deserialize_from_storage_does_not_verify_hash_mismatch_but_verify_detects_it()
-> TestResult {
    let mut block = valid_block(2, 91)?;
    block.reward = block.reward.saturating_add(1);

    let bytes = serialize_block_without_prevalidation(&block)?;

    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure(
        !decoded.verify_block_hash()?,
        "deserialize_from_storage performs structural checks but does not reject hash mismatch",
    )?;
    require_validation_error(decoded.validate(None), "Block hash mismatch")
}

#[test]
fn blocks_92_deserialize_with_sizes_does_not_verify_hash_mismatch_but_verify_detects_it()
-> TestResult {
    let mut block = valid_block(2, 92)?;
    block.reward = block.reward.saturating_add(1);

    let bytes = serialize_block_without_prevalidation(&block)?;

    let (decoded, actual_size, stored_size) = Block::deserialize_with_sizes(&bytes)?;

    ensure(actual_size > 0, "actual decoded size should be positive")?;
    ensure_eq(
        &actual_size,
        &stored_size,
        "canonical payload sizes should match",
    )?;
    ensure(
        !decoded.verify_block_hash()?,
        "deserialize_with_sizes performs structural checks but does not reject hash mismatch",
    )?;
    require_validation_error(decoded.validate(None), "Block hash mismatch")
}

#[test]
fn blocks_93_sign_block_sets_signature_updates_hash_and_validate_passes() -> TestResult {
    let seed = [93_u8; 32];
    let (_vk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let mut block = valid_block(2, 93)?;
    let old_hash = block.block_hash;
    let zero_sig = [0_u8; ml_dsa_65::SIG_LEN];

    block.sign_block(&sk)?;

    ensure_ne(
        &block.metadata.guardian_signature,
        &zero_sig,
        "sign_block should install a nonzero ML-DSA-65 signature",
    )?;
    ensure_ne(
        &block.block_hash,
        &old_hash,
        "sign_block should update block hash after signature insertion",
    )?;
    block.validate(None)?;
    Ok(())
}

#[test]
fn blocks_94_verify_block_signature_rejects_signed_block_with_wrong_key() -> TestResult {
    let signing_seed = [94_u8; 32];
    let wrong_seed = [95_u8; 32];
    let (_right_vk, sk) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
    let (wrong_vk, _wrong_sk) = ml_dsa_65::KG::keygen_from_seed(&wrong_seed);

    let mut block = valid_block(2, 94)?;
    block.sign_block(&sk)?;

    require_signature_error(block.verify_block_signature(&wrong_vk))
}

#[test]
fn blocks_95_verify_block_signature_rejects_after_batch_key_tamper() -> TestResult {
    let seed = [96_u8; 32];
    let (vk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let mut block = valid_block(2, 95)?;

    block.sign_block(&sk)?;
    block.batch_key = Some(String::from("tampered-after-signing"));

    require_signature_error(block.verify_block_signature(&vk))
}

#[test]
fn blocks_96_manual_oversized_batch_key_can_serialize_but_validate_rejects() -> TestResult {
    let mut block = valid_block(2, 96)?;
    block.batch_key = Some("x".repeat(4097));

    let bytes = serialize_block_without_prevalidation(&block)?;

    ensure(
        !bytes.is_empty(),
        "manual oversized batch_key should still raw-encode when bypassing public validation",
    )?;
    require_validation_error(block.validate(None), "batch_key too long")?;
    require_validation_error(
        Block::deserialize_from_storage(&bytes),
        "batch_key too long",
    )
}

#[test]
fn blocks_97_large_valid_batch_key_roundtrips_and_validates() -> TestResult {
    let block = Block::new(
        valid_metadata(2, 97),
        Some("x".repeat(4096)),
        canonical_wallet(),
        97_u64,
    )?;

    block.validate(None)?;

    let bytes = block.serialize_for_storage()?;
    let decoded = Block::deserialize_from_storage(&bytes)?;

    ensure_eq(
        &decoded,
        &block,
        "4096-byte batch_key block should roundtrip and validate",
    )
}

#[test]
fn blocks_98_repeated_same_inputs_produce_identical_blocks_and_hashes() -> TestResult {
    let metadata = valid_metadata(2, 98);
    let batch_key = Some(String::from("repeatable-vector-key"));
    let miner = canonical_wallet();
    let reward = 98_u64;

    let first = Block::new(metadata.clone(), batch_key.clone(), miner.clone(), reward)?;
    let second = Block::new(metadata, batch_key, miner, reward)?;

    ensure_eq(
        &first,
        &second,
        "same inputs should produce identical Block values",
    )?;
    ensure_eq(
        &first.hash_hex(),
        &second.hash_hex(),
        "same inputs should produce identical hash_hex values",
    )
}

#[test]
fn blocks_99_property_many_blocks_have_128_lowercase_hashes_and_valid_storage_roundtrips()
-> TestResult {
    let mut seed = 99_u8;

    for index in 1_u64..=128_u64 {
        let block = valid_block(index, seed)?;
        let hash = block.hash_hex();

        ensure_eq(&hash.len(), &128_usize, "hash_hex should be 128 chars")?;
        ensure(is_lowercase_hex(&hash), "hash_hex should be lowercase hex")?;
        ensure(block.verify_block_hash()?, "block hash should verify")?;

        let bytes = block.serialize_for_storage()?;
        let decoded = Block::deserialize_from_storage(&bytes)?;
        ensure_eq(
            &decoded,
            &block,
            "block should roundtrip through storage bytes",
        )?;

        seed = seed.wrapping_add(1);
    }

    Ok(())
}

#[test]
fn blocks_100_adversarial_load_hash_mismatch_validate_rejects_after_deserialize_survives()
-> TestResult {
    let mut seen_hashes = BTreeSet::new();
    let mut seed = 120_u8;

    for index in 1_u64..=256_u64 {
        let mut block = valid_block(index, seed)?;
        ensure(
            seen_hashes.insert(block.hash_hex()),
            "adversarial load should start with unique block hashes",
        )?;

        let valid_bytes = block.serialize_for_storage()?;
        let valid_decoded = Block::deserialize_from_storage(&valid_bytes)?;
        ensure_eq(
            &valid_decoded,
            &block,
            "valid block should deserialize before tampering",
        )?;

        block.reward = block.reward.saturating_add(1);

        let tampered_bytes = serialize_block_without_prevalidation(&block)?;
        let tampered_decoded = Block::deserialize_from_storage(&tampered_bytes)?;

        ensure(
            !tampered_decoded.verify_block_hash()?,
            "tampered reward should make stored hash mismatch detectable",
        )?;
        require_validation_error(tampered_decoded.validate(None), "Block hash mismatch")?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &seen_hashes.len(),
        &256_usize,
        "adversarial load should process 256 unique initial block hashes",
    )
}
