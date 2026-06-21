// tests/block_003_puzzleproof_tests.rs

use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::consensus::por_002_puzzle_engine::PorPuzzleEngine;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use std::collections::BTreeSet;
use std::error::Error as StdError;

type TestResult = Result<(), Box<dyn StdError>>;

fn fail(message: impl Into<String>) -> Box<dyn StdError> {
    std::io::Error::other(message.into()).into()
}

fn repeated_validator_char(ch: char) -> String {
    let mut validator = String::from("r");
    for _ in 0..128 {
        validator.push(ch);
    }
    validator
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

fn canonical_validator() -> String {
    let mut validator = String::from("r");
    for _ in 0..128 {
        validator.push('1');
    }
    validator
}

fn alternate_validator() -> String {
    let mut validator = String::from("r");
    for _ in 0..128 {
        validator.push('2');
    }
    validator
}

fn uppercase_validator() -> String {
    let mut validator = String::from("R");
    for _ in 0..128 {
        validator.push('A');
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

fn valid_proof(height: u64, seed: u8) -> Result<BlockPuzzleProof, ErrorDetection> {
    BlockPuzzleProof::new(
        height,
        canonical_validator(),
        patterned_hash(seed),
        u128::from(seed).saturating_add(1),
    )
}

fn valid_gossip_proof(height: u64, seed: u8) -> PorPuzzleProof {
    PorPuzzleProof {
        height,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(seed),
        output: u128::from(seed).saturating_add(1),
    }
}

fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
}

fn is_all_zero_64(bytes: &[u8; 64]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[test]
fn block_003_puzzleproof_01_new_preserves_valid_fields() -> TestResult {
    let height = 7_u64;
    let validator = canonical_validator();
    let prev_block_hash = patterned_hash(1);
    let output = 123_u128;

    let proof = BlockPuzzleProof::new(height, validator.clone(), prev_block_hash, output)?;

    ensure_eq(&proof.height, &height, "height should be preserved")?;
    ensure_eq(
        &proof.validator,
        &validator,
        "validator should be preserved",
    )?;
    ensure_eq(
        &proof.prev_block_hash,
        &prev_block_hash,
        "prev_block_hash should be preserved",
    )?;
    ensure_eq(&proof.output, &output, "output should be preserved")
}

#[test]
fn block_003_puzzleproof_02_new_canonicalizes_uppercase_validator() -> TestResult {
    let proof = BlockPuzzleProof::new(1_u64, uppercase_validator(), patterned_hash(2), 2_u128)?;

    ensure_eq(
        &proof.validator,
        &uppercase_validator().to_ascii_lowercase(),
        "new should canonicalize uppercase wallet validator",
    )
}

#[test]
fn block_003_puzzleproof_03_new_trims_and_canonicalizes_validator() -> TestResult {
    let padded = format!("  {}\n", uppercase_validator());

    let proof = BlockPuzzleProof::new(1_u64, padded, patterned_hash(3), 3_u128)?;

    ensure_eq(
        &proof.validator,
        &uppercase_validator().to_ascii_lowercase(),
        "new should trim and canonicalize validator at boundary",
    )
}

#[test]
fn block_003_puzzleproof_04_new_accepts_max_reasonable_height() -> TestResult {
    let proof = BlockPuzzleProof::new(
        10_000_000_u64,
        canonical_validator(),
        patterned_hash(4),
        4_u128,
    )?;

    ensure_eq(
        &proof.height,
        &10_000_000_u64,
        "max reasonable height should be accepted",
    )
}

#[test]
fn block_003_puzzleproof_05_new_rejects_height_over_limit() -> TestResult {
    require_validation_error(
        BlockPuzzleProof::new(
            10_000_001_u64,
            canonical_validator(),
            patterned_hash(5),
            5_u128,
        ),
        "height out of bounds",
    )
}

#[test]
fn block_003_puzzleproof_06_new_rejects_empty_validator() -> TestResult {
    require_validation_error_any(BlockPuzzleProof::new(
        1_u64,
        String::new(),
        patterned_hash(6),
        6_u128,
    ))
}

#[test]
fn block_003_puzzleproof_07_new_rejects_short_validator() -> TestResult {
    require_validation_error_any(BlockPuzzleProof::new(
        1_u64,
        String::from("r1234"),
        patterned_hash(7),
        7_u128,
    ))
}

#[test]
fn block_003_puzzleproof_08_new_rejects_wrong_validator_prefix() -> TestResult {
    let mut validator = String::from("x");
    for _ in 0..128 {
        validator.push('1');
    }

    require_validation_error_any(BlockPuzzleProof::new(
        1_u64,
        validator,
        patterned_hash(8),
        8_u128,
    ))
}

#[test]
fn block_003_puzzleproof_09_new_rejects_non_hex_validator_body() -> TestResult {
    let mut validator = String::from("r");
    for _ in 0..127 {
        validator.push('1');
    }
    validator.push('z');

    require_validation_error_any(BlockPuzzleProof::new(
        1_u64,
        validator,
        patterned_hash(9),
        9_u128,
    ))
}

#[test]
fn block_003_puzzleproof_10_new_rejects_validator_over_256_bytes() -> TestResult {
    require_validation_error(
        BlockPuzzleProof::new(1_u64, "r".repeat(257), patterned_hash(10), 10_u128),
        "validator too long",
    )
}

#[test]
fn block_003_puzzleproof_11_new_rejects_zero_prev_block_hash() -> TestResult {
    require_validation_error(
        BlockPuzzleProof::new(1_u64, canonical_validator(), [0_u8; 64], 11_u128),
        "invalid sentinel",
    )
}

#[test]
fn block_003_puzzleproof_12_new_rejects_ff_prev_block_hash() -> TestResult {
    require_validation_error(
        BlockPuzzleProof::new(1_u64, canonical_validator(), [0xFF_u8; 64], 12_u128),
        "invalid sentinel",
    )
}

#[test]
fn block_003_puzzleproof_13_new_rejects_zero_output() -> TestResult {
    require_validation_error(
        BlockPuzzleProof::new(1_u64, canonical_validator(), patterned_hash(13), 0_u128),
        "output cannot be 0",
    )
}

#[test]
fn block_003_puzzleproof_14_new_accepts_u128_max_output() -> TestResult {
    let proof = BlockPuzzleProof::new(1_u64, canonical_validator(), patterned_hash(14), u128::MAX)?;

    ensure_eq(
        &proof.output,
        &u128::MAX,
        "u128::MAX output should be preserved",
    )
}

#[test]
fn block_003_puzzleproof_15_validate_structural_accepts_valid_manual_proof() -> TestResult {
    let proof = BlockPuzzleProof {
        height: 1_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(15),
        output: 15_u128,
    };

    proof.validate_structural()?;
    Ok(())
}

#[test]
fn block_003_puzzleproof_16_validate_structural_rejects_manual_noncanonical_validator() -> TestResult
{
    let proof = BlockPuzzleProof {
        height: 1_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(16),
        output: 16_u128,
    };

    require_validation_error(proof.validate_structural(), "validator is not canonical")
}

#[test]
fn block_003_puzzleproof_17_validate_structural_rejects_manual_padded_validator() -> TestResult {
    let proof = BlockPuzzleProof {
        height: 1_u64,
        validator: format!("  {}\n", canonical_validator()),
        prev_block_hash: patterned_hash(17),
        output: 17_u128,
    };

    require_validation_error(proof.validate_structural(), "validator is not canonical")
}

#[test]
fn block_003_puzzleproof_18_validate_structural_rejects_manual_empty_validator() -> TestResult {
    let proof = BlockPuzzleProof {
        height: 1_u64,
        validator: String::new(),
        prev_block_hash: patterned_hash(18),
        output: 18_u128,
    };

    require_validation_error(proof.validate_structural(), "validator is empty")
}

#[test]
fn block_003_puzzleproof_19_validate_structural_rejects_manual_validator_over_256() -> TestResult {
    let proof = BlockPuzzleProof {
        height: 1_u64,
        validator: "r".repeat(257),
        prev_block_hash: patterned_hash(19),
        output: 19_u128,
    };

    require_validation_error(proof.validate_structural(), "validator too long")
}

#[test]
fn block_003_puzzleproof_20_from_gossip_preserves_valid_gossip_fields() -> TestResult {
    let gossip = valid_gossip_proof(20_u64, 20);

    let block_proof = BlockPuzzleProof::from_gossip(&gossip)?;

    ensure_eq(&block_proof.height, &gossip.height, "height should match")?;
    ensure_eq(
        &block_proof.validator,
        &gossip.validator,
        "validator should match",
    )?;
    ensure_eq(
        &block_proof.prev_block_hash,
        &gossip.prev_block_hash,
        "prev_block_hash should match",
    )?;
    ensure_eq(&block_proof.output, &gossip.output, "output should match")
}

#[test]
fn block_003_puzzleproof_21_from_gossip_canonicalizes_uppercase_validator() -> TestResult {
    let gossip = PorPuzzleProof {
        height: 21_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(21),
        output: 21_u128,
    };

    let proof = BlockPuzzleProof::from_gossip(&gossip)?;

    ensure_eq(
        &proof.validator,
        &uppercase_validator().to_ascii_lowercase(),
        "from_gossip should canonicalize validator through new",
    )
}

#[test]
fn block_003_puzzleproof_22_from_gossip_rejects_zero_output() -> TestResult {
    let gossip = PorPuzzleProof {
        height: 22_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(22),
        output: 0_u128,
    };

    require_validation_error(BlockPuzzleProof::from_gossip(&gossip), "output cannot be 0")
}

#[test]
fn block_003_puzzleproof_23_from_gossip_rejects_zero_prev_hash() -> TestResult {
    let gossip = PorPuzzleProof {
        height: 23_u64,
        validator: canonical_validator(),
        prev_block_hash: [0_u8; 64],
        output: 23_u128,
    };

    require_validation_error(BlockPuzzleProof::from_gossip(&gossip), "invalid sentinel")
}

#[test]
fn block_003_puzzleproof_24_to_gossip_preserves_all_fields() -> TestResult {
    let proof = valid_proof(24_u64, 24)?;

    let gossip = proof.to_gossip();

    ensure_eq(&gossip.height, &proof.height, "height should match")?;
    ensure_eq(
        &gossip.validator,
        &proof.validator,
        "validator should match",
    )?;
    ensure_eq(
        &gossip.prev_block_hash,
        &proof.prev_block_hash,
        "prev_block_hash should match",
    )?;
    ensure_eq(&gossip.output, &proof.output, "output should match")
}

#[test]
fn block_003_puzzleproof_25_gossip_roundtrip_preserves_block_proof() -> TestResult {
    let original = valid_proof(25_u64, 25)?;

    let gossip = original.to_gossip();
    let roundtrip = BlockPuzzleProof::from_gossip(&gossip)?;

    ensure_eq(
        &roundtrip,
        &original,
        "BlockPuzzleProof -> PorPuzzleProof -> BlockPuzzleProof should roundtrip",
    )
}

#[test]
fn block_003_puzzleproof_26_commitment_bytes_are_64_bytes_and_nonzero() -> TestResult {
    let proof = valid_proof(26_u64, 26)?;

    let commitment = proof.commitment_bytes()?;

    ensure_eq(
        &commitment.len(),
        &64_usize,
        "commitment_bytes should return 64 bytes",
    )?;
    ensure(
        !is_all_zero_64(&commitment),
        "valid proof commitment should not be all zeros",
    )
}

#[test]
fn block_003_puzzleproof_27_commitment_hex_is_128_lowercase_hex() -> TestResult {
    let proof = valid_proof(27_u64, 27)?;

    let commitment_hex = proof.commitment_hex()?;

    ensure_eq(
        &commitment_hex.len(),
        &128_usize,
        "commitment_hex should be 128 chars",
    )?;
    ensure(
        is_lowercase_hex(&commitment_hex),
        "commitment_hex should be lowercase hex",
    )
}

#[test]
fn block_003_puzzleproof_28_commitment_hex_matches_hex_encoded_commitment_bytes() -> TestResult {
    let proof = valid_proof(28_u64, 28)?;

    let bytes = proof.commitment_bytes()?;
    let hex = proof.commitment_hex()?;

    ensure_eq(
        &hex,
        &hex::encode(bytes),
        "commitment_hex should be hex encoding of commitment_bytes",
    )
}

#[test]
fn block_003_puzzleproof_29_commitment_matches_remzarhash_of_postcard_bytes() -> TestResult {
    let proof = valid_proof(29_u64, 29)?;

    let encoded = postcard::to_allocvec(&proof)?;
    let expected = RemzarHash::compute_bytes_hash(&encoded);

    ensure_eq(
        &proof.commitment_bytes()?,
        &expected,
        "commitment_bytes should be RemzarHash over postcard-encoded proof",
    )
}

#[test]
fn block_003_puzzleproof_30_commitment_is_deterministic() -> TestResult {
    let proof = valid_proof(30_u64, 30)?;

    let first = proof.commitment_hex()?;
    let second = proof.commitment_hex()?;

    ensure_eq(
        &first,
        &second,
        "same proof should commit deterministically",
    )
}

#[test]
fn block_003_puzzleproof_31_commitment_changes_when_height_changes() -> TestResult {
    let first = valid_proof(31_u64, 31)?;
    let second = valid_proof(32_u64, 31)?;

    ensure_ne(
        &first.commitment_hex()?,
        &second.commitment_hex()?,
        "height should affect commitment",
    )
}

#[test]
fn block_003_puzzleproof_32_commitment_changes_when_validator_changes() -> TestResult {
    let first = valid_proof(32_u64, 32)?;
    let second = BlockPuzzleProof::new(32_u64, alternate_validator(), patterned_hash(32), 33_u128)?;

    ensure_ne(
        &first.commitment_hex()?,
        &second.commitment_hex()?,
        "validator should affect commitment",
    )
}

#[test]
fn block_003_puzzleproof_33_commitment_changes_when_prev_hash_changes() -> TestResult {
    let first = valid_proof(33_u64, 33)?;
    let second = BlockPuzzleProof::new(33_u64, canonical_validator(), patterned_hash(34), 34_u128)?;

    ensure_ne(
        &first.commitment_hex()?,
        &second.commitment_hex()?,
        "prev_block_hash should affect commitment",
    )
}

#[test]
fn block_003_puzzleproof_34_commitment_changes_when_output_changes() -> TestResult {
    let first = valid_proof(34_u64, 34)?;
    let second = BlockPuzzleProof::new(34_u64, canonical_validator(), patterned_hash(34), 36_u128)?;

    ensure_ne(
        &first.commitment_hex()?,
        &second.commitment_hex()?,
        "output should affect commitment",
    )
}

#[test]
fn block_003_puzzleproof_35_postcard_roundtrip_preserves_valid_proof() -> TestResult {
    let proof = valid_proof(35_u64, 35)?;

    let bytes = postcard::to_allocvec(&proof)?;
    let decoded: BlockPuzzleProof = postcard::from_bytes(&bytes)?;

    ensure_eq(
        &decoded,
        &proof,
        "postcard roundtrip should preserve BlockPuzzleProof",
    )
}

#[test]
fn block_003_puzzleproof_36_json_roundtrip_preserves_valid_proof() -> TestResult {
    let proof = valid_proof(36_u64, 36)?;

    let json = serde_json::to_string(&proof)?;
    let decoded: BlockPuzzleProof = serde_json::from_str(&json)?;

    ensure_eq(
        &decoded,
        &proof,
        "JSON roundtrip should preserve BlockPuzzleProof",
    )
}

#[test]
fn block_003_puzzleproof_37_json_rejects_unknown_fields() -> TestResult {
    let proof = valid_proof(37_u64, 37)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("hostile_extra_field"),
                serde_json::Value::Bool(true),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(
        decoded.is_err(),
        "deny_unknown_fields should reject hostile extra field",
    )
}

#[test]
fn block_003_puzzleproof_38_verify_with_engine_checked_rejects_structurally_invalid_proof()
-> TestResult {
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof {
        height: 38_u64,
        validator: canonical_validator(),
        prev_block_hash: [0_u8; 64],
        output: 38_u128,
    };

    require_validation_error(
        proof.verify_with_engine_checked(&engine),
        "invalid sentinel",
    )
}

#[test]
fn block_003_puzzleproof_39_verify_with_engine_boolean_returns_false_on_invalid_proof() -> TestResult
{
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof {
        height: 39_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(39),
        output: 0_u128,
    };

    ensure(
        !proof.verify_with_engine(&engine),
        "boolean verify_with_engine should return false on validation error",
    )
}

#[test]
fn block_003_puzzleproof_40_load_property_many_valid_proofs_have_unique_commitments() -> TestResult
{
    let mut commitments = BTreeSet::new();
    let mut seed = 40_u8;

    for height in 1_u64..=256_u64 {
        let proof = valid_proof(height, seed)?;
        proof.validate_structural()?;

        let commitment = proof.commitment_hex()?;
        ensure_eq(
            &commitment.len(),
            &128_usize,
            "each load commitment should be 128 hex chars",
        )?;
        ensure(
            is_lowercase_hex(&commitment),
            "each load commitment should be lowercase hex",
        )?;
        ensure(
            commitments.insert(commitment),
            "unique proof vectors should produce unique commitments",
        )?;

        let bytes = postcard::to_allocvec(&proof)?;
        let decoded: BlockPuzzleProof = postcard::from_bytes(&bytes)?;
        ensure_eq(
            &decoded,
            &proof,
            "proof should roundtrip during load/property pass",
        )?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &commitments.len(),
        &256_usize,
        "load/property pass should collect 256 unique commitments",
    )
}

#[test]
fn block_003_puzzleproof_41_new_accepts_height_zero_for_structural_proof() -> TestResult {
    let proof = BlockPuzzleProof::new(0_u64, canonical_validator(), patterned_hash(41), 41_u128)?;

    ensure_eq(
        &proof.height,
        &0_u64,
        "height zero should be structurally accepted",
    )
}

#[test]
fn block_003_puzzleproof_42_new_accepts_min_nonzero_output() -> TestResult {
    let proof = BlockPuzzleProof::new(42_u64, canonical_validator(), patterned_hash(42), 1_u128)?;

    ensure_eq(
        &proof.output,
        &1_u128,
        "minimum nonzero output should be accepted",
    )
}

#[test]
fn block_003_puzzleproof_43_new_rejects_validator_exactly_256_if_not_valid_wallet() -> TestResult {
    let validator = "r".repeat(256);

    require_validation_error_any(BlockPuzzleProof::new(
        43_u64,
        validator,
        patterned_hash(43),
        43_u128,
    ))
}

#[test]
fn block_003_puzzleproof_44_validate_structural_rejects_manual_validator_exactly_256_invalid_wallet()
-> TestResult {
    let proof = BlockPuzzleProof {
        height: 44_u64,
        validator: "r".repeat(256),
        prev_block_hash: patterned_hash(44),
        output: 44_u128,
    };

    require_validation_error_any(proof.validate_structural())
}

#[test]
fn block_003_puzzleproof_45_validate_structural_rejects_manual_uppercase_prefix_validator()
-> TestResult {
    let mut validator = String::from("R");
    for _ in 0..128 {
        validator.push('1');
    }

    let proof = BlockPuzzleProof {
        height: 45_u64,
        validator,
        prev_block_hash: patterned_hash(45),
        output: 45_u128,
    };

    require_validation_error(proof.validate_structural(), "validator is not canonical")
}

#[test]
fn block_003_puzzleproof_46_validate_structural_accepts_u128_max_output() -> TestResult {
    let proof = BlockPuzzleProof {
        height: 46_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(46),
        output: u128::MAX,
    };

    proof.validate_structural()?;
    Ok(())
}

#[test]
fn block_003_puzzleproof_47_validate_structural_accepts_prev_hash_with_one_nonzero_byte()
-> TestResult {
    let mut prev_hash = [0_u8; 64];
    for byte in prev_hash.iter_mut().take(1) {
        *byte = 1_u8;
    }

    let proof = BlockPuzzleProof::new(47_u64, canonical_validator(), prev_hash, 47_u128)?;

    proof.validate_structural()?;
    Ok(())
}

#[test]
fn block_003_puzzleproof_48_validate_structural_accepts_prev_hash_with_one_non_ff_byte()
-> TestResult {
    let mut prev_hash = [0xFF_u8; 64];
    for byte in prev_hash.iter_mut().take(1) {
        *byte = 0xFE_u8;
    }

    let proof = BlockPuzzleProof::new(48_u64, canonical_validator(), prev_hash, 48_u128)?;

    proof.validate_structural()?;
    Ok(())
}

#[test]
fn block_003_puzzleproof_49_json_rejects_prev_hash_with_63_elements() -> TestResult {
    let proof = valid_proof(49_u64, 49)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("prev_block_hash"),
                serde_json::Value::Array(
                    (0_u8..63_u8)
                        .map(|_| serde_json::Value::from(0_u8))
                        .collect(),
                ),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(
        decoded.is_err(),
        "serde_u8_array_64 should reject prev_block_hash arrays shorter than 64",
    )
}

#[test]
fn block_003_puzzleproof_50_json_rejects_prev_hash_with_65_elements() -> TestResult {
    let proof = valid_proof(50_u64, 50)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("prev_block_hash"),
                serde_json::Value::Array(
                    (0_u8..65_u8)
                        .map(|_| serde_json::Value::from(0_u8))
                        .collect(),
                ),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(
        decoded.is_err(),
        "serde_u8_array_64 should reject prev_block_hash arrays longer than 64",
    )
}

#[test]
fn block_003_puzzleproof_51_json_rejects_prev_hash_as_string() -> TestResult {
    let proof = valid_proof(51_u64, 51)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("prev_block_hash"),
                serde_json::Value::String("00".repeat(64)),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(
        decoded.is_err(),
        "prev_block_hash must deserialize as fixed 64-byte tuple/array, not string",
    )
}

#[test]
fn block_003_puzzleproof_52_json_rejects_validator_as_number() -> TestResult {
    let proof = valid_proof(52_u64, 52)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(String::from("validator"), serde_json::Value::from(123_u64));
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(decoded.is_err(), "validator must deserialize as a string")
}

#[test]
fn block_003_puzzleproof_53_json_rejects_output_as_string() -> TestResult {
    let proof = valid_proof(53_u64, 53)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("output"),
                serde_json::Value::String(String::from("53")),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(decoded.is_err(), "output must deserialize as u128 number")
}

#[test]
fn block_003_puzzleproof_54_json_decodes_zero_output_but_structural_validation_rejects_it()
-> TestResult {
    let proof = valid_proof(54_u64, 54)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(String::from("output"), serde_json::Value::from(0_u64));
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value)?;

    require_validation_error(decoded.validate_structural(), "output cannot be 0")
}

#[test]
fn block_003_puzzleproof_55_json_rejects_missing_height() -> TestResult {
    let proof = valid_proof(55_u64, 55)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("height");
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(decoded.is_err(), "missing height field should be rejected")
}

#[test]
fn block_003_puzzleproof_56_json_rejects_missing_validator() -> TestResult {
    let proof = valid_proof(56_u64, 56)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("validator");
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(
        decoded.is_err(),
        "missing validator field should be rejected",
    )
}

#[test]
fn block_003_puzzleproof_57_json_rejects_missing_prev_block_hash() -> TestResult {
    let proof = valid_proof(57_u64, 57)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("prev_block_hash");
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(
        decoded.is_err(),
        "missing prev_block_hash field should be rejected",
    )
}

#[test]
fn block_003_puzzleproof_58_json_rejects_missing_output() -> TestResult {
    let proof = valid_proof(58_u64, 58)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("output");
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value);

    ensure(decoded.is_err(), "missing output field should be rejected")
}

#[test]
fn block_003_puzzleproof_59_commitment_bytes_succeeds_for_manual_structurally_invalid_zero_output()
-> TestResult {
    let proof = BlockPuzzleProof {
        height: 59_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(59),
        output: 0_u128,
    };

    require_validation_error(proof.validate_structural(), "output cannot be 0")?;

    let commitment = proof.commitment_bytes()?;

    ensure(
        !is_all_zero_64(&commitment),
        "commitment_bytes hashes the struct and does not run structural validation",
    )
}

#[test]
fn block_003_puzzleproof_60_commitment_bytes_succeeds_for_manual_noncanonical_validator()
-> TestResult {
    let proof = BlockPuzzleProof {
        height: 60_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(60),
        output: 60_u128,
    };

    require_validation_error(proof.validate_structural(), "validator is not canonical")?;

    let commitment = proof.commitment_bytes()?;

    ensure(
        !is_all_zero_64(&commitment),
        "commitment_bytes should serialize/hash even manually noncanonical structs",
    )
}

#[test]
fn block_003_puzzleproof_61_from_gossip_rejects_height_over_limit() -> TestResult {
    let gossip = PorPuzzleProof {
        height: 10_000_001_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(61),
        output: 61_u128,
    };

    require_validation_error(
        BlockPuzzleProof::from_gossip(&gossip),
        "height out of bounds",
    )
}

#[test]
fn block_003_puzzleproof_62_from_gossip_rejects_ff_prev_hash() -> TestResult {
    let gossip = PorPuzzleProof {
        height: 62_u64,
        validator: canonical_validator(),
        prev_block_hash: [0xFF_u8; 64],
        output: 62_u128,
    };

    require_validation_error(BlockPuzzleProof::from_gossip(&gossip), "invalid sentinel")
}

#[test]
fn block_003_puzzleproof_63_to_gossip_preserves_manual_invalid_zero_output_without_validation()
-> TestResult {
    let proof = BlockPuzzleProof {
        height: 63_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(63),
        output: 0_u128,
    };

    let gossip = proof.to_gossip();

    ensure_eq(
        &gossip.output,
        &0_u128,
        "to_gossip should preserve output exactly",
    )?;
    require_validation_error(BlockPuzzleProof::from_gossip(&gossip), "output cannot be 0")
}

#[test]
fn block_003_puzzleproof_64_verify_with_engine_checked_returns_false_for_wrong_but_structural_output()
-> TestResult {
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof::new(64_u64, canonical_validator(), patterned_hash(64), 1_u128)?;

    let verified = proof.verify_with_engine_checked(&engine)?;

    ensure(
        !verified,
        "structurally valid but wrong puzzle output should return Ok(false)",
    )
}

#[test]
fn block_003_puzzleproof_65_verify_with_engine_boolean_false_for_manual_noncanonical_validator()
-> TestResult {
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof {
        height: 65_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(65),
        output: 65_u128,
    };

    ensure(
        !proof.verify_with_engine(&engine),
        "boolean verify_with_engine should return false for noncanonical validator",
    )
}

#[test]
fn block_003_puzzleproof_66_clone_preserves_equality_and_commitment() -> TestResult {
    let proof = valid_proof(66_u64, 66)?;
    let cloned = proof.clone();

    ensure_eq(&cloned, &proof, "clone should preserve proof equality")?;
    ensure_eq(
        &cloned.commitment_hex()?,
        &proof.commitment_hex()?,
        "clone should preserve proof commitment",
    )
}

#[test]
fn block_003_puzzleproof_67_debug_output_mentions_struct_name_and_validator() -> TestResult {
    let proof = valid_proof(67_u64, 67)?;
    let debug = format!("{proof:?}");

    ensure(
        debug.contains("BlockPuzzleProof"),
        "Debug output should include struct name",
    )?;
    ensure(
        debug.contains(&proof.validator),
        "Debug output should include validator field",
    )
}

#[test]
fn block_003_puzzleproof_68_partial_eq_detects_output_difference() -> TestResult {
    let first = valid_proof(68_u64, 68)?;
    let second = BlockPuzzleProof::new(68_u64, canonical_validator(), patterned_hash(68), 70_u128)?;

    ensure_ne(&first, &second, "PartialEq should detect output difference")
}

#[test]
fn block_003_puzzleproof_69_partial_eq_detects_prev_hash_difference() -> TestResult {
    let first = valid_proof(69_u64, 69)?;
    let second = BlockPuzzleProof::new(69_u64, canonical_validator(), patterned_hash(70), 70_u128)?;

    ensure_ne(
        &first,
        &second,
        "PartialEq should detect prev_block_hash difference",
    )
}

#[test]
fn block_003_puzzleproof_70_postcard_rejects_short_malformed_payload() -> TestResult {
    let decoded = postcard::from_bytes::<BlockPuzzleProof>(&[1_u8, 2_u8, 3_u8]);

    ensure(
        decoded.is_err(),
        "short malformed postcard payload should fail",
    )
}

#[test]
fn block_003_puzzleproof_71_postcard_decodes_then_validation_rejects_zero_prev_hash() -> TestResult
{
    let proof = BlockPuzzleProof {
        height: 71_u64,
        validator: canonical_validator(),
        prev_block_hash: [0_u8; 64],
        output: 71_u128,
    };
    let bytes = postcard::to_allocvec(&proof)?;
    let decoded: BlockPuzzleProof = postcard::from_bytes(&bytes)?;

    require_validation_error(decoded.validate_structural(), "invalid sentinel")
}

#[test]
fn block_003_puzzleproof_72_postcard_decodes_then_validation_rejects_ff_prev_hash() -> TestResult {
    let proof = BlockPuzzleProof {
        height: 72_u64,
        validator: canonical_validator(),
        prev_block_hash: [0xFF_u8; 64],
        output: 72_u128,
    };
    let bytes = postcard::to_allocvec(&proof)?;
    let decoded: BlockPuzzleProof = postcard::from_bytes(&bytes)?;

    require_validation_error(decoded.validate_structural(), "invalid sentinel")
}

#[test]
fn block_003_puzzleproof_73_postcard_decodes_then_validation_rejects_height_over_limit()
-> TestResult {
    let proof = BlockPuzzleProof {
        height: 10_000_001_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(73),
        output: 73_u128,
    };
    let bytes = postcard::to_allocvec(&proof)?;
    let decoded: BlockPuzzleProof = postcard::from_bytes(&bytes)?;

    require_validation_error(decoded.validate_structural(), "height out of bounds")
}

#[test]
fn block_003_puzzleproof_74_json_valid_hash_array_has_exact_64_elements() -> TestResult {
    let proof = valid_proof(74_u64, 74)?;
    let value = serde_json::to_value(&proof)?;

    let len = value
        .get("prev_block_hash")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| fail("prev_block_hash should serialize as JSON array"))?;

    ensure_eq(
        &len,
        &64_usize,
        "prev_block_hash JSON array should have exactly 64 elements",
    )
}

#[test]
fn block_003_puzzleproof_75_json_roundtrip_then_validate_structural() -> TestResult {
    let proof = valid_proof(75_u64, 75)?;
    let json = serde_json::to_string(&proof)?;
    let decoded: BlockPuzzleProof = serde_json::from_str(&json)?;

    decoded.validate_structural()?;
    ensure_eq(
        &decoded,
        &proof,
        "JSON roundtrip should preserve valid proof",
    )
}

#[test]
fn block_003_puzzleproof_76_commitment_hex_decodes_back_to_commitment_bytes() -> TestResult {
    let proof = valid_proof(76_u64, 76)?;
    let hex = proof.commitment_hex()?;
    let bytes = proof.commitment_bytes()?;
    let mut decoded = [0_u8; 64];

    hex::decode_to_slice(&hex, &mut decoded)?;

    ensure_eq(
        &decoded,
        &bytes,
        "commitment_hex should decode back to commitment_bytes",
    )
}

#[test]
fn block_003_puzzleproof_77_commitment_differs_for_canonicalized_constructor_vs_manual_uppercase()
-> TestResult {
    let constructed =
        BlockPuzzleProof::new(77_u64, uppercase_validator(), patterned_hash(77), 77_u128)?;

    let manual = BlockPuzzleProof {
        height: 77_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(77),
        output: 77_u128,
    };

    ensure_ne(
        &constructed.commitment_hex()?,
        &manual.commitment_hex()?,
        "constructor canonicalization changes serialized commitment compared with manual uppercase struct",
    )
}

#[test]
fn block_003_puzzleproof_78_from_gossip_and_to_gossip_canonicalize_uppercase_to_lowercase()
-> TestResult {
    let gossip = PorPuzzleProof {
        height: 78_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(78),
        output: 78_u128,
    };

    let block_proof = BlockPuzzleProof::from_gossip(&gossip)?;
    let back_to_gossip = block_proof.to_gossip();

    ensure_eq(
        &back_to_gossip.validator,
        &uppercase_validator().to_ascii_lowercase(),
        "from_gossip should canonicalize before to_gossip returns value",
    )
}

#[test]
fn block_003_puzzleproof_79_to_gossip_does_not_change_manual_noncanonical_validator() -> TestResult
{
    let proof = BlockPuzzleProof {
        height: 79_u64,
        validator: uppercase_validator(),
        prev_block_hash: patterned_hash(79),
        output: 79_u128,
    };

    let gossip = proof.to_gossip();

    ensure_eq(
        &gossip.validator,
        &uppercase_validator(),
        "to_gossip is a field conversion and does not validate/canonicalize manual structs",
    )
}

#[test]
fn block_003_puzzleproof_80_validate_structural_rejects_multiple_bad_heights_in_loop() -> TestResult
{
    for height in [10_000_001_u64, 10_000_002_u64, u64::MAX] {
        let proof = BlockPuzzleProof {
            height,
            validator: canonical_validator(),
            prev_block_hash: patterned_hash(80),
            output: 80_u128,
        };

        require_validation_error(proof.validate_structural(), "height out of bounds")?;
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_81_validate_structural_rejects_multiple_bad_validators_in_loop()
-> TestResult {
    let validators = vec![
        String::new(),
        String::from("r1234"),
        String::from(
            "x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        ),
        "r".repeat(257),
    ];

    for validator in validators {
        let proof = BlockPuzzleProof {
            height: 81_u64,
            validator,
            prev_block_hash: patterned_hash(81),
            output: 81_u128,
        };

        require_validation_error_any(proof.validate_structural())?;
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_82_validate_structural_rejects_sentinel_hashes_in_loop() -> TestResult {
    for prev_block_hash in [[0_u8; 64], [0xFF_u8; 64]] {
        let proof = BlockPuzzleProof {
            height: 82_u64,
            validator: canonical_validator(),
            prev_block_hash,
            output: 82_u128,
        };

        require_validation_error(proof.validate_structural(), "invalid sentinel")?;
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_83_many_output_values_validate_and_commit() -> TestResult {
    let outputs = [
        1_u128,
        2_u128,
        3_u128,
        255_u128,
        256_u128,
        u64::MAX as u128,
        u128::MAX,
    ];

    for output in outputs {
        let proof =
            BlockPuzzleProof::new(83_u64, canonical_validator(), patterned_hash(83), output)?;

        proof.validate_structural()?;
        ensure_eq(
            &proof.commitment_hex()?.len(),
            &128_usize,
            "each output vector should produce a 128-char commitment",
        )?;
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_84_commitments_unique_across_output_vectors() -> TestResult {
    let mut commitments = BTreeSet::new();

    for output in 1_u128..=128_u128 {
        let proof =
            BlockPuzzleProof::new(84_u64, canonical_validator(), patterned_hash(84), output)?;

        ensure(
            commitments.insert(proof.commitment_hex()?),
            "different output vectors should produce unique commitments in this test set",
        )?;
    }

    ensure_eq(
        &commitments.len(),
        &128_usize,
        "should collect 128 unique output commitments",
    )
}

#[test]
fn block_003_puzzleproof_85_commitments_unique_across_validator_vectors() -> TestResult {
    let validators = vec![
        repeated_validator_char('1'),
        repeated_validator_char('2'),
        repeated_validator_char('3'),
        repeated_validator_char('a'),
        repeated_validator_char('b'),
        repeated_validator_char('c'),
    ];

    let mut commitments = BTreeSet::new();

    for validator in validators {
        let proof = BlockPuzzleProof::new(85_u64, validator, patterned_hash(85), 85_u128)?;

        ensure(
            commitments.insert(proof.commitment_hex()?),
            "different validators should produce unique commitments in this vector set",
        )?;
    }

    ensure_eq(
        &commitments.len(),
        &6_usize,
        "should collect six unique validator commitments",
    )
}

#[test]
fn block_003_puzzleproof_86_commitments_unique_across_prev_hash_vectors() -> TestResult {
    let mut commitments = BTreeSet::new();

    for seed in 1_u8..=64_u8 {
        let proof =
            BlockPuzzleProof::new(86_u64, canonical_validator(), patterned_hash(seed), 86_u128)?;

        ensure(
            commitments.insert(proof.commitment_hex()?),
            "different prev_block_hash vectors should produce unique commitments",
        )?;
    }

    ensure_eq(
        &commitments.len(),
        &64_usize,
        "should collect 64 unique prev-hash commitments",
    )
}

#[test]
fn block_003_puzzleproof_87_commitments_unique_across_height_vectors() -> TestResult {
    let mut commitments = BTreeSet::new();

    for height in 1_u64..=128_u64 {
        let proof =
            BlockPuzzleProof::new(height, canonical_validator(), patterned_hash(87), 87_u128)?;

        ensure(
            commitments.insert(proof.commitment_hex()?),
            "different height vectors should produce unique commitments",
        )?;
    }

    ensure_eq(
        &commitments.len(),
        &128_usize,
        "should collect 128 unique height commitments",
    )
}

#[test]
fn block_003_puzzleproof_88_verify_with_engine_checked_propagates_structural_height_error()
-> TestResult {
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof {
        height: 10_000_001_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(88),
        output: 88_u128,
    };

    require_validation_error(
        proof.verify_with_engine_checked(&engine),
        "height out of bounds",
    )
}

#[test]
fn block_003_puzzleproof_89_verify_with_engine_checked_propagates_structural_validator_error()
-> TestResult {
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof {
        height: 89_u64,
        validator: "r".repeat(257),
        prev_block_hash: patterned_hash(89),
        output: 89_u128,
    };

    require_validation_error(
        proof.verify_with_engine_checked(&engine),
        "validator too long",
    )
}

#[test]
fn block_003_puzzleproof_90_verify_with_engine_checked_propagates_structural_output_error()
-> TestResult {
    let engine = PorPuzzleEngine::from_globals();
    let proof = BlockPuzzleProof {
        height: 90_u64,
        validator: canonical_validator(),
        prev_block_hash: patterned_hash(90),
        output: 0_u128,
    };

    require_validation_error(
        proof.verify_with_engine_checked(&engine),
        "output cannot be 0",
    )
}

#[test]
fn block_003_puzzleproof_91_verify_with_engine_boolean_false_for_sentinel_hashes() -> TestResult {
    let engine = PorPuzzleEngine::from_globals();

    for prev_block_hash in [[0_u8; 64], [0xFF_u8; 64]] {
        let proof = BlockPuzzleProof {
            height: 91_u64,
            validator: canonical_validator(),
            prev_block_hash,
            output: 91_u128,
        };

        ensure(
            !proof.verify_with_engine(&engine),
            "boolean verifier should return false for sentinel hash validation errors",
        )?;
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_92_adversarial_json_decodes_noncanonical_but_validation_rejects()
-> TestResult {
    let proof = valid_proof(92_u64, 92)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("validator"),
                serde_json::Value::String(uppercase_validator()),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value)?;

    require_validation_error(decoded.validate_structural(), "validator is not canonical")
}

#[test]
fn block_003_puzzleproof_93_adversarial_json_decodes_height_over_limit_but_validation_rejects()
-> TestResult {
    let proof = valid_proof(93_u64, 93)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("height"),
                serde_json::Value::from(10_000_001_u64),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value)?;

    require_validation_error(decoded.validate_structural(), "height out of bounds")
}

#[test]
fn block_003_puzzleproof_94_adversarial_json_decodes_zero_sentinel_hash_but_validation_rejects()
-> TestResult {
    let proof = valid_proof(94_u64, 94)?;
    let mut value = serde_json::to_value(proof)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("prev_block_hash"),
                serde_json::Value::Array(
                    (0_u8..64_u8)
                        .map(|_| serde_json::Value::from(0_u8))
                        .collect(),
                ),
            );
        }
        None => return Err(fail("BlockPuzzleProof should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<BlockPuzzleProof>(value)?;

    require_validation_error(decoded.validate_structural(), "invalid sentinel")
}

#[test]
fn block_003_puzzleproof_95_adversarial_gossip_inputs_are_rejected_by_from_gossip() -> TestResult {
    let bad_gossips = vec![
        PorPuzzleProof {
            height: 10_000_001_u64,
            validator: canonical_validator(),
            prev_block_hash: patterned_hash(95),
            output: 95_u128,
        },
        PorPuzzleProof {
            height: 95_u64,
            validator: canonical_validator(),
            prev_block_hash: [0_u8; 64],
            output: 95_u128,
        },
        PorPuzzleProof {
            height: 95_u64,
            validator: canonical_validator(),
            prev_block_hash: patterned_hash(95),
            output: 0_u128,
        },
        PorPuzzleProof {
            height: 95_u64,
            validator: String::from("bad-validator"),
            prev_block_hash: patterned_hash(95),
            output: 95_u128,
        },
    ];

    for gossip in bad_gossips {
        require_validation_error_any(BlockPuzzleProof::from_gossip(&gossip))?;
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_96_load_json_and_postcard_roundtrip_many_valid_proofs() -> TestResult {
    let mut seed = 96_u8;

    for height in 1_u64..=128_u64 {
        let proof = valid_proof(height, seed)?;

        let json = serde_json::to_string(&proof)?;
        let json_decoded: BlockPuzzleProof = serde_json::from_str(&json)?;
        ensure_eq(
            &json_decoded,
            &proof,
            "JSON roundtrip should preserve proof during load pass",
        )?;

        let bytes = postcard::to_allocvec(&proof)?;
        let postcard_decoded: BlockPuzzleProof = postcard::from_bytes(&bytes)?;
        ensure_eq(
            &postcard_decoded,
            &proof,
            "postcard roundtrip should preserve proof during load pass",
        )?;

        seed = seed.wrapping_add(1);
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_97_load_gossip_roundtrip_many_valid_proofs() -> TestResult {
    let mut seed = 97_u8;

    for height in 1_u64..=128_u64 {
        let proof = valid_proof(height, seed)?;
        let gossip = proof.to_gossip();
        let roundtrip = BlockPuzzleProof::from_gossip(&gossip)?;

        ensure_eq(
            &roundtrip,
            &proof,
            "gossip conversion should roundtrip during load pass",
        )?;

        seed = seed.wrapping_add(1);
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_98_load_commitment_bytes_match_hex_for_many_valid_proofs() -> TestResult {
    let mut seed = 98_u8;

    for height in 1_u64..=128_u64 {
        let proof = valid_proof(height, seed)?;
        let bytes = proof.commitment_bytes()?;
        let hex = proof.commitment_hex()?;
        let mut decoded = [0_u8; 64];

        hex::decode_to_slice(&hex, &mut decoded)?;

        ensure_eq(
            &decoded,
            &bytes,
            "commitment_hex should decode to commitment_bytes during load pass",
        )?;

        seed = seed.wrapping_add(1);
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_99_property_constructor_canonicalization_matches_from_gossip() -> TestResult
{
    let mut seed = 99_u8;

    for height in 1_u64..=64_u64 {
        let constructor_proof = BlockPuzzleProof::new(
            height,
            uppercase_validator(),
            patterned_hash(seed),
            u128::from(seed).saturating_add(1),
        )?;

        let gossip = PorPuzzleProof {
            height,
            validator: uppercase_validator(),
            prev_block_hash: patterned_hash(seed),
            output: u128::from(seed).saturating_add(1),
        };
        let gossip_proof = BlockPuzzleProof::from_gossip(&gossip)?;

        ensure_eq(
            &constructor_proof,
            &gossip_proof,
            "constructor and from_gossip should canonicalize uppercase validators identically",
        )?;

        seed = seed.wrapping_add(1);
    }

    Ok(())
}

#[test]
fn block_003_puzzleproof_100_adversarial_load_valid_and_invalid_proofs() -> TestResult {
    let mut commitments = BTreeSet::new();
    let mut seed = 100_u8;

    for height in 1_u64..=256_u64 {
        let valid = valid_proof(height, seed)?;
        valid.validate_structural()?;
        ensure(
            commitments.insert(valid.commitment_hex()?),
            "valid adversarial-load proof should produce unique commitment",
        )?;

        let mut zero_output = valid.clone();
        zero_output.output = 0_u128;
        require_validation_error(zero_output.validate_structural(), "output cannot be 0")?;

        let mut bad_height = valid.clone();
        bad_height.height = 10_000_001_u64;
        require_validation_error(bad_height.validate_structural(), "height out of bounds")?;

        let mut zero_hash = valid.clone();
        zero_hash.prev_block_hash = [0_u8; 64];
        require_validation_error(zero_hash.validate_structural(), "invalid sentinel")?;

        seed = seed.wrapping_add(1);
    }

    ensure_eq(
        &commitments.len(),
        &256_usize,
        "adversarial load should collect 256 unique valid commitments",
    )
}
