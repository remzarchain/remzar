use blake3::Hasher;
use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::consensus::por_002_puzzle_engine::{
    PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
};
use remzar::consensus::por_003_puzzle_pool::PorPuzzlePool;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use serde_json::json;
use std::error::Error;
use std::io;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const MAX_FACT_N_FOR_TEST: u64 = 1_u64 << 48;

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn prev_hash(seed: u64) -> [u8; 64] {
    let mut out = [0_u8; 64];
    let mut state = seed;

    for byte in &mut out {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = state.to_be_bytes()[7];
    }

    if out == [0_u8; 64] || out == [0xFF_u8; 64] {
        out[0] = 1;
    }

    out
}

fn zero_delay_engine(kind: PorPuzzleKind) -> PorPuzzleEngine {
    PorPuzzleEngine::new(PorConsensusConfig {
        target_block_time: Duration::ZERO,
        puzzle_kind: kind,
        max_local_puzzle_ms: 1,
    })
}

fn validation_message<T>(result: Result<T, ErrorDetection>) -> TestResult<String> {
    match result {
        Ok(_) => Err(test_error("expected validation error but got Ok")),
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert_eq!(tx_id, None);
            Ok(message)
        }
        Err(other) => Err(Box::new(io::Error::other(format!(
            "unexpected error variant: {other:?}"
        )))),
    }
}

fn valid_fibonacci_solution(
    height: u64,
    seed: u64,
) -> TestResult<(PorPuzzleEngine, PorPuzzleSolution)> {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(seed);
    let hash = prev_hash(seed);
    let header = engine.derive_puzzle(height, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    Ok((engine, solution))
}

fn valid_fibonacci_proof(height: u64, seed: u64) -> TestResult<(PorPuzzleEngine, PorPuzzleProof)> {
    let (engine, solution) = valid_fibonacci_solution(height, seed)?;
    Ok((engine, PorPuzzleProof::from_solution(&solution)))
}

fn factor_n_from_header(header: &PorPuzzleHeader) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(&header.prev_block_hash);
    hasher.update(&header.height.to_be_bytes());
    hasher.update(header.validator.as_bytes());

    let seed = hasher.finalize();
    let sb = seed.as_bytes();

    let mut n = u64::from_be_bytes([sb[0], sb[1], sb[2], sb[3], sb[4], sb[5], sb[6], sb[7]]);
    n |= 1;
    n = n.max(3);

    let shift = header.param & 0x03;
    n >>= shift;

    n
}

fn packed_factor_solution(n: u64, p: u64) -> u128 {
    (u128::from(n) << 64) | u128::from(p)
}

fn valid_factorization_proof() -> TestResult<(PorPuzzleEngine, PorPuzzleProof, u64)> {
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let validator = wallet(9_000);

    for seed in 0_u64..1_000_000_u64 {
        let height = seed % 10_000_000;
        let header = engine.derive_puzzle(height, &validator, prev_hash(seed));
        let n = factor_n_from_header(&header);

        if (3..=MAX_FACT_N_FOR_TEST).contains(&n) {
            let solution = PorPuzzleSolution {
                header,
                output: packed_factor_solution(n, n),
                solved_in_ms: 0,
            };
            return Ok((engine, PorPuzzleProof::from_solution(&solution), n));
        }
    }

    Err(test_error(
        "could not find bounded factorization proof vector",
    ))
}

#[test]
fn test_01_from_solution_copies_core_fields() -> TestResult {
    let (_engine, solution) = valid_fibonacci_solution(1, 1)?;
    let proof = PorPuzzleProof::from_solution(&solution);

    assert_eq!(proof.height, solution.header.height);
    assert_eq!(proof.validator, solution.header.validator);
    assert_eq!(proof.prev_block_hash, solution.header.prev_block_hash);
    assert_eq!(proof.output, solution.output);
    Ok(())
}

#[test]
fn test_02_from_solution_omits_non_consensus_solved_in_ms() -> TestResult {
    let (_engine, mut solution) = valid_fibonacci_solution(2, 2)?;
    solution.solved_in_ms = u64::MAX;

    let proof = PorPuzzleProof::from_solution(&solution);

    assert_eq!(proof.output, solution.output);
    assert_eq!(proof.height, solution.header.height);
    Ok(())
}

#[test]
fn test_03_valid_proof_passes_structural_validation() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(3, 3)?;

    proof.validate_structural()?;

    Ok(())
}

#[test]
fn test_04_valid_proof_verifies_with_engine_checked_true() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(4, 4)?;

    assert!(proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_05_valid_proof_verifies_with_boolean_wrapper_true() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(5, 5)?;

    assert!(proof.verify_with_engine(&engine));
    Ok(())
}

#[test]
fn test_06_verify_and_record_checked_records_valid_proof() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(6, 6)?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    assert_eq!(pool.winners_for_height(6), vec![proof.validator]);
    assert!(pool.entropy_for_height(6).is_some());
    Ok(())
}

#[test]
fn test_07_verify_and_record_boolean_wrapper_records_valid_proof() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(7, 7)?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record(&engine, &mut pool));
    assert_eq!(pool.winners_for_height(7), vec![proof.validator]);
    assert!(pool.entropy_for_height(7).is_some());
    Ok(())
}

#[test]
fn test_08_verify_and_record_invalid_output_returns_false_without_recording() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(8, 8)?;
    let mut pool = PorPuzzlePool::new();

    proof.output = proof.output.saturating_add(1);

    assert!(!proof.verify_and_record_checked(&engine, &mut pool)?);
    assert!(pool.winners_for_height(8).is_empty());
    assert_eq!(pool.entropy_for_height(8), None);
    Ok(())
}

#[test]
fn test_09_verify_with_engine_checked_wrong_output_returns_false_not_error() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(9, 9)?;

    proof.output = proof.output.saturating_add(1);

    assert!(!proof.verify_with_engine_checked(&engine)?);
    assert!(!proof.verify_with_engine(&engine));
    Ok(())
}

#[test]
fn test_10_structural_rejects_non_canonical_uppercase_validator() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(10, 10)?;
    proof.validator = proof.validator.to_ascii_uppercase();

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("validator is not canonical"));
    Ok(())
}

#[test]
fn test_11_structural_rejects_trimmed_validator_even_if_canonicalizable() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(11, 11)?;
    proof.validator = format!("  {}  ", proof.validator);

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("validator is not canonical"));
    Ok(())
}

#[test]
fn test_12_structural_rejects_invalid_validator() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(12, 12)?;
    proof.validator = "not-a-wallet".to_string();

    let message = validation_message(proof.validate_structural())?;

    assert!(!message.is_empty());
    Ok(())
}

#[test]
fn test_13_structural_rejects_too_long_validator_before_wallet_canonicalization() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(13, 13)?;
    proof.validator = "r".repeat(257);

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("validator string too long"));
    assert!(message.contains("max=256"));
    Ok(())
}

#[test]
fn test_14_structural_rejects_height_above_bound() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(14, 14)?;
    proof.height = 10_000_001;

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("height out of bounds"));
    Ok(())
}

#[test]
fn test_15_structural_accepts_height_upper_bound_exactly() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(10_000_000, 15)?;
    let validator = proof.validator.clone();
    let hash = proof.prev_block_hash;
    let header = engine.derive_puzzle(10_000_000, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    proof.output = solution.output;

    proof.validate_structural()?;
    assert!(proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_16_structural_rejects_all_zero_prev_hash() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(16, 16)?;
    proof.prev_block_hash = [0_u8; 64];

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("prev_block_hash is invalid sentinel"));
    Ok(())
}

#[test]
fn test_17_structural_rejects_all_ff_prev_hash() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(17, 17)?;
    proof.prev_block_hash = [0xFF_u8; 64];

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("prev_block_hash is invalid sentinel"));
    Ok(())
}

#[test]
fn test_18_structural_rejects_zero_output() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(18, 18)?;
    proof.output = 0;

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("output cannot be 0"));
    Ok(())
}

#[test]
fn test_19_structural_error_order_validator_before_height() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(19, 19)?;
    proof.validator = "bad-wallet".to_string();
    proof.height = 10_000_001;

    let message = validation_message(proof.validate_structural())?;

    assert!(!message.contains("height out of bounds"));
    Ok(())
}

#[test]
fn test_20_structural_error_order_height_before_prev_hash() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(20, 20)?;
    proof.height = 10_000_001;
    proof.prev_block_hash = [0_u8; 64];

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("height out of bounds"));
    assert!(!message.contains("prev_block_hash"));
    Ok(())
}

#[test]
fn test_21_structural_error_order_prev_hash_before_output() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(21, 21)?;
    proof.prev_block_hash = [0_u8; 64];
    proof.output = 0;

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("prev_block_hash is invalid sentinel"));
    assert!(!message.contains("output cannot be 0"));
    Ok(())
}

#[test]
fn test_22_verify_with_engine_boolean_returns_false_for_structural_error() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(22, 22)?;
    proof.output = 0;

    assert!(!proof.verify_with_engine(&engine));
    Ok(())
}

#[test]
fn test_23_verify_and_record_boolean_returns_false_for_structural_error() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(23, 23)?;
    let mut pool = PorPuzzlePool::new();

    proof.output = 0;

    assert!(!proof.verify_and_record(&engine, &mut pool));
    assert!(pool.winners_for_height(23).is_empty());
    Ok(())
}

#[test]
fn test_24_verify_and_record_checked_structural_error_does_not_mutate_pool() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(24, 24)?;
    let mut pool = PorPuzzlePool::new();

    proof.prev_block_hash = [0_u8; 64];

    assert!(proof.verify_and_record_checked(&engine, &mut pool).is_err());
    assert!(pool.winners_for_height(24).is_empty());
    assert_eq!(pool.entropy_for_height(24), None);
    Ok(())
}

#[test]
fn test_25_clone_preserves_all_proof_fields() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(25, 25)?;
    let cloned = proof.clone();

    assert_eq!(cloned.height, proof.height);
    assert_eq!(cloned.validator, proof.validator);
    assert_eq!(cloned.prev_block_hash, proof.prev_block_hash);
    assert_eq!(cloned.output, proof.output);
    Ok(())
}

#[test]
fn test_26_debug_output_contains_type_and_fields() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(26, 26)?;
    let debug_text = format!("{proof:?}");

    assert!(debug_text.contains("PorPuzzleProof"));
    assert!(debug_text.contains("height"));
    assert!(debug_text.contains("validator"));
    assert!(debug_text.contains("prev_block_hash"));
    assert!(debug_text.contains("output"));
    Ok(())
}

#[test]
fn test_27_postcard_round_trip_preserves_valid_proof() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(27, 27)?;

    let bytes = postcard::to_allocvec(&proof)?;
    let decoded = postcard::from_bytes::<PorPuzzleProof>(&bytes)?;

    assert_eq!(decoded.height, proof.height);
    assert_eq!(decoded.validator, proof.validator);
    assert_eq!(decoded.prev_block_hash, proof.prev_block_hash);
    assert_eq!(decoded.output, proof.output);
    Ok(())
}

#[test]
fn test_28_json_round_trip_preserves_valid_proof() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(28, 28)?;

    let encoded = serde_json::to_string(&proof)?;
    let decoded = serde_json::from_str::<PorPuzzleProof>(&encoded)?;

    assert_eq!(decoded.height, proof.height);
    assert_eq!(decoded.validator, proof.validator);
    assert_eq!(decoded.prev_block_hash, proof.prev_block_hash);
    assert_eq!(decoded.output, proof.output);
    Ok(())
}

#[test]
fn test_29_json_unknown_field_is_denied() -> TestResult {
    let proof_json = json!({
        "height": 29,
        "validator": wallet(29),
        "prev_block_hash": prev_hash(29).to_vec(),
        "output": 1_u128,
        "unknown": true
    });

    let result = serde_json::from_value::<PorPuzzleProof>(proof_json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_30_json_missing_field_is_rejected() -> TestResult {
    let proof_json = json!({
        "height": 30,
        "validator": wallet(30),
        "prev_block_hash": prev_hash(30).to_vec()
    });

    let result = serde_json::from_value::<PorPuzzleProof>(proof_json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_31_json_prev_block_hash_wrong_length_is_rejected() -> TestResult {
    let proof_json = json!({
        "height": 31,
        "validator": wallet(31),
        "prev_block_hash": [1, 2, 3],
        "output": 1
    });

    let result = serde_json::from_value::<PorPuzzleProof>(proof_json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_32_verify_with_wrong_engine_kind_returns_false() -> TestResult {
    let (_fib_engine, proof) = valid_fibonacci_proof(32, 32)?;
    let fact_engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);

    assert!(!proof.verify_with_engine_checked(&fact_engine)?);
    assert!(!proof.verify_with_engine(&fact_engine));
    Ok(())
}

#[test]
fn test_33_verify_and_record_with_wrong_engine_kind_returns_false_without_recording() -> TestResult
{
    let (_fib_engine, proof) = valid_fibonacci_proof(33, 33)?;
    let fact_engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let mut pool = PorPuzzlePool::new();

    assert!(!proof.verify_and_record_checked(&fact_engine, &mut pool)?);
    assert!(pool.winners_for_height(33).is_empty());
    assert_eq!(pool.entropy_for_height(33), None);
    Ok(())
}

#[test]
fn test_34_verify_rejects_mutated_height_with_recomputed_structural_validity() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(34, 34)?;
    proof.height = 35;

    assert!(proof.validate_structural().is_ok());
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_35_verify_mutated_prev_hash_is_self_contained_and_may_still_verify() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(35, 35)?;
    proof.prev_block_hash[0] ^= 0x01;

    proof.validate_structural()?;

    let verified = proof.verify_with_engine_checked(&engine)?;
    if verified {
        assert!(proof.verify_with_engine(&engine));
    } else {
        assert!(!proof.verify_with_engine(&engine));
    }

    Ok(())
}

#[test]
fn test_36_verify_rejects_mutated_output_to_nonzero_wrong_value() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(36, 36)?;
    proof.output = proof.output.saturating_add(999);

    assert!(proof.validate_structural().is_ok());
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_37_factorization_valid_proof_verifies() -> TestResult {
    let (engine, proof, _n) = valid_factorization_proof()?;

    proof.validate_structural()?;
    assert!(proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_38_factorization_valid_proof_records_to_pool() -> TestResult {
    let (engine, proof, _n) = valid_factorization_proof()?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    assert_eq!(pool.winners_for_height(proof.height), vec![proof.validator]);
    assert!(pool.entropy_for_height(proof.height).is_some());
    Ok(())
}

#[test]
fn test_39_factorization_wrong_output_returns_false_not_error() -> TestResult {
    let (engine, mut proof, _n) = valid_factorization_proof()?;

    proof.output = proof.output.saturating_add(1);

    assert!(proof.validate_structural().is_ok());
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_40_load_many_valid_fibonacci_proofs_verify_and_record() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let mut pool = PorPuzzlePool::new();

    for seed in 0_u64..64_u64 {
        let validator = wallet(seed);
        let hash = prev_hash(seed);
        let height = seed;
        let header = engine.derive_puzzle(height, &validator, hash);
        let solution = engine.solve_locally_checked(&header)?;
        let proof = PorPuzzleProof::from_solution(&solution);

        assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
        assert_eq!(pool.winners_for_height(height), vec![validator]);
        assert!(pool.entropy_for_height(height).is_some());
    }

    Ok(())
}

#[test]
fn test_41_height_zero_valid_proof_verifies() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(0, 41)?;

    proof.validate_structural()?;
    assert!(proof.verify_with_engine_checked(&engine)?);
    assert!(proof.verify_with_engine(&engine));
    Ok(())
}

#[test]
fn test_42_height_zero_valid_proof_records_to_pool() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(0, 42)?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    assert_eq!(pool.winners_for_height(0), vec![proof.validator.clone()]);
    assert!(pool.entropy_for_height(0).is_some());
    Ok(())
}

#[test]
fn test_43_height_upper_bound_valid_proof_records_to_pool() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(10_000_000, 43)?;
    let mut pool = PorPuzzlePool::new();

    proof.validate_structural()?;
    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    assert_eq!(
        pool.winners_for_height(10_000_000),
        vec![proof.validator.clone()]
    );
    assert!(pool.entropy_for_height(10_000_000).is_some());
    Ok(())
}

#[test]
fn test_44_height_above_bound_boolean_wrappers_return_false() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(44, 44)?;
    let mut pool = PorPuzzlePool::new();

    proof.height = 10_000_001;

    assert!(!proof.verify_with_engine(&engine));
    assert!(!proof.verify_and_record(&engine, &mut pool));
    assert!(pool.winners_for_height(10_000_001).is_empty());
    Ok(())
}

#[test]
fn test_45_uppercase_validator_checked_verifier_returns_error_not_false() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(45, 45)?;

    proof.validator = proof.validator.to_ascii_uppercase();

    let message = validation_message(proof.verify_with_engine_checked(&engine))?;

    assert!(message.contains("validator is not canonical"));
    Ok(())
}

#[test]
fn test_46_uppercase_validator_checked_record_returns_error_without_pool_mutation() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(46, 46)?;
    let mut pool = PorPuzzlePool::new();

    proof.validator = proof.validator.to_ascii_uppercase();

    let message = validation_message(proof.verify_and_record_checked(&engine, &mut pool))?;

    assert!(message.contains("validator is not canonical"));
    assert!(pool.winners_for_height(46).is_empty());
    assert_eq!(pool.entropy_for_height(46), None);
    Ok(())
}

#[test]
fn test_47_all_zero_prev_hash_boolean_wrappers_return_false() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(47, 47)?;
    let mut pool = PorPuzzlePool::new();

    proof.prev_block_hash = [0_u8; 64];

    assert!(!proof.verify_with_engine(&engine));
    assert!(!proof.verify_and_record(&engine, &mut pool));
    assert!(pool.winners_for_height(47).is_empty());
    Ok(())
}

#[test]
fn test_48_all_ff_prev_hash_boolean_wrappers_return_false() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(48, 48)?;
    let mut pool = PorPuzzlePool::new();

    proof.prev_block_hash = [0xFF_u8; 64];

    assert!(!proof.verify_with_engine(&engine));
    assert!(!proof.verify_and_record(&engine, &mut pool));
    assert!(pool.winners_for_height(48).is_empty());
    Ok(())
}

#[test]
fn test_49_near_zero_prev_hash_is_not_sentinel_and_verifies() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(49);
    let mut hash = [0_u8; 64];
    hash[0] = 1;

    let header = engine.derive_puzzle(49, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;
    let proof = PorPuzzleProof::from_solution(&solution);

    proof.validate_structural()?;
    assert!(proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_50_near_ff_prev_hash_is_not_sentinel_and_verifies() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(50);
    let mut hash = [0xFF_u8; 64];
    hash[63] = 0xFE;

    let header = engine.derive_puzzle(50, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;
    let proof = PorPuzzleProof::from_solution(&solution);

    proof.validate_structural()?;
    assert!(proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_51_postcard_round_trip_proof_still_verifies() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(51, 51)?;

    let bytes = postcard::to_allocvec(&proof)?;
    let decoded = postcard::from_bytes::<PorPuzzleProof>(&bytes)?;

    assert!(decoded.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_52_postcard_round_trip_invalid_validator_still_fails_structural_validation() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(52, 52)?;
    proof.validator = "bad-wallet".to_string();

    let bytes = postcard::to_allocvec(&proof)?;
    let decoded = postcard::from_bytes::<PorPuzzleProof>(&bytes)?;

    assert!(decoded.validate_structural().is_err());
    Ok(())
}

#[test]
fn test_53_json_prev_block_hash_length_65_is_rejected() -> TestResult {
    let proof_json = json!({
        "height": 53,
        "validator": wallet(53),
        "prev_block_hash": vec![1_u8; 65],
        "output": 1
    });

    let result = serde_json::from_value::<PorPuzzleProof>(proof_json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_54_json_prev_block_hash_empty_array_is_rejected() -> TestResult {
    let proof_json = json!({
        "height": 54,
        "validator": wallet(54),
        "prev_block_hash": Vec::<u8>::new(),
        "output": 1
    });

    let result = serde_json::from_value::<PorPuzzleProof>(proof_json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_55_json_zero_output_deserializes_then_structural_validation_rejects() -> TestResult {
    let proof_json = json!({
        "height": 55,
        "validator": wallet(55),
        "prev_block_hash": prev_hash(55).to_vec(),
        "output": 0_u128
    });

    let proof = serde_json::from_value::<PorPuzzleProof>(proof_json)?;
    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("output cannot be 0"));
    Ok(())
}

#[test]
fn test_56_json_all_zero_prev_hash_deserializes_then_structural_validation_rejects() -> TestResult {
    let proof_json = json!({
        "height": 56,
        "validator": wallet(56),
        "prev_block_hash": vec![0_u8; 64],
        "output": 1_u128
    });

    let proof = serde_json::from_value::<PorPuzzleProof>(proof_json)?;
    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("prev_block_hash is invalid sentinel"));
    Ok(())
}

#[test]
fn test_57_json_uppercase_validator_deserializes_then_structural_validation_rejects() -> TestResult
{
    let proof_json = json!({
        "height": 57,
        "validator": wallet(57).to_ascii_uppercase(),
        "prev_block_hash": prev_hash(57).to_vec(),
        "output": 1_u128
    });

    let proof = serde_json::from_value::<PorPuzzleProof>(proof_json)?;
    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("validator is not canonical"));
    Ok(())
}

#[test]
fn test_58_factorization_from_solution_copies_core_fields() -> TestResult {
    let (engine, proof, n) = valid_factorization_proof()?;
    let header = engine.derive_puzzle(proof.height, &proof.validator, proof.prev_block_hash);
    let solution = PorPuzzleSolution {
        header,
        output: packed_factor_solution(n, n),
        solved_in_ms: u64::MAX,
    };
    let rebuilt = PorPuzzleProof::from_solution(&solution);

    assert_eq!(rebuilt.height, proof.height);
    assert_eq!(rebuilt.validator, proof.validator);
    assert_eq!(rebuilt.prev_block_hash, proof.prev_block_hash);
    assert_eq!(rebuilt.output, proof.output);
    Ok(())
}

#[test]
fn test_59_factorization_boolean_record_wrapper_records_valid_proof() -> TestResult {
    let (engine, proof, _n) = valid_factorization_proof()?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record(&engine, &mut pool));
    assert_eq!(
        pool.winners_for_height(proof.height),
        vec![proof.validator.clone()]
    );
    assert!(pool.entropy_for_height(proof.height).is_some());
    Ok(())
}

#[test]
fn test_60_factorization_wrong_output_record_checked_returns_false_without_pool_mutation()
-> TestResult {
    let (engine, mut proof, _n) = valid_factorization_proof()?;
    let mut pool = PorPuzzlePool::new();

    proof.output = proof.output.saturating_add(2);

    assert!(!proof.verify_and_record_checked(&engine, &mut pool)?);
    assert!(pool.winners_for_height(proof.height).is_empty());
    assert_eq!(pool.entropy_for_height(proof.height), None);
    Ok(())
}

#[test]
fn test_61_factorization_zero_output_boolean_wrappers_return_false() -> TestResult {
    let (engine, mut proof, _n) = valid_factorization_proof()?;
    let mut pool = PorPuzzlePool::new();

    proof.output = 0;

    assert!(!proof.verify_with_engine(&engine));
    assert!(!proof.verify_and_record(&engine, &mut pool));
    assert!(pool.winners_for_height(proof.height).is_empty());
    Ok(())
}

#[test]
fn test_62_checked_verifier_returns_error_for_structural_zero_output() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(62, 62)?;

    proof.output = 0;

    let message = validation_message(proof.verify_with_engine_checked(&engine))?;

    assert!(message.contains("output cannot be 0"));
    Ok(())
}

#[test]
fn test_63_checked_record_structural_error_does_not_mutate_existing_pool_entry() -> TestResult {
    let (engine, good_proof) = valid_fibonacci_proof(63, 63)?;
    let mut bad_proof = good_proof.clone();
    let mut pool = PorPuzzlePool::new();

    assert!(good_proof.verify_and_record_checked(&engine, &mut pool)?);
    let before = pool.entropy_for_height(63);

    bad_proof.output = 0;

    assert!(
        bad_proof
            .verify_and_record_checked(&engine, &mut pool)
            .is_err()
    );
    assert_eq!(pool.winners_for_height(63), vec![good_proof.validator]);
    assert_eq!(pool.entropy_for_height(63), before);
    Ok(())
}

#[test]
fn test_64_repeated_verify_and_record_same_proof_is_idempotent_for_pool_winners() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(64, 64)?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    let first_entropy = pool.entropy_for_height(64);

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);

    assert_eq!(pool.winners_for_height(64), vec![proof.validator]);
    assert_eq!(pool.entropy_for_height(64), first_entropy);
    Ok(())
}

#[test]
fn test_65_invalid_nonzero_output_after_valid_record_does_not_overwrite_pool_entropy() -> TestResult
{
    let (engine, good_proof) = valid_fibonacci_proof(65, 65)?;
    let mut bad_proof = good_proof.clone();
    let mut pool = PorPuzzlePool::new();

    assert!(good_proof.verify_and_record_checked(&engine, &mut pool)?);
    let before = pool.entropy_for_height(65);

    bad_proof.output = bad_proof.output.saturating_add(1);

    assert!(!bad_proof.verify_and_record_checked(&engine, &mut pool)?);
    assert_eq!(pool.winners_for_height(65), vec![good_proof.validator]);
    assert_eq!(pool.entropy_for_height(65), before);
    Ok(())
}

#[test]
fn test_66_two_valid_proofs_same_height_record_two_sorted_winners() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let mut pool = PorPuzzlePool::new();
    let height = 66_u64;

    let mut expected = Vec::new();

    for seed in [67_u64, 66_u64] {
        let validator = wallet(seed);
        let hash = prev_hash(seed);
        let header = engine.derive_puzzle(height, &validator, hash);
        let solution = engine.solve_locally_checked(&header)?;
        let proof = PorPuzzleProof::from_solution(&solution);

        assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
        expected.push(validator);
    }

    expected.sort();

    assert_eq!(pool.winners_for_height(height), expected);
    assert!(pool.entropy_for_height(height).is_some());
    Ok(())
}

#[test]
fn test_67_reverse_order_valid_proofs_same_height_produce_same_pool_winners() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let height = 67_u64;
    let seeds = [70_u64, 71_u64, 72_u64, 73_u64];
    let mut forward = PorPuzzlePool::new();
    let mut reverse = PorPuzzlePool::new();

    let mut proofs = Vec::new();
    for seed in seeds {
        let validator = wallet(seed);
        let hash = prev_hash(seed);
        let header = engine.derive_puzzle(height, &validator, hash);
        let solution = engine.solve_locally_checked(&header)?;
        proofs.push(PorPuzzleProof::from_solution(&solution));
    }

    for proof in &proofs {
        assert!(proof.verify_and_record_checked(&engine, &mut forward)?);
    }

    for proof in proofs.iter().rev() {
        assert!(proof.verify_and_record_checked(&engine, &mut reverse)?);
    }

    assert_eq!(
        forward.winners_for_height(height),
        reverse.winners_for_height(height)
    );
    assert_eq!(
        forward.entropy_for_height(height),
        reverse.entropy_for_height(height)
    );
    Ok(())
}

#[test]
fn test_68_clone_can_be_mutated_without_changing_original_proof() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(68, 68)?;
    let mut cloned = proof.clone();

    cloned.output = cloned.output.saturating_add(1);
    cloned.height = cloned.height.saturating_add(1);

    assert_ne!(cloned.output, proof.output);
    assert_ne!(cloned.height, proof.height);
    assert_eq!(cloned.validator, proof.validator);
    Ok(())
}

#[test]
fn test_69_json_serialized_proof_contains_expected_field_names() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(69, 69)?;
    let encoded = serde_json::to_string(&proof)?;

    assert!(encoded.contains("height"));
    assert!(encoded.contains("validator"));
    assert!(encoded.contains("prev_block_hash"));
    assert!(encoded.contains("output"));
    Ok(())
}

#[test]
fn test_70_postcard_encoding_is_deterministic_for_same_proof() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(70, 70)?;

    let first = postcard::to_allocvec(&proof)?;
    let second = postcard::to_allocvec(&proof)?;

    assert_eq!(first, second);
    assert!(!first.is_empty());
    Ok(())
}

#[test]
fn test_71_postcard_encoding_changes_when_output_changes() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(71, 71)?;
    let mut changed = proof.clone();

    changed.output = changed.output.saturating_add(1);

    let first = postcard::to_allocvec(&proof)?;
    let second = postcard::to_allocvec(&changed)?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_72_validator_error_precedes_output_error() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(72, 72)?;

    proof.validator = "bad-wallet".to_string();
    proof.output = 0;

    let message = validation_message(proof.validate_structural())?;

    assert!(!message.contains("output cannot be 0"));
    Ok(())
}

#[test]
fn test_73_wrong_engine_kind_checked_record_returns_false_without_error() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(73, 73)?;
    let wrong_engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let mut pool = PorPuzzlePool::new();

    assert!(!proof.verify_and_record_checked(&wrong_engine, &mut pool)?);
    assert!(pool.winners_for_height(73).is_empty());
    Ok(())
}

#[test]
fn test_74_mutated_canonical_validator_returns_false_without_structural_error() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(74, 74)?;

    proof.validator = wallet(75);

    proof.validate_structural()?;
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_75_mutated_canonical_validator_does_not_record_old_or_new_wallet() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(75, 75)?;
    let original_validator = proof.validator.clone();
    let mutated_validator = wallet(76);
    let mut pool = PorPuzzlePool::new();

    proof.validator = mutated_validator.clone();

    assert!(!proof.verify_and_record_checked(&engine, &mut pool)?);
    assert!(pool.winners_for_height(75).is_empty());
    assert!(!pool.winners_for_height(75).contains(&original_validator));
    assert!(!pool.winners_for_height(75).contains(&mutated_validator));
    Ok(())
}

#[test]
fn test_76_mutated_validator_to_all_zero_wallet_is_structurally_valid_but_fails_proof() -> TestResult
{
    let (engine, mut proof) = valid_fibonacci_proof(76, 76)?;
    let all_zero_wallet = format!("r{}", "0".repeat(128));

    proof.validator = all_zero_wallet;

    proof.validate_structural()?;
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_77_json_round_trip_allows_height_zero_valid_structure() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(0, 77)?;
    let encoded = serde_json::to_string(&proof)?;
    let decoded = serde_json::from_str::<PorPuzzleProof>(&encoded)?;

    decoded.validate_structural()?;
    assert!(decoded.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_78_json_round_trip_allows_height_upper_bound_valid_structure() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(10_000_000, 78)?;
    let encoded = serde_json::to_string(&proof)?;
    let decoded = serde_json::from_str::<PorPuzzleProof>(&encoded)?;

    decoded.validate_structural()?;
    assert!(decoded.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_79_load_many_valid_proofs_structural_validation_only() -> TestResult {
    for seed in 0_u64..128_u64 {
        let (_engine, proof) = valid_fibonacci_proof(seed, seed)?;
        proof.validate_structural()?;
    }

    Ok(())
}

#[test]
fn test_80_adversarial_invalid_structural_matrix_returns_false_for_boolean_wrappers() -> TestResult
{
    let (engine, base_proof) = valid_fibonacci_proof(80, 80)?;

    let mut invalids = Vec::new();

    let mut bad_validator = base_proof.clone();
    bad_validator.validator = "bad-wallet".to_string();
    invalids.push(bad_validator);

    let mut bad_height = base_proof.clone();
    bad_height.height = 10_000_001;
    invalids.push(bad_height);

    let mut bad_hash_zero = base_proof.clone();
    bad_hash_zero.prev_block_hash = [0_u8; 64];
    invalids.push(bad_hash_zero);

    let mut bad_hash_ff = base_proof.clone();
    bad_hash_ff.prev_block_hash = [0xFF_u8; 64];
    invalids.push(bad_hash_ff);

    let mut bad_output = base_proof;
    bad_output.output = 0;
    invalids.push(bad_output);

    for proof in invalids {
        let mut pool = PorPuzzlePool::new();
        assert!(!proof.verify_with_engine(&engine));
        assert!(!proof.verify_and_record(&engine, &mut pool));
        assert!(pool.winners_for_height(proof.height).is_empty());
    }

    Ok(())
}

#[test]
fn test_81_edge_u128_max_output_is_structurally_valid_but_fails_fibonacci_verify() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(81, 81)?;

    proof.output = u128::MAX;

    proof.validate_structural()?;
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_82_vector_all_zero_validator_is_structurally_valid_but_fails_original_proof() -> TestResult
{
    let (engine, mut proof) = valid_fibonacci_proof(82, 82)?;
    let all_zero_validator = format!("r{}", "0".repeat(128));

    proof.validator = all_zero_validator;

    proof.validate_structural()?;
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_83_vector_all_f_validator_is_structurally_valid_but_fails_original_proof() -> TestResult {
    let (engine, mut proof) = valid_fibonacci_proof(83, 83)?;
    let all_f_validator = format!("r{}", "f".repeat(128));

    proof.validator = all_f_validator;

    proof.validate_structural()?;
    assert!(!proof.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_84_edge_validator_length_256_reaches_wallet_validation_not_too_long_branch() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(84, 84)?;
    proof.validator = format!("r{}", "0".repeat(255));

    let message = validation_message(proof.validate_structural())?;

    assert!(!message.contains("validator string too long"));
    assert!(!message.is_empty());
    Ok(())
}

#[test]
fn test_85_edge_validator_length_257_reaches_too_long_branch() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(85, 85)?;
    proof.validator = format!("r{}", "0".repeat(256));

    let message = validation_message(proof.validate_structural())?;

    assert!(message.contains("validator string too long"));
    assert!(message.contains("len=257"));
    assert!(message.contains("max=256"));
    Ok(())
}

#[test]
fn test_86_vector_json_u128_max_output_deserializes_and_is_structurally_valid() -> TestResult {
    let proof = PorPuzzleProof {
        height: 86,
        validator: wallet(86),
        prev_block_hash: prev_hash(86),
        output: u128::MAX,
    };

    let encoded = serde_json::to_string(&proof)?;
    let decoded = serde_json::from_str::<PorPuzzleProof>(&encoded)?;

    decoded.validate_structural()?;
    assert_eq!(decoded.output, u128::MAX);
    Ok(())
}

#[test]
fn test_87_vector_postcard_u128_max_output_round_trips() -> TestResult {
    let (_engine, mut proof) = valid_fibonacci_proof(87, 87)?;
    proof.output = u128::MAX;

    let bytes = postcard::to_allocvec(&proof)?;
    let decoded = postcard::from_bytes::<PorPuzzleProof>(&bytes)?;

    assert_eq!(decoded.height, proof.height);
    assert_eq!(decoded.validator, proof.validator);
    assert_eq!(decoded.prev_block_hash, proof.prev_block_hash);
    assert_eq!(decoded.output, u128::MAX);
    decoded.validate_structural()?;
    Ok(())
}

#[test]
fn test_88_vector_one_byte_prev_hash_changes_are_structurally_valid_and_deterministic() -> TestResult
{
    let (engine, proof) = valid_fibonacci_proof(88, 88)?;

    for index in [0_usize, 1, 31, 32, 63] {
        let mut mutated = proof.clone();
        mutated.prev_block_hash[index] ^= 0x01;

        mutated.validate_structural()?;

        let first = mutated.verify_with_engine_checked(&engine)?;
        let second = mutated.verify_with_engine_checked(&engine)?;

        assert_eq!(first, second);
        assert_eq!(mutated.verify_with_engine(&engine), first);
    }

    Ok(())
}

#[test]
fn test_89_vector_height_mutations_within_bounds_are_structurally_valid_but_fail_verify()
-> TestResult {
    let (engine, proof) = valid_fibonacci_proof(89, 89)?;

    for mutated_height in [0_u64, 1, 88, 90, 10_000_000] {
        if mutated_height == proof.height {
            continue;
        }

        let mut mutated = proof.clone();
        mutated.height = mutated_height;

        mutated.validate_structural()?;
        assert!(!mutated.verify_with_engine_checked(&engine)?);
    }

    Ok(())
}

#[test]
fn test_90_vector_nonzero_wrong_outputs_are_structurally_valid_but_fail_verify() -> TestResult {
    let (engine, proof) = valid_fibonacci_proof(90, 90)?;
    let wrong_outputs = [
        1_u128,
        2_u128,
        proof.output.saturating_add(1),
        proof.output.saturating_add(999),
        u128::MAX,
    ];

    for output in wrong_outputs {
        if output == proof.output {
            continue;
        }

        let mut mutated = proof.clone();
        mutated.output = output;

        mutated.validate_structural()?;
        assert!(!mutated.verify_with_engine_checked(&engine)?);
    }

    Ok(())
}

#[test]
fn test_91_edge_verify_and_record_overwrites_same_height_same_validator_when_second_valid()
-> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(91);
    let height = 91_u64;
    let mut pool = PorPuzzlePool::new();

    let first_header = engine.derive_puzzle(height, &validator, prev_hash(910));
    let first_solution = engine.solve_locally_checked(&first_header)?;
    let first_proof = PorPuzzleProof::from_solution(&first_solution);

    let second_header = engine.derive_puzzle(height, &validator, prev_hash(911));
    let second_solution = engine.solve_locally_checked(&second_header)?;
    let second_proof = PorPuzzleProof::from_solution(&second_solution);

    assert!(first_proof.verify_and_record_checked(&engine, &mut pool)?);
    let first_entropy = pool.entropy_for_height(height);

    assert!(second_proof.verify_and_record_checked(&engine, &mut pool)?);
    let second_entropy = pool.entropy_for_height(height);

    assert_eq!(pool.winners_for_height(height), vec![validator]);
    assert_ne!(first_entropy, second_entropy);
    Ok(())
}

#[test]
fn test_92_edge_verify_and_record_same_validator_same_output_keeps_pool_entropy_stable()
-> TestResult {
    let (engine, proof) = valid_fibonacci_proof(92, 92)?;
    let mut pool = PorPuzzlePool::new();

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    let first_entropy = pool.entropy_for_height(92);

    assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
    let second_entropy = pool.entropy_for_height(92);

    assert_eq!(first_entropy, second_entropy);
    assert_eq!(pool.winners_for_height(92), vec![proof.validator]);
    Ok(())
}

#[test]
fn test_93_vector_multiple_valid_proofs_same_height_have_sorted_pool_winners() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let height = 93_u64;
    let mut pool = PorPuzzlePool::new();
    let seeds = [99_u64, 96, 98, 97];
    let mut expected = Vec::new();

    for seed in seeds {
        let validator = wallet(seed);
        let header = engine.derive_puzzle(height, &validator, prev_hash(seed));
        let solution = engine.solve_locally_checked(&header)?;
        let proof = PorPuzzleProof::from_solution(&solution);

        assert!(proof.verify_and_record_checked(&engine, &mut pool)?);
        expected.push(validator);
    }

    expected.sort();

    assert_eq!(pool.winners_for_height(height), expected);
    assert!(pool.entropy_for_height(height).is_some());
    Ok(())
}

#[test]
fn test_94_vector_postcard_encoding_differs_when_prev_hash_changes() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(94, 94)?;
    let mut changed = proof.clone();

    changed.prev_block_hash[0] ^= 0x01;

    let first = postcard::to_allocvec(&proof)?;
    let second = postcard::to_allocvec(&changed)?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_95_vector_postcard_encoding_differs_when_validator_changes() -> TestResult {
    let (_engine, proof) = valid_fibonacci_proof(95, 95)?;
    let mut changed = proof.clone();

    changed.validator = wallet(96);

    let first = postcard::to_allocvec(&proof)?;
    let second = postcard::to_allocvec(&changed)?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_96_vector_json_round_trip_factorization_proof_still_verifies() -> TestResult {
    let (engine, proof, _n) = valid_factorization_proof()?;

    let encoded = serde_json::to_string(&proof)?;
    let decoded = serde_json::from_str::<PorPuzzleProof>(&encoded)?;

    decoded.validate_structural()?;
    assert!(decoded.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_97_vector_postcard_round_trip_factorization_proof_still_verifies() -> TestResult {
    let (engine, proof, _n) = valid_factorization_proof()?;

    let encoded = postcard::to_allocvec(&proof)?;
    let decoded = postcard::from_bytes::<PorPuzzleProof>(&encoded)?;

    decoded.validate_structural()?;
    assert!(decoded.verify_with_engine_checked(&engine)?);
    Ok(())
}

#[test]
fn test_98_load_vector_json_round_trip_many_valid_fibonacci_proofs() -> TestResult {
    for seed in 0_u64..64_u64 {
        let (engine, proof) = valid_fibonacci_proof(seed, seed)?;

        let encoded = serde_json::to_string(&proof)?;
        let decoded = serde_json::from_str::<PorPuzzleProof>(&encoded)?;

        decoded.validate_structural()?;
        assert!(decoded.verify_with_engine_checked(&engine)?);
    }

    Ok(())
}

#[test]
fn test_99_load_vector_postcard_round_trip_many_valid_fibonacci_proofs() -> TestResult {
    for seed in 0_u64..64_u64 {
        let (engine, proof) = valid_fibonacci_proof(seed, seed)?;

        let encoded = postcard::to_allocvec(&proof)?;
        let decoded = postcard::from_bytes::<PorPuzzleProof>(&encoded)?;

        decoded.validate_structural()?;
        assert!(decoded.verify_with_engine_checked(&engine)?);
    }

    Ok(())
}

#[test]
fn test_100_adversarial_vector_valid_structure_false_verify_does_not_record_any_height()
-> TestResult {
    let (engine, base_proof) = valid_fibonacci_proof(100, 100)?;
    let mut pool = PorPuzzlePool::new();

    let mut mutated_validator = base_proof.clone();
    mutated_validator.validator = wallet(101);

    let mut mutated_output = base_proof;
    mutated_output.output = mutated_output.output.saturating_add(1);

    for proof in [mutated_validator, mutated_output] {
        proof.validate_structural()?;
        assert!(!proof.verify_and_record_checked(&engine, &mut pool)?);
        assert!(pool.winners_for_height(proof.height).is_empty());
    }

    Ok(())
}
