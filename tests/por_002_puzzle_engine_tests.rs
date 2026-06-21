use blake3::Hasher;
use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::consensus::por_002_puzzle_engine::{
    PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::canon_wallet_id_checked;
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

fn packed_n_part(packed: u128) -> TestResult<u64> {
    u64::try_from(packed >> 64).map_err(|_| test_error("packed n part did not fit in u64"))
}

fn packed_p_part(packed: u128) -> TestResult<u64> {
    u64::try_from(packed & u128::from(u64::MAX))
        .map_err(|_| test_error("packed p part did not fit in u64"))
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

    out
}

fn test_config(kind: PorPuzzleKind, target_secs: u64) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(target_secs),
        puzzle_kind: kind,
        max_local_puzzle_ms: 1,
    }
}

fn zero_delay_engine(kind: PorPuzzleKind) -> PorPuzzleEngine {
    PorPuzzleEngine::new(PorConsensusConfig {
        target_block_time: Duration::ZERO,
        puzzle_kind: kind,
        max_local_puzzle_ms: 1,
    })
}

fn fib_u128(n: u32) -> u128 {
    if n == 0 {
        return 0;
    }

    if n == 1 {
        return 1;
    }

    let mut a = 0_u128;
    let mut b = 1_u128;

    for _ in 0_u32..n {
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }

    a
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

fn find_verifiable_factorization_case() -> TestResult<(PorPuzzleEngine, PorPuzzleHeader, u64, u128)>
{
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let validator = wallet(900);

    for seed in 0_u64..1_000_000_u64 {
        let header = engine.derive_puzzle(seed, &validator, prev_hash(seed));
        let n = factor_n_from_header(&header);

        if n <= MAX_FACT_N_FOR_TEST {
            let output = packed_factor_solution(n, n);
            return Ok((engine, header, n, output));
        }
    }

    Err(test_error("could not find bounded factorization case"))
}

fn validation_message(result: Result<(), ErrorDetection>) -> TestResult<String> {
    match result {
        Ok(()) => Err(test_error(
            "expected validation error but validation succeeded",
        )),
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert_eq!(tx_id, None);
            Ok(message)
        }
        Err(other) => Err(Box::new(io::Error::other(format!(
            "unexpected error variant: {other:?}"
        )))),
    }
}

#[test]
fn test_01_from_globals_engine_uses_from_globals_config() {
    let engine = PorPuzzleEngine::from_globals();

    assert_eq!(
        engine.config().puzzle_kind,
        PorConsensusConfig::from_globals().puzzle_kind
    );
    assert_eq!(
        engine.config().target_block_time,
        PorConsensusConfig::from_globals().target_block_time
    );
}

#[test]
fn test_02_new_engine_retains_supplied_config_fields() {
    let cfg = test_config(PorPuzzleKind::FibonacciDelayDev, 7);
    let engine = PorPuzzleEngine::new(cfg.clone());

    assert_eq!(engine.config().target_block_time, cfg.target_block_time);
    assert_eq!(engine.config().puzzle_kind, cfg.puzzle_kind);
    assert_eq!(engine.config().max_local_puzzle_ms, cfg.max_local_puzzle_ms);
}

#[test]
fn test_03_engine_clone_preserves_configuration() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 5));
    let cloned = engine.clone();

    assert_eq!(
        cloned.config().target_block_time,
        engine.config().target_block_time
    );
    assert_eq!(cloned.config().puzzle_kind, engine.config().puzzle_kind);
    assert_eq!(
        cloned.config().max_local_puzzle_ms,
        engine.config().max_local_puzzle_ms
    );
}

#[test]
fn test_04_engine_debug_contains_type_and_config_field() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let debug_text = format!("{engine:?}");

    assert!(debug_text.contains("PorPuzzleEngine"));
    assert!(debug_text.contains("cfg"));
}

#[test]
fn test_05_derive_puzzle_is_deterministic_for_same_inputs() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(5);
    let hash = prev_hash(5);

    let first = engine.derive_puzzle(10, &validator, hash);
    let second = engine.derive_puzzle(10, &validator, hash);

    assert_eq!(first.height, second.height);
    assert_eq!(first.validator, second.validator);
    assert_eq!(first.prev_block_hash, second.prev_block_hash);
    assert_eq!(first.kind, second.kind);
    assert_eq!(first.param, second.param);
}

#[test]
fn test_06_derive_puzzle_records_expected_height() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(123_456, &wallet(6), prev_hash(6));

    assert_eq!(header.height, 123_456);
}

#[test]
fn test_07_derive_puzzle_records_expected_prev_hash() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let hash = prev_hash(7);
    let header = engine.derive_puzzle(7, &wallet(7), hash);

    assert_eq!(header.prev_block_hash, hash);
}

#[test]
fn test_08_derive_puzzle_uses_engine_puzzle_kind() {
    let fib_engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let fact_engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let validator = wallet(8);
    let hash = prev_hash(8);

    let fib_header = fib_engine.derive_puzzle(8, &validator, hash);
    let fact_header = fact_engine.derive_puzzle(8, &validator, hash);

    assert_eq!(fib_header.kind, PorPuzzleKind::FibonacciDelayDev);
    assert_eq!(fact_header.kind, PorPuzzleKind::FactorizationDelayDev);
}

#[test]
fn test_09_derive_puzzle_canonicalizes_uppercase_wallet() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let canonical = wallet(9);
    let uppercase = canonical.to_ascii_uppercase();

    let header = engine.derive_puzzle(9, &uppercase, prev_hash(9));

    assert_eq!(header.validator, canonical);
    assert_eq!(header.validator, canon_wallet_id_checked(&uppercase)?);
    Ok(())
}

#[test]
fn test_10_derive_puzzle_canonicalizes_trimmed_wallet() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let canonical = wallet(10);
    let trimmed = format!(" \n{}\t ", canonical.to_ascii_uppercase());

    let header = engine.derive_puzzle(10, &trimmed, prev_hash(10));

    assert_eq!(header.validator, canonical);
    assert_eq!(header.validator, canon_wallet_id_checked(&trimmed)?);
    Ok(())
}

#[test]
fn test_11_derive_puzzle_uses_fixed_marker_for_invalid_wallet() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);

    let header = engine.derive_puzzle(11, "not-a-wallet", prev_hash(11));

    assert_eq!(header.validator, "por:<invalid-wallet>");
}

#[test]
fn test_12_fibonacci_param_for_target_1_sec_is_in_expected_vector_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 1));
    let header = engine.derive_puzzle(12, &wallet(12), prev_hash(12));

    assert!((26..=33).contains(&header.param));
}

#[test]
fn test_13_fibonacci_param_for_target_15_sec_is_in_expected_vector_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 15));
    let header = engine.derive_puzzle(13, &wallet(13), prev_hash(13));

    assert!((30..=37).contains(&header.param));
}

#[test]
fn test_14_fibonacci_param_for_target_30_sec_is_in_expected_vector_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 30));
    let header = engine.derive_puzzle(14, &wallet(14), prev_hash(14));

    assert!((32..=39).contains(&header.param));
}

#[test]
fn test_15_fibonacci_param_for_target_50_sec_is_in_expected_vector_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 50));
    let header = engine.derive_puzzle(15, &wallet(15), prev_hash(15));

    assert!((34..=41).contains(&header.param));
}

#[test]
fn test_16_fibonacci_param_for_target_61_sec_is_in_expected_vector_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 61));
    let header = engine.derive_puzzle(16, &wallet(16), prev_hash(16));

    assert!((36..=43).contains(&header.param));
}

#[test]
fn test_17_factorization_param_is_always_between_one_and_four() {
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);

    for seed in 0_u64..128_u64 {
        let header = engine.derive_puzzle(seed, &wallet(seed), prev_hash(seed));
        assert!((1..=4).contains(&header.param));
    }
}

#[test]
fn test_18_solve_fibonacci_returns_header_and_expected_output() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(18, &wallet(18), prev_hash(18));

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.height, header.height);
    assert_eq!(solution.header.validator, header.validator);
    assert_eq!(solution.header.prev_block_hash, header.prev_block_hash);
    assert_eq!(solution.header.kind, header.kind);
    assert_eq!(solution.header.param, header.param);
    assert_eq!(solution.output, fib_u128(header.param));
    Ok(())
}

#[test]
fn test_19_verify_checked_accepts_valid_fibonacci_solution() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(19);
    let hash = prev_hash(19);
    let header = engine.derive_puzzle(19, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    engine.verify_checked(&solution, 19, &validator, hash)?;

    Ok(())
}

#[test]
fn test_20_verify_boolean_accepts_valid_fibonacci_solution() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(20);
    let hash = prev_hash(20);
    let header = engine.derive_puzzle(20, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    assert!(engine.verify(&solution, 20, &validator, hash));
    Ok(())
}

#[test]
fn test_21_verify_checked_rejects_wrong_expected_height() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(21);
    let hash = prev_hash(21);
    let header = engine.derive_puzzle(21, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    let message = validation_message(engine.verify_checked(&solution, 22, &validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_22_verify_checked_rejects_wrong_expected_validator() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(22);
    let wrong_validator = wallet(23);
    let hash = prev_hash(22);
    let header = engine.derive_puzzle(22, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    let message = validation_message(engine.verify_checked(&solution, 22, &wrong_validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_23_verify_checked_rejects_wrong_expected_prev_hash() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(23);
    let hash = prev_hash(23);
    let wrong_hash = prev_hash(24);
    let header = engine.derive_puzzle(23, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    let message = validation_message(engine.verify_checked(&solution, 23, &validator, wrong_hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_24_verify_checked_rejects_wrong_fibonacci_output() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(24);
    let hash = prev_hash(24);
    let header = engine.derive_puzzle(24, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.output = solution.output.saturating_add(1);

    let message = validation_message(engine.verify_checked(&solution, 24, &validator, hash))?;

    assert!(message.contains("Fibonacci puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_25_verify_boolean_rejects_wrong_fibonacci_output() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(25);
    let hash = prev_hash(25);
    let header = engine.derive_puzzle(25, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.output = solution.output.saturating_add(1);

    assert!(!engine.verify(&solution, 25, &validator, hash));
    Ok(())
}

#[test]
fn test_26_solve_normalizes_malicious_fibonacci_param_above_cap() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 26,
        validator: wallet(26),
        prev_block_hash: prev_hash(26),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 10_000,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 44);
    assert_eq!(solution.output, fib_u128(44));
    Ok(())
}

#[test]
fn test_27_solve_normalizes_invalid_wallet_to_fixed_marker() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 27,
        validator: "not-a-wallet".to_string(),
        prev_block_hash: prev_hash(27),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 30,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.validator, "por:<invalid-wallet>");
    assert_eq!(solution.output, fib_u128(30));
    Ok(())
}

#[test]
fn test_28_verify_accepts_solution_header_with_uppercase_validator_after_normalization()
-> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(28);
    let hash = prev_hash(28);
    let header = engine.derive_puzzle(28, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.header.validator = validator.to_ascii_uppercase();

    engine.verify_checked(&solution, 28, &validator, hash)?;
    assert!(engine.verify(&solution, 28, &validator, hash));
    Ok(())
}

#[test]
fn test_29_verify_rejects_solution_with_modified_header_param() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(29);
    let hash = prev_hash(29);
    let header = engine.derive_puzzle(29, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.header.param = solution.header.param.saturating_add(1);

    let message = validation_message(engine.verify_checked(&solution, 29, &validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_30_verify_rejects_solution_with_modified_header_kind() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(30);
    let hash = prev_hash(30);
    let header = engine.derive_puzzle(30, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.header.kind = PorPuzzleKind::FactorizationDelayDev;

    let message = validation_message(engine.verify_checked(&solution, 30, &validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_31_factorization_manual_valid_packed_solution_verifies() -> TestResult {
    let (engine, header, _n, output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output,
        solved_in_ms: 0,
    };

    engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    )?;
    assert!(engine.verify(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash
    ));
    Ok(())
}

#[test]
fn test_32_factorization_rejects_wrong_n_part() -> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let wrong_n = n
        .checked_add(2)
        .ok_or_else(|| test_error("factor n overflowed in test"))?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(wrong_n, n),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_33_factorization_rejects_factor_below_three() -> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(n, 1),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_34_factorization_rejects_non_dividing_factor() -> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let non_dividing_factor = n
        .checked_add(2)
        .ok_or_else(|| test_error("factor overflowed in test"))?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(n, non_dividing_factor),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_35_factorization_rejects_wrong_expected_height() -> TestResult {
    let (engine, header, _n, output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output,
        solved_in_ms: 0,
    };
    let wrong_height = header
        .height
        .checked_add(1)
        .ok_or_else(|| test_error("height overflowed in test"))?;

    let message = validation_message(engine.verify_checked(
        &solution,
        wrong_height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_36_solve_factorization_normalizes_param_to_one_through_four() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let header = PorPuzzleHeader {
        height: 36,
        validator: wallet(36),
        prev_block_hash: prev_hash(36),
        kind: PorPuzzleKind::FactorizationDelayDev,
        param: 99,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert!((1..=4).contains(&solution.header.param));
    assert_eq!(solution.header.kind, PorPuzzleKind::FactorizationDelayDev);
    Ok(())
}

#[test]
fn test_37_adversarial_solution_with_huge_fib_param_rejects_against_derived_header() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(37);
    let hash = prev_hash(37);
    let mut header = engine.derive_puzzle(37, &validator, hash);

    header.param = 10_000;

    let solution = PorPuzzleSolution {
        header,
        output: fib_u128(44),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(&solution, 37, &validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_38_vector_multiple_fibonacci_heights_solve_and_verify() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(38);

    for height in [0_u64, 1, 2, 10, 100, 1_000, u64::MAX] {
        let hash = prev_hash(height);
        let header = engine.derive_puzzle(height, &validator, hash);
        let solution = engine.solve_locally_checked(&header)?;

        engine.verify_checked(&solution, height, &validator, hash)?;
    }

    Ok(())
}

#[test]
fn test_39_fuzz_invalid_wallet_inputs_all_use_same_marker() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let invalid_wallets = [
        "",
        "r",
        "not-a-wallet",
        "x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "☃",
    ];

    for invalid_wallet in invalid_wallets {
        let header = engine.derive_puzzle(39, invalid_wallet, prev_hash(39));
        assert_eq!(header.validator, "por:<invalid-wallet>");
    }
}

#[test]
fn test_40_load_repeated_fibonacci_derive_solve_verify_stays_consistent() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);

    for seed in 0_u64..64_u64 {
        let validator = wallet(seed);
        let hash = prev_hash(seed);
        let header = engine.derive_puzzle(seed, &validator, hash);
        let solution = engine.solve_locally_checked(&header)?;

        assert_eq!(solution.output, fib_u128(header.param));
        engine.verify_checked(&solution, seed, &validator, hash)?;
        assert!(engine.verify(&solution, seed, &validator, hash));
    }

    Ok(())
}

#[test]
fn test_41_derive_puzzle_accepts_height_zero() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(41);
    let hash = prev_hash(41);

    let header = engine.derive_puzzle(0, &validator, hash);

    assert_eq!(header.height, 0);
    assert_eq!(header.validator, validator);
    assert_eq!(header.prev_block_hash, hash);
}

#[test]
fn test_42_derive_puzzle_accepts_u64_max_height() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(42);
    let hash = prev_hash(42);

    let header = engine.derive_puzzle(u64::MAX, &validator, hash);

    assert_eq!(header.height, u64::MAX);
    assert_eq!(header.validator, validator);
    assert_eq!(header.prev_block_hash, hash);
}

#[test]
fn test_43_vector_all_zero_prev_hash_solves_and_verifies() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(43);
    let hash = [0_u8; 64];

    let header = engine.derive_puzzle(43, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.prev_block_hash, hash);
    engine.verify_checked(&solution, 43, &validator, hash)?;
    Ok(())
}

#[test]
fn test_44_vector_all_ff_prev_hash_solves_and_verifies() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(44);
    let hash = [0xFF_u8; 64];

    let header = engine.derive_puzzle(44, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.prev_block_hash, hash);
    engine.verify_checked(&solution, 44, &validator, hash)?;
    Ok(())
}

#[test]
fn test_45_different_heights_are_reflected_in_headers() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(45);
    let hash = prev_hash(45);

    let first = engine.derive_puzzle(45, &validator, hash);
    let second = engine.derive_puzzle(46, &validator, hash);

    assert_ne!(first.height, second.height);
    assert_eq!(first.validator, second.validator);
    assert_eq!(first.prev_block_hash, second.prev_block_hash);
}

#[test]
fn test_46_different_validators_are_reflected_in_headers() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let hash = prev_hash(46);
    let validator_a = wallet(46);
    let validator_b = wallet(47);

    let first = engine.derive_puzzle(46, &validator_a, hash);
    let second = engine.derive_puzzle(46, &validator_b, hash);

    assert_ne!(first.validator, second.validator);
    assert_eq!(first.height, second.height);
    assert_eq!(first.prev_block_hash, second.prev_block_hash);
}

#[test]
fn test_47_zero_target_duration_uses_one_second_effective_fibonacci_range() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(47, &wallet(47), prev_hash(47));

    assert!((26..=33).contains(&header.param));
}

#[test]
fn test_48_vector_fibonacci_target_10_seconds_uses_lowest_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 10));
    let header = engine.derive_puzzle(48, &wallet(48), prev_hash(48));

    assert!((26..=33).contains(&header.param));
}

#[test]
fn test_49_vector_fibonacci_target_11_seconds_uses_second_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 11));
    let header = engine.derive_puzzle(49, &wallet(49), prev_hash(49));

    assert!((30..=37).contains(&header.param));
}

#[test]
fn test_50_vector_fibonacci_target_20_seconds_uses_second_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 20));
    let header = engine.derive_puzzle(50, &wallet(50), prev_hash(50));

    assert!((30..=37).contains(&header.param));
}

#[test]
fn test_51_vector_fibonacci_target_21_seconds_uses_third_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 21));
    let header = engine.derive_puzzle(51, &wallet(51), prev_hash(51));

    assert!((32..=39).contains(&header.param));
}

#[test]
fn test_52_vector_fibonacci_target_40_seconds_uses_third_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 40));
    let header = engine.derive_puzzle(52, &wallet(52), prev_hash(52));

    assert!((32..=39).contains(&header.param));
}

#[test]
fn test_53_vector_fibonacci_target_41_seconds_uses_fourth_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 41));
    let header = engine.derive_puzzle(53, &wallet(53), prev_hash(53));

    assert!((34..=41).contains(&header.param));
}

#[test]
fn test_54_vector_fibonacci_target_60_seconds_uses_fourth_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 60));
    let header = engine.derive_puzzle(54, &wallet(54), prev_hash(54));

    assert!((34..=41).contains(&header.param));
}

#[test]
fn test_55_vector_fibonacci_target_above_60_seconds_uses_highest_base_range() {
    let engine = PorPuzzleEngine::new(test_config(PorPuzzleKind::FibonacciDelayDev, 999));
    let header = engine.derive_puzzle(55, &wallet(55), prev_hash(55));

    assert!((36..=43).contains(&header.param));
}

#[test]
fn test_56_manual_fibonacci_param_zero_outputs_zero() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 56,
        validator: wallet(56),
        prev_block_hash: prev_hash(56),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 0,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 0);
    assert_eq!(solution.output, 0);
    Ok(())
}

#[test]
fn test_57_manual_fibonacci_param_one_outputs_one() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 57,
        validator: wallet(57),
        prev_block_hash: prev_hash(57),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 1,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 1);
    assert_eq!(solution.output, 1);
    Ok(())
}

#[test]
fn test_58_manual_fibonacci_param_two_outputs_one() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 58,
        validator: wallet(58),
        prev_block_hash: prev_hash(58),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 2,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 2);
    assert_eq!(solution.output, 1);
    Ok(())
}

#[test]
fn test_59_manual_fibonacci_param_ten_outputs_known_vector() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 59,
        validator: wallet(59),
        prev_block_hash: prev_hash(59),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 10,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 10);
    assert_eq!(solution.output, 55);
    Ok(())
}

#[test]
fn test_60_manual_fibonacci_param_forty_four_outputs_helper_vector() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 60,
        validator: wallet(60),
        prev_block_hash: prev_hash(60),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: 44,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 44);
    assert_eq!(solution.output, fib_u128(44));
    Ok(())
}

#[test]
fn test_61_header_clone_preserves_all_fields() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(61, &wallet(61), prev_hash(61));
    let cloned = header.clone();

    assert_eq!(cloned.height, header.height);
    assert_eq!(cloned.validator, header.validator);
    assert_eq!(cloned.prev_block_hash, header.prev_block_hash);
    assert_eq!(cloned.kind, header.kind);
    assert_eq!(cloned.param, header.param);
}

#[test]
fn test_62_solution_clone_preserves_all_fields() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(62, &wallet(62), prev_hash(62));
    let solution = engine.solve_locally_checked(&header)?;
    let cloned = solution.clone();

    assert_eq!(cloned.header.height, solution.header.height);
    assert_eq!(cloned.header.validator, solution.header.validator);
    assert_eq!(
        cloned.header.prev_block_hash,
        solution.header.prev_block_hash
    );
    assert_eq!(cloned.header.kind, solution.header.kind);
    assert_eq!(cloned.header.param, solution.header.param);
    assert_eq!(cloned.output, solution.output);
    assert_eq!(cloned.solved_in_ms, solution.solved_in_ms);
    Ok(())
}

#[test]
fn test_63_header_debug_contains_type_and_fields() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(63, &wallet(63), prev_hash(63));
    let debug_text = format!("{header:?}");

    assert!(debug_text.contains("PorPuzzleHeader"));
    assert!(debug_text.contains("height"));
    assert!(debug_text.contains("validator"));
    assert!(debug_text.contains("prev_block_hash"));
    assert!(debug_text.contains("kind"));
    assert!(debug_text.contains("param"));
}

#[test]
fn test_64_solution_debug_contains_type_and_fields() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = engine.derive_puzzle(64, &wallet(64), prev_hash(64));
    let solution = engine.solve_locally_checked(&header)?;
    let debug_text = format!("{solution:?}");

    assert!(debug_text.contains("PorPuzzleSolution"));
    assert!(debug_text.contains("header"));
    assert!(debug_text.contains("output"));
    assert!(debug_text.contains("solved_in_ms"));
    Ok(())
}

#[test]
fn test_65_verify_ignores_observational_solved_in_ms() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(65);
    let hash = prev_hash(65);
    let header = engine.derive_puzzle(65, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.solved_in_ms = u64::MAX;

    engine.verify_checked(&solution, 65, &validator, hash)?;
    assert!(engine.verify(&solution, 65, &validator, hash));
    Ok(())
}

#[test]
fn test_66_verify_accepts_uppercase_expected_validator() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(66);
    let hash = prev_hash(66);
    let header = engine.derive_puzzle(66, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    engine.verify_checked(&solution, 66, &validator.to_ascii_uppercase(), hash)?;
    Ok(())
}

#[test]
fn test_67_verify_accepts_trimmed_uppercase_expected_validator() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(67);
    let hash = prev_hash(67);
    let header = engine.derive_puzzle(67, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;
    let expected_validator = format!(" \n{}\t ", validator.to_ascii_uppercase());

    engine.verify_checked(&solution, 67, &expected_validator, hash)?;
    Ok(())
}

#[test]
fn test_68_invalid_expected_wallet_uses_same_deterministic_marker() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let hash = prev_hash(68);
    let header = engine.derive_puzzle(68, "not-a-wallet", hash);
    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.validator, "por:<invalid-wallet>");
    engine.verify_checked(&solution, 68, "", hash)?;
    Ok(())
}

#[test]
fn test_69_factorization_valid_solution_verifies_with_uppercase_expected_validator() -> TestResult {
    let (engine, header, _n, output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output,
        solved_in_ms: 0,
    };

    engine.verify_checked(
        &solution,
        header.height,
        &header.validator.to_ascii_uppercase(),
        header.prev_block_hash,
    )?;
    Ok(())
}

#[test]
fn test_70_factorization_valid_solution_ignores_solved_in_ms() -> TestResult {
    let (engine, header, _n, output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output,
        solved_in_ms: u64::MAX,
    };

    engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    )?;
    Ok(())
}

#[test]
fn test_71_factorization_rejects_zero_factor_part() -> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(n, 0),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_72_factorization_rejects_factor_two() -> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(n, 2),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_73_factorization_rejects_non_dividing_large_factor() -> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let non_dividing = n
        .checked_add(4)
        .ok_or_else(|| test_error("non-dividing factor overflowed in test"))?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(n, non_dividing),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_74_factorization_rejects_zero_packed_output() -> TestResult {
    let (engine, header, _n, _output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: 0,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_75_factorization_rejects_modified_header_param() -> TestResult {
    let (engine, mut header, _n, output) = find_verifiable_factorization_case()?;
    let original_header = header.clone();

    header.param = header
        .param
        .checked_add(1)
        .ok_or_else(|| test_error("header param overflowed in test"))?;

    let solution = PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        original_header.height,
        &original_header.validator,
        original_header.prev_block_hash,
    ))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_76_factorization_rejects_modified_header_kind() -> TestResult {
    let (engine, mut header, _n, output) = find_verifiable_factorization_case()?;
    let original_header = header.clone();

    header.kind = PorPuzzleKind::FibonacciDelayDev;

    let solution = PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        original_header.height,
        &original_header.validator,
        original_header.prev_block_hash,
    ))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_77_solve_factorization_normalizes_param_zero_to_one() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let header = PorPuzzleHeader {
        height: 77,
        validator: wallet(77),
        prev_block_hash: prev_hash(77),
        kind: PorPuzzleKind::FactorizationDelayDev,
        param: 0,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 1);
    assert_eq!(solution.header.kind, PorPuzzleKind::FactorizationDelayDev);
    Ok(())
}

#[test]
fn test_78_solve_factorization_normalizes_param_u32_max_to_four() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let header = PorPuzzleHeader {
        height: 78,
        validator: wallet(78),
        prev_block_hash: prev_hash(78),
        kind: PorPuzzleKind::FactorizationDelayDev,
        param: u32::MAX,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 4);
    assert_eq!(solution.header.kind, PorPuzzleKind::FactorizationDelayDev);
    Ok(())
}

#[test]
fn test_79_load_manual_factorization_verification_for_bounded_cases() -> TestResult {
    let (engine, header, n, output) = find_verifiable_factorization_case()?;

    for solved_in_ms in 0_u64..64_u64 {
        let solution = PorPuzzleSolution {
            header: header.clone(),
            output,
            solved_in_ms,
        };

        engine.verify_checked(
            &solution,
            header.height,
            &header.validator,
            header.prev_block_hash,
        )?;

        assert!(engine.verify(
            &solution,
            header.height,
            &header.validator,
            header.prev_block_hash,
        ));

        assert_eq!(packed_n_part(solution.output)?, n);
        assert_eq!(packed_p_part(solution.output)?, n);
    }

    Ok(())
}

#[test]
fn test_80_adversarial_fibonacci_solution_rejected_by_factorization_engine() -> TestResult {
    let fib_engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let fact_engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let validator = wallet(80);
    let hash = prev_hash(80);
    let header = fib_engine.derive_puzzle(80, &validator, hash);
    let solution = fib_engine.solve_locally_checked(&header)?;

    let message = validation_message(fact_engine.verify_checked(&solution, 80, &validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_81_edge_fibonacci_verify_accepts_solution_with_solved_in_ms_zero() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(81);
    let hash = prev_hash(81);
    let header = engine.derive_puzzle(81, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;

    solution.solved_in_ms = 0;

    engine.verify_checked(&solution, 81, &validator, hash)?;
    assert!(engine.verify(&solution, 81, &validator, hash));
    Ok(())
}

#[test]
fn test_82_edge_fibonacci_solution_with_output_zero_rejected_for_derived_nonzero_param()
-> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(82);
    let hash = prev_hash(82);
    let header = engine.derive_puzzle(82, &validator, hash);
    let solution = PorPuzzleSolution {
        header,
        output: 0,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(&solution, 82, &validator, hash))?;

    assert!(message.contains("Fibonacci puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_83_edge_fibonacci_solution_with_u128_max_output_rejected() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(83);
    let hash = prev_hash(83);
    let header = engine.derive_puzzle(83, &validator, hash);
    let solution = PorPuzzleSolution {
        header,
        output: u128::MAX,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(&solution, 83, &validator, hash))?;

    assert!(message.contains("Fibonacci puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_84_edge_fibonacci_solution_with_prev_hash_one_byte_changed_rejected() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(84);
    let hash = prev_hash(84);
    let mut wrong_hash = hash;
    wrong_hash[0] ^= 0x01;

    let header = engine.derive_puzzle(84, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    let message = validation_message(engine.verify_checked(&solution, 84, &validator, wrong_hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_85_edge_fibonacci_solution_with_last_prev_hash_byte_changed_rejected() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(85);
    let hash = prev_hash(85);
    let mut wrong_hash = hash;
    wrong_hash[63] ^= 0x80;

    let header = engine.derive_puzzle(85, &validator, hash);
    let solution = engine.solve_locally_checked(&header)?;

    let message = validation_message(engine.verify_checked(&solution, 85, &validator, wrong_hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_86_vector_fibonacci_known_manual_outputs_zero_through_twelve() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let vectors = [
        (0_u32, 0_u128),
        (1_u32, 1_u128),
        (2_u32, 1_u128),
        (3_u32, 2_u128),
        (4_u32, 3_u128),
        (5_u32, 5_u128),
        (6_u32, 8_u128),
        (7_u32, 13_u128),
        (8_u32, 21_u128),
        (9_u32, 34_u128),
        (10_u32, 55_u128),
        (11_u32, 89_u128),
        (12_u32, 144_u128),
    ];

    for (param, expected_output) in vectors {
        let header = PorPuzzleHeader {
            height: u64::from(param),
            validator: wallet(8600_u64 + u64::from(param)),
            prev_block_hash: prev_hash(8600_u64 + u64::from(param)),
            kind: PorPuzzleKind::FibonacciDelayDev,
            param,
        };
        let solution = engine.solve_locally_checked(&header)?;

        assert_eq!(solution.header.param, param);
        assert_eq!(solution.output, expected_output);
    }

    Ok(())
}

#[test]
fn test_87_vector_fibonacci_manual_outputs_twenty_thirty_and_forty() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let vectors = [
        (20_u32, 6_765_u128),
        (30_u32, 832_040_u128),
        (40_u32, 102_334_155_u128),
    ];

    for (param, expected_output) in vectors {
        let header = PorPuzzleHeader {
            height: u64::from(param),
            validator: wallet(8700_u64 + u64::from(param)),
            prev_block_hash: prev_hash(8700_u64 + u64::from(param)),
            kind: PorPuzzleKind::FibonacciDelayDev,
            param,
        };
        let solution = engine.solve_locally_checked(&header)?;

        assert_eq!(solution.header.param, param);
        assert_eq!(solution.output, expected_output);
    }

    Ok(())
}

#[test]
fn test_88_edge_fibonacci_manual_param_u32_max_clamps_to_44() -> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let header = PorPuzzleHeader {
        height: 88,
        validator: wallet(88),
        prev_block_hash: prev_hash(88),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: u32::MAX,
    };

    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.param, 44);
    assert_eq!(solution.output, fib_u128(44));
    Ok(())
}

#[test]
fn test_89_edge_factorization_solution_with_u128_max_output_rejected() -> TestResult {
    let (engine, header, _n, _output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: u128::MAX,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_90_edge_factorization_solution_with_n_part_correct_and_p_part_u64_max_rejected()
-> TestResult {
    let (engine, header, n, _output) = find_verifiable_factorization_case()?;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: packed_factor_solution(n, u64::MAX),
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        header.prev_block_hash,
    ))?;

    assert!(message.contains("Factorization puzzle output mismatch"));
    Ok(())
}

#[test]
fn test_91_vector_factorization_packed_solution_parts_round_trip() -> TestResult {
    let n = 0x0123_4567_89AB_CDEF_u64;
    let p = 0x0000_0000_0000_00EF_u64;
    let packed = packed_factor_solution(n, p);

    assert_eq!(packed_n_part(packed)?, n);
    assert_eq!(packed_p_part(packed)?, p);
    Ok(())
}

#[test]
fn test_92_vector_factorization_packed_zero_parts_round_trip() -> TestResult {
    let packed = packed_factor_solution(0, 0);

    assert_eq!(packed_n_part(packed)?, 0);
    assert_eq!(packed_p_part(packed)?, 0);
    Ok(())
}

#[test]
fn test_93_vector_factorization_packed_max_parts_round_trip() -> TestResult {
    let packed = packed_factor_solution(u64::MAX, u64::MAX);

    assert_eq!(packed_n_part(packed)?, u64::MAX);
    assert_eq!(packed_p_part(packed)?, u64::MAX);
    Ok(())
}

#[test]
fn test_94_edge_factorization_verify_rejects_wrong_prev_hash_first_byte() -> TestResult {
    let (engine, header, _n, output) = find_verifiable_factorization_case()?;
    let mut wrong_hash = header.prev_block_hash;
    wrong_hash[0] ^= 0x01;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        wrong_hash,
    ))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_95_edge_factorization_verify_rejects_wrong_prev_hash_last_byte() -> TestResult {
    let (engine, header, _n, output) = find_verifiable_factorization_case()?;
    let mut wrong_hash = header.prev_block_hash;
    wrong_hash[63] ^= 0x40;
    let solution = PorPuzzleSolution {
        header: header.clone(),
        output,
        solved_in_ms: 0,
    };

    let message = validation_message(engine.verify_checked(
        &solution,
        header.height,
        &header.validator,
        wrong_hash,
    ))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_96_edge_solution_header_invalid_wallet_marker_verifies_when_expected_wallet_invalid()
-> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let hash = prev_hash(96);
    let header = engine.derive_puzzle(96, "bad-wallet", hash);
    let solution = engine.solve_locally_checked(&header)?;

    assert_eq!(solution.header.validator, "por:<invalid-wallet>");
    engine.verify_checked(&solution, 96, "also-bad-wallet", hash)?;
    Ok(())
}

#[test]
fn test_97_edge_solution_header_invalid_wallet_marker_rejects_when_expected_wallet_valid()
-> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let hash = prev_hash(97);
    let header = engine.derive_puzzle(97, "bad-wallet", hash);
    let solution = engine.solve_locally_checked(&header)?;
    let valid_validator = wallet(97);

    let message = validation_message(engine.verify_checked(&solution, 97, &valid_validator, hash))?;

    assert!(message.contains("Puzzle header mismatch"));
    Ok(())
}

#[test]
fn test_98_vector_header_derivation_is_stable_across_cloned_engines() {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let cloned = engine.clone();
    let validator = wallet(98);
    let hash = prev_hash(98);

    let first = engine.derive_puzzle(98, &validator, hash);
    let second = cloned.derive_puzzle(98, &validator, hash);

    assert_eq!(first.height, second.height);
    assert_eq!(first.validator, second.validator);
    assert_eq!(first.prev_block_hash, second.prev_block_hash);
    assert_eq!(first.kind, second.kind);
    assert_eq!(first.param, second.param);
}

#[test]
fn test_99_vector_factorization_header_derivation_is_stable_across_cloned_engines() {
    let engine = zero_delay_engine(PorPuzzleKind::FactorizationDelayDev);
    let cloned = engine.clone();
    let validator = wallet(99);
    let hash = prev_hash(99);

    let first = engine.derive_puzzle(99, &validator, hash);
    let second = cloned.derive_puzzle(99, &validator, hash);

    assert_eq!(first.height, second.height);
    assert_eq!(first.validator, second.validator);
    assert_eq!(first.prev_block_hash, second.prev_block_hash);
    assert_eq!(first.kind, second.kind);
    assert_eq!(first.param, second.param);
}

#[test]
fn test_100_edge_repeated_verify_with_mutated_solved_in_ms_values_still_accepts_valid_proof()
-> TestResult {
    let engine = zero_delay_engine(PorPuzzleKind::FibonacciDelayDev);
    let validator = wallet(100);
    let hash = prev_hash(100);
    let header = engine.derive_puzzle(100, &validator, hash);
    let mut solution = engine.solve_locally_checked(&header)?;
    let solved_in_vectors = [0_u64, 1_u64, 999_u64, 1_000_u64, u64::MAX];

    for solved_in_ms in solved_in_vectors {
        solution.solved_in_ms = solved_in_ms;
        engine.verify_checked(&solution, 100, &validator, hash)?;
        assert!(engine.verify(&solution, 100, &validator, hash));
    }

    Ok(())
}
