use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::consensus::por_002_puzzle_engine::{
    PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
};

use std::time::Duration;

const MAX_FIB_N_TEST: u32 = 44;
const MAX_FACT_N_TEST: u64 = 1u64 << 48;
const MAX_FACT_TRIAL_STEPS_TEST: u64 = 2_000_000;

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn messy_wallet(seed: u64) -> String {
    format!(" \t{}\n", wallet(seed).to_ascii_uppercase())
}

fn invalid_wallet(seed: u64) -> String {
    format!("p{seed:0128x}")
}

fn valid_hash(seed: u64) -> [u8; 64] {
    let mut out = [0x42u8; 64];

    out[..8].copy_from_slice(&seed.to_le_bytes());
    out[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    out[16..24].copy_from_slice(&seed.rotate_right(11).to_le_bytes());

    out
}

fn fib_engine_with_secs(secs: u64) -> PorPuzzleEngine {
    PorPuzzleEngine::new(PorConsensusConfig {
        target_block_time: Duration::from_secs(secs.max(1)),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: secs.max(1).saturating_mul(1_000),
    })
}

fn fact_engine_with_secs(secs: u64) -> PorPuzzleEngine {
    PorPuzzleEngine::new(PorConsensusConfig {
        target_block_time: Duration::from_secs(secs.max(1)),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: secs.max(1).saturating_mul(1_000),
    })
}

fn fib_iter_for_test(n: u32) -> u128 {
    if n == 0 {
        return 0;
    }

    if n == 1 {
        return 1;
    }

    let mut a: u128 = 0;
    let mut b: u128 = 1;

    for _ in 0..n {
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }

    a
}

fn derive_n_from_header_for_test(header: &PorPuzzleHeader) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&header.prev_block_hash);
    hasher.update(&header.height.to_be_bytes());
    hasher.update(header.validator.as_bytes());

    let seed = hasher.finalize();
    let sb = seed.as_bytes();

    let mut n: u64 = u64::from_be_bytes([sb[0], sb[1], sb[2], sb[3], sb[4], sb[5], sb[6], sb[7]]);

    n |= 1;
    n = n.max(3);

    let shift = header.param & 0x03;
    n >>= shift;

    n
}

fn solve_factorization_for_test(header: &PorPuzzleHeader) -> Option<u128> {
    let n = derive_n_from_header_for_test(header);

    if n > MAX_FACT_N_TEST {
        return None;
    }

    let mut candidate_p: u64 = 3;
    let mut found_p: Option<u64> = None;
    let mut steps: u64 = 0;

    while candidate_p.saturating_mul(candidate_p) <= n {
        if steps >= MAX_FACT_TRIAL_STEPS_TEST {
            return None;
        }

        if n.is_multiple_of(candidate_p) {
            found_p = Some(candidate_p);
            break;
        }

        candidate_p = candidate_p.saturating_add(2);
        steps = steps.saturating_add(1);
    }

    let p = found_p.unwrap_or(n);
    Some(((n as u128) << 64) | (p as u128))
}

fn fib_solution(
    engine: &PorPuzzleEngine,
    height: u64,
    validator: &str,
    prev_hash: [u8; 64],
) -> PorPuzzleSolution {
    let header = engine.derive_puzzle(height, validator, prev_hash);
    let output = fib_iter_for_test(header.param);

    PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_from_globals_returns_valid_mandatory_config(
        _probe in any::<u8>(),
    ) {
        let engine = PorPuzzleEngine::from_globals();

        prop_assert!(
            engine.config().validate().is_ok(),
            "PorPuzzleEngine::from_globals must produce a valid mandatory network config"
        );

        prop_assert_eq!(
            engine.config().puzzle_kind,
            PorPuzzleKind::FibonacciDelayDev,
            "mandatory network puzzle kind must be FibonacciDelayDev"
        );

        prop_assert!(
            engine.config().target_block_time.as_secs() >= 1,
            "target puzzle delay must be at least one second"
        );

        prop_assert!(
            engine.config().max_local_puzzle_ms >= 1_000,
            "max_local_puzzle_ms must be nonzero in mandatory puzzle mode"
        );
    }

    // 02/25
    #[test]
    fn test_002_engine_new_preserves_config_fields(
        secs in 1u64..=120u64,
        max_ms_extra in 0u64..=10_000u64,
    ) {
        let cfg = PorConsensusConfig {
            target_block_time: Duration::from_secs(secs),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: secs.saturating_mul(1_000).saturating_add(max_ms_extra),
        };

        let engine = PorPuzzleEngine::new(cfg.clone());

        prop_assert_eq!(
            engine.config().target_block_time,
            cfg.target_block_time,
            "engine must preserve target_block_time"
        );

        prop_assert_eq!(
            engine.config().puzzle_kind,
            cfg.puzzle_kind,
            "engine must preserve puzzle_kind"
        );

        prop_assert_eq!(
            engine.config().max_local_puzzle_ms,
            cfg.max_local_puzzle_ms,
            "engine must preserve max_local_puzzle_ms"
        );
    }

    // 03/25
    #[test]
    fn test_003_derive_puzzle_is_deterministic_for_same_inputs(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let header_a = engine.derive_puzzle(height, &validator, prev_hash);
        let header_b = engine.derive_puzzle(height, &validator, prev_hash);

        prop_assert_eq!(
            header_a.height,
            header_b.height,
            "derived height must be deterministic"
        );

        prop_assert_eq!(
            header_a.validator,
            header_b.validator,
            "derived validator must be deterministic"
        );

        prop_assert_eq!(
            header_a.prev_block_hash,
            header_b.prev_block_hash,
            "derived previous hash must be deterministic"
        );

        prop_assert_eq!(
            header_a.kind,
            header_b.kind,
            "derived puzzle kind must be deterministic"
        );

        prop_assert_eq!(
            header_a.param,
            header_b.param,
            "derived puzzle parameter must be deterministic"
        );
    }

    // 04/25
    #[test]
    fn test_004_derive_puzzle_canonicalizes_uppercase_trimmed_validator(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let canonical = wallet(validator_seed);
        let messy = messy_wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let canonical_header = engine.derive_puzzle(height, &canonical, prev_hash);
        let messy_header = engine.derive_puzzle(height, &messy, prev_hash);

        prop_assert_eq!(
            messy_header.validator.as_str(),
            canonical.as_str(),
            "derive_puzzle must canonicalize validator wallet"
        );

        prop_assert_eq!(
            messy_header.param,
            canonical_header.param,
            "canonical-equivalent validator strings must derive the same parameter"
        );
    }

    // 05/25
    #[test]
    fn test_005_derive_puzzle_maps_invalid_validator_to_fixed_marker(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let bad_validator = invalid_wallet(validator_seed);

        let header = engine.derive_puzzle(height, &bad_validator, valid_hash(hash_seed));

        prop_assert_eq!(
            header.validator.as_str(),
            "por:<invalid-wallet>",
            "invalid validator must map to deterministic invalid marker"
        );
    }

    // 06/25
    #[test]
    fn test_006_fibonacci_param_is_bounded_by_safety_cap(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=10_000u64,
    ) {
        let engine = fib_engine_with_secs(secs);

        let header = engine.derive_puzzle(
            height,
            &wallet(validator_seed),
            valid_hash(hash_seed),
        );

        prop_assert_eq!(
            header.kind,
            PorPuzzleKind::FibonacciDelayDev,
            "fibonacci engine must derive FibonacciDelayDev headers"
        );

        prop_assert!(
            header.param <= MAX_FIB_N_TEST,
            "fibonacci parameter must be capped at MAX_FIB_N"
        );

        prop_assert!(
            header.param >= 26,
            "fibonacci parameter must stay in expected derived range"
        );
    }

    // 07/25
    #[test]
    fn test_007_fibonacci_param_tracks_target_time_bucket(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);

        let header = engine.derive_puzzle(
            height,
            &wallet(validator_seed),
            valid_hash(hash_seed),
        );

        let expected_base = if secs <= 10 {
            26
        } else if secs <= 20 {
            30
        } else if secs <= 40 {
            32
        } else if secs <= 60 {
            34
        } else {
            36
        };

        prop_assert!(
            header.param >= expected_base,
            "fibonacci parameter must be at least the bucket base"
        );

        prop_assert!(
            header.param <= expected_base.saturating_add(7).min(MAX_FIB_N_TEST),
            "fibonacci parameter must stay within bucket base + jitter"
        );
    }

    // 08/25
    #[test]
    fn test_008_factorization_param_is_always_one_through_four(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fact_engine_with_secs(secs);

        let header = engine.derive_puzzle(
            height,
            &wallet(validator_seed),
            valid_hash(hash_seed),
        );

        prop_assert_eq!(
            header.kind,
            PorPuzzleKind::FactorizationDelayDev,
            "factorization engine must derive FactorizationDelayDev headers"
        );

        prop_assert!(
            (1..=4).contains(&header.param),
            "factorization parameter must be bounded to 1..=4"
        );
    }

    // 09/25
    #[test]
    fn test_009_derive_puzzle_is_height_sensitive(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let header_a = engine.derive_puzzle(height, &validator, prev_hash);
        let header_b = engine.derive_puzzle(height.wrapping_add(1), &validator, prev_hash);

        prop_assert_ne!(
            header_a.height,
            header_b.height,
            "height field must reflect input height"
        );

        if header_a.param == header_b.param {
            prop_assert_ne!(
                header_a.height,
                header_b.height,
                "same param is allowed, but header still differs by height"
            );
        }
    }

    // 10/25
    #[test]
    fn test_010_derive_puzzle_is_validator_sensitive(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator_a = wallet(validator_seed);
        let validator_b = wallet(validator_seed.saturating_add(1));
        let prev_hash = valid_hash(hash_seed);

        prop_assume!(validator_a != validator_b);

        let header_a = engine.derive_puzzle(height, &validator_a, prev_hash);
        let header_b = engine.derive_puzzle(height, &validator_b, prev_hash);

        prop_assert_ne!(
            header_a.validator,
            header_b.validator,
            "derived header must preserve distinct canonical validators"
        );
    }

    // 11/25
    #[test]
    fn test_011_derive_puzzle_is_prev_hash_sensitive(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);

        let hash_a = valid_hash(hash_seed);
        let hash_b = valid_hash(hash_seed.saturating_add(1));

        prop_assume!(hash_a != hash_b);

        let header_a = engine.derive_puzzle(height, &validator, hash_a);
        let header_b = engine.derive_puzzle(height, &validator, hash_b);

        prop_assert_ne!(
            header_a.prev_block_hash,
            header_b.prev_block_hash,
            "derived header must preserve distinct previous hashes"
        );
    }

    // 12/25
    #[test]
    fn test_012_fibonacci_solution_verifies_for_exact_expected_inputs(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let solution = fib_solution(&engine, height, &validator, prev_hash);

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, prev_hash)
                .is_ok(),
            "correct Fibonacci solution must verify"
        );

        prop_assert!(
            engine.verify(&solution, height, &validator, prev_hash),
            "boolean verify wrapper must accept correct solution"
        );
    }

    // 13/25
    #[test]
    fn test_013_fibonacci_verify_rejects_wrong_height(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let solution = fib_solution(&engine, height, &validator, prev_hash);

        prop_assert!(
            engine
                .verify_checked(&solution, height.wrapping_add(1), &validator, prev_hash)
                .is_err(),
            "verify_checked must reject wrong expected height"
        );

        prop_assert!(
            !engine.verify(&solution, height.wrapping_add(1), &validator, prev_hash),
            "boolean verify wrapper must reject wrong expected height"
        );
    }

    // 14/25
    #[test]
    fn test_014_fibonacci_verify_rejects_wrong_validator(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let wrong_validator = wallet(validator_seed.saturating_add(1));
        let prev_hash = valid_hash(hash_seed);

        prop_assume!(validator != wrong_validator);

        let solution = fib_solution(&engine, height, &validator, prev_hash);

        prop_assert!(
            engine
                .verify_checked(&solution, height, &wrong_validator, prev_hash)
                .is_err(),
            "verify_checked must reject wrong expected validator"
        );
    }

    // 15/25
    #[test]
    fn test_015_fibonacci_verify_rejects_wrong_prev_hash(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);
        let wrong_hash = valid_hash(hash_seed.saturating_add(1));

        prop_assume!(prev_hash != wrong_hash);

        let solution = fib_solution(&engine, height, &validator, prev_hash);

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, wrong_hash)
                .is_err(),
            "verify_checked must reject wrong expected previous hash"
        );
    }

    // 16/25
    #[test]
    fn test_016_fibonacci_verify_rejects_wrong_output(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
        delta in 1u128..=1_000_000u128,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let mut solution = fib_solution(&engine, height, &validator, prev_hash);
        solution.output = solution.output.saturating_add(delta);

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, prev_hash)
                .is_err(),
            "verify_checked must reject wrong Fibonacci output"
        );
    }

    // 17/25
    #[test]
    fn test_017_verify_normalizes_solution_header_validator(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let messy = messy_wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let mut solution = fib_solution(&engine, height, &validator, prev_hash);
        solution.header.validator = messy;

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, prev_hash)
                .is_ok(),
            "verify_checked must normalize canonical-equivalent solution header validator"
        );
    }

    // 18/25
    #[test]
    fn test_018_verify_rejects_solution_header_kind_mismatch(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let mut solution = fib_solution(&engine, height, &validator, prev_hash);
        solution.header.kind = PorPuzzleKind::FactorizationDelayDev;

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, prev_hash)
                .is_err(),
            "verify_checked must reject solution header with wrong puzzle kind"
        );
    }

    // 19/25
    #[test]
    fn test_019_verify_rejects_solution_header_param_mismatch(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
        delta in 1u32..=100u32,
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let mut solution = fib_solution(&engine, height, &validator, prev_hash);
        solution.header.param = solution.header.param.saturating_add(delta);

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, prev_hash)
                .is_err(),
            "verify_checked must reject solution header with wrong parameter"
        );
    }

    // 20/25
    #[test]
    fn test_020_verify_ignores_solved_in_ms_for_consensus_validity(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
        solved_in_ms in any::<u64>(),
    ) {
        let engine = fib_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let mut solution = fib_solution(&engine, height, &validator, prev_hash);
        solution.solved_in_ms = solved_in_ms;

        prop_assert!(
            engine
                .verify_checked(&solution, height, &validator, prev_hash)
                .is_ok(),
            "solved_in_ms must not affect deterministic consensus verification"
        );
    }

    // 21/25
    #[test]
    fn test_021_factorization_valid_solution_verifies_when_within_safety_bounds(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in 0u64..=10_000u64,
        secs in 1u64..=120u64,
    ) {
        let engine = fact_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let header = engine.derive_puzzle(height, &validator, prev_hash);

        if let Some(output) = solve_factorization_for_test(&header) {
            let solution = PorPuzzleSolution {
                header,
                output,
                solved_in_ms: 0,
            };

            prop_assert!(
                engine
                    .verify_checked(&solution, height, &validator, prev_hash)
                    .is_ok(),
                "valid bounded factorization solution must verify"
            );
        }
    }

    // 22/25
    #[test]
    fn test_022_factorization_verify_rejects_wrong_packed_n_part(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in 0u64..=10_000u64,
        secs in 1u64..=120u64,
    ) {
        let engine = fact_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let header = engine.derive_puzzle(height, &validator, prev_hash);

        if let Some(output) = solve_factorization_for_test(&header) {
            let bad_output = output ^ (1u128 << 64);

            let solution = PorPuzzleSolution {
                header,
                output: bad_output,
                solved_in_ms: 0,
            };

            prop_assert!(
                engine
                    .verify_checked(&solution, height, &validator, prev_hash)
                    .is_err(),
                "factorization verify must reject wrong packed n part"
            );
        }
    }

    // 23/25
    #[test]
    fn test_023_factorization_verify_rejects_too_small_factor_part(
        height in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in 0u64..=10_000u64,
        secs in 1u64..=120u64,
    ) {
        let engine = fact_engine_with_secs(secs);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let header = engine.derive_puzzle(height, &validator, prev_hash);
        let n = derive_n_from_header_for_test(&header);

        if n <= MAX_FACT_N_TEST {
            let bad_output = (n as u128) << 64;

            let solution = PorPuzzleSolution {
                header,
                output: bad_output,
                solved_in_ms: 0,
            };

            prop_assert!(
                engine
                    .verify_checked(&solution, height, &validator, prev_hash)
                    .is_err(),
                "factorization verify must reject factor part below 3"
            );
        }
    }

    // 24/25
    #[test]
    fn test_024_verify_checked_never_panics_for_malformed_public_solution_shapes(
        height in any::<u64>(),
        validator in ".{0,512}",
        expected_validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output in any::<u128>(),
        param in any::<u32>(),
        kind_choice in 0usize..2usize,
        solved_in_ms in any::<u64>(),
    ) {
        let engine = fib_engine_with_secs(1);
        let expected_validator = wallet(expected_validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let kind = if kind_choice == 0 {
            PorPuzzleKind::FibonacciDelayDev
        } else {
            PorPuzzleKind::FactorizationDelayDev
        };

        let solution = PorPuzzleSolution {
            header: PorPuzzleHeader {
                height,
                validator,
                prev_block_hash: prev_hash,
                kind,
                param,
            },
            output,
            solved_in_ms,
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.verify_checked(&solution, height, &expected_validator, prev_hash)
        }));

        prop_assert!(
            result.is_ok(),
            "verify_checked must return Ok/Err, not panic, for malformed public solution shapes"
        );
    }

    // 25/25
    #[test]
    fn test_025_derive_and_verify_public_entrypoints_never_panic_for_arbitrary_inputs(
        height in any::<u64>(),
        validator in ".{0,512}",
        expected_validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output in any::<u128>(),
        param in any::<u32>(),
        kind_choice in 0usize..2usize,
    ) {
        let engine = fib_engine_with_secs(1);
        let prev_hash = valid_hash(hash_seed);

        let kind = if kind_choice == 0 {
            PorPuzzleKind::FibonacciDelayDev
        } else {
            PorPuzzleKind::FactorizationDelayDev
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let header = engine.derive_puzzle(height, &validator, prev_hash);

            let solution = PorPuzzleSolution {
                header: PorPuzzleHeader {
                    height: header.height,
                    validator: header.validator,
                    prev_block_hash: header.prev_block_hash,
                    kind,
                    param,
                },
                output,
                solved_in_ms: 0,
            };

            let expected_validator = wallet(expected_validator_seed);

            let _ = engine.verify_checked(&solution, height, &expected_validator, prev_hash);
            let _ = engine.verify(&solution, height, &expected_validator, prev_hash);
        }));

        prop_assert!(
            result.is_ok(),
            "derive_puzzle + verify wrappers must never panic for arbitrary public inputs"
        );
    }
}
