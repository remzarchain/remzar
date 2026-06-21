use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::consensus::por_002_puzzle_engine::{
    PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
};
use remzar::consensus::por_003_puzzle_pool::PorPuzzlePool;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;

use std::time::Duration;

const MAX_VALID_PROOF_HEIGHT: u64 = 10_000_000;

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn messy_wallet(seed: u64) -> String {
    format!(" \t{}\n", wallet(seed).to_ascii_uppercase())
}

fn wrong_prefix_wallet(seed: u64) -> String {
    format!("p{seed:0128x}")
}

fn non_hex_wallet(seed: u64) -> String {
    format!("rz{seed:0127x}")
}

fn long_wallet(extra_len: usize) -> String {
    format!("r{}{}", "a".repeat(128), "b".repeat(extra_len))
}

fn valid_height(seed: u64) -> u64 {
    seed % (MAX_VALID_PROOF_HEIGHT.saturating_add(1))
}

fn valid_hash(seed: u64) -> [u8; 64] {
    let mut out = [0x42u8; 64];

    out[..8].copy_from_slice(&seed.to_le_bytes());
    out[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    out[16..24].copy_from_slice(&seed.rotate_right(11).to_le_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[0] = 0;
    }

    out
}

fn valid_output(seed: u128) -> u128 {
    seed.saturating_add(1)
}

fn fib_engine_with_secs(secs: u64) -> PorPuzzleEngine {
    let secs = secs.max(1);

    PorPuzzleEngine::new(PorConsensusConfig {
        target_block_time: Duration::from_secs(secs),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: secs.saturating_mul(1_000),
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

fn valid_fib_solution(
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

fn valid_fib_proof(
    engine: &PorPuzzleEngine,
    height_seed: u64,
    validator_seed: u64,
    hash_seed: u64,
) -> PorPuzzleProof {
    let height = valid_height(height_seed);
    let validator = wallet(validator_seed);
    let prev_hash = valid_hash(hash_seed);
    let solution = valid_fib_solution(engine, height, &validator, prev_hash);

    PorPuzzleProof::from_solution(&solution)
}

fn manual_valid_proof(
    height_seed: u64,
    validator_seed: u64,
    hash_seed: u64,
    output_seed: u128,
) -> PorPuzzleProof {
    PorPuzzleProof {
        height: valid_height(height_seed),
        validator: wallet(validator_seed),
        prev_block_hash: valid_hash(hash_seed),
        output: valid_output(output_seed),
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
    fn test_001_from_solution_preserves_consensus_fields(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let height = valid_height(height_seed);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);

        let solution = valid_fib_solution(&engine, height, &validator, prev_hash);
        let proof = PorPuzzleProof::from_solution(&solution);

        prop_assert_eq!(
            proof.height,
            solution.header.height,
            "from_solution must preserve header height"
        );

        prop_assert_eq!(
            proof.validator.as_str(),
            solution.header.validator.as_str(),
            "from_solution must preserve header validator exactly"
        );

        prop_assert_eq!(
            proof.prev_block_hash,
            solution.header.prev_block_hash,
            "from_solution must preserve previous block hash"
        );

        prop_assert_eq!(
            proof.output,
            solution.output,
            "from_solution must preserve puzzle output"
        );
    }

    // 02/25
    #[test]
    fn test_002_validate_structural_accepts_canonical_valid_manual_proof(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = manual_valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        prop_assert!(
            proof.validate_structural().is_ok(),
            "canonical structurally valid proof must validate"
        );
    }

    // 03/25
    #[test]
    fn test_003_validate_structural_rejects_uppercase_stored_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut proof = manual_valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        proof.validator = proof.validator.to_ascii_uppercase();

        prop_assert!(
            proof.validate_structural().is_err(),
            "stored validator must already be canonical lowercase"
        );
    }

    // 04/25
    #[test]
    fn test_004_validate_structural_rejects_whitespace_wrapped_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut proof = manual_valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        proof.validator = format!(" \t{}\n", proof.validator);

        prop_assert!(
            proof.validate_structural().is_err(),
            "stored validator must not contain surrounding whitespace"
        );
    }

    // 05/25
    #[test]
    fn test_005_validate_structural_rejects_wrong_prefix_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: wrong_prefix_wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "wrong-prefix validator must be rejected"
        );
    }

    // 06/25
    #[test]
    fn test_006_validate_structural_rejects_non_hex_validator_body(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: non_hex_wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "non-hex validator body must be rejected"
        );
    }

    // 07/25
    #[test]
    fn test_007_validate_structural_rejects_short_validator(
        height_seed in any::<u64>(),
        short_body in "[0-9a-f]{0,127}",
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: format!("r{short_body}"),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "short validator must be rejected"
        );
    }

    // 08/25
    #[test]
    fn test_008_validate_structural_rejects_overlong_validator_before_canonicalization(
        height_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
        extra_len in 128usize..512usize,
    ) {
        let validator = long_wallet(extra_len);

        prop_assert!(
            validator.len() > 256,
            "test setup must exceed proof validator length cap"
        );

        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator,
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "overlong validator must be rejected"
        );
    }

    // 09/25
    #[test]
    fn test_009_validate_structural_rejects_height_above_bound(
        extra in 1u64..=1_000_000u64,
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: MAX_VALID_PROOF_HEIGHT.saturating_add(extra),
            validator: wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "height above 10,000,000 must be rejected"
        );
    }

    // 10/25
    #[test]
    fn test_010_validate_structural_accepts_height_boundary(
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: MAX_VALID_PROOF_HEIGHT,
            validator: wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_ok(),
            "height exactly 10,000,000 must be accepted"
        );
    }

    // 11/25
    #[test]
    fn test_011_validate_structural_rejects_zero_prev_block_hash(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: wallet(validator_seed),
            prev_block_hash: [0u8; 64],
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "all-zero previous block hash sentinel must be rejected"
        );
    }

    // 12/25
    #[test]
    fn test_012_validate_structural_rejects_ff_prev_block_hash(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: wallet(validator_seed),
            prev_block_hash: [0xFFu8; 64],
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "all-0xFF previous block hash sentinel must be rejected"
        );
    }

    // 13/25
    #[test]
    fn test_013_validate_structural_rejects_zero_output(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
    ) {
        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: 0,
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "zero puzzle output must be rejected"
        );
    }

    // 14/25
    #[test]
    fn test_014_verify_with_engine_checked_accepts_valid_fibonacci_proof(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);

        let verified = proof
            .verify_with_engine_checked(&engine)
            .expect("structurally valid proof verification should run");

        prop_assert!(
            verified,
            "valid Fibonacci proof must verify"
        );
    }

    // 15/25
    #[test]
    fn test_015_verify_with_engine_boolean_accepts_valid_fibonacci_proof(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);

        prop_assert!(
            proof.verify_with_engine(&engine),
            "boolean verifier must accept valid Fibonacci proof"
        );
    }

    // 16/25
    #[test]
    fn test_016_verify_with_engine_checked_rejects_wrong_output_as_false_not_error(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
        delta in 1u128..=1_000_000u128,
    ) {
        let engine = fib_engine_with_secs(secs);
        let mut proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);

        proof.output = proof.output.saturating_add(delta);

        let verified = proof
            .verify_with_engine_checked(&engine)
            .expect("structurally valid wrong-output proof should return Ok(false)");

        prop_assert!(
            !verified,
            "wrong Fibonacci output must not verify"
        );
    }

    // 17/25
    #[test]
    fn test_017_verify_with_engine_boolean_rejects_wrong_output(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
        delta in 1u128..=1_000_000u128,
    ) {
        let engine = fib_engine_with_secs(secs);
        let mut proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);

        proof.output = proof.output.saturating_add(delta);

        prop_assert!(
            !proof.verify_with_engine(&engine),
            "boolean verifier must reject wrong Fibonacci output"
        );
    }

    // 18/25
    #[test]
    fn test_018_verify_with_engine_checked_returns_error_for_structurally_invalid_proof(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);

        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: wrong_prefix_wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: 1,
        };

        prop_assert!(
            proof.verify_with_engine_checked(&engine).is_err(),
            "structurally invalid proof must return Err from checked verifier"
        );

        prop_assert!(
            !proof.verify_with_engine(&engine),
            "boolean verifier must return false for structurally invalid proof"
        );
    }

    // 19/25
    #[test]
    fn test_019_verify_and_record_checked_accepts_valid_proof_and_records_pool_entry(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);
        let mut pool = PorPuzzlePool::new();

        let ok = proof
            .verify_and_record_checked(&engine, &mut pool)
            .expect("valid proof verify_and_record should run");

        prop_assert!(
            ok,
            "valid proof must verify and record"
        );

        prop_assert_eq!(
            pool.winners_for_height(proof.height),
            vec![proof.validator.clone()],
            "verified proof must record canonical validator in puzzle pool"
        );

        prop_assert!(
            pool.entropy_for_height(proof.height).is_some(),
            "verified proof must create pool entropy for height"
        );
    }

    // 20/25
    #[test]
    fn test_020_verify_and_record_boolean_accepts_valid_proof_and_records_pool_entry(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);
        let mut pool = PorPuzzlePool::new();

        prop_assert!(
            proof.verify_and_record(&engine, &mut pool),
            "boolean verify_and_record must accept valid proof"
        );

        prop_assert_eq!(
            pool.winners_for_height(proof.height),
            vec![proof.validator.clone()],
            "boolean verify_and_record must record valid proof"
        );
    }

    // 21/25
    #[test]
    fn test_021_verify_and_record_checked_wrong_output_returns_false_and_does_not_record(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
        delta in 1u128..=1_000_000u128,
    ) {
        let engine = fib_engine_with_secs(secs);
        let mut proof = valid_fib_proof(&engine, height_seed, validator_seed, hash_seed);
        let mut pool = PorPuzzlePool::new();

        proof.output = proof.output.saturating_add(delta);

        let ok = proof
            .verify_and_record_checked(&engine, &mut pool)
            .expect("structurally valid wrong-output proof should return Ok(false)");

        prop_assert!(
            !ok,
            "wrong output must not verify"
        );

        prop_assert!(
            pool.winners_for_height(proof.height).is_empty(),
            "wrong-output proof must not record into pool"
        );

        prop_assert!(
            pool.entropy_for_height(proof.height).is_none(),
            "wrong-output proof must not create pool entropy"
        );
    }

    // 22/25
    #[test]
    fn test_022_verify_and_record_checked_invalid_structural_proof_returns_error_and_does_not_record(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        secs in 1u64..=120u64,
    ) {
        let engine = fib_engine_with_secs(secs);
        let mut pool = PorPuzzlePool::new();

        let proof = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: non_hex_wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: 1,
        };

        prop_assert!(
            proof.verify_and_record_checked(&engine, &mut pool).is_err(),
            "structurally invalid proof must return Err from checked verify_and_record"
        );

        prop_assert!(
            pool.winners_for_height(proof.height).is_empty(),
            "invalid structural proof must not record into pool"
        );

        prop_assert!(
            !proof.verify_and_record(&engine, &mut pool),
            "boolean verify_and_record must return false for invalid structural proof"
        );
    }

    // 23/25
    #[test]
    fn test_023_from_solution_does_not_hide_noncanonical_header_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let solution = PorPuzzleSolution {
            header: PorPuzzleHeader {
                height: valid_height(height_seed),
                validator: messy_wallet(validator_seed),
                prev_block_hash: valid_hash(hash_seed),
                kind: PorPuzzleKind::FibonacciDelayDev,
                param: 26,
            },
            output: valid_output(output_seed),
            solved_in_ms: 0,
        };

        let proof = PorPuzzleProof::from_solution(&solution);

        prop_assert_eq!(
            proof.validator.as_str(),
            solution.header.validator.as_str(),
            "from_solution must preserve header validator exactly"
        );

        prop_assert!(
            proof.validate_structural().is_err(),
            "noncanonical header validator must remain detectable after from_solution"
        );
    }

    // 24/25
    #[test]
    fn test_024_postcard_roundtrip_preserves_fields_and_revalidates(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let proof = manual_valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let encoded = postcard::to_allocvec(&proof)
            .expect("valid proof should serialize with postcard");

        let decoded: PorPuzzleProof = postcard::from_bytes(&encoded)
            .expect("valid proof should deserialize with postcard");

        prop_assert_eq!(
            decoded.height,
            proof.height,
            "postcard roundtrip must preserve height"
        );

        prop_assert_eq!(
            decoded.validator.as_str(),
            proof.validator.as_str(),
            "postcard roundtrip must preserve validator"
        );

        prop_assert_eq!(
            decoded.prev_block_hash,
            proof.prev_block_hash,
            "postcard roundtrip must preserve previous block hash"
        );

        prop_assert_eq!(
            decoded.output,
            proof.output,
            "postcard roundtrip must preserve output"
        );

        prop_assert!(
            decoded.validate_structural().is_ok(),
            "postcard-decoded valid proof must validate structurally"
        );
    }

    // 25/25
    #[test]
    fn test_025_public_entrypoints_never_panic_for_arbitrary_public_shapes(
        height in any::<u64>(),
        validator in ".{0,512}",
        hash_seed in any::<u64>(),
        output in any::<u128>(),
        secs in 1u64..=120u64,
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let engine = fib_engine_with_secs(secs);
        let mut pool = PorPuzzlePool::new();

        let proof = PorPuzzleProof {
            height,
            validator,
            prev_block_hash: valid_hash(hash_seed),
            output,
        };

        let public_method_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = proof.validate_structural();
            let _ = proof.verify_with_engine_checked(&engine);
            let _ = proof.verify_with_engine(&engine);
            let _ = proof.verify_and_record_checked(&engine, &mut pool);
            let _ = proof.verify_and_record(&engine, &mut pool);
        }));

        prop_assert!(
            public_method_result.is_ok(),
            "PorPuzzleProof public validation/verification/recording entrypoints must not panic"
        );

        let deserialize_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let decoded = postcard::from_bytes::<PorPuzzleProof>(&bytes);

            if let Ok(decoded_proof) = decoded {
                let _ = decoded_proof.validate_structural();
                let _ = decoded_proof.verify_with_engine_checked(&engine);
                let _ = decoded_proof.verify_with_engine(&engine);
            }
        }));

        prop_assert!(
            deserialize_result.is_ok(),
            "postcard deserialize plus public validation path must not panic for arbitrary bytes"
        );
    }
}
