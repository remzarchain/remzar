use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;

const MAX_REASONABLE_HEIGHT_TEST: u64 = 10_000_000;

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

fn valid_hash(seed: u64) -> [u8; 64] {
    let mut out = [0x42u8; 64];

    out[..8].copy_from_slice(&seed.to_le_bytes());
    out[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    out[16..24].copy_from_slice(&seed.rotate_right(9).to_le_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[0] = 0;
    }

    out
}

fn valid_output(seed: u64) -> u128 {
    u128::from(seed).saturating_add(1)
}

fn valid_height(seed: u64) -> u64 {
    seed % (MAX_REASONABLE_HEIGHT_TEST.saturating_add(1))
}

fn valid_proof(
    height_seed: u64,
    validator_seed: u64,
    hash_seed: u64,
    output_seed: u64,
) -> BlockPuzzleProof {
    BlockPuzzleProof::new(
        valid_height(height_seed),
        wallet(validator_seed),
        valid_hash(hash_seed),
        valid_output(output_seed),
    )
    .expect("generated valid BlockPuzzleProof should construct")
}

fn gossip_proof(
    height_seed: u64,
    validator_seed: u64,
    hash_seed: u64,
    output_seed: u64,
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
    fn test_001_new_accepts_canonical_validator_and_preserves_fields(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let height = valid_height(height_seed);
        let validator = wallet(validator_seed);
        let prev_hash = valid_hash(hash_seed);
        let output = valid_output(output_seed);

        let proof = BlockPuzzleProof::new(
            height,
            validator.clone(),
            prev_hash,
            output,
        )
        .expect("canonical proof should construct");

        prop_assert_eq!(
            proof.height,
            height,
            "constructor must preserve height"
        );

        prop_assert_eq!(
            proof.validator.as_str(),
            validator.as_str(),
            "constructor must preserve canonical validator"
        );

        prop_assert_eq!(
            proof.prev_block_hash,
            prev_hash,
            "constructor must preserve previous block hash"
        );

        prop_assert_eq!(
            proof.output,
            output,
            "constructor must preserve output"
        );

        prop_assert!(
            proof.validate_structural().is_ok(),
            "fresh canonical proof must validate structurally"
        );
    }

    // 02/25
    #[test]
    fn test_002_new_canonicalizes_trimmed_uppercase_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let expected = wallet(validator_seed);

        let proof = BlockPuzzleProof::new(
            valid_height(height_seed),
            messy_wallet(validator_seed),
            valid_hash(hash_seed),
            valid_output(output_seed),
        )
        .expect("constructor should canonicalize trimmed uppercase validator");

        prop_assert_eq!(
            proof.validator.as_str(),
            expected.as_str(),
            "constructor must store canonical lowercase validator"
        );

        prop_assert!(
            proof.validate_structural().is_ok(),
            "canonicalized proof must validate"
        );
    }

    // 03/25
    #[test]
    fn test_003_new_rejects_overlong_validator_before_canonicalization(
        height_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
        extra_len in 128usize..512usize,
    ) {
        let validator = format!("r{}{}", "a".repeat(128), "b".repeat(extra_len));

        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                validator,
                valid_hash(hash_seed),
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject overlong validator strings"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_rejects_short_validator(
        height_seed in any::<u64>(),
        short_body in "[0-9a-f]{0,127}",
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let validator = format!("r{short_body}");

        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                validator,
                valid_hash(hash_seed),
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject short validator wallet"
        );
    }

    // 05/25
    #[test]
    fn test_005_new_rejects_wrong_validator_prefix(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                wrong_prefix_wallet(validator_seed),
                valid_hash(hash_seed),
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject validator with wrong prefix"
        );
    }

    // 06/25
    #[test]
    fn test_006_new_rejects_non_hex_validator_body(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                non_hex_wallet(validator_seed),
                valid_hash(hash_seed),
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject non-hex validator body"
        );
    }

    // 07/25
    #[test]
    fn test_007_new_rejects_height_above_reasonable_bound(
        height_extra in 1u64..=1_000_000u64,
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let height = MAX_REASONABLE_HEIGHT_TEST.saturating_add(height_extra);

        prop_assert!(
            BlockPuzzleProof::new(
                height,
                wallet(validator_seed),
                valid_hash(hash_seed),
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject implausibly high puzzle proof height"
        );
    }

    // 08/25
    #[test]
    fn test_008_new_rejects_zero_prev_block_hash_sentinel(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                wallet(validator_seed),
                [0u8; 64],
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject all-zero previous block hash sentinel"
        );
    }

    // 09/25
    #[test]
    fn test_009_new_rejects_ff_prev_block_hash_sentinel(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                wallet(validator_seed),
                [0xFFu8; 64],
                valid_output(output_seed),
            )
            .is_err(),
            "constructor must reject all-0xFF previous block hash sentinel"
        );
    }

    // 10/25
    #[test]
    fn test_010_new_rejects_zero_output(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
    ) {
        prop_assert!(
            BlockPuzzleProof::new(
                valid_height(height_seed),
                wallet(validator_seed),
                valid_hash(hash_seed),
                0,
            )
            .is_err(),
            "constructor must reject zero puzzle output"
        );
    }

    // 11/25
    #[test]
    fn test_011_validate_structural_accepts_valid_manual_proof(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = BlockPuzzleProof {
            height: valid_height(height_seed),
            validator: wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_ok(),
            "manual canonical proof must validate structurally"
        );
    }

    // 12/25
    #[test]
    fn test_012_validate_structural_rejects_noncanonical_uppercase_stored_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = BlockPuzzleProof {
            height: valid_height(height_seed),
            validator: wallet(validator_seed).to_ascii_uppercase(),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "stored validator must already be canonical lowercase"
        );
    }

    // 13/25
    #[test]
    fn test_013_validate_structural_rejects_whitespace_wrapped_stored_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = BlockPuzzleProof {
            height: valid_height(height_seed),
            validator: format!(" {} ", wallet(validator_seed)),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "stored validator must not contain surrounding whitespace"
        );
    }

    // 14/25
    #[test]
    fn test_014_validate_structural_rejects_empty_or_blank_validator(
        height_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
        blanks in "[ \\t\\n\\r]{0,32}",
    ) {
        let proof = BlockPuzzleProof {
            height: valid_height(height_seed),
            validator: blanks,
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            proof.validate_structural().is_err(),
            "empty or blank validator must fail structural validation"
        );
    }

    // 15/25
    #[test]
    fn test_015_from_gossip_preserves_fields_and_canonicalizes_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let mut gossip = gossip_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        gossip.validator = messy_wallet(validator_seed);

        let proof = BlockPuzzleProof::from_gossip(&gossip)
            .expect("valid canonicalizable gossip proof should convert");

        let expected_validator = wallet(validator_seed);

        prop_assert_eq!(
            proof.height,
            gossip.height,
            "from_gossip must preserve height"
        );

        prop_assert_eq!(
            proof.validator.as_str(),
            expected_validator.as_str(),
            "from_gossip must canonicalize validator"
        );

        prop_assert_eq!(
            proof.prev_block_hash,
            gossip.prev_block_hash,
            "from_gossip must preserve previous block hash"
        );

        prop_assert_eq!(
            proof.output,
            gossip.output,
            "from_gossip must preserve output"
        );
    }

    // 16/25
    #[test]
    fn test_016_from_gossip_rejects_invalid_gossip_validator(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let gossip = PorPuzzleProof {
            height: valid_height(height_seed),
            validator: wrong_prefix_wallet(validator_seed),
            prev_block_hash: valid_hash(hash_seed),
            output: valid_output(output_seed),
        };

        prop_assert!(
            BlockPuzzleProof::from_gossip(&gossip).is_err(),
            "from_gossip must reject invalid validator identity"
        );
    }

    // 17/25
    #[test]
    fn test_017_from_gossip_rejects_invalid_gossip_hash_or_output(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u64>(),
        case in 0usize..3usize,
    ) {
        let mut gossip = gossip_proof(
            height_seed,
            validator_seed,
            123,
            output_seed,
        );

        match case {
            0 => gossip.prev_block_hash = [0u8; 64],
            1 => gossip.prev_block_hash = [0xFFu8; 64],
            _ => gossip.output = 0,
        }

        prop_assert!(
            BlockPuzzleProof::from_gossip(&gossip).is_err(),
            "from_gossip must reject structurally invalid gossip proof"
        );
    }

    // 18/25
    #[test]
    fn test_018_to_gossip_preserves_all_consensus_fields(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let gossip = proof.to_gossip();

        prop_assert_eq!(
            gossip.height,
            proof.height,
            "to_gossip must preserve height"
        );

        prop_assert_eq!(
            gossip.validator.as_str(),
            proof.validator.as_str(),
            "to_gossip must preserve validator"
        );

        prop_assert_eq!(
            gossip.prev_block_hash,
            proof.prev_block_hash,
            "to_gossip must preserve previous block hash"
        );

        prop_assert_eq!(
            gossip.output,
            proof.output,
            "to_gossip must preserve output"
        );
    }

    // 19/25
    #[test]
    fn test_019_gossip_roundtrip_preserves_block_committed_proof(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let gossip = proof.to_gossip();

        let roundtrip = BlockPuzzleProof::from_gossip(&gossip)
            .expect("gossip roundtrip should reconstruct valid block proof");

        prop_assert_eq!(
            &roundtrip,
            &proof,
            "BlockPuzzleProof -> PorPuzzleProof -> BlockPuzzleProof must preserve proof"
        );
    }

    // 20/25
    #[test]
    fn test_020_postcard_roundtrip_preserves_valid_proof_and_revalidates(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let encoded = postcard::to_allocvec(&proof)
            .expect("valid proof should postcard serialize");

        let decoded: BlockPuzzleProof = postcard::from_bytes(&encoded)
            .expect("valid proof should postcard deserialize");

        prop_assert_eq!(
            &decoded,
            &proof,
            "postcard roundtrip must preserve BlockPuzzleProof"
        );

        prop_assert!(
            decoded.validate_structural().is_ok(),
            "postcard-decoded proof must still validate structurally"
        );
    }

    // 21/25
    #[test]
    fn test_021_commitment_bytes_is_64_bytes_and_deterministic(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let commitment_a = proof.commitment_bytes()
            .expect("commitment should compute");

        let commitment_b = proof.commitment_bytes()
            .expect("commitment should be deterministic");

        prop_assert_eq!(
            commitment_a.len(),
            64,
            "commitment_bytes must be exactly 64 bytes"
        );

        prop_assert_eq!(
            commitment_a,
            commitment_b,
            "commitment_bytes must be deterministic"
        );
    }

    // 22/25
    #[test]
    fn test_022_commitment_hex_is_128_lowercase_hex_and_matches_bytes(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof = valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let bytes = proof.commitment_bytes()
            .expect("commitment bytes should compute");

        let hex = proof.commitment_hex()
            .expect("commitment hex should compute");

        let expected_hex = hex::encode(bytes);

        prop_assert_eq!(
            hex.len(),
            128,
            "commitment_hex must encode 64 bytes as 128 hex chars"
        );

        prop_assert_eq!(
            hex.as_str(),
            expected_hex.as_str(),
            "commitment_hex must be lowercase hex encoding of commitment_bytes"
        );

        prop_assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "commitment_hex must be lowercase ASCII hex"
        );
    }

    // 23/25
    #[test]
    fn test_023_commitment_changes_when_height_changes(
        height_seed in 0u64..MAX_REASONABLE_HEIGHT_TEST,
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
    ) {
        let proof_a = BlockPuzzleProof::new(
            height_seed,
            wallet(validator_seed),
            valid_hash(hash_seed),
            valid_output(output_seed),
        )
        .expect("proof A should construct");

        let proof_b = BlockPuzzleProof::new(
            height_seed.saturating_add(1),
            wallet(validator_seed),
            valid_hash(hash_seed),
            valid_output(output_seed),
        )
        .expect("proof B should construct");

        prop_assert_ne!(
            proof_a.commitment_bytes().expect("commitment A should compute"),
            proof_b.commitment_bytes().expect("commitment B should compute"),
            "changing height must change proof commitment"
        );
    }

    // 24/25
    #[test]
    fn test_024_commitment_changes_when_validator_hash_or_output_changes(
        height_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        hash_seed in any::<u64>(),
        output_seed in any::<u64>(),
        case in 0usize..3usize,
    ) {
        let base = valid_proof(
            height_seed,
            validator_seed,
            hash_seed,
            output_seed,
        );

        let changed = match case {
            0 => BlockPuzzleProof::new(
                base.height,
                wallet(validator_seed.saturating_add(1)),
                base.prev_block_hash,
                base.output,
            )
            .expect("validator-changed proof should construct"),
            1 => BlockPuzzleProof::new(
                base.height,
                base.validator.clone(),
                valid_hash(hash_seed.saturating_add(1)),
                base.output,
            )
            .expect("hash-changed proof should construct"),
            _ => BlockPuzzleProof::new(
                base.height,
                base.validator.clone(),
                base.prev_block_hash,
                base.output.saturating_add(1),
            )
            .expect("output-changed proof should construct"),
        };

        prop_assert_ne!(
            base.commitment_bytes().expect("base commitment should compute"),
            changed.commitment_bytes().expect("changed commitment should compute"),
            "changing validator, prev_block_hash, or output must change commitment"
        );
    }

    // 25/25
    #[test]
    fn test_025_public_entrypoints_never_panic_for_arbitrary_external_shapes(
        height in any::<u64>(),
        validator in ".{0,512}",
        hash_seed in any::<u64>(),
        output in any::<u128>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let new_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            BlockPuzzleProof::new(
                height,
                validator.clone(),
                valid_hash(hash_seed),
                output,
            )
        }));

        prop_assert!(
            new_result.is_ok(),
            "BlockPuzzleProof::new must not panic for arbitrary validator/height/output shapes"
        );

        let raw_decode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            postcard::from_bytes::<BlockPuzzleProof>(&bytes)
                .map(|proof| {
                    let _ = proof.validate_structural();
                    let _ = proof.commitment_bytes();
                    let _ = proof.commitment_hex();
                    let _ = proof.to_gossip();
                })
        }));

        prop_assert!(
            raw_decode_result.is_ok(),
            "deserialize/validate/commitment/to_gossip path must not panic for arbitrary bytes"
        );
    }
}
