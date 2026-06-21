use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::hash_system_remzarhash::RemzarHash;

fn valid_size(seed: u64) -> u64 {
    let min = GlobalConfiguration::MIN_BLOCK_SIZE;
    let max = GlobalConfiguration::MAX_BLOCK_SIZE;

    if max <= min {
        return min;
    }

    let span = max.saturating_sub(min).saturating_add(1);
    min.saturating_add(seed % span)
}

fn valid_timestamp(seed: u64) -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(seed % 1_000_000_000)
}

fn valid_index(seed: u64) -> u64 {
    1u64.saturating_add(seed % 10_000_000)
}

fn nonzero_hash(tag: u8, seed: u64) -> [u8; 64] {
    let mut out = [tag.max(1); 64];
    out[..8].copy_from_slice(&seed.to_be_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    out
}

fn nonzero_signature(seed: u64) -> [u8; ml_dsa_65::SIG_LEN] {
    let byte = u8::try_from(seed % 255)
        .expect("seed modulo 255 should fit into u8")
        .saturating_add(1);

    [byte; ml_dsa_65::SIG_LEN]
}

fn valid_non_genesis_metadata(
    index_seed: u64,
    timestamp_seed: u64,
    previous_seed: u64,
    merkle_seed: u64,
    signature_seed: u64,
    size_seed: u64,
) -> BlockMetadata {
    BlockMetadata::new(
        valid_index(index_seed),
        valid_timestamp(timestamp_seed),
        nonzero_hash(0x11, previous_seed),
        nonzero_hash(0xAA, merkle_seed),
        nonzero_signature(signature_seed),
        None,
        valid_size(size_seed),
    )
}

fn valid_genesis_metadata(
    timestamp_seed: u64,
    previous_seed: u64,
    merkle_seed: u64,
    size_seed: u64,
) -> BlockMetadata {
    BlockMetadata::new(
        0,
        valid_timestamp(timestamp_seed),
        nonzero_hash(0x22, previous_seed),
        nonzero_hash(0xBB, merkle_seed),
        [0u8; ml_dsa_65::SIG_LEN],
        None,
        valid_size(size_seed),
    )
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_preserves_fields_and_valid_non_genesis_metadata_passes_structural_validation(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        prop_assert!(
            metadata.validate_structural().is_ok(),
            "valid non-genesis metadata must pass structural validation"
        );

        prop_assert!(
            metadata.index >= 1 && metadata.index <= 10_000_000,
            "non-genesis metadata index must stay inside structural bounds"
        );

        prop_assert!(
            metadata.timestamp >= GlobalConfiguration::MIN_TIMESTAMP_SECS,
            "metadata timestamp must be at or above configured minimum"
        );

        prop_assert!(
            metadata.size >= GlobalConfiguration::MIN_BLOCK_SIZE,
            "metadata size must be at or above minimum block size"
        );

        prop_assert!(
            metadata.size <= GlobalConfiguration::MAX_BLOCK_SIZE,
            "metadata size must be at or below maximum block size"
        );

        prop_assert_ne!(
            metadata.previous_hash,
            [0u8; 64],
            "non-genesis previous hash must not be all zeros"
        );

        prop_assert_ne!(
            metadata.merkle_root,
            [0u8; 64],
            "non-genesis Merkle root must not be all zeros"
        );

        prop_assert_ne!(
            metadata.guardian_signature,
            [0u8; ml_dsa_65::SIG_LEN],
            "non-genesis guardian signature must not be all zeros"
        );

        prop_assert_ne!(
            metadata.previous_hash,
            metadata.merkle_root,
            "non-genesis previous_hash and merkle_root must differ"
        );
    }

    // 02/25
    #[test]
    fn test_002_genesis_metadata_allows_zero_guardian_signature_but_requires_nonzero_merkle_root(
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_genesis_metadata(
            timestamp_seed,
            previous_seed,
            merkle_seed,
            size_seed,
        );

        prop_assert_eq!(
            metadata.index,
            0,
            "genesis metadata index must be zero"
        );

        prop_assert_eq!(
            metadata.guardian_signature,
            [0u8; ml_dsa_65::SIG_LEN],
            "genesis metadata may use zero guardian signature by design"
        );

        prop_assert_ne!(
            metadata.merkle_root,
            [0u8; 64],
            "genesis metadata must have nonzero Merkle root"
        );

        prop_assert!(
            metadata.validate_structural().is_ok(),
            "valid genesis metadata must pass structural validation"
        );
    }

    // 03/25
    #[test]
    fn test_003_genesis_metadata_rejects_zero_merkle_root(
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let mut metadata = valid_genesis_metadata(
            timestamp_seed,
            previous_seed,
            1,
            size_seed,
        );

        metadata.merkle_root = [0u8; 64];

        prop_assert!(
            metadata.validate_structural().is_err(),
            "genesis metadata must reject all-zero Merkle root"
        );
    }

    // 04/25
    #[test]
    fn test_004_non_genesis_metadata_rejects_zero_hashes_zero_signature_or_equal_hashes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        invalid_case in 0usize..4usize,
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        match invalid_case {
            0 => metadata.previous_hash = [0u8; 64],
            1 => metadata.merkle_root = [0u8; 64],
            2 => metadata.guardian_signature = [0u8; ml_dsa_65::SIG_LEN],
            _ => metadata.merkle_root = metadata.previous_hash,
        }

        prop_assert!(
            metadata.validate_structural().is_err(),
            "non-genesis metadata must reject zero previous hash, zero Merkle root, zero signature, or equal hashes"
        );
    }

    // 05/25
    #[test]
    fn test_005_structural_validation_rejects_out_of_bounds_index_size_and_timestamp(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        invalid_case in 0usize..4usize,
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        match invalid_case {
            0 => metadata.index = 10_000_001,
            1 => metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1),
            2 => metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1),
            _ => metadata.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1),
        }

        prop_assert!(
            metadata.validate_structural().is_err(),
            "metadata structural validation must reject out-of-bounds index, size, or timestamp"
        );
    }

    // 06/25
    #[test]
    fn test_006_to_bytes_from_bytes_roundtrip_preserves_valid_metadata(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let encoded = metadata
            .to_bytes()
            .expect("valid metadata should serialize");

        let decoded = BlockMetadata::from_bytes(&encoded)
            .expect("valid serialized metadata should deserialize");

        prop_assert_eq!(
            &decoded,
            &metadata,
            "metadata postcard roundtrip must preserve all fields"
        );

        prop_assert!(
            decoded.validate_structural().is_ok(),
            "decoded metadata must pass structural validation"
        );
    }

    // 07/25
    #[test]
    fn test_007_from_bytes_rejects_truncated_metadata_bytes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        keep_seed in any::<usize>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let encoded = metadata
            .to_bytes()
            .expect("valid metadata should serialize");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            BlockMetadata::from_bytes(truncated).is_err(),
            "metadata deserializer must reject truncated bytes"
        );
    }

    // 08/25
    #[test]
    fn test_008_compute_hash_is_deterministic_and_verify_hash_accepts_only_exact_expected_hash(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        byte_index in 0usize..128usize,
        _replacement in any::<u8>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let hash_a = metadata
            .compute_hash()
            .expect("metadata hash should compute");

        let hash_b = metadata
            .compute_hash()
            .expect("metadata hash should be deterministic");

        prop_assert_eq!(
            &hash_a,
            &hash_b,
            "metadata hash must be deterministic"
        );

        prop_assert_eq!(
            hash_a.len(),
            128,
            "metadata hash must be 128 lowercase hex chars"
        );

        prop_assert!(
            hash_a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "metadata hash must be lowercase hex"
        );

        prop_assert!(
            metadata
                .verify_hash(&hash_a)
                .expect("valid expected hash length should verify cleanly"),
            "verify_hash must accept the exact computed hash"
        );

        prop_assert!(
            metadata.verify_hash(&hash_a[..127]).is_err(),
            "verify_hash must reject wrong expected hash length"
        );

        let mut wrong_bytes = hash_a.into_bytes();

        wrong_bytes[byte_index] = if wrong_bytes[byte_index] == b'0' {
            b'1'
        } else {
            b'0'
        };

        let wrong_hash = String::from_utf8(wrong_bytes)
            .expect("ASCII hex mutation should remain valid UTF-8");

        prop_assert_eq!(
            wrong_hash.len(),
            128,
            "wrong hash must still be 128 chars"
        );

        prop_assert_ne!(
            &wrong_hash,
            &hash_b,
            "wrong hash must differ from real hash"
        );

        prop_assert!(
            !metadata
                .verify_hash(&wrong_hash)
                .expect("128-char wrong hash should be accepted as input and return false"),
            "verify_hash must reject a different 128-char expected hash"
        );
    }

    // 09/25
    #[test]
    fn test_009_validate_against_now_accepts_within_future_drift_and_rejects_too_far_future(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        now in GlobalConfiguration::MIN_TIMESTAMP_SECS..=4_000_000_000u64,
        drift_offset in 0u64..=1_000u64,
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let max_future = now.saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS);

        metadata.timestamp = max_future;

        prop_assert!(
            metadata.validate_against_now(now).is_ok(),
            "timestamp at max allowed future drift must be accepted"
        );

        metadata.timestamp = max_future
            .saturating_add(1)
            .saturating_add(drift_offset);

        prop_assert!(
            metadata.validate_against_now(now).is_err(),
            "timestamp beyond max future drift must be rejected"
        );
    }

    // 10/25
    #[test]
    fn test_010_validate_timestamp_requires_block_interval_after_previous_timestamp(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        previous_timestamp in GlobalConfiguration::MIN_TIMESTAMP_SECS..=4_000_000_000u64,
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let min_allowed = previous_timestamp
            .saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS);

        metadata.timestamp = min_allowed;

        prop_assert!(
            metadata.validate_timestamp(previous_timestamp).is_ok(),
            "timestamp exactly one block interval after previous timestamp must be accepted"
        );

        if min_allowed > 0 {
            metadata.timestamp = min_allowed.saturating_sub(1);

            prop_assert!(
                metadata.validate_timestamp(previous_timestamp).is_err(),
                "timestamp before required block interval must be rejected"
            );
        }
    }

    // 11/25
    #[test]
    fn test_011_validate_size_accepts_valid_size_and_rejects_below_or_above_limits(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.size = valid_size(size_seed);

        prop_assert!(
            metadata.validate_size().is_ok(),
            "valid metadata size must pass validate_size"
        );

        metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);

        prop_assert!(
            metadata.validate_size().is_err(),
            "size below MIN_BLOCK_SIZE must be rejected"
        );

        metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);

        prop_assert!(
            metadata.validate_size().is_err(),
            "size above MAX_BLOCK_SIZE must be rejected"
        );
    }

    // 12/25
    #[test]
    fn test_012_set_merkle_root_is_deterministic_and_matches_dummy_hash_for_empty_transactions(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        txs in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            1..32
        ),
    ) {
        let mut metadata_a = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut metadata_b = metadata_a.clone();

        metadata_a
            .set_merkle_root(&txs)
            .expect("setting Merkle root from generated transactions should succeed");

        metadata_b
            .set_merkle_root(&txs)
            .expect("setting Merkle root should be deterministic");

        prop_assert_eq!(
            metadata_a.merkle_root,
            metadata_b.merkle_root,
            "set_merkle_root must be deterministic for the same transactions"
        );

        let expected_hex = RemzarHash::compute_merkle_root(&txs)
            .expect("expected Merkle root helper should compute");

        let mut expected = [0u8; 64];
        hex::decode_to_slice(&expected_hex, &mut expected)
            .expect("expected Merkle root hex should decode into 64 bytes");

        prop_assert_eq!(
            metadata_a.merkle_root,
            expected,
            "set_merkle_root must store the 64-byte Merkle root from RemzarHash"
        );

        let empty: Vec<Vec<u8>> = Vec::new();

        metadata_a
            .set_merkle_root(&empty)
            .expect("setting empty Merkle root should use dummy hash");

        let dummy_hex = RemzarHash::compute_dummy_hash();
        let mut dummy = [0u8; 64];
        hex::decode_to_slice(&dummy_hex, &mut dummy)
            .expect("dummy hash hex should decode into 64 bytes");

        prop_assert_eq!(
            metadata_a.merkle_root,
            dummy,
            "empty transaction list must set Merkle root to dummy hash"
        );
    }

    // 13/25
    #[test]
    fn test_013_puzzle_commitment_without_proof_is_zero_64_bytes_and_128_hex_chars(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let commitment = metadata
            .puzzle_commitment_bytes()
            .expect("metadata without proof should return zero commitment");

        let commitment_hex = metadata
            .puzzle_commitment_hex()
            .expect("metadata without proof should return zero commitment hex");

        prop_assert_eq!(
            commitment,
            [0u8; 64],
            "metadata without puzzle proof must commit to zero hash"
        );

        prop_assert_eq!(
            commitment_hex.len(),
            128,
            "puzzle commitment hex must be 128 chars"
        );

        prop_assert_eq!(
            commitment_hex,
            hex::encode([0u8; 64]),
            "puzzle commitment hex without proof must be 64 zero bytes encoded as hex"
        );

        prop_assert!(
            metadata.puzzle_proof().is_none(),
            "generated metadata helper should have no puzzle proof"
        );
    }

    // 14/25
    #[test]
    fn test_014_to_bytes_is_deterministic_for_same_metadata(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let encoded_a = metadata
            .to_bytes()
            .expect("first metadata serialization should succeed");

        let encoded_b = metadata
            .to_bytes()
            .expect("second metadata serialization should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing the same metadata twice must produce identical bytes"
        );

        prop_assert!(
            !encoded_a.is_empty(),
            "serialized metadata must not be empty"
        );
    }

    // 15/25
    #[test]
    fn test_015_from_bytes_rejects_serialized_metadata_with_trailing_bytes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        extra in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut encoded = metadata
            .to_bytes()
            .expect("valid metadata should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            BlockMetadata::from_bytes(&encoded).is_err(),
            "metadata deserializer must reject trailing bytes after a valid postcard object"
        );
    }

    // 16/25
    #[test]
    fn test_016_verify_hash_trims_surrounding_whitespace(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let hash = metadata
            .compute_hash()
            .expect("metadata hash should compute");

        let padded = format!(" \n\t{hash}\r\n ");

        prop_assert!(
            metadata
                .verify_hash(&padded)
                .expect("verify_hash should trim surrounding whitespace"),
            "verify_hash must accept exact hash with surrounding whitespace"
        );
    }

    // 17/25
    #[test]
    fn test_017_set_guardian_signature_can_repair_zero_signature_non_genesis_metadata(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.guardian_signature = [0u8; ml_dsa_65::SIG_LEN];

        prop_assert!(
            metadata.validate_structural().is_err(),
            "non-genesis metadata with zero guardian signature must fail validation"
        );

        let repaired_signature = nonzero_signature(signature_seed.saturating_add(1));
        metadata.set_guardian_signature(repaired_signature);

        prop_assert_eq!(
            metadata.guardian_signature,
            repaired_signature,
            "set_guardian_signature must store the exact provided signature bytes"
        );

        prop_assert!(
            metadata.validate_structural().is_ok(),
            "non-genesis metadata should validate after setting a nonzero guardian signature"
        );
    }

    // 18/25
    #[test]
    fn test_018_compute_hash_changes_when_guardian_signature_changes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let hash_before = metadata
            .compute_hash()
            .expect("metadata hash before mutation should compute");

        let mut changed_signature = metadata.guardian_signature;
        changed_signature[0] = changed_signature[0].wrapping_add(1);
        if changed_signature == [0u8; ml_dsa_65::SIG_LEN] {
            changed_signature[0] = 1;
        }

        metadata.set_guardian_signature(changed_signature);

        let hash_after = metadata
            .compute_hash()
            .expect("metadata hash after mutation should compute");

        prop_assert_ne!(
            &hash_before,
            &hash_after,
            "metadata hash must change when guardian signature changes"
        );
    }

    // 19/25
    #[test]
    fn test_019_from_bytes_rejects_structurally_invalid_serialized_metadata(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.previous_hash = [0u8; 64];

        let encoded = postcard::to_allocvec(&metadata)
            .expect("direct postcard encoding of invalid metadata should succeed");

        prop_assert!(
            BlockMetadata::from_bytes(&encoded).is_err(),
            "from_bytes must deserialize and then reject structurally invalid metadata"
        );
    }

    // 20/25
    #[test]
    fn test_020_validate_timestamp_rejects_overflowing_previous_timestamp(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        if GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS > 0 {
            prop_assert!(
                metadata.validate_timestamp(u64::MAX).is_err(),
                "validate_timestamp must reject checked_add overflow"
            );
        } else {
            prop_assert!(
                metadata.validate_timestamp(u64::MAX).is_ok()
                    || metadata.validate_timestamp(u64::MAX).is_err(),
                "zero interval configuration keeps this branch total"
            );
        }
    }

    // 21/25
    #[test]
    fn test_021_validate_against_now_accepts_past_present_and_boundary_future_timestamps(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        now in GlobalConfiguration::MIN_TIMESTAMP_SECS..=4_000_000_000u64,
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS;

        prop_assert!(
            metadata.validate_against_now(now).is_ok(),
            "old-but-structurally-valid timestamps should pass validate_against_now"
        );

        metadata.timestamp = now;

        prop_assert!(
            metadata.validate_against_now(now).is_ok(),
            "timestamp equal to caller-provided now should pass"
        );

        metadata.timestamp = now.saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS);

        prop_assert!(
            metadata.validate_against_now(now).is_ok(),
            "timestamp exactly at future drift boundary should pass"
        );
    }

    // 22/25
    #[test]
    fn test_022_set_merkle_root_changes_metadata_hash_and_preserves_structural_validity(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let hash_before = metadata
            .compute_hash()
            .expect("metadata hash before Merkle update should compute");

        let tx = vec![0xAB, 0xCD];
        let txs = vec![tx, tail];

        metadata
            .set_merkle_root(&txs)
            .expect("setting Merkle root should succeed");

        let hash_after = metadata
            .compute_hash()
            .expect("metadata hash after Merkle update should compute");

        prop_assert_ne!(
            &hash_before,
            &hash_after,
            "metadata hash should change after Merkle root changes"
        );

        prop_assert!(
            metadata.validate_structural().is_ok(),
            "metadata should remain structurally valid after setting a nonzero Merkle root"
        );
    }

    // 23/25
    #[test]
    fn test_023_clone_preserves_equality_serialization_and_hash(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let cloned = metadata.clone();

        prop_assert_eq!(
            &cloned,
            &metadata,
            "BlockMetadata clone must preserve equality"
        );

        prop_assert_eq!(
            cloned.to_bytes().expect("clone serialization should succeed"),
            metadata.to_bytes().expect("original serialization should succeed"),
            "clone and original must serialize identically"
        );

        prop_assert_eq!(
            cloned.compute_hash().expect("clone hash should compute"),
            metadata.compute_hash().expect("original hash should compute"),
            "clone and original must hash identically"
        );
    }

    // 24/25
    #[test]
    fn test_024_from_bytes_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            BlockMetadata::from_bytes(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "BlockMetadata::from_bytes must never panic on arbitrary external bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_set_puzzle_proof_none_is_idempotent_and_keeps_zero_commitment(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.set_puzzle_proof(None);
        metadata.set_puzzle_proof(None);

        prop_assert!(
            metadata.puzzle_proof().is_none(),
            "setting puzzle proof to None repeatedly must keep puzzle proof absent"
        );

        prop_assert_eq!(
            metadata
                .puzzle_commitment_bytes()
                .expect("None puzzle proof commitment should compute"),
            [0u8; 64],
            "None puzzle proof must keep zero commitment"
        );

        prop_assert!(
            metadata.validate_structural().is_ok(),
            "metadata must remain structurally valid after idempotent None puzzle proof assignment"
        );
    }
}
