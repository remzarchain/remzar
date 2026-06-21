use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::utility::hash_system_remzarhash::RemzarHash;

fn prefixed_vec(prefix: u8, tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tail.len() + 1);
    out.push(prefix);
    out.extend_from_slice(tail);
    out
}

fn array64_from_tail(prefix: u8, tail: &[u8]) -> [u8; 64] {
    let mut out = [prefix; 64];

    for (index, byte) in tail.iter().take(64).enumerate() {
        out[index] = out[index].wrapping_add(*byte);
    }

    out
}

fn blake3_xof64_reference(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn blake3_xof64_hex_reference(bytes: &[u8]) -> String {
    hex::encode(blake3_xof64_reference(bytes))
}

fn is_lower_hex_with_len(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn tamper_lower_hex_string(s: &str) -> String {
    let mut bytes = s.as_bytes().to_vec();

    let first = bytes
        .first_mut()
        .expect("test hash string should never be empty");

    *first = if *first == b'0' { b'1' } else { b'0' };

    String::from_utf8(bytes).expect("tampered hex should stay valid UTF-8")
}

fn manual_legacy_merkle_root_hex<T: serde::Serialize>(transactions: &[T]) -> String {
    let mut hasher = blake3::Hasher::new();

    if transactions.is_empty() {
        hasher.update(b"EMPTY_MERKLE_ROOT");
    } else {
        for tx in transactions {
            let bytes = postcard::to_allocvec(tx)
                .expect("bounded test transaction should postcard serialize");
            hasher.update(&bytes);
        }
    }

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    hex::encode(out)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn test_001_compute_bytes_hash_is_64_bytes_deterministic_and_input_sensitive(
        tail in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let input_a = prefixed_vec(0u8, &tail);
        let input_b = prefixed_vec(1u8, &tail);

        let hash_a1 = RemzarHash::compute_bytes_hash(&input_a);
        let hash_a2 = RemzarHash::compute_bytes_hash(&input_a);
        let hash_b = RemzarHash::compute_bytes_hash(&input_b);

        prop_assert_eq!(
            hash_a1.len(),
            64,
            "Remzar byte hash must always be exactly 64 bytes"
        );

        prop_assert_eq!(
            hash_a1,
            hash_a2,
            "same bytes must always produce the same 64-byte hash"
        );

        prop_assert_ne!(
            hash_a1,
            hash_b,
            "different byte input should produce a different 64-byte hash"
        );
    }

    // 002/25
    #[test]
    fn test_002_compute_bytes_hash_hex_is_128_lowercase_hex_and_matches_raw_hash(
        data in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let raw = RemzarHash::compute_bytes_hash(&data);
        let hex_hash = RemzarHash::compute_bytes_hash_hex(&data);

        prop_assert_eq!(
            hex_hash.len(),
            128,
            "64-byte Remzar hash must encode to 128 lowercase hex chars"
        );

        prop_assert!(
            hex_hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "hash hex must be lowercase hexadecimal"
        );

        prop_assert_eq!(
            hex_hash,
            hex::encode(raw),
            "hex helper must encode the same bytes returned by compute_bytes_hash"
        );
    }

    // 003/25
    #[test]
    fn test_003_compute_data_hash_verifies_same_data_and_rejects_changed_data(
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let data_a = prefixed_vec(0u8, &tail);
        let data_b = prefixed_vec(1u8, &tail);

        let hash_a = RemzarHash::compute_data_hash(&data_a)
            .expect("data hash should serialize and hash Vec<u8>");

        prop_assert_eq!(
            hash_a.len(),
            128,
            "data hash must be 128 hex chars"
        );

        prop_assert!(
            RemzarHash::verify_data_hash(&data_a, &hash_a)
                .expect("valid expected hash should verify cleanly"),
            "computed data hash must verify for the original data"
        );

        prop_assert!(
            !RemzarHash::verify_data_hash(&data_b, &hash_a)
                .expect("valid expected hash should verify cleanly"),
            "computed data hash must not verify for changed data"
        );
    }

    // 004/25
    #[test]
    fn test_004_compute_data_hash_batch_matches_individual_hashes_and_verifies(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
    ) {
        let batch_hashes = RemzarHash::compute_data_hash_batch(&items)
            .expect("batch data hashing should succeed for non-empty bounded items");

        let individual_hashes = items
            .iter()
            .map(|item| RemzarHash::compute_data_hash(item).expect("individual hash should succeed"))
            .collect::<Vec<String>>();

        prop_assert_eq!(
            &batch_hashes,
            &individual_hashes,
            "batch hash output must match individual hashing in the same order"
        );

        let verified = RemzarHash::verify_data_hash_batch(&items, &batch_hashes)
            .expect("batch verification should succeed with valid expected hashes");

        prop_assert_eq!(
            verified.len(),
            items.len(),
            "batch verification result length must match item count"
        );

        prop_assert!(
            verified.iter().all(|ok| *ok),
            "all batch hashes must verify against their original items"
        );
    }

    // 005/25
    #[test]
    fn test_005_verify_data_hash_rejects_malformed_expected_hex(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        bad_tail in "[0-9a-f]{0,127}",
    ) {
        let bad_expected = format!("f{bad_tail}");

        prop_assume!(bad_expected.len() != 128);

        prop_assert!(
            RemzarHash::verify_data_hash(&data, &bad_expected).is_err(),
            "verify_data_hash must reject malformed expected hash length"
        );
    }

    // 006/25
    #[test]
    fn test_006_truncated_hash_is_16_hex_chars_deterministic_and_verifiable(
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let data_a = prefixed_vec(0u8, &tail);
        let data_b = prefixed_vec(1u8, &tail);

        let truncated_a1 = RemzarHash::compute_truncated_hash(&data_a)
            .expect("truncated hash should succeed");
        let truncated_a2 = RemzarHash::compute_truncated_hash(&data_a)
            .expect("truncated hash should be deterministic");
        let truncated_b = RemzarHash::compute_truncated_hash(&data_b)
            .expect("truncated hash for changed input should succeed");

        prop_assert_eq!(
            truncated_a1.len(),
            16,
            "truncated hash must be 16 hex chars"
        );

        prop_assert_eq!(
            &truncated_a1,
            &truncated_a2,
            "truncated hash must be deterministic"
        );

        prop_assert!(
            RemzarHash::verify_truncated_hash(&data_a, &truncated_a1)
                .expect("valid truncated hash should verify cleanly"),
            "truncated hash must verify for original data"
        );

        prop_assert!(
            !RemzarHash::verify_truncated_hash(&data_b, &truncated_a1)
                .expect("valid truncated hash should verify cleanly"),
            "truncated hash must not verify for changed data"
        );

        prop_assert_ne!(
            &truncated_a1,
            &truncated_b,
            "different prefixed inputs should produce different truncated hashes"
        );
    }

    // 007/25
    #[test]
    fn test_007_truncated_hash_batch_matches_individual_hashes_and_rejects_length_mismatch(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        extra in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let batch_hashes = RemzarHash::compute_truncated_hash_batch(&items)
            .expect("truncated batch hashing should succeed for non-empty bounded items");

        let individual_hashes = items
            .iter()
            .map(|item| RemzarHash::compute_truncated_hash(item).expect("individual truncated hash should succeed"))
            .collect::<Vec<String>>();

        prop_assert_eq!(
            &batch_hashes,
            &individual_hashes,
            "truncated batch hash output must match individual hashing in the same order"
        );

        let verified = RemzarHash::verify_truncated_hash_batch(&items, &batch_hashes)
            .expect("truncated batch verification should succeed with valid expected hashes");

        prop_assert!(
            verified.iter().all(|ok| *ok),
            "all truncated batch hashes must verify"
        );

        let mut wrong_expected = batch_hashes.clone();
        wrong_expected.push(
            RemzarHash::compute_truncated_hash(&extra)
                .expect("extra truncated hash should succeed")
        );

        prop_assert!(
            RemzarHash::verify_truncated_hash_batch(&items, &wrong_expected).is_err(),
            "truncated batch verification must reject item/expected length mismatch"
        );
    }

    // 008/25
    #[test]
    fn test_008_legacy_merkle_root_helper_is_128_hex_deterministic_and_order_sensitive(
        left_tail in proptest::collection::vec(any::<u8>(), 0..256),
        right_tail in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let left = prefixed_vec(0u8, &left_tail);
        let right = prefixed_vec(1u8, &right_tail);

        let original = vec![left.clone(), right.clone()];
        let reordered = vec![right, left];

        let root_a1 = RemzarHash::compute_merkle_root(&original)
            .expect("legacy Merkle root helper should hash bounded transactions");
        let root_a2 = RemzarHash::compute_merkle_root(&original)
            .expect("legacy Merkle root helper should be deterministic");
        let root_b = RemzarHash::compute_merkle_root(&reordered)
            .expect("legacy Merkle root helper should hash reordered transactions");

        prop_assert_eq!(
            root_a1.len(),
            128,
            "legacy Merkle root helper must return 128 hex chars"
        );

        prop_assert_eq!(
            &root_a1,
            &root_a2,
            "legacy Merkle root helper must be deterministic"
        );

        prop_assert_ne!(
            &root_a1,
            &root_b,
            "legacy Merkle root helper must be order-sensitive"
        );
    }

    // 009/25
    #[test]
    fn test_009_header_hash_bytes_and_hex_are_deterministic_verifiable_and_nonce_sensitive(
        prev_tail in proptest::collection::vec(any::<u8>(), 0..64),
        merkle_tail in proptest::collection::vec(any::<u8>(), 0..64),
        nonce in any::<u64>(),
    ) {
        let prev = array64_from_tail(0x11, &prev_tail);
        let merkle = array64_from_tail(0xAA, &merkle_tail);
        let changed_nonce = nonce.wrapping_add(1);

        let hash_bytes_1 = RemzarHash::compute_header_hash_bytes(&prev, &merkle, nonce);
        let hash_bytes_2 = RemzarHash::compute_header_hash_bytes(&prev, &merkle, nonce);
        let hash_hex = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);
        let changed_hex = RemzarHash::compute_header_hash_hex(&prev, &merkle, changed_nonce);
        let expected_hash_hex = hex::encode(hash_bytes_1);

        prop_assert_eq!(
            hash_bytes_1.len(),
            64,
            "header hash bytes must be exactly 64 bytes"
        );

        prop_assert_eq!(
            hash_bytes_1,
            hash_bytes_2,
            "header hash bytes must be deterministic"
        );

        prop_assert_eq!(
            &hash_hex,
            &expected_hash_hex,
            "header hash hex must encode the same bytes"
        );

        prop_assert!(
            RemzarHash::verify_header_hash(&prev, &merkle, nonce, &hash_hex),
            "header hash verification must accept correct expected hex"
        );

        prop_assert!(
            !RemzarHash::verify_header_hash(&prev, &merkle, changed_nonce, &hash_hex),
            "header hash verification must reject changed nonce"
        );

        prop_assert_ne!(
            &hash_hex,
            &changed_hex,
            "header hash should change when nonce changes"
        );
    }

    // 010/25
    #[test]
    fn test_010_header_struct_hash_is_128_hex_deterministic_and_nonce_sensitive(
        payload in proptest::collection::vec(any::<u8>(), 0..512),
        nonce in any::<u8>(),
    ) {
        let changed_nonce = nonce.wrapping_add(1);

        let hash_a1 = RemzarHash::compute_header_struct_hash_hex(&payload, nonce)
            .expect("header struct hash should succeed for bounded serializable payload");
        let hash_a2 = RemzarHash::compute_header_struct_hash_hex(&payload, nonce)
            .expect("header struct hash should be deterministic");
        let hash_b = RemzarHash::compute_header_struct_hash_hex(&payload, changed_nonce)
            .expect("header struct hash should succeed with changed nonce");

        prop_assert_eq!(
            hash_a1.len(),
            128,
            "header struct hash must return 128 hex chars"
        );

        prop_assert_eq!(
            &hash_a1,
            &hash_a2,
            "header struct hash must be deterministic"
        );

        prop_assert_ne!(
            &hash_a1,
            &hash_b,
            "header struct hash should change when nonce changes"
        );
    }

    // 011/25
    #[test]
    fn test_011_genesis_hash_with_timestamp_is_64_bytes_deterministic_and_timestamp_sensitive(
        ts in any::<u64>(),
    ) {
        let changed_ts = ts.wrapping_add(1);

        let genesis = RemzarHash::compute_genesis_hash();
        let with_ts_1 = RemzarHash::compute_genesis_hash_with_ts(ts);
        let with_ts_2 = RemzarHash::compute_genesis_hash_with_ts(ts);
        let with_changed_ts = RemzarHash::compute_genesis_hash_with_ts(changed_ts);
        let dummy = RemzarHash::compute_dummy_hash();

        prop_assert_eq!(
            genesis.len(),
            64,
            "genesis hash must be exactly 64 bytes"
        );

        prop_assert_eq!(
            with_ts_1.len(),
            64,
            "timestamped genesis hash must be exactly 64 bytes"
        );

        prop_assert_eq!(
            with_ts_1,
            with_ts_2,
            "timestamped genesis hash must be deterministic"
        );

        prop_assert_ne!(
            with_ts_1,
            with_changed_ts,
            "timestamped genesis hash should change when timestamp changes"
        );

        prop_assert_eq!(
            dummy.len(),
            128,
            "dummy hash must be 128 hex chars"
        );

        prop_assert!(
            dummy.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "dummy hash must be lowercase hex"
        );
    }

    // 012/25
    #[test]
    fn test_012_compute_bytes_hash_matches_blake3_xof64_reference(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let actual = RemzarHash::compute_bytes_hash(&data);
        let expected = blake3_xof64_reference(&data);

        prop_assert_eq!(
            actual,
            expected,
            "compute_bytes_hash must be exactly BLAKE3-XOF-64 over the input bytes"
        );

        prop_assert_eq!(
            RemzarHash::compute_bytes_hash_hex(&data),
            hex::encode(expected),
            "compute_bytes_hash_hex must hex-encode the same BLAKE3-XOF-64 digest"
        );
    }

    // 013/25
    #[test]
    fn test_013_compute_data_hash_matches_postcard_serialized_bytes_hash(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let serialized = postcard::to_allocvec(&data)
            .expect("Vec<u8> should postcard serialize");

        let expected = RemzarHash::compute_bytes_hash_hex(&serialized);
        let actual = RemzarHash::compute_data_hash(&data)
            .expect("compute_data_hash should succeed for bounded Vec<u8>");

        prop_assert_eq!(
            actual,
            expected,
            "compute_data_hash must hash the canonical postcard serialization, not raw object memory"
        );
    }

    // 014/25
    #[test]
    fn test_014_verify_data_hash_rejects_non_hex_expected_even_with_correct_length(
        data in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let non_hex_expected = "g".repeat(128);

        prop_assert!(
            RemzarHash::verify_data_hash(&data, &non_hex_expected).is_err(),
            "verify_data_hash must reject non-hex expected strings even when length is 128"
        );
    }

    // 015/25
    #[test]
    fn test_015_compute_data_hash_batch_rejects_empty_input(
        marker in any::<u8>(),
    ) {
        let empty: Vec<Vec<u8>> = Vec::new();

        prop_assert!(
            RemzarHash::compute_data_hash_batch(&empty).is_err(),
            "data hash batch must reject empty input"
        );

        let non_empty = vec![vec![marker]];

        prop_assert!(
            RemzarHash::compute_data_hash_batch(&non_empty).is_ok(),
            "data hash batch must accept non-empty input"
        );
    }

    // 016/25
    #[test]
    fn test_016_verify_data_hash_batch_rejects_item_expected_length_mismatch(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            1..32
        ),
        extra in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut expected = RemzarHash::compute_data_hash_batch(&items)
            .expect("batch hashing should succeed for non-empty items");

        expected.push(
            RemzarHash::compute_data_hash(&extra)
                .expect("extra item hash should compute")
        );

        prop_assert!(
            RemzarHash::verify_data_hash_batch(&items, &expected).is_err(),
            "verify_data_hash_batch must reject items/expected length mismatch"
        );
    }

    // 017/25
    #[test]
    fn test_017_verify_data_hash_batch_detects_single_tampered_expected_hash(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            2..32
        ),
        tamper_seed in any::<usize>(),
    ) {
        let mut expected = RemzarHash::compute_data_hash_batch(&items)
            .expect("batch hashing should succeed");

        let tamper_index = tamper_seed % expected.len();
        expected[tamper_index] = tamper_lower_hex_string(&expected[tamper_index]);

        let verified = RemzarHash::verify_data_hash_batch(&items, &expected)
            .expect("tampered but valid-length valid-hex expected hashes should return bool results");

        prop_assert_eq!(
            verified.len(),
            items.len(),
            "verification result length must match item count"
        );

        prop_assert!(
            !verified[tamper_index],
            "tampered expected hash at selected index must verify false"
        );
    }

    // 018/25
    #[test]
    fn test_018_compute_truncated_hash_is_prefix_of_full_serialized_data_hash(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let full = RemzarHash::compute_data_hash(&data)
            .expect("full data hash should compute");
        let truncated = RemzarHash::compute_truncated_hash(&data)
            .expect("truncated data hash should compute");

        prop_assert_eq!(
            truncated.as_str(),
            &full[..16],
            "truncated hash must be the first 16 hex chars of the full serialized data hash"
        );

        prop_assert!(
            is_lower_hex_with_len(&truncated, 16),
            "truncated hash must be 16 lowercase hex chars"
        );
    }

    // 019/25
    #[test]
    fn test_019_verify_truncated_hash_rejects_malformed_expected_hex(
        data in proptest::collection::vec(any::<u8>(), 0..512),
        short_tail in "[0-9a-f]{0,15}",
    ) {
        let short_expected = format!("f{short_tail}");
        prop_assume!(short_expected.len() != 16);

        let non_hex_expected = "g".repeat(16);

        prop_assert!(
            RemzarHash::verify_truncated_hash(&data, &short_expected).is_err(),
            "verify_truncated_hash must reject wrong expected length"
        );

        prop_assert!(
            RemzarHash::verify_truncated_hash(&data, &non_hex_expected).is_err(),
            "verify_truncated_hash must reject non-hex expected strings even when length is 16"
        );
    }

    // 020/25
    #[test]
    fn test_020_compute_truncated_hash_batch_rejects_empty_input(
        marker in any::<u8>(),
    ) {
        let empty: Vec<Vec<u8>> = Vec::new();

        prop_assert!(
            RemzarHash::compute_truncated_hash_batch(&empty).is_err(),
            "truncated hash batch must reject empty input"
        );

        let non_empty = vec![vec![marker]];

        prop_assert!(
            RemzarHash::compute_truncated_hash_batch(&non_empty).is_ok(),
            "truncated hash batch must accept non-empty input"
        );
    }

    // 021/25
    #[test]
    fn test_021_verify_truncated_hash_batch_detects_single_tampered_expected_hash(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            2..32
        ),
        tamper_seed in any::<usize>(),
    ) {
        let mut expected = RemzarHash::compute_truncated_hash_batch(&items)
            .expect("truncated batch hashing should succeed");

        let tamper_index = tamper_seed % expected.len();
        expected[tamper_index] = tamper_lower_hex_string(&expected[tamper_index]);

        let verified = RemzarHash::verify_truncated_hash_batch(&items, &expected)
            .expect("tampered but valid-length valid-hex truncated hashes should return bool results");

        prop_assert_eq!(
            verified.len(),
            items.len(),
            "truncated verification result length must match item count"
        );

        prop_assert!(
            !verified[tamper_index],
            "tampered truncated hash at selected index must verify false"
        );
    }

    // 022/25
    #[test]
    fn test_022_legacy_merkle_root_empty_input_is_stable_128_lowercase_hex(
        marker in any::<u8>(),
    ) {
        let empty: Vec<Vec<u8>> = Vec::new();

        let root_a = RemzarHash::compute_merkle_root(&empty)
            .expect("empty legacy Merkle root should compute");
        let root_b = RemzarHash::compute_merkle_root(&empty)
            .expect("empty legacy Merkle root should be deterministic");

        prop_assert_eq!(
            &root_a,
            &root_b,
            "empty legacy Merkle root must be deterministic"
        );

        prop_assert!(
            is_lower_hex_with_len(&root_a, 128),
            "empty legacy Merkle root must be 128 lowercase hex chars"
        );

        let non_empty = vec![vec![marker]];
        let non_empty_root = RemzarHash::compute_merkle_root(&non_empty)
            .expect("non-empty legacy Merkle root should compute");

        prop_assert_ne!(
            &root_a,
            &non_empty_root,
            "empty-root domain separator should differ from a one-item Merkle root"
        );
    }

    // 023/25
    #[test]
    fn test_023_legacy_merkle_root_matches_manual_postcard_concatenation_reference(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let actual = RemzarHash::compute_merkle_root(&items)
            .expect("legacy Merkle root should compute for bounded items");
        let expected = manual_legacy_merkle_root_hex(&items);

        prop_assert_eq!(
            actual,
            expected,
            "legacy Merkle root must hash postcard blobs in order using the documented BLAKE3-XOF-64 flow"
        );
    }

    // 024/25
    #[test]
    fn test_024_verify_header_hash_rejects_malformed_expected_hex(
        prev_tail in proptest::collection::vec(any::<u8>(), 0..64),
        merkle_tail in proptest::collection::vec(any::<u8>(), 0..64),
        nonce in any::<u64>(),
        short_tail in "[0-9a-f]{0,127}",
    ) {
        let prev = array64_from_tail(0x71, &prev_tail);
        let merkle = array64_from_tail(0xE3, &merkle_tail);

        let short_expected = format!("a{short_tail}");
        prop_assume!(short_expected.len() != 128);

        let non_hex_expected = "z".repeat(128);

        prop_assert!(
            !RemzarHash::verify_header_hash(&prev, &merkle, nonce, &short_expected),
            "verify_header_hash must return false for wrong-length expected hex"
        );

        prop_assert!(
            !RemzarHash::verify_header_hash(&prev, &merkle, nonce, &non_hex_expected),
            "verify_header_hash must return false for non-hex expected strings"
        );
    }

    // 025/25
    #[test]
    fn test_025_genesis_and_dummy_hashes_match_documented_preimages(
        ts in any::<u64>(),
    ) {
        let zero_prehash = [0u8; 64];

        let expected_genesis = RemzarHash::compute_bytes_hash(&zero_prehash);
        let actual_genesis = RemzarHash::compute_genesis_hash();

        prop_assert_eq!(
            actual_genesis,
            expected_genesis,
            "genesis hash must be BLAKE3-XOF-64 over the 64-byte zero genesis prehash"
        );

        let mut timestamped_preimage = Vec::with_capacity(72);
        timestamped_preimage.extend_from_slice(&zero_prehash);
        timestamped_preimage.extend_from_slice(&ts.to_be_bytes());

        let expected_timestamped = RemzarHash::compute_bytes_hash(&timestamped_preimage);
        let actual_timestamped = RemzarHash::compute_genesis_hash_with_ts(ts);

        prop_assert_eq!(
            actual_timestamped,
            expected_timestamped,
            "timestamped genesis hash must hash zero prehash plus big-endian timestamp"
        );

        prop_assert_eq!(
            RemzarHash::compute_dummy_hash(),
            blake3_xof64_hex_reference(b"remzar_empty_block_mint"),
            "dummy hash must use the documented empty-block mint domain string"
        );
    }
}
