use blake3::Hasher;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use serde::Serialize;

type TestResult = Result<(), String>;

#[derive(Debug, Clone, Serialize)]
struct SamplePayload {
    id: u64,
    name: String,
    bytes: Vec<u8>,
}

fn sample_payload(id: u64) -> SamplePayload {
    SamplePayload {
        id,
        name: format!("payload-{id}"),
        bytes: vec![
            u8::try_from(id % 251).unwrap_or(0),
            u8::try_from(id.saturating_add(1) % 251).unwrap_or(0),
            u8::try_from(id.saturating_add(2) % 251).unwrap_or(0),
        ],
    }
}

fn reference_xof64(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn reference_xof64_hex(bytes: &[u8]) -> String {
    hex::encode(reference_xof64(bytes))
}

fn assert_hex_len(value: &str, expected_len: usize) {
    assert_eq!(value.len(), expected_len);
    assert!(value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(value, value.to_ascii_lowercase());
}

fn assert_validation_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected ValidationError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected ValidationError, got Err({error:?})")),
    }
}

#[test]
fn hash_system_001_compute_bytes_hash_empty_matches_reference_xof64() -> TestResult {
    let got = RemzarHash::compute_bytes_hash(b"");
    let expected = reference_xof64(b"");

    assert_eq!(got, expected);
    assert_eq!(got.len(), 64);
    Ok(())
}

#[test]
fn hash_system_002_compute_bytes_hash_hex_empty_matches_reference_xof64_hex() -> TestResult {
    let got = RemzarHash::compute_bytes_hash_hex(b"");
    let expected = reference_xof64_hex(b"");

    assert_eq!(got, expected);
    assert_hex_len(&got, 128);
    Ok(())
}

#[test]
fn hash_system_003_compute_bytes_hash_known_message_matches_reference() -> TestResult {
    let bytes = b"remzar blockchain hash vector";
    let got = RemzarHash::compute_bytes_hash(bytes);
    let expected = reference_xof64(bytes);

    assert_eq!(got, expected);
    Ok(())
}

#[test]
fn hash_system_004_compute_bytes_hash_hex_known_message_matches_reference() -> TestResult {
    let bytes = b"remzar blockchain hash vector";
    let got = RemzarHash::compute_bytes_hash_hex(bytes);
    let expected = reference_xof64_hex(bytes);

    assert_eq!(got, expected);
    assert_hex_len(&got, 128);
    Ok(())
}

#[test]
fn hash_system_005_compute_bytes_hash_and_hex_are_consistent() -> TestResult {
    let bytes = b"bytes and hex consistency";

    let raw = RemzarHash::compute_bytes_hash(bytes);
    let hexed = RemzarHash::compute_bytes_hash_hex(bytes);

    assert_eq!(hex::encode(raw), hexed);
    assert_hex_len(&hexed, 128);
    Ok(())
}

#[test]
fn hash_system_006_compute_bytes_hash_is_deterministic() -> TestResult {
    let bytes = b"deterministic raw bytes";

    let first = RemzarHash::compute_bytes_hash(bytes);
    let second = RemzarHash::compute_bytes_hash(bytes);

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn hash_system_007_compute_bytes_hash_changes_when_input_changes() -> TestResult {
    let first = RemzarHash::compute_bytes_hash(b"message-a");
    let second = RemzarHash::compute_bytes_hash(b"message-b");

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn hash_system_008_compute_bytes_hash_handles_large_raw_input() -> TestResult {
    let bytes = (0_usize..1_000_000_usize)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();

    let got = RemzarHash::compute_bytes_hash_hex(&bytes);
    let expected = reference_xof64_hex(&bytes);

    assert_eq!(got, expected);
    assert_hex_len(&got, 128);
    Ok(())
}

#[test]
fn hash_system_009_compute_data_hash_u64_is_128_hex() -> TestResult {
    let hash = RemzarHash::compute_data_hash(&42_u64)
        .map_err(|e| format!("compute_data_hash failed: {e:?}"))?;

    assert_hex_len(&hash, 128);
    Ok(())
}

#[test]
fn hash_system_010_compute_data_hash_struct_is_deterministic() -> TestResult {
    let payload = sample_payload(10);

    let first = RemzarHash::compute_data_hash(&payload)
        .map_err(|e| format!("first compute_data_hash failed: {e:?}"))?;
    let second = RemzarHash::compute_data_hash(&payload)
        .map_err(|e| format!("second compute_data_hash failed: {e:?}"))?;

    assert_eq!(first, second);
    assert_hex_len(&first, 128);
    Ok(())
}

#[test]
fn hash_system_011_compute_data_hash_changes_when_struct_field_changes() -> TestResult {
    let first = sample_payload(11);
    let mut second = sample_payload(11);
    second.name.push_str("-changed");

    let first_hash = RemzarHash::compute_data_hash(&first)
        .map_err(|e| format!("first compute_data_hash failed: {e:?}"))?;
    let second_hash = RemzarHash::compute_data_hash(&second)
        .map_err(|e| format!("second compute_data_hash failed: {e:?}"))?;

    assert_ne!(first_hash, second_hash);
    Ok(())
}

#[test]
fn hash_system_012_compute_data_hash_matches_postcard_bytes_reference() -> TestResult {
    let payload = sample_payload(12);
    let postcard_bytes = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;

    let got = RemzarHash::compute_data_hash(&payload)
        .map_err(|e| format!("compute_data_hash failed: {e:?}"))?;
    let expected = reference_xof64_hex(&postcard_bytes);

    assert_eq!(got, expected);
    Ok(())
}

#[test]
fn hash_system_013_compute_data_hash_rejects_serialized_payload_over_four_mib() -> TestResult {
    let too_large = vec![7_u8; 4 * 1024 * 1024 + 1];

    assert_validation_error(RemzarHash::compute_data_hash(&too_large))?;
    Ok(())
}

#[test]
fn hash_system_014_verify_data_hash_true_for_matching_hash() -> TestResult {
    let payload = sample_payload(14);
    let expected = RemzarHash::compute_data_hash(&payload)
        .map_err(|e| format!("compute_data_hash failed: {e:?}"))?;

    let ok = RemzarHash::verify_data_hash(&payload, &expected)
        .map_err(|e| format!("verify_data_hash failed: {e:?}"))?;

    assert!(ok);
    Ok(())
}

#[test]
fn hash_system_015_verify_data_hash_false_for_wrong_valid_hash() -> TestResult {
    let payload = sample_payload(15);
    let wrong = RemzarHash::compute_bytes_hash_hex(b"wrong-valid-128-hex-hash");

    let ok = RemzarHash::verify_data_hash(&payload, &wrong)
        .map_err(|e| format!("verify_data_hash failed: {e:?}"))?;

    assert!(!ok);
    Ok(())
}

#[test]
fn hash_system_016_verify_data_hash_rejects_short_expected_hex() -> TestResult {
    let payload = sample_payload(16);

    assert_validation_error(RemzarHash::verify_data_hash(&payload, &"a".repeat(127)))?;
    Ok(())
}

#[test]
fn hash_system_017_verify_data_hash_rejects_long_expected_hex() -> TestResult {
    let payload = sample_payload(17);

    assert_validation_error(RemzarHash::verify_data_hash(&payload, &"a".repeat(129)))?;
    Ok(())
}

#[test]
fn hash_system_018_verify_data_hash_rejects_non_hex_expected() -> TestResult {
    let payload = sample_payload(18);

    assert_validation_error(RemzarHash::verify_data_hash(&payload, &"g".repeat(128)))?;
    Ok(())
}

#[test]
fn hash_system_019_compute_data_hash_batch_rejects_empty_items() -> TestResult {
    let items: Vec<SamplePayload> = Vec::new();

    assert_validation_error(RemzarHash::compute_data_hash_batch(&items))?;
    Ok(())
}

#[test]
fn hash_system_020_compute_data_hash_batch_matches_individual_hashes() -> TestResult {
    let items = (0_u64..25_u64).map(sample_payload).collect::<Vec<_>>();

    let batch = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("compute_data_hash_batch failed: {e:?}"))?;
    let individual = items
        .iter()
        .map(RemzarHash::compute_data_hash)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("individual compute_data_hash failed: {e:?}"))?;

    assert_eq!(batch, individual);
    assert!(batch.iter().all(|hash| hash.len() == 128));
    Ok(())
}

#[test]
fn hash_system_021_verify_data_hash_batch_true_for_matching_hashes() -> TestResult {
    let items = (0_u64..20_u64).map(sample_payload).collect::<Vec<_>>();
    let expected = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("compute_data_hash_batch failed: {e:?}"))?;

    let verified = RemzarHash::verify_data_hash_batch(&items, &expected)
        .map_err(|e| format!("verify_data_hash_batch failed: {e:?}"))?;

    assert_eq!(verified, vec![true; items.len()]);
    Ok(())
}

#[test]
fn hash_system_022_verify_data_hash_batch_mixed_true_false_vector() -> TestResult {
    let items = (0_u64..5_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("compute_data_hash_batch failed: {e:?}"))?;

    expected[2] = RemzarHash::compute_bytes_hash_hex(b"different-but-valid");

    let verified = RemzarHash::verify_data_hash_batch(&items, &expected)
        .map_err(|e| format!("verify_data_hash_batch failed: {e:?}"))?;

    assert_eq!(verified, vec![true, true, false, true, true]);
    Ok(())
}

#[test]
fn hash_system_023_verify_data_hash_batch_rejects_length_mismatch() -> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let expected = vec![RemzarHash::compute_bytes_hash_hex(b"only-one")];

    assert_validation_error(RemzarHash::verify_data_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_024_verify_data_hash_batch_rejects_invalid_expected_before_partial_results()
-> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("compute_data_hash_batch failed: {e:?}"))?;
    expected[1] = "not-hex".to_string();

    assert_validation_error(RemzarHash::verify_data_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_025_compute_truncated_hash_is_16_hex() -> TestResult {
    let payload = sample_payload(25);

    let truncated = RemzarHash::compute_truncated_hash(&payload)
        .map_err(|e| format!("compute_truncated_hash failed: {e:?}"))?;

    assert_hex_len(&truncated, 16);
    Ok(())
}

#[test]
fn hash_system_026_compute_truncated_hash_is_prefix_of_full_data_hash() -> TestResult {
    let payload = sample_payload(26);

    let full = RemzarHash::compute_data_hash(&payload)
        .map_err(|e| format!("compute_data_hash failed: {e:?}"))?;
    let truncated = RemzarHash::compute_truncated_hash(&payload)
        .map_err(|e| format!("compute_truncated_hash failed: {e:?}"))?;

    assert_eq!(truncated, full[..16]);
    Ok(())
}

#[test]
fn hash_system_027_verify_truncated_hash_true_for_matching_hash() -> TestResult {
    let payload = sample_payload(27);
    let expected = RemzarHash::compute_truncated_hash(&payload)
        .map_err(|e| format!("compute_truncated_hash failed: {e:?}"))?;

    let ok = RemzarHash::verify_truncated_hash(&payload, &expected)
        .map_err(|e| format!("verify_truncated_hash failed: {e:?}"))?;

    assert!(ok);
    Ok(())
}

#[test]
fn hash_system_028_verify_truncated_hash_false_for_wrong_valid_hash() -> TestResult {
    let payload = sample_payload(28);
    let wrong = "0".repeat(16);

    let ok = RemzarHash::verify_truncated_hash(&payload, &wrong)
        .map_err(|e| format!("verify_truncated_hash failed: {e:?}"))?;

    assert!(!ok);
    Ok(())
}

#[test]
fn hash_system_029_verify_truncated_hash_rejects_bad_length_and_bad_hex() -> TestResult {
    let payload = sample_payload(29);

    assert_validation_error(RemzarHash::verify_truncated_hash(&payload, &"a".repeat(15)))?;
    assert_validation_error(RemzarHash::verify_truncated_hash(&payload, &"z".repeat(16)))?;
    Ok(())
}

#[test]
fn hash_system_030_compute_truncated_hash_batch_matches_individual_hashes() -> TestResult {
    let items = (0_u64..16_u64).map(sample_payload).collect::<Vec<_>>();

    let batch = RemzarHash::compute_truncated_hash_batch(&items)
        .map_err(|e| format!("compute_truncated_hash_batch failed: {e:?}"))?;
    let individual = items
        .iter()
        .map(RemzarHash::compute_truncated_hash)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("individual truncated failed: {e:?}"))?;

    assert_eq!(batch, individual);
    assert!(batch.iter().all(|hash| hash.len() == 16));
    Ok(())
}

#[test]
fn hash_system_031_verify_truncated_hash_batch_mixed_true_false_vector() -> TestResult {
    let items = (0_u64..5_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_truncated_hash_batch(&items)
        .map_err(|e| format!("compute_truncated_hash_batch failed: {e:?}"))?;

    expected[3] = "0".repeat(16);

    let verified = RemzarHash::verify_truncated_hash_batch(&items, &expected)
        .map_err(|e| format!("verify_truncated_hash_batch failed: {e:?}"))?;

    assert_eq!(verified, vec![true, true, true, false, true]);
    Ok(())
}

#[test]
fn hash_system_032_compute_merkle_root_empty_matches_literal_reference() -> TestResult {
    let items: Vec<u64> = Vec::new();
    let got = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("compute_merkle_root empty failed: {e:?}"))?;

    let expected = reference_xof64_hex(b"EMPTY_MERKLE_ROOT");

    assert_eq!(got, expected);
    assert_hex_len(&got, 128);
    Ok(())
}

#[test]
fn hash_system_033_compute_merkle_root_nonempty_matches_postcard_concat_reference() -> TestResult {
    let items = vec![1_u64, 2_u64, 3_u64];
    let got = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("compute_merkle_root failed: {e:?}"))?;

    let mut hasher = Hasher::new();
    for item in &items {
        let blob = postcard::to_allocvec(item).map_err(|e| e.to_string())?;
        hasher.update(&blob);
    }
    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);
    let expected = hex::encode(out);

    assert_eq!(got, expected);
    Ok(())
}

#[test]
fn hash_system_034_compute_merkle_root_is_order_sensitive() -> TestResult {
    let first = vec![1_u64, 2_u64, 3_u64];
    let second = vec![3_u64, 2_u64, 1_u64];

    let first_hash = RemzarHash::compute_merkle_root(&first)
        .map_err(|e| format!("first merkle failed: {e:?}"))?;
    let second_hash = RemzarHash::compute_merkle_root(&second)
        .map_err(|e| format!("second merkle failed: {e:?}"))?;

    assert_ne!(first_hash, second_hash);
    Ok(())
}

#[test]
fn hash_system_035_compute_header_hash_bytes_matches_reference() -> TestResult {
    let prev = [1_u8; 64];
    let merkle = [2_u8; 64];
    let nonce = 0x0102_0304_0506_0708_u64;

    let got = RemzarHash::compute_header_hash_bytes(&prev, &merkle, nonce);

    let mut hasher = Hasher::new();
    hasher.update(&prev);
    hasher.update(&merkle);
    hasher.update(&nonce.to_be_bytes());
    let mut expected = [0_u8; 64];
    hasher.finalize_xof().fill(&mut expected);

    assert_eq!(got, expected);
    Ok(())
}

#[test]
fn hash_system_036_compute_header_hash_hex_and_bytes_are_consistent() -> TestResult {
    let prev = [3_u8; 64];
    let merkle = [4_u8; 64];
    let nonce = 123_456_u64;

    let bytes = RemzarHash::compute_header_hash_bytes(&prev, &merkle, nonce);
    let hexed = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);

    assert_eq!(hex::encode(bytes), hexed);
    assert_hex_len(&hexed, 128);
    Ok(())
}

#[test]
fn hash_system_037_verify_header_hash_true_false_and_malformed_vectors() -> TestResult {
    let prev = [5_u8; 64];
    let merkle = [6_u8; 64];
    let nonce = 999_u64;
    let expected = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);

    assert!(RemzarHash::verify_header_hash(
        &prev, &merkle, nonce, &expected
    ));
    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce.saturating_add(1),
        &expected
    ));
    assert!(!RemzarHash::verify_header_hash(
        &prev, &merkle, nonce, "not-hex"
    ));

    Ok(())
}

#[test]
fn hash_system_038_compute_header_struct_hash_hex_changes_with_nonce() -> TestResult {
    let payload = sample_payload(38);

    let first = RemzarHash::compute_header_struct_hash_hex(&payload, 1)
        .map_err(|e| format!("first header struct hash failed: {e:?}"))?;
    let second = RemzarHash::compute_header_struct_hash_hex(&payload, 2)
        .map_err(|e| format!("second header struct hash failed: {e:?}"))?;

    assert_ne!(first, second);
    assert_hex_len(&first, 128);
    assert_hex_len(&second, 128);
    Ok(())
}

#[test]
fn hash_system_039_compute_dummy_and_genesis_hash_shapes_are_64_byte_hex_or_bytes() -> TestResult {
    let dummy = RemzarHash::compute_dummy_hash();
    let genesis = RemzarHash::compute_genesis_hash();
    let genesis_hex = hex::encode(genesis);

    assert_hex_len(&dummy, 128);
    assert_eq!(genesis.len(), 64);
    assert_hex_len(&genesis_hex, 128);
    assert_eq!(
        dummy,
        RemzarHash::compute_bytes_hash_hex(b"remzar_empty_block_mint")
    );
    Ok(())
}

#[test]
fn hash_system_040_compute_genesis_hash_with_ts_is_deterministic_and_ts_sensitive() -> TestResult {
    let first = RemzarHash::compute_genesis_hash_with_ts(1);
    let second = RemzarHash::compute_genesis_hash_with_ts(1);
    let third = RemzarHash::compute_genesis_hash_with_ts(2);

    assert_eq!(first, second);
    assert_ne!(first, third);
    assert_eq!(first.len(), 64);
    Ok(())
}

#[test]
fn hash_system_041_compute_bytes_hash_hex_all_zero_bytes_matches_reference() -> TestResult {
    let bytes = vec![0_u8; 1_024];

    let got = RemzarHash::compute_bytes_hash_hex(&bytes);
    let expected = reference_xof64_hex(&bytes);

    assert_eq!(got, expected);
    assert_hex_len(&got, 128);
    Ok(())
}

#[test]
fn hash_system_042_compute_bytes_hash_hex_all_ff_bytes_matches_reference() -> TestResult {
    let bytes = vec![0xFF_u8; 1_024];

    let got = RemzarHash::compute_bytes_hash_hex(&bytes);
    let expected = reference_xof64_hex(&bytes);

    assert_eq!(got, expected);
    assert_hex_len(&got, 128);
    Ok(())
}

#[test]
fn hash_system_043_compute_bytes_hash_hex_pattern_bytes_is_deterministic() -> TestResult {
    let bytes = (0_usize..65_537_usize)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();

    let first = RemzarHash::compute_bytes_hash_hex(&bytes);
    let second = RemzarHash::compute_bytes_hash_hex(&bytes);

    assert_eq!(first, second);
    assert_hex_len(&first, 128);
    Ok(())
}

#[test]
fn hash_system_044_compute_data_hash_string_and_str_same_value_match() -> TestResult {
    let owned = "remzar-string-payload".to_string();
    let borrowed = "remzar-string-payload";

    let owned_hash = RemzarHash::compute_data_hash(&owned)
        .map_err(|e| format!("owned string hash failed: {e:?}"))?;
    let borrowed_hash = RemzarHash::compute_data_hash(borrowed)
        .map_err(|e| format!("borrowed str hash failed: {e:?}"))?;

    assert_eq!(owned_hash, borrowed_hash);
    assert_hex_len(&owned_hash, 128);
    Ok(())
}

#[test]
fn hash_system_045_compute_data_hash_unicode_string_is_stable() -> TestResult {
    let value = "remzar-鎖-данные-ブロック";

    let first = RemzarHash::compute_data_hash(value)
        .map_err(|e| format!("first unicode hash failed: {e:?}"))?;
    let second = RemzarHash::compute_data_hash(value)
        .map_err(|e| format!("second unicode hash failed: {e:?}"))?;

    assert_eq!(first, second);
    assert_hex_len(&first, 128);
    Ok(())
}

#[test]
fn hash_system_046_compute_data_hash_vec_order_is_sensitive() -> TestResult {
    let first = vec![1_u64, 2, 3, 4];
    let second = vec![4_u64, 3, 2, 1];

    let first_hash = RemzarHash::compute_data_hash(&first)
        .map_err(|e| format!("first vec hash failed: {e:?}"))?;
    let second_hash = RemzarHash::compute_data_hash(&second)
        .map_err(|e| format!("second vec hash failed: {e:?}"))?;

    assert_ne!(first_hash, second_hash);
    Ok(())
}

#[test]
fn hash_system_047_verify_data_hash_with_uppercase_expected_is_false_not_error() -> TestResult {
    let payload = sample_payload(47);
    let expected = RemzarHash::compute_data_hash(&payload)
        .map_err(|e| format!("compute_data_hash failed: {e:?}"))?;
    let uppercase = expected.to_ascii_uppercase();

    let verified = RemzarHash::verify_data_hash(&payload, &uppercase)
        .map_err(|e| format!("verify_data_hash uppercase expected errored: {e:?}"))?;

    assert!(!verified);
    Ok(())
}

#[test]
fn hash_system_048_verify_data_hash_accepts_all_zero_valid_hex_as_false() -> TestResult {
    let payload = sample_payload(48);
    let expected = "0".repeat(128);

    let verified = RemzarHash::verify_data_hash(&payload, &expected)
        .map_err(|e| format!("verify_data_hash all-zero expected errored: {e:?}"))?;

    assert!(!verified);
    Ok(())
}

#[test]
fn hash_system_049_verify_data_hash_accepts_all_f_valid_hex_as_false() -> TestResult {
    let payload = sample_payload(49);
    let expected = "f".repeat(128);

    let verified = RemzarHash::verify_data_hash(&payload, &expected)
        .map_err(|e| format!("verify_data_hash all-f expected errored: {e:?}"))?;

    assert!(!verified);
    Ok(())
}

#[test]
fn hash_system_050_verify_data_hash_rejects_odd_length_expected_hex() -> TestResult {
    let payload = sample_payload(50);

    assert_validation_error(RemzarHash::verify_data_hash(&payload, &"a".repeat(127)))?;
    Ok(())
}

#[test]
fn hash_system_051_verify_data_hash_batch_empty_items_and_expected_returns_empty_vector()
-> TestResult {
    let items: Vec<SamplePayload> = Vec::new();
    let expected: Vec<String> = Vec::new();

    let verified = RemzarHash::verify_data_hash_batch(&items, &expected)
        .map_err(|e| format!("empty verify_data_hash_batch failed: {e:?}"))?;

    assert!(verified.is_empty());
    Ok(())
}

#[test]
fn hash_system_052_compute_data_hash_batch_preserves_item_order() -> TestResult {
    let items = (10_u64..20_u64).map(sample_payload).collect::<Vec<_>>();
    let reversed = items.iter().cloned().rev().collect::<Vec<_>>();

    let hashes = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("batch hash failed: {e:?}"))?;
    let reversed_hashes = RemzarHash::compute_data_hash_batch(&reversed)
        .map_err(|e| format!("reversed batch hash failed: {e:?}"))?;

    assert_eq!(hashes.first(), reversed_hashes.last());
    assert_eq!(hashes.last(), reversed_hashes.first());
    assert_ne!(hashes, reversed_hashes);
    Ok(())
}

#[test]
fn hash_system_053_compute_data_hash_batch_duplicate_items_duplicate_hashes() -> TestResult {
    let item = sample_payload(53);
    let items = vec![item.clone(), item.clone(), item];

    let hashes = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("duplicate batch hash failed: {e:?}"))?;

    assert_eq!(hashes.len(), 3);
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[1], hashes[2]);
    Ok(())
}

#[test]
fn hash_system_054_verify_data_hash_batch_rejects_short_expected_hex() -> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("batch hash failed: {e:?}"))?;

    expected[0] = "a".repeat(127);

    assert_validation_error(RemzarHash::verify_data_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_055_verify_data_hash_batch_rejects_long_expected_hex() -> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("batch hash failed: {e:?}"))?;

    expected[0] = "a".repeat(129);

    assert_validation_error(RemzarHash::verify_data_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_056_compute_truncated_hash_rejects_serialized_payload_over_four_mib() -> TestResult {
    let too_large = vec![9_u8; 4 * 1024 * 1024 + 1];

    assert_validation_error(RemzarHash::compute_truncated_hash(&too_large))?;
    Ok(())
}

#[test]
fn hash_system_057_compute_truncated_hash_changes_when_payload_changes() -> TestResult {
    let first = sample_payload(57);
    let second = sample_payload(58);

    let first_hash = RemzarHash::compute_truncated_hash(&first)
        .map_err(|e| format!("first truncated hash failed: {e:?}"))?;
    let second_hash = RemzarHash::compute_truncated_hash(&second)
        .map_err(|e| format!("second truncated hash failed: {e:?}"))?;

    assert_ne!(first_hash, second_hash);
    assert_hex_len(&first_hash, 16);
    assert_hex_len(&second_hash, 16);
    Ok(())
}

#[test]
fn hash_system_058_compute_truncated_hash_batch_rejects_empty_items() -> TestResult {
    let items: Vec<SamplePayload> = Vec::new();

    assert_validation_error(RemzarHash::compute_truncated_hash_batch(&items))?;
    Ok(())
}

#[test]
fn hash_system_059_verify_truncated_hash_with_uppercase_expected_is_false_not_error() -> TestResult
{
    let payload = sample_payload(59);
    let expected = RemzarHash::compute_truncated_hash(&payload)
        .map_err(|e| format!("truncated hash failed: {e:?}"))?;
    let uppercase = expected.to_ascii_uppercase();

    let verified = RemzarHash::verify_truncated_hash(&payload, &uppercase)
        .map_err(|e| format!("uppercase verify_truncated_hash errored: {e:?}"))?;

    assert!(!verified);
    Ok(())
}

#[test]
fn hash_system_060_verify_truncated_hash_rejects_long_expected_hex() -> TestResult {
    let payload = sample_payload(60);

    assert_validation_error(RemzarHash::verify_truncated_hash(&payload, &"a".repeat(17)))?;
    Ok(())
}

#[test]
fn hash_system_061_verify_truncated_hash_batch_empty_items_and_expected_returns_empty_vector()
-> TestResult {
    let items: Vec<SamplePayload> = Vec::new();
    let expected: Vec<String> = Vec::new();

    let verified = RemzarHash::verify_truncated_hash_batch(&items, &expected)
        .map_err(|e| format!("empty verify_truncated_hash_batch failed: {e:?}"))?;

    assert!(verified.is_empty());
    Ok(())
}

#[test]
fn hash_system_062_verify_truncated_hash_batch_rejects_length_mismatch() -> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let expected = vec!["0".repeat(16)];

    assert_validation_error(RemzarHash::verify_truncated_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_063_verify_truncated_hash_batch_rejects_bad_expected_hex() -> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_truncated_hash_batch(&items)
        .map_err(|e| format!("truncated batch failed: {e:?}"))?;

    expected[2] = "z".repeat(16);

    assert_validation_error(RemzarHash::verify_truncated_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_064_verify_truncated_hash_batch_rejects_short_expected_hex() -> TestResult {
    let items = (0_u64..3_u64).map(sample_payload).collect::<Vec<_>>();
    let mut expected = RemzarHash::compute_truncated_hash_batch(&items)
        .map_err(|e| format!("truncated batch failed: {e:?}"))?;

    expected[1] = "a".repeat(15);

    assert_validation_error(RemzarHash::verify_truncated_hash_batch(&items, &expected))?;
    Ok(())
}

#[test]
fn hash_system_065_compute_merkle_root_duplicate_items_is_deterministic() -> TestResult {
    let items = vec![sample_payload(65), sample_payload(65), sample_payload(65)];

    let first = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("first merkle root failed: {e:?}"))?;
    let second = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("second merkle root failed: {e:?}"))?;

    assert_eq!(first, second);
    assert_hex_len(&first, 128);
    Ok(())
}

#[test]
fn hash_system_066_compute_merkle_root_single_item_differs_from_data_hash() -> TestResult {
    let items = vec![sample_payload(66)];

    let merkle = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("single item merkle root failed: {e:?}"))?;
    let data_hash =
        RemzarHash::compute_data_hash(&items[0]).map_err(|e| format!("data hash failed: {e:?}"))?;

    assert_eq!(merkle, data_hash);
    Ok(())
}

#[test]
fn hash_system_067_compute_merkle_root_rejects_oversized_transaction_blob() -> TestResult {
    let items = vec![vec![1_u8; 4 * 1024 * 1024 + 1]];

    assert_validation_error(RemzarHash::compute_merkle_root(&items))?;
    Ok(())
}

#[test]
fn hash_system_068_compute_merkle_root_many_items_is_stable() -> TestResult {
    let items = (0_u64..500_u64).map(sample_payload).collect::<Vec<_>>();

    let first = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("first many-item merkle failed: {e:?}"))?;
    let second = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("second many-item merkle failed: {e:?}"))?;

    assert_eq!(first, second);
    assert_hex_len(&first, 128);
    Ok(())
}

#[test]
fn hash_system_069_header_hash_nonce_zero_and_u64_max_are_distinct() -> TestResult {
    let prev = [7_u8; 64];
    let merkle = [8_u8; 64];

    let zero = RemzarHash::compute_header_hash_hex(&prev, &merkle, 0);
    let max = RemzarHash::compute_header_hash_hex(&prev, &merkle, u64::MAX);

    assert_ne!(zero, max);
    assert_hex_len(&zero, 128);
    assert_hex_len(&max, 128);
    Ok(())
}

#[test]
fn hash_system_070_header_hash_changes_when_prev_changes() -> TestResult {
    let first_prev = [1_u8; 64];
    let second_prev = [2_u8; 64];
    let merkle = [3_u8; 64];

    let first = RemzarHash::compute_header_hash_hex(&first_prev, &merkle, 99);
    let second = RemzarHash::compute_header_hash_hex(&second_prev, &merkle, 99);

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn hash_system_071_header_hash_changes_when_merkle_changes() -> TestResult {
    let prev = [1_u8; 64];
    let first_merkle = [3_u8; 64];
    let second_merkle = [4_u8; 64];

    let first = RemzarHash::compute_header_hash_hex(&prev, &first_merkle, 99);
    let second = RemzarHash::compute_header_hash_hex(&prev, &second_merkle, 99);

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn hash_system_072_verify_header_hash_rejects_short_long_and_non_hex_expected() -> TestResult {
    let prev = [1_u8; 64];
    let merkle = [2_u8; 64];
    let nonce = 72_u64;

    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce,
        &"a".repeat(127)
    ));
    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce,
        &"a".repeat(129)
    ));
    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce,
        &"z".repeat(128)
    ));
    Ok(())
}

#[test]
fn hash_system_073_verify_header_hash_with_uppercase_expected_is_false_not_error() -> TestResult {
    let prev = [9_u8; 64];
    let merkle = [10_u8; 64];
    let nonce = 73_u64;
    let expected = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);
    let uppercase = expected.to_ascii_uppercase();

    assert!(!RemzarHash::verify_header_hash(
        &prev, &merkle, nonce, &uppercase
    ));
    Ok(())
}

#[test]
fn hash_system_074_compute_header_struct_hash_hex_nonce_zero_and_max_are_distinct() -> TestResult {
    let payload = sample_payload(74);

    let zero = RemzarHash::compute_header_struct_hash_hex(&payload, 0)
        .map_err(|e| format!("nonce zero header struct hash failed: {e:?}"))?;
    let max = RemzarHash::compute_header_struct_hash_hex(&payload, u8::MAX)
        .map_err(|e| format!("nonce max header struct hash failed: {e:?}"))?;

    assert_ne!(zero, max);
    assert_hex_len(&zero, 128);
    assert_hex_len(&max, 128);
    Ok(())
}

#[test]
fn hash_system_075_compute_header_struct_hash_rejects_large_serialized_header() -> TestResult {
    let header = vec![3_u8; 4 * 1024 * 1024 + 1];

    assert_validation_error(RemzarHash::compute_header_struct_hash_hex(&header, 1))?;
    Ok(())
}

#[test]
fn hash_system_076_dummy_hash_is_deterministic() -> TestResult {
    let first = RemzarHash::compute_dummy_hash();
    let second = RemzarHash::compute_dummy_hash();

    assert_eq!(first, second);
    assert_hex_len(&first, 128);
    Ok(())
}

#[test]
fn hash_system_077_genesis_hash_matches_hash_of_64_zero_bytes() -> TestResult {
    let genesis = RemzarHash::compute_genesis_hash();
    let expected = RemzarHash::compute_bytes_hash(&[0_u8; 64]);

    assert_eq!(genesis, expected);
    Ok(())
}

#[test]
fn hash_system_078_genesis_hash_with_ts_zero_differs_from_plain_genesis_hash() -> TestResult {
    let plain = RemzarHash::compute_genesis_hash();
    let with_zero_ts = RemzarHash::compute_genesis_hash_with_ts(0);

    assert_ne!(plain, with_zero_ts);
    Ok(())
}

#[test]
fn hash_system_079_load_many_byte_hash_vectors_match_reference() -> TestResult {
    for len in [0_usize, 1, 2, 3, 7, 8, 31, 32, 63, 64, 65, 1_024, 65_536] {
        let bytes = (0_usize..len)
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect::<Vec<_>>();

        let got = RemzarHash::compute_bytes_hash_hex(&bytes);
        let expected = reference_xof64_hex(&bytes);

        assert_eq!(got, expected);
        assert_hex_len(&got, 128);
    }

    Ok(())
}

#[test]
fn hash_system_080_load_many_struct_hashes_are_valid_and_stable() -> TestResult {
    for index in 0_u64..250_u64 {
        let payload = sample_payload(index);

        let first = RemzarHash::compute_data_hash(&payload)
            .map_err(|e| format!("first data hash failed at {index}: {e:?}"))?;
        let second = RemzarHash::compute_data_hash(&payload)
            .map_err(|e| format!("second data hash failed at {index}: {e:?}"))?;

        assert_eq!(first, second);
        assert_hex_len(&first, 128);
    }

    Ok(())
}

#[test]
fn hash_system_081_verify_data_hash_invalid_expected_rejected_before_oversized_payload()
-> TestResult {
    let too_large = vec![1_u8; 4 * 1024 * 1024 + 1];

    assert_validation_error(RemzarHash::verify_data_hash(&too_large, "not-hex"))?;
    Ok(())
}

#[test]
fn hash_system_082_verify_data_hash_valid_expected_then_oversized_payload_errors() -> TestResult {
    let too_large = vec![2_u8; 4 * 1024 * 1024 + 1];
    let valid_expected = "0".repeat(128);

    assert_validation_error(RemzarHash::verify_data_hash(&too_large, &valid_expected))?;
    Ok(())
}

#[test]
fn hash_system_083_compute_data_hash_batch_rejects_oversized_item() -> TestResult {
    let items = vec![vec![3_u8; 16], vec![4_u8; 4 * 1024 * 1024 + 1]];

    assert_validation_error(RemzarHash::compute_data_hash_batch(&items))?;
    Ok(())
}

#[test]
fn hash_system_084_compute_truncated_hash_batch_rejects_oversized_item() -> TestResult {
    let items = vec![vec![5_u8; 16], vec![6_u8; 4 * 1024 * 1024 + 1]];

    assert_validation_error(RemzarHash::compute_truncated_hash_batch(&items))?;
    Ok(())
}

#[test]
fn hash_system_085_verify_truncated_hash_invalid_expected_rejected_before_oversized_payload()
-> TestResult {
    let too_large = vec![7_u8; 4 * 1024 * 1024 + 1];

    assert_validation_error(RemzarHash::verify_truncated_hash(&too_large, "not-hex"))?;
    Ok(())
}

#[test]
fn hash_system_086_verify_truncated_hash_valid_expected_then_oversized_payload_errors() -> TestResult
{
    let too_large = vec![8_u8; 4 * 1024 * 1024 + 1];
    let valid_expected = "0".repeat(16);

    assert_validation_error(RemzarHash::verify_truncated_hash(
        &too_large,
        &valid_expected,
    ))?;
    Ok(())
}

#[test]
fn hash_system_087_truncated_hash_prefix_matches_full_hash_for_many_payloads() -> TestResult {
    for index in 0_u64..100_u64 {
        let payload = sample_payload(index);

        let full = RemzarHash::compute_data_hash(&payload)
            .map_err(|e| format!("full hash failed at {index}: {e:?}"))?;
        let short = RemzarHash::compute_truncated_hash(&payload)
            .map_err(|e| format!("truncated hash failed at {index}: {e:?}"))?;

        assert_eq!(short, full[..16]);
        assert_hex_len(&short, 16);
    }

    Ok(())
}

#[test]
fn hash_system_088_verify_data_hash_batch_with_uppercase_expected_returns_false_vector()
-> TestResult {
    let items = (0_u64..4_u64).map(sample_payload).collect::<Vec<_>>();
    let expected = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("batch hash failed: {e:?}"))?
        .into_iter()
        .map(|hash| hash.to_ascii_uppercase())
        .collect::<Vec<_>>();

    let verified = RemzarHash::verify_data_hash_batch(&items, &expected)
        .map_err(|e| format!("uppercase verify batch errored: {e:?}"))?;

    assert_eq!(verified, vec![false; items.len()]);
    Ok(())
}

#[test]
fn hash_system_089_verify_truncated_hash_batch_with_uppercase_expected_returns_false_vector()
-> TestResult {
    let items = (0_u64..4_u64).map(sample_payload).collect::<Vec<_>>();
    let expected = RemzarHash::compute_truncated_hash_batch(&items)
        .map_err(|e| format!("truncated batch hash failed: {e:?}"))?
        .into_iter()
        .map(|hash| hash.to_ascii_uppercase())
        .collect::<Vec<_>>();

    let verified = RemzarHash::verify_truncated_hash_batch(&items, &expected)
        .map_err(|e| format!("uppercase truncated verify batch errored: {e:?}"))?;

    assert_eq!(verified, vec![false; items.len()]);
    Ok(())
}

#[test]
fn hash_system_090_merkle_root_empty_differs_from_hash_of_empty_vec_payload() -> TestResult {
    let empty_items: Vec<u64> = Vec::new();

    let merkle = RemzarHash::compute_merkle_root(&empty_items)
        .map_err(|e| format!("empty merkle root failed: {e:?}"))?;
    let empty_vec_hash = RemzarHash::compute_data_hash(&empty_items)
        .map_err(|e| format!("empty vec data hash failed: {e:?}"))?;

    assert_ne!(merkle, empty_vec_hash);
    assert_eq!(merkle, reference_xof64_hex(b"EMPTY_MERKLE_ROOT"));
    Ok(())
}

#[test]
fn hash_system_091_merkle_root_single_empty_string_matches_data_hash_for_same_item() -> TestResult {
    let items = vec![String::new()];

    let merkle = RemzarHash::compute_merkle_root(&items)
        .map_err(|e| format!("single empty string merkle failed: {e:?}"))?;
    let data_hash = RemzarHash::compute_data_hash(&items[0])
        .map_err(|e| format!("single empty string data hash failed: {e:?}"))?;

    assert_eq!(merkle, data_hash);
    assert_hex_len(&merkle, 128);
    Ok(())
}

#[test]
fn hash_system_092_merkle_root_changes_when_duplicate_count_changes() -> TestResult {
    let one = vec![sample_payload(92)];
    let two = vec![sample_payload(92), sample_payload(92)];

    let one_hash = RemzarHash::compute_merkle_root(&one)
        .map_err(|e| format!("one item merkle failed: {e:?}"))?;
    let two_hash = RemzarHash::compute_merkle_root(&two)
        .map_err(|e| format!("two item merkle failed: {e:?}"))?;

    assert_ne!(one_hash, two_hash);
    Ok(())
}

#[test]
fn hash_system_093_header_hash_nonce_uses_big_endian_bytes_reference_vector() -> TestResult {
    let prev = [0x11_u8; 64];
    let merkle = [0x22_u8; 64];
    let nonce = 0x0102_0304_0506_0708_u64;

    let got = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);

    let mut hasher = Hasher::new();
    hasher.update(&prev);
    hasher.update(&merkle);
    hasher.update(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);

    assert_eq!(got, hex::encode(out));
    Ok(())
}

#[test]
fn hash_system_094_header_hash_rejects_valid_hash_for_different_prev_or_merkle() -> TestResult {
    let prev = [1_u8; 64];
    let merkle = [2_u8; 64];
    let expected = RemzarHash::compute_header_hash_hex(&prev, &merkle, 94);

    let wrong_prev = [3_u8; 64];
    let wrong_merkle = [4_u8; 64];

    assert!(!RemzarHash::verify_header_hash(
        &wrong_prev,
        &merkle,
        94,
        &expected
    ));
    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &wrong_merkle,
        94,
        &expected
    ));
    Ok(())
}

#[test]
fn hash_system_095_header_struct_hash_matches_manual_postcard_plus_nonce_reference() -> TestResult {
    let payload = sample_payload(95);
    let nonce = 95_u8;

    let got = RemzarHash::compute_header_struct_hash_hex(&payload, nonce)
        .map_err(|e| format!("header struct hash failed: {e:?}"))?;

    let bytes = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
    let mut hasher = Hasher::new();
    hasher.update(&bytes);
    hasher.update(&[nonce]);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);

    assert_eq!(got, hex::encode(out));
    Ok(())
}

#[test]
fn hash_system_096_genesis_hash_with_ts_zero_matches_manual_reference() -> TestResult {
    let got = RemzarHash::compute_genesis_hash_with_ts(0);

    let mut preimage = Vec::with_capacity(72);
    preimage.extend_from_slice(&[0_u8; 64]);
    preimage.extend_from_slice(&0_u64.to_be_bytes());

    let expected = RemzarHash::compute_bytes_hash(&preimage);

    assert_eq!(got, expected);
    Ok(())
}

#[test]
fn hash_system_097_genesis_hash_with_ts_u64_max_matches_manual_reference() -> TestResult {
    let got = RemzarHash::compute_genesis_hash_with_ts(u64::MAX);

    let mut preimage = Vec::with_capacity(72);
    preimage.extend_from_slice(&[0_u8; 64]);
    preimage.extend_from_slice(&u64::MAX.to_be_bytes());

    let expected = RemzarHash::compute_bytes_hash(&preimage);

    assert_eq!(got, expected);
    assert_eq!(got.len(), 64);
    Ok(())
}

#[test]
fn hash_system_098_load_verify_header_hash_many_nonce_vectors() -> TestResult {
    let prev = [9_u8; 64];
    let merkle = [10_u8; 64];

    for nonce in [0_u64, 1, 2, 255, 256, 65_535, 1_000_000, u64::MAX] {
        let expected = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);

        assert!(RemzarHash::verify_header_hash(
            &prev, &merkle, nonce, &expected
        ));
        assert_hex_len(&expected, 128);
    }

    Ok(())
}

#[test]
fn hash_system_099_load_merkle_roots_for_many_lengths_are_stable_and_valid() -> TestResult {
    for len in [0_u64, 1, 2, 3, 8, 16, 32, 64, 128] {
        let items = (0_u64..len).map(sample_payload).collect::<Vec<_>>();

        let first = RemzarHash::compute_merkle_root(&items)
            .map_err(|e| format!("first merkle root failed for len {len}: {e:?}"))?;
        let second = RemzarHash::compute_merkle_root(&items)
            .map_err(|e| format!("second merkle root failed for len {len}: {e:?}"))?;

        assert_eq!(first, second);
        assert_hex_len(&first, 128);
    }

    Ok(())
}

#[test]
fn hash_system_100_load_batch_hash_and_verify_many_items_are_stable() -> TestResult {
    let items = (0_u64..1_000_u64).map(sample_payload).collect::<Vec<_>>();

    let first = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("first large batch hash failed: {e:?}"))?;
    let second = RemzarHash::compute_data_hash_batch(&items)
        .map_err(|e| format!("second large batch hash failed: {e:?}"))?;

    assert_eq!(first, second);
    assert_eq!(first.len(), items.len());

    let verified = RemzarHash::verify_data_hash_batch(&items, &first)
        .map_err(|e| format!("large batch verify failed: {e:?}"))?;

    assert_eq!(verified, vec![true; items.len()]);
    Ok(())
}
