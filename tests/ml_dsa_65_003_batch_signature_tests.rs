use fips204::ml_dsa_65;
use fips204::traits::Verifier;
use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::cryptography::ml_dsa_65_002_merkleproof::compute_merkle_root;
use remzar::cryptography::ml_dsa_65_003_batch_signature::MlDsa65BatchSignature;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use std::sync::{Mutex, MutexGuard};

type TestResult = Result<(), String>;

static ML_DSA_TEST_LOCK: Mutex<()> = Mutex::new(());

fn ml_dsa_test_lock() -> Result<MutexGuard<'static, ()>, String> {
    ML_DSA_TEST_LOCK
        .lock()
        .map_err(|_| "ML-DSA test mutex poisoned".to_string())
}

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn generate_keypair() -> Result<MlDsa65Keypair, String> {
    let _guard = ml_dsa_test_lock()?;
    MlDsa65Keypair::generate().map_err(debug_err)
}

fn sign_for(kp: &MlDsa65Keypair, batch: &[&[u8]]) -> Result<Vec<u8>, String> {
    let _guard = ml_dsa_test_lock()?;
    let signing_key = kp.get_signing_key().map_err(debug_err)?;
    MlDsa65BatchSignature::sign_batch(&signing_key, batch).map_err(debug_err)
}

fn verify_for(kp: &MlDsa65Keypair, batch: &[&[u8]], signature: &[u8]) -> Result<(), String> {
    let _guard = ml_dsa_test_lock()?;
    let verifying_key = kp.get_verifying_key().map_err(debug_err)?;
    MlDsa65BatchSignature::verify_batch(&verifying_key, batch, signature).map_err(debug_err)
}

fn leaf_hash64(data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();

    if GlobalConfiguration::DOMAIN_SEPARATION_ON {
        hasher.update(GlobalConfiguration::DOMAIN_TAG);
    }

    hasher.update(data);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn batch_merkle_root(batch: &[&[u8]]) -> Result<[u8; 64], String> {
    let leaves: Vec<[u8; 64]> = batch.iter().map(|tx| leaf_hash64(tx)).collect();
    let (root, _) = compute_merkle_root(&leaves).map_err(debug_err)?;
    Ok(root)
}

fn tx_vectors(prefix: &str, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|n| format!("{prefix}-{n}").into_bytes())
        .collect()
}

fn tx_refs(txs: &[Vec<u8>]) -> Vec<&[u8]> {
    txs.iter().map(Vec::as_slice).collect()
}

fn flip_byte(data: &mut [u8], position: usize) -> TestResult {
    let byte = data
        .get_mut(position)
        .ok_or_else(|| format!("byte position {position} out of bounds"))?;
    *byte ^= 1;
    Ok(())
}

fn manual_verify_root(
    kp: &MlDsa65Keypair,
    root: &[u8; 64],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, String> {
    let _guard = ml_dsa_test_lock()?;
    let verifying_key = kp.get_verifying_key().map_err(debug_err)?;
    let sig_array: &[u8; ml_dsa_65::SIG_LEN] = signature
        .try_into()
        .map_err(|_| "signature length could not convert to ML-DSA-65 array".to_string())?;

    Ok(verifying_key.verify(root, sig_array, context))
}

#[test]
fn batchsig_001_signature_length_constant_matches_config_and_fips() -> TestResult {
    assert_eq!(GlobalConfiguration::GUARDIAN_SIG_LEN, ml_dsa_65::SIG_LEN);
    Ok(())
}

#[test]
fn batchsig_002_sign_empty_batch_returns_exact_signature_length() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = Vec::new();
    let signature = sign_for(&kp, &batch)?;

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    assert_eq!(signature.len(), GlobalConfiguration::GUARDIAN_SIG_LEN);

    Ok(())
}

#[test]
fn batchsig_003_verify_empty_batch_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = Vec::new();
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_004_sign_single_transaction_returns_exact_signature_length() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"tx-single".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);

    Ok(())
}

#[test]
fn batchsig_005_verify_single_transaction_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"tx-single".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_006_verify_two_transaction_batch_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"tx-a".as_slice(), b"tx-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_007_verify_odd_three_transaction_batch_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"tx-a".as_slice(), b"tx-b".as_slice(), b"tx-c".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_008_empty_transaction_inside_batch_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"prefix".as_slice(), b"".as_slice(), b"suffix".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_009_binary_transaction_with_zero_bytes_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let tx_a = [0_u8, 1, 2, 0, 3, 255, 0, 4];
    let tx_b = [9_u8, 8, 7, 0, 6];
    let batch: Vec<&[u8]> = vec![tx_a.as_slice(), tx_b.as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_010_duplicate_transactions_batch_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![
        b"dup".as_slice(),
        b"middle".as_slice(),
        b"dup".as_slice(),
        b"tail".as_slice(),
    ];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_011_wrong_verifying_key_rejects_signature() -> TestResult {
    let signer = generate_keypair()?;
    let verifier = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let signature = sign_for(&signer, &batch)?;

    assert!(verify_for(&verifier, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_012_flipped_signature_byte_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;

    flip_byte(&mut signature, 0)?;

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_013_signature_short_by_one_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;

    signature.truncate(signature.len().saturating_sub(1));

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_014_signature_long_by_one_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;

    signature.push(0);

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_015_empty_signature_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice()];

    assert!(verify_for(&kp, &batch, &[]).is_err());

    Ok(())
}

#[test]
fn batchsig_016_all_zero_exact_length_signature_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice()];
    let signature = vec![0_u8; ml_dsa_65::SIG_LEN];

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_017_repeated_byte_exact_length_signature_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"a".as_slice()];
    let signature = vec![0xAB_u8; ml_dsa_65::SIG_LEN];

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_018_changed_transaction_content_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let changed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"changed-b".as_slice()];
    let signature = sign_for(&kp, &signed_batch)?;

    assert!(verify_for(&kp, &changed_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_019_reordered_batch_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"tx-0".as_slice(), b"tx-1".as_slice(), b"tx-2".as_slice()];
    let reordered_batch: Vec<&[u8]> =
        vec![b"tx-2".as_slice(), b"tx-1".as_slice(), b"tx-0".as_slice()];
    let signature = sign_for(&kp, &signed_batch)?;

    assert!(verify_for(&kp, &reordered_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_020_appended_transaction_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let appended_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let signature = sign_for(&kp, &signed_batch)?;

    assert!(verify_for(&kp, &appended_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_021_removed_transaction_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let removed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let signature = sign_for(&kp, &signed_batch)?;

    assert!(verify_for(&kp, &removed_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_022_inserted_duplicate_transaction_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let duplicate_inserted: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
    ];
    let signature = sign_for(&kp, &signed_batch)?;

    assert!(verify_for(&kp, &duplicate_inserted, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_023_empty_batch_signature_does_not_verify_nonempty_batch() -> TestResult {
    let kp = generate_keypair()?;
    let empty_batch: Vec<&[u8]> = Vec::new();
    let nonempty_batch: Vec<&[u8]> = vec![b"a".as_slice()];
    let signature = sign_for(&kp, &empty_batch)?;

    assert!(verify_for(&kp, &nonempty_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_024_nonempty_batch_signature_does_not_verify_empty_batch() -> TestResult {
    let kp = generate_keypair()?;
    let empty_batch: Vec<&[u8]> = Vec::new();
    let nonempty_batch: Vec<&[u8]> = vec![b"a".as_slice()];
    let signature = sign_for(&kp, &nonempty_batch)?;

    assert!(verify_for(&kp, &empty_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_025_signature_verifies_manually_against_expected_merkle_root() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![
        b"manual-a".as_slice(),
        b"manual-b".as_slice(),
        b"manual-c".as_slice(),
    ];
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    assert!(manual_verify_root(&kp, &root, &signature, b"")?);

    Ok(())
}

#[test]
fn batchsig_026_signature_fails_manually_against_wrong_merkle_root() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let wrong_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"changed-b".as_slice()];
    let signature = sign_for(&kp, &signed_batch)?;
    let wrong_root = batch_merkle_root(&wrong_batch)?;

    assert!(!manual_verify_root(&kp, &wrong_root, &signature, b"")?);

    Ok(())
}

#[test]
fn batchsig_027_signature_fails_with_nonempty_context() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"context-a".as_slice(), b"context-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    assert!(!manual_verify_root(
        &kp,
        &root,
        &signature,
        b"wrong-context"
    )?);

    Ok(())
}

#[test]
fn batchsig_028_signing_same_batch_twice_produces_verifiable_signatures() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"repeat-a".as_slice(), b"repeat-b".as_slice()];
    let first = sign_for(&kp, &batch)?;
    let second = sign_for(&kp, &batch)?;

    assert_eq!(first.len(), ml_dsa_65::SIG_LEN);
    assert_eq!(second.len(), ml_dsa_65::SIG_LEN);
    verify_for(&kp, &batch, &first)?;
    verify_for(&kp, &batch, &second)?;

    Ok(())
}

#[test]
fn batchsig_029_property_batches_of_size_zero_through_eight_verify() -> TestResult {
    let kp = generate_keypair()?;

    for count in 0..=8 {
        let txs = tx_vectors("prop-size", count);
        let batch = tx_refs(&txs);
        let signature = sign_for(&kp, &batch)?;

        verify_for(&kp, &batch, &signature)?;
    }

    Ok(())
}

#[test]
fn batchsig_030_property_each_single_position_content_change_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let original_txs = tx_vectors("content-change", 6);
    let original_batch = tx_refs(&original_txs);
    let signature = sign_for(&kp, &original_batch)?;

    for position in 0..original_txs.len() {
        let mut changed_txs = original_txs.clone();
        let tx = changed_txs
            .get_mut(position)
            .ok_or_else(|| format!("missing tx at position {position}"))?;
        tx.push(0xFF);

        let changed_batch = tx_refs(&changed_txs);
        assert!(
            verify_for(&kp, &changed_batch, &signature).is_err(),
            "changed transaction at position {position} verified unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn batchsig_031_sign_rejects_batch_count_above_max_items() -> TestResult {
    let kp = generate_keypair()?;
    let item = b"x".as_slice();
    let batch = vec![item; GlobalConfiguration::MAX_BATCH_ITEMS.saturating_add(1)];

    assert!(sign_for(&kp, &batch).is_err());

    Ok(())
}

#[test]
fn batchsig_032_verify_rejects_batch_count_above_max_items() -> TestResult {
    let kp = generate_keypair()?;
    let valid_batch: Vec<&[u8]> = vec![b"x".as_slice()];
    let signature = sign_for(&kp, &valid_batch)?;

    let item = b"x".as_slice();
    let too_many = vec![item; GlobalConfiguration::MAX_BATCH_ITEMS.saturating_add(1)];

    assert!(verify_for(&kp, &too_many, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_033_sign_rejects_item_larger_than_max_item_bytes() -> TestResult {
    let kp = generate_keypair()?;
    let too_large = vec![7_u8; GlobalConfiguration::MAX_ITEM_BYTES.saturating_add(1)];
    let batch: Vec<&[u8]> = vec![too_large.as_slice()];

    assert!(sign_for(&kp, &batch).is_err());

    Ok(())
}

#[test]
fn batchsig_034_verify_rejects_item_larger_than_max_item_bytes() -> TestResult {
    let kp = generate_keypair()?;
    let valid_batch: Vec<&[u8]> = vec![b"valid".as_slice()];
    let signature = sign_for(&kp, &valid_batch)?;

    let too_large = vec![8_u8; GlobalConfiguration::MAX_ITEM_BYTES.saturating_add(1)];
    let invalid_batch: Vec<&[u8]> = vec![too_large.as_slice()];

    assert!(verify_for(&kp, &invalid_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_035_sign_rejects_batch_over_total_byte_limit() -> TestResult {
    let kp = generate_keypair()?;
    let chunk_len = GlobalConfiguration::MAX_ITEM_BYTES.clamp(1, 1024 * 1024);
    let chunk = vec![9_u8; chunk_len];
    let repeat_count = GlobalConfiguration::MAX_TOTAL_BATCH_BYTES
        .div_euclid(chunk_len)
        .saturating_add(1);
    let batch = vec![chunk.as_slice(); repeat_count];

    assert!(sign_for(&kp, &batch).is_err());

    Ok(())
}

#[test]
fn batchsig_036_verify_rejects_batch_over_total_byte_limit() -> TestResult {
    let kp = generate_keypair()?;
    let valid_batch: Vec<&[u8]> = vec![b"valid".as_slice()];
    let signature = sign_for(&kp, &valid_batch)?;

    let chunk_len = GlobalConfiguration::MAX_ITEM_BYTES.clamp(1, 1024 * 1024);
    let chunk = vec![10_u8; chunk_len];
    let repeat_count = GlobalConfiguration::MAX_TOTAL_BATCH_BYTES
        .div_euclid(chunk_len)
        .saturating_add(1);
    let oversized_batch = vec![chunk.as_slice(); repeat_count];

    assert!(verify_for(&kp, &oversized_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_037_adversarial_signature_byte_by_byte_reassembly_verifies() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"net-a".as_slice(), b"net-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let mut reassembled = Vec::with_capacity(signature.len());

    for byte in signature.iter().copied() {
        reassembled.push(byte);
    }

    verify_for(&kp, &batch, &reassembled)?;

    Ok(())
}

#[test]
fn batchsig_038_adversarial_signature_fragment_swap_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"net-a".as_slice(), b"net-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    let first = signature
        .get(..64)
        .ok_or_else(|| "missing first signature fragment".to_string())?;
    let middle = signature
        .get(64..128)
        .ok_or_else(|| "missing middle signature fragment".to_string())?;
    let tail = signature
        .get(128..)
        .ok_or_else(|| "missing tail signature fragment".to_string())?;

    let mut swapped = Vec::with_capacity(signature.len());
    swapped.extend_from_slice(middle);
    swapped.extend_from_slice(first);
    swapped.extend_from_slice(tail);

    assert_eq!(swapped.len(), signature.len());
    assert!(verify_for(&kp, &batch, &swapped).is_err());

    Ok(())
}

#[test]
fn batchsig_039_load_test_sign_and_verify_many_small_batches() -> TestResult {
    let kp = generate_keypair()?;

    for round in 0..24 {
        let txs = tx_vectors("load-small", round % 9);
        let batch = tx_refs(&txs);
        let signature = sign_for(&kp, &batch)?;

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        verify_for(&kp, &batch, &signature)?;
    }

    Ok(())
}

#[test]
fn batchsig_040_load_test_large_batch_sign_verify_and_manual_root_verify() -> TestResult {
    let kp = generate_keypair()?;
    let txs = tx_vectors("load-large", 128);
    let batch = tx_refs(&txs);
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    verify_for(&kp, &batch, &signature)?;
    assert!(manual_verify_root(&kp, &root, &signature, b"")?);

    Ok(())
}

#[test]
fn batchsig_041_empty_batch_signature_verifies_manually_against_dummy_merkle_root() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = Vec::new();
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    assert!(manual_verify_root(&kp, &root, &signature, b"")?);

    Ok(())
}

#[test]
fn batchsig_042_empty_batch_signature_rejects_single_empty_transaction_batch() -> TestResult {
    let kp = generate_keypair()?;
    let empty_batch: Vec<&[u8]> = Vec::new();
    let single_empty: Vec<&[u8]> = vec![b"".as_slice()];
    let signature = sign_for(&kp, &empty_batch)?;

    assert!(verify_for(&kp, &single_empty, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_043_single_empty_transaction_signature_rejects_empty_batch() -> TestResult {
    let kp = generate_keypair()?;
    let empty_batch: Vec<&[u8]> = Vec::new();
    let single_empty: Vec<&[u8]> = vec![b"".as_slice()];
    let signature = sign_for(&kp, &single_empty)?;

    assert!(verify_for(&kp, &empty_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_044_single_zero_byte_transaction_differs_from_empty_transaction() -> TestResult {
    let kp = generate_keypair()?;
    let empty_tx_batch: Vec<&[u8]> = vec![b"".as_slice()];
    let zero_byte = [0_u8];
    let zero_tx_batch: Vec<&[u8]> = vec![zero_byte.as_slice()];
    let signature = sign_for(&kp, &empty_tx_batch)?;

    assert!(verify_for(&kp, &zero_tx_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_045_same_bytes_different_allocations_verify() -> TestResult {
    let kp = generate_keypair()?;
    let tx_a = b"allocation-a".to_vec();
    let tx_b = b"allocation-b".to_vec();
    let signed_txs = vec![tx_a.clone(), tx_b.clone()];
    let verify_txs = vec![tx_a, tx_b];

    let signed_batch = tx_refs(&signed_txs);
    let verify_batch_refs = tx_refs(&verify_txs);
    let signature = sign_for(&kp, &signed_batch)?;

    verify_for(&kp, &verify_batch_refs, &signature)?;

    Ok(())
}

#[test]
fn batchsig_046_same_concatenated_bytes_different_transaction_boundaries_reject() -> TestResult {
    let kp = generate_keypair()?;
    let signed_batch: Vec<&[u8]> = vec![b"ab".as_slice(), b"c".as_slice()];
    let changed_boundary_batch: Vec<&[u8]> = vec![b"a".as_slice(), b"bc".as_slice()];
    let signature = sign_for(&kp, &signed_batch)?;

    assert!(verify_for(&kp, &changed_boundary_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_047_signature_for_three_leaves_verifies_fourth_duplicate_last_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let three: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let four_with_duplicate_last: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"c".as_slice(),
    ];
    let signature = sign_for(&kp, &three)?;

    verify_for(&kp, &four_with_duplicate_last, &signature)?;

    Ok(())
}

#[test]
fn batchsig_048_signature_for_five_leaves_verifies_sixth_duplicate_last_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let five: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
    ];
    let six_with_duplicate_last: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"e".as_slice(),
    ];
    let signature = sign_for(&kp, &five)?;

    verify_for(&kp, &six_with_duplicate_last, &signature)?;

    Ok(())
}

#[test]
fn batchsig_049_signature_for_single_leaf_rejects_two_duplicate_leaves() -> TestResult {
    let kp = generate_keypair()?;
    let single: Vec<&[u8]> = vec![b"x".as_slice()];
    let duplicate_pair: Vec<&[u8]> = vec![b"x".as_slice(), b"x".as_slice()];
    let signature = sign_for(&kp, &single)?;

    assert!(verify_for(&kp, &duplicate_pair, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_050_signature_for_three_leaves_rejects_fourth_different_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let three: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let four_with_different_last: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
    ];
    let signature = sign_for(&kp, &three)?;

    assert!(verify_for(&kp, &four_with_different_last, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_051_middle_signature_byte_flip_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"middle-a".as_slice(), b"middle-b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;
    let middle = signature.len().div_euclid(2);

    flip_byte(&mut signature, middle)?;

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_052_last_signature_byte_flip_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"last-a".as_slice(), b"last-b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;
    let last = signature
        .len()
        .checked_sub(1)
        .ok_or_else(|| "signature unexpectedly empty".to_string())?;

    flip_byte(&mut signature, last)?;

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_053_reversed_exact_length_signature_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"reverse-a".as_slice(), b"reverse-b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;

    signature.reverse();

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_054_rotated_exact_length_signature_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"rotate-a".as_slice(), b"rotate-b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;

    signature.rotate_left(1);

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_055_drop_first_signature_byte_and_pad_end_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"pad-a".as_slice(), b"pad-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let shifted = signature
        .get(1..)
        .ok_or_else(|| "missing shifted signature".to_string())?;

    let mut modified = Vec::with_capacity(signature.len());
    modified.extend_from_slice(shifted);
    modified.push(0);

    assert_eq!(modified.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &modified).is_err());

    Ok(())
}

#[test]
fn batchsig_056_add_leading_zero_and_drop_last_signature_byte_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"lead-a".as_slice(), b"lead-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let without_last = signature
        .get(..signature.len().saturating_sub(1))
        .ok_or_else(|| "missing shortened signature".to_string())?;

    let mut modified = Vec::with_capacity(signature.len());
    modified.push(0);
    modified.extend_from_slice(without_last);

    assert_eq!(modified.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &modified).is_err());

    Ok(())
}

#[test]
fn batchsig_057_split_and_duplicate_signature_fragment_is_rejected() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"frag-a".as_slice(), b"frag-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    let first = signature
        .get(..64)
        .ok_or_else(|| "missing first signature fragment".to_string())?;
    let middle = signature
        .get(64..signature.len().saturating_sub(64))
        .ok_or_else(|| "missing middle signature fragment".to_string())?;

    let mut modified = Vec::with_capacity(signature.len());
    modified.extend_from_slice(first);
    modified.extend_from_slice(first);
    modified.extend_from_slice(middle);
    modified.truncate(signature.len());

    assert_eq!(modified.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &modified).is_err());

    Ok(())
}

#[test]
fn batchsig_058_signature_from_key_a_rejects_key_b_even_for_same_public_batch() -> TestResult {
    let key_a = generate_keypair()?;
    let key_b = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"key-a".as_slice(), b"key-b".as_slice()];
    let signature = sign_for(&key_a, &batch)?;

    verify_for(&key_a, &batch, &signature)?;
    assert!(verify_for(&key_b, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_059_two_keypairs_signatures_verify_only_with_own_keys() -> TestResult {
    let key_a = generate_keypair()?;
    let key_b = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"shared-a".as_slice(), b"shared-b".as_slice()];

    let signature_a = sign_for(&key_a, &batch)?;
    let signature_b = sign_for(&key_b, &batch)?;

    verify_for(&key_a, &batch, &signature_a)?;
    verify_for(&key_b, &batch, &signature_b)?;
    assert!(verify_for(&key_a, &batch, &signature_b).is_err());
    assert!(verify_for(&key_b, &batch, &signature_a).is_err());

    Ok(())
}

#[test]
fn batchsig_060_manual_verify_empty_context_succeeds_but_one_byte_context_fails() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"context-edge-a".as_slice(), b"context-edge-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    assert!(manual_verify_root(&kp, &root, &signature, b"")?);
    assert!(!manual_verify_root(&kp, &root, &signature, &[0_u8])?);

    Ok(())
}

#[test]
fn batchsig_061_all_targets_same_batch_root_matches_batch_merkle_root() -> TestResult {
    let kp = generate_keypair()?;
    let txs = tx_vectors("root-match", 10);
    let batch = tx_refs(&txs);
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    assert!(manual_verify_root(&kp, &root, &signature, b"")?);
    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_062_property_reordering_each_adjacent_pair_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let original_txs = tx_vectors("swap", 7);
    let original_batch = tx_refs(&original_txs);
    let signature = sign_for(&kp, &original_batch)?;

    for position in 0..original_txs.len().saturating_sub(1) {
        let mut changed_txs = original_txs.clone();
        changed_txs.swap(position, position.saturating_add(1));
        let changed_batch = tx_refs(&changed_txs);

        assert!(
            verify_for(&kp, &changed_batch, &signature).is_err(),
            "adjacent swap at position {position} verified unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn batchsig_063_property_each_signature_probe_byte_flip_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"probe-a".as_slice(), b"probe-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    let positions = [
        0_usize,
        1_usize,
        64_usize,
        ml_dsa_65::SIG_LEN.div_euclid(2),
        ml_dsa_65::SIG_LEN.saturating_sub(2),
        ml_dsa_65::SIG_LEN.saturating_sub(1),
    ];

    for position in positions {
        let mut changed = signature.clone();
        flip_byte(&mut changed, position)?;
        assert!(
            verify_for(&kp, &batch, &changed).is_err(),
            "signature byte flip at position {position} verified unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn batchsig_064_property_signature_invalid_lengths_near_boundary_reject() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"length-a".as_slice(), b"length-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    let lengths = [
        0_usize,
        1_usize,
        ml_dsa_65::SIG_LEN.saturating_sub(2),
        ml_dsa_65::SIG_LEN.saturating_sub(1),
        ml_dsa_65::SIG_LEN.saturating_add(1),
        ml_dsa_65::SIG_LEN.saturating_add(2),
    ];

    for len in lengths {
        let candidate = if len <= signature.len() {
            signature
                .get(..len)
                .ok_or_else(|| format!("missing signature prefix length {len}"))?
                .to_vec()
        } else {
            let mut longer = signature.clone();
            while longer.len() < len {
                longer.push(0);
            }
            longer
        };

        assert!(
            verify_for(&kp, &batch, &candidate).is_err(),
            "invalid signature length {len} verified unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn batchsig_065_sign_and_verify_transaction_at_exact_small_power_of_two_counts() -> TestResult {
    let kp = generate_keypair()?;

    for count in [1_usize, 2, 4, 8, 16, 32] {
        let txs = tx_vectors("power-two", count);
        let batch = tx_refs(&txs);
        let signature = sign_for(&kp, &batch)?;

        verify_for(&kp, &batch, &signature)?;
    }

    Ok(())
}

#[test]
fn batchsig_066_sign_and_verify_transaction_at_odd_counts() -> TestResult {
    let kp = generate_keypair()?;

    for count in [3_usize, 5, 7, 9, 15, 17] {
        let txs = tx_vectors("odd-count", count);
        let batch = tx_refs(&txs);
        let signature = sign_for(&kp, &batch)?;

        verify_for(&kp, &batch, &signature)?;
    }

    Ok(())
}

#[test]
fn batchsig_067_large_valid_item_at_one_kib_succeeds() -> TestResult {
    let kp = generate_keypair()?;
    let tx = vec![42_u8; 1024];
    let batch: Vec<&[u8]> = vec![tx.as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_068_many_empty_transactions_succeed() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"".as_slice(); 16];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_069_many_identical_nonempty_transactions_succeed() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"same".as_slice(); 16];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_070_many_identical_transactions_reject_when_one_value_changes() -> TestResult {
    let kp = generate_keypair()?;
    let signed: Vec<&[u8]> = vec![b"same".as_slice(); 16];
    let changed: Vec<&[u8]> = vec![
        b"same".as_slice(),
        b"same".as_slice(),
        b"changed".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
        b"same".as_slice(),
    ];
    let signature = sign_for(&kp, &signed)?;

    assert!(verify_for(&kp, &changed, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_071_manual_merkle_root_changes_when_batch_boundaries_change() -> TestResult {
    let first: Vec<&[u8]> = vec![b"ab".as_slice(), b"cd".as_slice()];
    let second: Vec<&[u8]> = vec![b"a".as_slice(), b"bcd".as_slice()];

    let first_root = batch_merkle_root(&first)?;
    let second_root = batch_merkle_root(&second)?;

    assert_ne!(first_root, second_root);

    Ok(())
}

#[test]
fn batchsig_072_manual_merkle_root_empty_batch_differs_from_single_empty_transaction() -> TestResult
{
    let empty_batch: Vec<&[u8]> = Vec::new();
    let single_empty: Vec<&[u8]> = vec![b"".as_slice()];

    let empty_root = batch_merkle_root(&empty_batch)?;
    let single_empty_root = batch_merkle_root(&single_empty)?;

    assert_ne!(empty_root, single_empty_root);

    Ok(())
}

#[test]
fn batchsig_073_signature_for_batch_with_trailing_empty_tx_rejects_without_trailing_empty_tx()
-> TestResult {
    let kp = generate_keypair()?;
    let with_trailing_empty: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"".as_slice()];
    let without_trailing_empty: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let signature = sign_for(&kp, &with_trailing_empty)?;

    assert!(verify_for(&kp, &without_trailing_empty, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_074_signature_for_batch_without_trailing_empty_tx_rejects_with_trailing_empty_tx()
-> TestResult {
    let kp = generate_keypair()?;
    let without_trailing_empty: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let with_trailing_empty: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"".as_slice()];
    let signature = sign_for(&kp, &without_trailing_empty)?;

    assert!(verify_for(&kp, &with_trailing_empty, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_075_adversarial_signature_duplicate_full_frame_rejects_by_length() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"dup-frame-a".as_slice(), b"dup-frame-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let mut duplicated = Vec::with_capacity(signature.len().saturating_mul(2));

    duplicated.extend_from_slice(&signature);
    duplicated.extend_from_slice(&signature);

    assert!(verify_for(&kp, &batch, &duplicated).is_err());

    Ok(())
}

#[test]
fn batchsig_076_adversarial_signature_missing_first_byte_rejects_by_length() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"missing-a".as_slice(), b"missing-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let missing_first = signature
        .get(1..)
        .ok_or_else(|| "missing shifted signature".to_string())?;

    assert!(verify_for(&kp, &batch, missing_first).is_err());

    Ok(())
}

#[test]
fn batchsig_077_adversarial_signature_missing_last_byte_rejects_by_length() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"missing-a".as_slice(), b"missing-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;
    let missing_last = signature
        .get(..signature.len().saturating_sub(1))
        .ok_or_else(|| "missing shortened signature".to_string())?;

    assert!(verify_for(&kp, &batch, missing_last).is_err());

    Ok(())
}

#[test]
fn batchsig_078_load_test_sign_verify_sixty_four_transaction_batch() -> TestResult {
    let kp = generate_keypair()?;
    let txs = tx_vectors("load-64", 64);
    let batch = tx_refs(&txs);
    let signature = sign_for(&kp, &batch)?;

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_079_load_test_multiple_keys_sign_same_batch() -> TestResult {
    let txs = tx_vectors("multi-key-load", 16);
    let batch = tx_refs(&txs);

    for round in 0..6 {
        let kp = generate_keypair()?;
        let signature = sign_for(&kp, &batch)?;

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        verify_for(&kp, &batch, &signature)
            .map_err(|err| format!("round {round} failed verification: {err}"))?;
    }

    Ok(())
}

#[test]
fn batchsig_080_load_test_many_batches_with_distinct_roots_verify() -> TestResult {
    let kp = generate_keypair()?;

    for round in 0..16 {
        let txs = tx_vectors("distinct-root-load", round + 1);
        let batch = tx_refs(&txs);
        let signature = sign_for(&kp, &batch)?;
        let root = batch_merkle_root(&batch)?;

        assert!(manual_verify_root(&kp, &root, &signature, b"")?);
        verify_for(&kp, &batch, &signature)?;
    }

    Ok(())
}

#[test]
fn batchsig_081_signature_for_seven_leaves_verifies_eighth_duplicate_last_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let seven: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"f".as_slice(),
        b"g".as_slice(),
    ];
    let eight_with_duplicate_last: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"f".as_slice(),
        b"g".as_slice(),
        b"g".as_slice(),
    ];
    let signature = sign_for(&kp, &seven)?;

    verify_for(&kp, &eight_with_duplicate_last, &signature)?;

    Ok(())
}

#[test]
fn batchsig_082_signature_for_seven_leaves_rejects_eighth_different_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let seven: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"f".as_slice(),
        b"g".as_slice(),
    ];
    let eight_with_different_last: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"f".as_slice(),
        b"g".as_slice(),
        b"h".as_slice(),
    ];
    let signature = sign_for(&kp, &seven)?;

    assert!(verify_for(&kp, &eight_with_different_last, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_083_signature_for_nine_leaves_verifies_tenth_duplicate_last_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let nine: Vec<&[u8]> = vec![
        b"n0".as_slice(),
        b"n1".as_slice(),
        b"n2".as_slice(),
        b"n3".as_slice(),
        b"n4".as_slice(),
        b"n5".as_slice(),
        b"n6".as_slice(),
        b"n7".as_slice(),
        b"n8".as_slice(),
    ];
    let ten_with_duplicate_last: Vec<&[u8]> = vec![
        b"n0".as_slice(),
        b"n1".as_slice(),
        b"n2".as_slice(),
        b"n3".as_slice(),
        b"n4".as_slice(),
        b"n5".as_slice(),
        b"n6".as_slice(),
        b"n7".as_slice(),
        b"n8".as_slice(),
        b"n8".as_slice(),
    ];
    let signature = sign_for(&kp, &nine)?;

    verify_for(&kp, &ten_with_duplicate_last, &signature)?;

    Ok(())
}

#[test]
fn batchsig_084_signature_for_nine_leaves_rejects_tenth_different_leaf() -> TestResult {
    let kp = generate_keypair()?;
    let nine: Vec<&[u8]> = vec![
        b"n0".as_slice(),
        b"n1".as_slice(),
        b"n2".as_slice(),
        b"n3".as_slice(),
        b"n4".as_slice(),
        b"n5".as_slice(),
        b"n6".as_slice(),
        b"n7".as_slice(),
        b"n8".as_slice(),
    ];
    let ten_with_different_last: Vec<&[u8]> = vec![
        b"n0".as_slice(),
        b"n1".as_slice(),
        b"n2".as_slice(),
        b"n3".as_slice(),
        b"n4".as_slice(),
        b"n5".as_slice(),
        b"n6".as_slice(),
        b"n7".as_slice(),
        b"n8".as_slice(),
        b"n9".as_slice(),
    ];
    let signature = sign_for(&kp, &nine)?;

    assert!(verify_for(&kp, &ten_with_different_last, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_085_seven_leaf_root_equals_eight_leaf_root_when_last_is_duplicate() -> TestResult {
    let seven: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"f".as_slice(),
        b"g".as_slice(),
    ];
    let eight_with_duplicate_last: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
        b"e".as_slice(),
        b"f".as_slice(),
        b"g".as_slice(),
        b"g".as_slice(),
    ];

    assert_eq!(
        batch_merkle_root(&seven)?,
        batch_merkle_root(&eight_with_duplicate_last)?
    );

    Ok(())
}

#[test]
fn batchsig_086_nine_leaf_root_equals_ten_leaf_root_when_last_is_duplicate() -> TestResult {
    let nine: Vec<&[u8]> = vec![
        b"n0".as_slice(),
        b"n1".as_slice(),
        b"n2".as_slice(),
        b"n3".as_slice(),
        b"n4".as_slice(),
        b"n5".as_slice(),
        b"n6".as_slice(),
        b"n7".as_slice(),
        b"n8".as_slice(),
    ];
    let ten_with_duplicate_last: Vec<&[u8]> = vec![
        b"n0".as_slice(),
        b"n1".as_slice(),
        b"n2".as_slice(),
        b"n3".as_slice(),
        b"n4".as_slice(),
        b"n5".as_slice(),
        b"n6".as_slice(),
        b"n7".as_slice(),
        b"n8".as_slice(),
        b"n8".as_slice(),
    ];

    assert_eq!(
        batch_merkle_root(&nine)?,
        batch_merkle_root(&ten_with_duplicate_last)?
    );

    Ok(())
}

#[test]
fn batchsig_087_largest_policy_allowed_single_item_signs_and_verifies() -> TestResult {
    let kp = generate_keypair()?;
    let valid_len =
        GlobalConfiguration::MAX_ITEM_BYTES.min(GlobalConfiguration::MAX_TOTAL_BATCH_BYTES);
    let tx = vec![0x5A_u8; valid_len];
    let batch: Vec<&[u8]> = vec![tx.as_slice()];
    let signature = sign_for(&kp, &batch)?;

    verify_for(&kp, &batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_088_largest_policy_allowed_single_item_rejects_one_byte_change() -> TestResult {
    let kp = generate_keypair()?;
    let valid_len =
        GlobalConfiguration::MAX_ITEM_BYTES.min(GlobalConfiguration::MAX_TOTAL_BATCH_BYTES);
    let tx = vec![0x5A_u8; valid_len];
    let mut changed_tx = tx.clone();

    if let Some(first) = changed_tx.first_mut() {
        *first ^= 1;
    }

    let batch: Vec<&[u8]> = vec![tx.as_slice()];
    let changed_batch: Vec<&[u8]> = vec![changed_tx.as_slice()];
    let signature = sign_for(&kp, &batch)?;

    assert!(verify_for(&kp, &changed_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_089_first_sixty_four_signature_bytes_zeroed_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"zero-head-a".as_slice(), b"zero-head-b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;

    let head = signature
        .get_mut(..64)
        .ok_or_else(|| "missing signature head".to_string())?;
    head.fill(0);

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_090_last_sixty_four_signature_bytes_zeroed_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"zero-tail-a".as_slice(), b"zero-tail-b".as_slice()];
    let mut signature = sign_for(&kp, &batch)?;
    let start = signature.len().saturating_sub(64);

    let tail = signature
        .get_mut(start..)
        .ok_or_else(|| "missing signature tail".to_string())?;
    tail.fill(0);

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_091_exact_length_all_max_byte_signature_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"max-byte-a".as_slice(), b"max-byte-b".as_slice()];
    let signature = vec![u8::MAX; ml_dsa_65::SIG_LEN];

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_092_exact_length_alternating_signature_rejects() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"alt-a".as_slice(), b"alt-b".as_slice()];
    let mut signature = vec![0_u8; ml_dsa_65::SIG_LEN];

    for (index, byte) in signature.iter_mut().enumerate() {
        *byte = if index % 2 == 0 { 0xAA } else { 0x55 };
    }

    assert!(verify_for(&kp, &batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_093_empty_batch_root_equals_single_dummy_marker_transaction_root() -> TestResult {
    let empty_batch: Vec<&[u8]> = Vec::new();
    let dummy_marker_batch: Vec<&[u8]> = vec![b"remzar_empty_block_mint".as_slice()];

    assert_eq!(
        batch_merkle_root(&empty_batch)?,
        batch_merkle_root(&dummy_marker_batch)?
    );

    Ok(())
}

#[test]
fn batchsig_094_empty_batch_signature_verifies_single_dummy_marker_transaction() -> TestResult {
    let kp = generate_keypair()?;
    let empty_batch: Vec<&[u8]> = Vec::new();
    let dummy_marker_batch: Vec<&[u8]> = vec![b"remzar_empty_block_mint".as_slice()];
    let signature = sign_for(&kp, &empty_batch)?;

    verify_for(&kp, &dummy_marker_batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_095_single_dummy_marker_signature_verifies_empty_batch() -> TestResult {
    let kp = generate_keypair()?;
    let empty_batch: Vec<&[u8]> = Vec::new();
    let dummy_marker_batch: Vec<&[u8]> = vec![b"remzar_empty_block_mint".as_slice()];
    let signature = sign_for(&kp, &dummy_marker_batch)?;

    verify_for(&kp, &empty_batch, &signature)?;

    Ok(())
}

#[test]
fn batchsig_096_dummy_marker_signature_rejects_dummy_marker_with_extra_byte() -> TestResult {
    let kp = generate_keypair()?;
    let dummy_marker_batch: Vec<&[u8]> = vec![b"remzar_empty_block_mint".as_slice()];
    let changed_marker_batch: Vec<&[u8]> = vec![b"remzar_empty_block_mint!".as_slice()];
    let signature = sign_for(&kp, &dummy_marker_batch)?;

    assert!(verify_for(&kp, &changed_marker_batch, &signature).is_err());

    Ok(())
}

#[test]
fn batchsig_097_property_sampled_signature_byte_flips_reject_across_full_length() -> TestResult {
    let kp = generate_keypair()?;
    let batch: Vec<&[u8]> = vec![b"sample-a".as_slice(), b"sample-b".as_slice()];
    let signature = sign_for(&kp, &batch)?;

    let step = ml_dsa_65::SIG_LEN.div_euclid(16).max(1);
    let mut position = 0_usize;

    while position < ml_dsa_65::SIG_LEN {
        let mut changed = signature.clone();
        flip_byte(&mut changed, position)?;

        assert!(
            verify_for(&kp, &batch, &changed).is_err(),
            "signature byte flip at position {position} verified unexpectedly"
        );

        position = position.saturating_add(step);
    }

    Ok(())
}

#[test]
fn batchsig_098_property_each_transaction_removal_rejects_for_ten_item_batch() -> TestResult {
    let kp = generate_keypair()?;
    let txs = tx_vectors("remove-each", 10);
    let batch = tx_refs(&txs);
    let signature = sign_for(&kp, &batch)?;

    for remove_index in 0..txs.len() {
        let changed_txs: Vec<Vec<u8>> = txs
            .iter()
            .enumerate()
            .filter_map(|(index, tx)| {
                if index == remove_index {
                    None
                } else {
                    Some(tx.clone())
                }
            })
            .collect();
        let changed_batch = tx_refs(&changed_txs);

        assert!(
            verify_for(&kp, &changed_batch, &signature).is_err(),
            "removing transaction {remove_index} verified unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn batchsig_099_load_test_sign_verify_one_hundred_twenty_eight_transaction_batch() -> TestResult {
    let kp = generate_keypair()?;
    let txs = tx_vectors("load-final-128", 128);
    let batch = tx_refs(&txs);
    let signature = sign_for(&kp, &batch)?;
    let root = batch_merkle_root(&batch)?;

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    verify_for(&kp, &batch, &signature)?;
    assert!(manual_verify_root(&kp, &root, &signature, b"")?);

    Ok(())
}

#[test]
fn batchsig_100_load_test_twelve_keys_sign_and_verify_same_empty_batch() -> TestResult {
    let batch: Vec<&[u8]> = Vec::new();

    for round in 0..12 {
        let kp = generate_keypair()?;
        let signature = sign_for(&kp, &batch)?;

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        verify_for(&kp, &batch, &signature)
            .map_err(|err| format!("empty-batch key round {round} failed: {err}"))?;
    }

    Ok(())
}
