use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;
use fips204::traits::{Signer, Verifier};
use std::sync::{Mutex, MutexGuard, OnceLock};

use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::cryptography::ml_dsa_65_002_merkleproof::compute_merkle_root;
use remzar::cryptography::ml_dsa_65_004_guardian_signature::GuardianSignature;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

const CONSENSUS_CTX_FOR_TEST: &[u8] = b"";

static GUARDIAN_SIGNATURE_PROPTEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn guardian_signature_proptest_guard() -> MutexGuard<'static, ()> {
    GUARDIAN_SIGNATURE_PROPTEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn fresh_keypair() -> MlDsa65Keypair {
    MlDsa65Keypair::generate().expect("ML-DSA-65 keypair generation should succeed")
}

fn fresh_guardian_signing_and_verifying_keys() -> (ml_dsa_65::PrivateKey, ml_dsa_65::PublicKey) {
    let kp = fresh_keypair();

    let signing_key = kp
        .get_signing_key()
        .expect("generated guardian secret key should parse");

    let verifying_key = kp
        .get_verifying_key()
        .expect("generated guardian public key should parse");

    (signing_key, verifying_key)
}

fn batch_refs(batch: &[Vec<u8>]) -> Vec<&[u8]> {
    batch.iter().map(Vec::as_slice).collect()
}

fn tagged_transaction(tag: u8, tail: &[u8]) -> Vec<u8> {
    let mut tx = Vec::with_capacity(tail.len() + 1);
    tx.push(tag);
    tx.extend_from_slice(tail);
    tx
}

fn test_hash_data(data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();

    if GlobalConfiguration::DOMAIN_SEPARATION_ON {
        hasher.update(GlobalConfiguration::DOMAIN_TAG);
    }

    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn test_batch_merkle_root(batch: &[Vec<u8>]) -> [u8; 64] {
    let hashes: Vec<[u8; 64]> = batch.iter().map(|tx| test_hash_data(tx)).collect();

    let (root, _levels) =
        compute_merkle_root(&hashes).expect("test Merkle root computation should succeed");

    root
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_guardian_sign_then_verify_accepts_valid_signature_for_arbitrary_batch(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian signing arbitrary bounded batch should succeed");

        prop_assert_eq!(
            signature.len(),
            ml_dsa_65::SIG_LEN,
            "guardian signature must have exact ML-DSA-65 signature length"
        );

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &refs, &signature).is_ok(),
            "valid guardian signature must verify for the same batch and public key"
        );
    }

    // 02/25
    #[test]
    fn test_002_guardian_verify_rejects_tampered_signature_byte(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
        sig_index in 0usize..ml_dsa_65::SIG_LEN,
        delta in 1u8..=255u8,
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let mut signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian signing arbitrary bounded batch should succeed");

        signature[sig_index] = signature[sig_index].wrapping_add(delta);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &refs, &signature).is_err(),
            "guardian verification must reject a tampered signature byte at index {sig_index}"
        );
    }

    // 03/25
    #[test]
    fn test_003_guardian_verify_rejects_tampered_transaction_contents(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            1..32
        ),
        tx_index_seed in any::<usize>(),
        byte_index_seed in any::<usize>(),
        delta in 1u8..=255u8,
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian signing original batch should succeed");

        let mut tampered_batch = batch.clone();
        let tx_index = tx_index_seed % tampered_batch.len();

        if tampered_batch[tx_index].is_empty() {
            tampered_batch[tx_index].push(delta);
        } else {
            let byte_index = byte_index_seed % tampered_batch[tx_index].len();
            tampered_batch[tx_index][byte_index] =
                tampered_batch[tx_index][byte_index].wrapping_add(delta);
        }

        let tampered_refs = batch_refs(&tampered_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &tampered_refs, &signature).is_err(),
            "guardian verification must reject changed transaction contents"
        );
    }

    // 04/25
    #[test]
    fn test_004_guardian_verify_rejects_appended_transaction(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..31
        ),
        extra_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian signing original batch should succeed");

        let mut modified_batch = batch.clone();

        let mut extra_tx = Vec::with_capacity(extra_tail.len() + 1);
        extra_tx.push(0xA5);
        extra_tx.extend_from_slice(&extra_tail);
        modified_batch.push(extra_tx);

        let modified_refs = batch_refs(&modified_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &modified_refs, &signature).is_err(),
            "guardian verification must reject a batch with an appended transaction"
        );
    }

    // 05/25
    #[test]
    fn test_005_guardian_verify_rejects_removed_transaction(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            1..32
        ),
        remove_index_seed in any::<usize>(),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian signing original batch should succeed");

        let mut modified_batch = batch.clone();
        let remove_index = remove_index_seed % modified_batch.len();
        modified_batch.remove(remove_index);

        let modified_refs = batch_refs(&modified_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &modified_refs, &signature).is_err(),
            "guardian verification must reject a batch with a removed transaction"
        );
    }

    // 06/25
    #[test]
    fn test_006_guardian_verify_rejects_reordered_distinct_transactions(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let left = tagged_transaction(0u8, &left_tail);
        let right = tagged_transaction(1u8, &right_tail);

        let original_batch = vec![left.clone(), right.clone()];
        let reordered_batch = vec![right, left];

        let original_refs = batch_refs(&original_batch);
        let reordered_refs = batch_refs(&reordered_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &original_refs)
            .expect("guardian signing original ordered batch should succeed");

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &reordered_refs, &signature).is_err(),
            "guardian verification must reject reordered distinct transactions"
        );
    }

    // 07/25
    #[test]
    fn test_007_guardian_verify_rejects_wrong_public_key(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let signer_kp = fresh_keypair();
        let wrong_kp = fresh_keypair();

        let signing_key = signer_kp
            .get_signing_key()
            .expect("generated guardian signer secret key should parse");

        let wrong_verifying_key = wrong_kp
            .get_verifying_key()
            .expect("generated wrong guardian public key should parse");

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian signing batch should succeed");

        prop_assert!(
            GuardianSignature::verify_batch(&wrong_verifying_key, &refs, &signature).is_err(),
            "guardian verification must reject a valid signature under the wrong public key"
        );
    }

    // 08/25
    #[test]
    fn test_008_guardian_verify_rejects_wrong_signature_lengths(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
        bad_len in 0usize..6000usize,
        fill in any::<u8>(),
    ) {
        let _guard = guardian_signature_proptest_guard();

        prop_assume!(bad_len != ml_dsa_65::SIG_LEN);

        let kp = fresh_keypair();

        let verifying_key = kp
            .get_verifying_key()
            .expect("generated guardian public key should parse");

        let refs = batch_refs(&batch);
        let bad_signature = vec![fill; bad_len];

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &refs, &bad_signature).is_err(),
            "guardian verification must reject signature length {bad_len}"
        );
    }

    // 09/25
    #[test]
    fn test_009_guardian_empty_batch_signs_and_verifies_against_dummy_merkle_root(
        _case in any::<u8>(),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let empty_batch: Vec<Vec<u8>> = Vec::new();
        let refs = batch_refs(&empty_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian empty batch signing should succeed because dummy Merkle leaf is supported");

        prop_assert_eq!(
            signature.len(),
            ml_dsa_65::SIG_LEN,
            "guardian empty batch signature must still have exact ML-DSA-65 signature length"
        );

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &refs, &signature).is_ok(),
            "guardian empty batch signature must verify against the same empty batch"
        );
    }

    // 10/25
    #[test]
    fn test_010_guardian_empty_batch_signature_rejects_single_empty_transaction(
        _case in any::<u8>(),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let empty_batch: Vec<Vec<u8>> = Vec::new();
        let empty_refs = batch_refs(&empty_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &empty_refs)
            .expect("guardian empty batch signing should succeed");

        let single_empty_batch = vec![Vec::<u8>::new()];
        let single_empty_refs = batch_refs(&single_empty_batch);

        prop_assert!(
            GuardianSignature::verify_batch(
                &verifying_key,
                &single_empty_refs,
                &signature
            ).is_err(),
            "guardian signature for empty batch must not verify as a batch containing one empty transaction"
        );
    }

    // 11/25
    #[test]
    fn test_011_guardian_single_empty_transaction_signature_rejects_empty_batch(
        _case in any::<u8>(),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let single_empty_batch = vec![Vec::<u8>::new()];
        let single_empty_refs = batch_refs(&single_empty_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &single_empty_refs)
            .expect("guardian single empty transaction batch signing should succeed");

        let empty_batch: Vec<Vec<u8>> = Vec::new();
        let empty_refs = batch_refs(&empty_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &empty_refs, &signature).is_err(),
            "guardian signature for one empty transaction must not verify as an empty batch"
        );
    }

    // 12/25
    #[test]
    fn test_012_guardian_signing_same_batch_twice_produces_verifiable_exact_length_signatures(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature_a = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("first guardian signing should succeed");

        let signature_b = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("second guardian signing should succeed");

        prop_assert_eq!(
            signature_a.len(),
            ml_dsa_65::SIG_LEN,
            "first guardian signature must have exact ML-DSA-65 length"
        );

        prop_assert_eq!(
            signature_b.len(),
            ml_dsa_65::SIG_LEN,
            "second guardian signature must have exact ML-DSA-65 length"
        );

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &refs, &signature_a).is_ok(),
            "first guardian signature over same batch must verify"
        );

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &refs, &signature_b).is_ok(),
            "second guardian signature over same batch must verify"
        );
    }

    // 13/25
    #[test]
    fn test_013_guardian_signature_verifies_against_independently_computed_merkle_root(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian batch signing should succeed");

        let independent_root = test_batch_merkle_root(&batch);

        let sig_array: &[u8; ml_dsa_65::SIG_LEN] = signature
            .as_slice()
            .try_into()
            .expect("guardian signature must be exact ML-DSA-65 length");

        prop_assert!(
            verifying_key.verify(&independent_root, sig_array, CONSENSUS_CTX_FOR_TEST),
            "guardian signature must verify against independently computed Merkle root"
        );
    }

    // 14/25
    #[test]
    fn test_014_guardian_batch_item_boundaries_are_signed_not_just_concatenated_bytes(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let left = tagged_transaction(0u8, &left_tail);
        let right = tagged_transaction(1u8, &right_tail);

        let split_batch = vec![left.clone(), right.clone()];
        let split_refs = batch_refs(&split_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &split_refs)
            .expect("guardian split batch signing should succeed");

        let mut combined = Vec::with_capacity(left.len() + right.len());
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);

        let combined_batch = vec![combined];
        let combined_refs = batch_refs(&combined_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &combined_refs, &signature).is_err(),
            "guardian signature for [left, right] must not verify for [left || right]"
        );
    }

    // 15/25
    #[test]
    fn test_015_guardian_concatenated_transaction_signature_does_not_verify_as_split_batch(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let left = tagged_transaction(0u8, &left_tail);
        let right = tagged_transaction(1u8, &right_tail);

        let mut combined = Vec::with_capacity(left.len() + right.len());
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);

        let combined_batch = vec![combined];
        let combined_refs = batch_refs(&combined_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &combined_refs)
            .expect("guardian combined batch signing should succeed");

        let split_batch = vec![left, right];
        let split_refs = batch_refs(&split_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &split_refs, &signature).is_err(),
            "guardian signature for [left || right] must not verify for [left, right]"
        );
    }

    // 16/25
    #[test]
    fn test_016_guardian_duplicate_transaction_multiplicity_is_signed(
        tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let tx = tagged_transaction(0xD0, &tail);

        let single_batch = vec![tx.clone()];
        let single_refs = batch_refs(&single_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &single_refs)
            .expect("guardian single duplicate-source batch signing should succeed");

        let duplicate_batch = vec![tx.clone(), tx];
        let duplicate_refs = batch_refs(&duplicate_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &duplicate_refs, &signature).is_err(),
            "guardian signature for one transaction must not verify for two identical copies"
        );
    }

    // 17/25
    #[test]
    fn test_017_guardian_duplicate_transaction_extra_copy_is_rejected(
        tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let tx = tagged_transaction(0xE1, &tail);

        let two_copy_batch = vec![tx.clone(), tx.clone()];
        let two_copy_refs = batch_refs(&two_copy_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &two_copy_refs)
            .expect("guardian two-copy batch signing should succeed");

        let three_copy_batch = vec![tx.clone(), tx.clone(), tx];
        let three_copy_refs = batch_refs(&three_copy_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &three_copy_refs, &signature).is_err(),
            "guardian signature for two identical transactions must not verify for three identical transactions"
        );
    }

    // 18/25
    #[test]
    fn test_018_guardian_three_distinct_transaction_rotation_is_rejected(
        a_tail in proptest::collection::vec(any::<u8>(), 0..128),
        b_tail in proptest::collection::vec(any::<u8>(), 0..128),
        c_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let a = tagged_transaction(0u8, &a_tail);
        let b = tagged_transaction(1u8, &b_tail);
        let c = tagged_transaction(2u8, &c_tail);

        let original_batch = vec![a.clone(), b.clone(), c.clone()];
        let rotated_batch = vec![b, c, a];

        let original_refs = batch_refs(&original_batch);
        let rotated_refs = batch_refs(&rotated_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &original_refs)
            .expect("guardian three-transaction batch signing should succeed");

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &rotated_refs, &signature).is_err(),
            "guardian verification must reject rotated three-transaction batch order"
        );
    }

    // 19/25
    #[test]
    fn test_019_guardian_swapping_first_and_last_in_larger_batch_is_rejected(
        a_tail in proptest::collection::vec(any::<u8>(), 0..128),
        b_tail in proptest::collection::vec(any::<u8>(), 0..128),
        c_tail in proptest::collection::vec(any::<u8>(), 0..128),
        d_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let a = tagged_transaction(0u8, &a_tail);
        let b = tagged_transaction(1u8, &b_tail);
        let c = tagged_transaction(2u8, &c_tail);
        let d = tagged_transaction(3u8, &d_tail);

        let original_batch = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let swapped_batch = vec![d, b, c, a];

        let original_refs = batch_refs(&original_batch);
        let swapped_refs = batch_refs(&swapped_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &original_refs)
            .expect("guardian four-transaction batch signing should succeed");

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &swapped_refs, &signature).is_err(),
            "guardian verification must reject first/last swap in a larger batch"
        );
    }

    // 20/25
    #[test]
    fn test_020_guardian_replacing_transaction_with_distinct_transaction_is_rejected(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
        replacement_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let left = tagged_transaction(0u8, &left_tail);
        let right = tagged_transaction(1u8, &right_tail);

        let original_batch = vec![left.clone(), right];
        let original_refs = batch_refs(&original_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &original_refs)
            .expect("guardian original batch signing should succeed");

        let replacement = tagged_transaction(2u8, &replacement_tail);
        let modified_batch = vec![left, replacement];
        let modified_refs = batch_refs(&modified_batch);

        prop_assert!(
            GuardianSignature::verify_batch(&verifying_key, &modified_refs, &signature).is_err(),
            "guardian verification must reject replacing a transaction even when batch shape remains valid"
        );
    }

    // 21/25
    #[test]
    fn test_021_guardian_whole_batch_replacement_with_same_item_count_is_rejected(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let a0 = tagged_transaction(0u8, &left_tail);
        let a1 = tagged_transaction(1u8, &right_tail);

        let b0 = tagged_transaction(2u8, &left_tail);
        let b1 = tagged_transaction(3u8, &right_tail);

        let original_batch = vec![a0, a1];
        let replacement_batch = vec![b0, b1];

        let original_refs = batch_refs(&original_batch);
        let replacement_refs = batch_refs(&replacement_batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &original_refs)
            .expect("guardian original batch signing should succeed");

        prop_assert!(
            GuardianSignature::verify_batch(
                &verifying_key,
                &replacement_refs,
                &signature
            ).is_err(),
            "guardian signature must be bound to transaction contents, not just item count"
        );
    }

    // 22/25
    #[test]
    fn test_022_guardian_verification_result_is_stable_across_repeated_calls(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let signature = GuardianSignature::sign_batch(&signing_key, &refs)
            .expect("guardian batch signing should succeed");

        let first = GuardianSignature::verify_batch(&verifying_key, &refs, &signature).is_ok();
        let second = GuardianSignature::verify_batch(&verifying_key, &refs, &signature).is_ok();

        prop_assert_eq!(
            first,
            second,
            "guardian verification result must be stable across repeated calls"
        );

        prop_assert!(
            first,
            "valid guardian signature must verify on repeated checks"
        );
    }

    // 23/25
    #[test]
    fn test_023_guardian_sign_batch_never_panics_for_arbitrary_bounded_batches(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, _verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            GuardianSignature::sign_batch(&signing_key, &refs)
        }));

        prop_assert!(
            result.is_ok(),
            "GuardianSignature::sign_batch must never panic for arbitrary bounded batches"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_ok(),
            "GuardianSignature::sign_batch should succeed for arbitrary bounded batches"
        );
    }

    // 24/25
    #[test]
    fn test_024_guardian_verify_batch_never_panics_for_arbitrary_external_signature_bytes(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
        signature_bytes in proptest::collection::vec(any::<u8>(), 0..6000),
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (_signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            GuardianSignature::verify_batch(&verifying_key, &refs, &signature_bytes)
        }));

        prop_assert!(
            result.is_ok(),
            "GuardianSignature::verify_batch must never panic for arbitrary external signature bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_guardian_direct_signature_over_wrong_root_does_not_verify_as_batch_signature(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..32
        ),
        byte_index in 0usize..64usize,
        delta in 1u8..=255u8,
    ) {
        let _guard = guardian_signature_proptest_guard();

        let (signing_key, verifying_key) = fresh_guardian_signing_and_verifying_keys();

        let refs = batch_refs(&batch);

        let mut wrong_root = test_batch_merkle_root(&batch);
        wrong_root[byte_index] = wrong_root[byte_index].wrapping_add(delta);

        let wrong_root_signature: [u8; ml_dsa_65::SIG_LEN] = signing_key
            .try_sign(&wrong_root, CONSENSUS_CTX_FOR_TEST)
            .expect("direct ML-DSA signing of wrong guardian root should succeed");

        prop_assert!(
            GuardianSignature::verify_batch(
                &verifying_key,
                &refs,
                &wrong_root_signature
            ).is_err(),
            "guardian signature over a different Merkle root must not verify as the batch signature"
        );
    }
}
