use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::cryptography::ml_dsa_65_002_merkleproof::{
    MerkleProof, compute_merkle_root, deserialize_merkle_proof, generate_merkle_proof,
    serialize_merkle_proof, verify_merkle_proof,
};
use remzar::utility::helper::Hash64;

fn batch_refs(batch: &[Vec<u8>]) -> Vec<&[u8]> {
    batch.iter().map(Vec::as_slice).collect()
}

fn vec64_to_array(bytes: &[u8]) -> [u8; 64] {
    assert_eq!(bytes.len(), 64, "test helper requires exactly 64 bytes");

    let mut out = [0u8; 64];
    out.copy_from_slice(bytes);
    out
}

fn vec64_to_hash64(bytes: &[u8]) -> Hash64 {
    Hash64::from_bytes(vec64_to_array(bytes))
}

fn vec64s_to_arrays(items: &[Vec<u8>]) -> Vec<[u8; 64]> {
    items.iter().map(|item| vec64_to_array(item)).collect()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_generated_proof_verifies_for_any_included_transaction(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed for included transaction");

        prop_assert!(
            verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "generated proof must verify against its Merkle root"
        );
    }

    // 02/25
    #[test]
    fn test_002_generated_proof_is_deterministic_for_same_batch_and_target(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof_a = generate_merkle_proof(&refs, target)
            .expect("first proof generation should succeed");

        let proof_b = generate_merkle_proof(&refs, target)
            .expect("second proof generation should succeed");

        prop_assert_eq!(
            proof_a.transaction_hash.as_bytes(),
            proof_b.transaction_hash.as_bytes(),
            "same batch and target must produce same transaction hash"
        );

        prop_assert_eq!(
            proof_a.merkle_root.as_bytes(),
            proof_b.merkle_root.as_bytes(),
            "same batch and target must produce same Merkle root"
        );

        prop_assert_eq!(
            proof_a.path,
            proof_b.path,
            "same batch and target must produce same path"
        );

        prop_assert_eq!(
            proof_a.sibling_hashes.len(),
            proof_b.sibling_hashes.len(),
            "same batch and target must produce same sibling count"
        );

        for (left, right) in proof_a.sibling_hashes.iter().zip(proof_b.sibling_hashes.iter()) {
            prop_assert_eq!(
                left.as_bytes(),
                right.as_bytes(),
                "same batch and target must produce same sibling hashes"
            );
        }
    }

    // 03/25
    #[test]
    fn test_003_tampered_signed_root_is_rejected(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
        byte_index in 0usize..64usize,
        delta in 1u8..=255u8,
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let mut tampered_root = *proof.merkle_root.as_bytes();
        tampered_root[byte_index] = tampered_root[byte_index].wrapping_add(delta);

        prop_assert!(
            !verify_merkle_proof(&proof, &tampered_root),
            "proof must reject tampered signed Merkle root"
        );
    }

    // 04/25
    #[test]
    fn test_004_tampered_sibling_hash_is_rejected(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            2..64
        ),
        target_index in any::<usize>(),
        sibling_index_seed in any::<usize>(),
        byte_index in 0usize..64usize,
        delta in 1u8..=255u8,
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let mut proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        prop_assume!(!proof.sibling_hashes.is_empty());

        let sibling_index = sibling_index_seed % proof.sibling_hashes.len();

        let mut tampered_sibling = *proof.sibling_hashes[sibling_index].as_bytes();
        tampered_sibling[byte_index] = tampered_sibling[byte_index].wrapping_add(delta);
        proof.sibling_hashes[sibling_index] = Hash64::from_bytes(tampered_sibling);

        prop_assert!(
            !verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "proof must reject tampered sibling hash"
        );
    }

    // 05/25
    #[test]
    fn test_005_serialize_deserialize_roundtrip_preserves_valid_proof(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let encoded = serialize_merkle_proof(&proof)
            .expect("proof serialization should succeed");

        let decoded = deserialize_merkle_proof(&encoded)
            .expect("proof deserialization should succeed");

        prop_assert_eq!(
            decoded.transaction_hash.as_bytes(),
            proof.transaction_hash.as_bytes(),
            "roundtrip must preserve transaction hash"
        );

        prop_assert_eq!(
            decoded.merkle_root.as_bytes(),
            proof.merkle_root.as_bytes(),
            "roundtrip must preserve Merkle root"
        );

        prop_assert_eq!(
            &decoded.path,
            &proof.path,
            "roundtrip must preserve path"
        );

        prop_assert_eq!(
            decoded.sibling_hashes.len(),
            proof.sibling_hashes.len(),
            "roundtrip must preserve sibling count"
        );

        for (left, right) in decoded.sibling_hashes.iter().zip(proof.sibling_hashes.iter()) {
            prop_assert_eq!(
                left.as_bytes(),
                right.as_bytes(),
                "roundtrip must preserve sibling hashes"
            );
        }

        prop_assert!(
            verify_merkle_proof(&decoded, decoded.merkle_root.as_bytes()),
            "deserialized proof must verify"
        );
    }

    // 06/25
    #[test]
    fn test_006_deserialize_rejects_serialized_proof_with_trailing_bytes(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
        extra in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let mut encoded = serialize_merkle_proof(&proof)
            .expect("proof serialization should succeed");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            deserialize_merkle_proof(&encoded).is_err(),
            "deserializer must reject proof bytes with trailing data"
        );
    }

    // 07/25
    #[test]
    fn test_007_deserialize_rejects_truncated_serialized_proof(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
        keep_seed in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let encoded = serialize_merkle_proof(&proof)
            .expect("proof serialization should succeed");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            deserialize_merkle_proof(truncated).is_err(),
            "deserializer must reject truncated proof bytes"
        );
    }

    // 08/25
    #[test]
    fn test_008_generate_merkle_proof_rejects_empty_batch(
        target in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let empty_batch: Vec<&[u8]> = Vec::new();

        prop_assert!(
            generate_merkle_proof(&empty_batch, &target).is_err(),
            "proof generation must reject empty batch"
        );
    }

    // 09/25
    #[test]
    fn test_009_generate_merkle_proof_rejects_target_not_in_batch(
        tails in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            1..64
        ),
        target_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let batch: Vec<Vec<u8>> = tails
            .into_iter()
            .map(|mut tail| {
                let mut tx = Vec::with_capacity(tail.len() + 1);
                tx.push(0u8);
                tx.append(&mut tail);
                tx
            })
            .collect();

        let mut target = Vec::with_capacity(target_tail.len() + 1);
        target.push(255u8);
        target.extend_from_slice(&target_tail);

        let refs = batch_refs(&batch);

        prop_assert!(
            generate_merkle_proof(&refs, &target).is_err(),
            "proof generation must reject target transaction that is not in batch"
        );
    }

    // 10/25
    #[test]
    fn test_010_generated_proof_has_consistent_shape_for_any_valid_batch(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        prop_assert_eq!(
            proof.sibling_hashes.len(),
            proof.path.len(),
            "generated proof must always have one path bit per sibling hash"
        );

        if refs.len() == 1 {
            prop_assert!(
                proof.sibling_hashes.is_empty(),
                "single-leaf proof must not need sibling hashes"
            );

            prop_assert!(
                proof.path.is_empty(),
                "single-leaf proof must not need path bits"
            );
        } else {
            prop_assert!(
                !proof.sibling_hashes.is_empty(),
                "multi-leaf proof must contain at least one sibling hash"
            );

            prop_assert!(
                !proof.path.is_empty(),
                "multi-leaf proof must contain at least one path bit"
            );
        }

        prop_assert!(
            verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "shape-valid generated proof must verify"
        );
    }

    // 11/25
    #[test]
    fn test_011_single_transaction_proof_has_empty_path_and_root_equals_transaction_hash(
        target in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let refs = vec![target.as_slice()];

        let proof = generate_merkle_proof(&refs, &target)
            .expect("single transaction proof generation should succeed");

        prop_assert!(
            proof.sibling_hashes.is_empty(),
            "single transaction proof must have no siblings"
        );

        prop_assert!(
            proof.path.is_empty(),
            "single transaction proof must have no path bits"
        );

        prop_assert_eq!(
            proof.transaction_hash.as_bytes(),
            proof.merkle_root.as_bytes(),
            "single transaction Merkle root must equal the transaction leaf hash"
        );

        prop_assert!(
            verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "single transaction proof must verify"
        );
    }

    // 12/25
    #[test]
    fn test_012_two_transaction_proofs_have_correct_left_and_right_path_direction(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut left_tx = Vec::with_capacity(left_tail.len() + 1);
        left_tx.push(0u8);
        left_tx.extend_from_slice(&left_tail);

        let mut right_tx = Vec::with_capacity(right_tail.len() + 1);
        right_tx.push(1u8);
        right_tx.extend_from_slice(&right_tail);

        let refs = vec![left_tx.as_slice(), right_tx.as_slice()];

        let left_proof = generate_merkle_proof(&refs, &left_tx)
            .expect("left proof generation should succeed");

        let right_proof = generate_merkle_proof(&refs, &right_tx)
            .expect("right proof generation should succeed");

        prop_assert_eq!(
            left_proof.path.as_slice(),
            &[true],
            "first transaction in a two-leaf tree must be marked as left child"
        );

        prop_assert_eq!(
            right_proof.path.as_slice(),
            &[false],
            "second transaction in a two-leaf tree must be marked as right child"
        );

        prop_assert_eq!(
            left_proof.sibling_hashes.len(),
            1,
            "two-leaf proof must have exactly one sibling"
        );

        prop_assert_eq!(
            right_proof.sibling_hashes.len(),
            1,
            "two-leaf proof must have exactly one sibling"
        );

        prop_assert_eq!(
            left_proof.sibling_hashes[0].as_bytes(),
            right_proof.transaction_hash.as_bytes(),
            "left proof sibling must be right transaction hash"
        );

        prop_assert_eq!(
            right_proof.sibling_hashes[0].as_bytes(),
            left_proof.transaction_hash.as_bytes(),
            "right proof sibling must be left transaction hash"
        );

        prop_assert!(
            verify_merkle_proof(&left_proof, left_proof.merkle_root.as_bytes()),
            "left proof must verify"
        );

        prop_assert!(
            verify_merkle_proof(&right_proof, right_proof.merkle_root.as_bytes()),
            "right proof must verify"
        );
    }

    // 13/25
    #[test]
    fn test_013_odd_leaf_tree_duplicates_last_leaf_as_first_sibling_for_last_target(
        first_tail in proptest::collection::vec(any::<u8>(), 0..128),
        second_tail in proptest::collection::vec(any::<u8>(), 0..128),
        third_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut first_tx = Vec::with_capacity(first_tail.len() + 1);
        first_tx.push(0u8);
        first_tx.extend_from_slice(&first_tail);

        let mut second_tx = Vec::with_capacity(second_tail.len() + 1);
        second_tx.push(1u8);
        second_tx.extend_from_slice(&second_tail);

        let mut third_tx = Vec::with_capacity(third_tail.len() + 1);
        third_tx.push(2u8);
        third_tx.extend_from_slice(&third_tail);

        let refs = vec![first_tx.as_slice(), second_tx.as_slice(), third_tx.as_slice()];

        let proof = generate_merkle_proof(&refs, &third_tx)
            .expect("odd three-leaf proof generation should succeed");

        prop_assert!(
            !proof.sibling_hashes.is_empty(),
            "three-leaf proof must have at least one sibling"
        );

        prop_assert!(
            !proof.path.is_empty(),
            "three-leaf proof must have at least one path bit"
        );

        prop_assert_eq!(
            proof.path[0],
            true,
            "third leaf index 2 is treated as a left child before duplicate-last pairing"
        );

        prop_assert_eq!(
            proof.sibling_hashes[0].as_bytes(),
            proof.transaction_hash.as_bytes(),
            "odd last leaf must use itself as its first sibling"
        );

        prop_assert!(
            verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "odd duplicate-last proof must verify"
        );
    }

    // 14/25
    #[test]
    fn test_014_serializing_same_valid_proof_twice_is_byte_deterministic(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let encoded_a = serialize_merkle_proof(&proof)
            .expect("first proof serialization should succeed");

        let encoded_b = serialize_merkle_proof(&proof)
            .expect("second proof serialization should succeed");

        prop_assert_eq!(
            encoded_a,
            encoded_b,
            "serializing the same proof twice must produce identical bytes"
        );
    }

    // 15/25
    #[test]
    fn test_015_deserialize_then_serialize_preserves_canonical_bytes_exactly(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let encoded = serialize_merkle_proof(&proof)
            .expect("proof serialization should succeed");

        let decoded = deserialize_merkle_proof(&encoded)
            .expect("proof deserialization should succeed");

        let reencoded = serialize_merkle_proof(&decoded)
            .expect("proof reserialization should succeed");

        prop_assert_eq!(
            reencoded,
            encoded,
            "deserialize -> serialize must preserve canonical postcard bytes exactly"
        );
    }

    // 16/25
    #[test]
    fn test_016_flipping_path_direction_rejects_two_leaf_proof(
        left_tail in proptest::collection::vec(any::<u8>(), 0..128),
        right_tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut left_tx = Vec::with_capacity(left_tail.len() + 1);
        left_tx.push(0u8);
        left_tx.extend_from_slice(&left_tail);

        let mut right_tx = Vec::with_capacity(right_tail.len() + 1);
        right_tx.push(1u8);
        right_tx.extend_from_slice(&right_tail);

        let refs = vec![left_tx.as_slice(), right_tx.as_slice()];

        let mut proof = generate_merkle_proof(&refs, &left_tx)
            .expect("two-leaf proof generation should succeed");

        prop_assert_eq!(
            proof.path.len(),
            1,
            "two-leaf proof must have one path bit"
        );

        proof.path[0] = !proof.path[0];

        prop_assert!(
            !verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "flipping left/right direction must invalidate the proof"
        );
    }

    // 17/25
    #[test]
    fn test_017_tampered_transaction_hash_is_rejected(
        target in proptest::collection::vec(any::<u8>(), 0..256),
        byte_index in 0usize..64usize,
        delta in 1u8..=255u8,
    ) {
        let refs = vec![target.as_slice()];

        let mut proof = generate_merkle_proof(&refs, &target)
            .expect("single transaction proof generation should succeed");

        let mut tampered_tx_hash = *proof.transaction_hash.as_bytes();
        tampered_tx_hash[byte_index] = tampered_tx_hash[byte_index].wrapping_add(delta);
        proof.transaction_hash = Hash64::from_bytes(tampered_tx_hash);

        prop_assert!(
            !verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
            "tampered transaction hash must invalidate the proof"
        );
    }

    // 18/25
    #[test]
    fn test_018_tampered_embedded_merkle_root_is_rejected_even_when_signed_root_is_original(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
        byte_index in 0usize..64usize,
        delta in 1u8..=255u8,
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let mut proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let signed_root = *proof.merkle_root.as_bytes();

        let mut tampered_embedded_root = *proof.merkle_root.as_bytes();
        tampered_embedded_root[byte_index] =
            tampered_embedded_root[byte_index].wrapping_add(delta);
        proof.merkle_root = Hash64::from_bytes(tampered_embedded_root);

        prop_assert!(
            !verify_merkle_proof(&proof, &signed_root),
            "proof must reject tampered embedded Merkle root even when signed root is correct"
        );
    }

    // 19/25
    #[test]
    fn test_019_verify_rejects_extra_sibling_without_matching_path_bit(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let mut proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let signed_root = *proof.merkle_root.as_bytes();
        proof.sibling_hashes.push(proof.transaction_hash);

        prop_assert!(
            !verify_merkle_proof(&proof, &signed_root),
            "verifier must reject sibling/path length mismatch with extra sibling"
        );
    }

    // 20/25
    #[test]
    fn test_020_verify_rejects_extra_path_bit_without_matching_sibling(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
        extra_direction in any::<bool>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let mut proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        let signed_root = *proof.merkle_root.as_bytes();
        proof.path.push(extra_direction);

        prop_assert!(
            !verify_merkle_proof(&proof, &signed_root),
            "verifier must reject sibling/path length mismatch with extra path bit"
        );
    }

    // 21/25
    #[test]
    fn test_021_safe_serializer_rejects_malformed_proof_with_extra_sibling(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let mut proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        proof.sibling_hashes.push(proof.transaction_hash);

        prop_assert!(
            serialize_merkle_proof(&proof).is_err(),
            "safe serializer must reject malformed proof where sibling count != path count"
        );
    }

    // 22/25
    #[test]
    fn test_022_deserializer_rejects_postcard_bytes_for_malformed_shape(
        batch in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256),
            1..64
        ),
        target_index in any::<usize>(),
        extra_direction in any::<bool>(),
    ) {
        let refs = batch_refs(&batch);
        let target = refs[target_index % refs.len()];

        let mut proof = generate_merkle_proof(&refs, target)
            .expect("proof generation should succeed");

        proof.path.push(extra_direction);

        let encoded = postcard::to_stdvec(&proof)
            .expect("direct postcard encoding should succeed for malformed test object");

        prop_assert!(
            deserialize_merkle_proof(&encoded).is_err(),
            "deserializer must reject postcard bytes whose decoded proof shape is malformed"
        );
    }

    // 23/25
    #[test]
    fn test_023_compute_merkle_root_is_deterministic_for_same_hash_inputs(
        hash_bytes in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 64..65),
            0..64
        ),
    ) {
        let hashes = vec64s_to_arrays(&hash_bytes);

        let (root_a, levels_a) = compute_merkle_root(&hashes)
            .expect("first Merkle root computation should succeed");

        let (root_b, levels_b) = compute_merkle_root(&hashes)
            .expect("second Merkle root computation should succeed");

        prop_assert_eq!(
            root_a,
            root_b,
            "same 64-byte hash inputs must produce same Merkle root"
        );

        prop_assert_eq!(
            levels_a.len(),
            levels_b.len(),
            "same 64-byte hash inputs must produce same number of levels"
        );

        for (level_a, level_b) in levels_a.iter().zip(levels_b.iter()) {
            prop_assert_eq!(
                level_a.len(),
                level_b.len(),
                "matching levels must have same width"
            );

            for (hash_a, hash_b) in level_a.iter().zip(level_b.iter()) {
                prop_assert_eq!(
                    hash_a.as_bytes(),
                    hash_b.as_bytes(),
                    "matching level hashes must be deterministic"
                );
            }
        }
    }

    // 24/25
    #[test]
    fn test_024_compute_merkle_root_empty_input_uses_single_deterministic_dummy_leaf(
        _case in any::<u8>(),
    ) {
        let empty: Vec<[u8; 64]> = Vec::new();

        let (root, levels) = compute_merkle_root(&empty)
            .expect("empty Merkle root computation should inject deterministic dummy leaf");

        prop_assert_eq!(
            levels.len(),
            1,
            "empty Merkle root computation must normalize to exactly one leaf level"
        );

        prop_assert_eq!(
            levels[0].len(),
            1,
            "empty Merkle root computation must contain exactly one dummy leaf"
        );

        prop_assert_eq!(
            levels[0][0].as_bytes(),
            &root,
            "empty Merkle root must equal the injected dummy leaf hash"
        );

        let proof = MerkleProof {
            transaction_hash: Hash64::from_bytes(root),
            sibling_hashes: Vec::new(),
            path: Vec::new(),
            merkle_root: Hash64::from_bytes(root),
        };

        prop_assert!(
            verify_merkle_proof(&proof, &root),
            "empty-tree dummy root should be self-consistent as an empty-depth proof"
        );
    }

    // 25/25
    #[test]
    fn test_025_verify_merkle_proof_never_panics_for_arbitrary_malformed_public_inputs(
        tx_hash in proptest::collection::vec(any::<u8>(), 64..65),
        embedded_root in proptest::collection::vec(any::<u8>(), 64..65),
        signed_root in proptest::collection::vec(any::<u8>(), 64..65),
        sibling_hashes in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 64..65),
            0..128
        ),
        path in proptest::collection::vec(any::<bool>(), 0..128),
    ) {
        let proof = MerkleProof {
            transaction_hash: vec64_to_hash64(&tx_hash),
            sibling_hashes: sibling_hashes
                .iter()
                .map(|bytes| vec64_to_hash64(bytes))
                .collect(),
            path,
            merkle_root: vec64_to_hash64(&embedded_root),
        };

        let signed_root = vec64_to_array(&signed_root);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_merkle_proof(&proof, &signed_root)
        }));

        prop_assert!(
            result.is_ok(),
            "verifier must never panic for arbitrary public MerkleProof-shaped inputs"
        );
    }
}
