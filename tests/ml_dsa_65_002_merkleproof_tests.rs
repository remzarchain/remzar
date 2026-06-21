use remzar::cryptography::ml_dsa_65_002_merkleproof::{
    MerkleProof, compute_merkle_root, deserialize_merkle_proof, generate_merkle_proof,
    serialize_merkle_proof, verify_merkle_proof,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::Hash64;

type TestResult = Result<(), String>;

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
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

fn node_hash64(left: &[u8; 64], right: &[u8; 64]) -> Result<[u8; 64], String> {
    let mut preimage = [0_u8; 128];

    let left_dst = preimage
        .get_mut(..64)
        .ok_or_else(|| "missing left node preimage range".to_string())?;
    left_dst.copy_from_slice(left);

    let right_dst = preimage
        .get_mut(64..)
        .ok_or_else(|| "missing right node preimage range".to_string())?;
    right_dst.copy_from_slice(right);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&preimage);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);
    Ok(out)
}

fn vector_hash(label: &[u8]) -> [u8; 64] {
    leaf_hash64(label)
}

fn expected_root_from_leaves(input: &[[u8; 64]]) -> Result<[u8; 64], String> {
    let mut nodes = if input.is_empty() {
        vec![leaf_hash64(b"remzar_empty_block_mint")]
    } else {
        input.to_vec()
    };

    while nodes.len() > 1 {
        let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));

        for pair in nodes.chunks(2) {
            let left = pair
                .first()
                .ok_or_else(|| "empty node pair while computing expected root".to_string())?;
            let right = pair.get(1).unwrap_or(left);
            parents.push(node_hash64(left, right)?);
        }

        nodes = parents;
    }

    nodes
        .first()
        .copied()
        .ok_or_else(|| "expected root computation produced no nodes".to_string())
}

fn assert_level_widths(levels: &[Vec<Hash64>], expected: &[usize]) -> TestResult {
    assert_eq!(levels.len(), expected.len());

    for (level, expected_len) in levels.iter().zip(expected.iter()) {
        assert_eq!(level.len(), *expected_len);
    }

    Ok(())
}

fn proof_for<'a>(batch: &'a [&'a [u8]], target: &'a [u8]) -> Result<MerkleProof, String> {
    generate_merkle_proof(batch, target).map_err(debug_err)
}

fn root_from_proof(proof: &MerkleProof) -> [u8; 64] {
    *proof.merkle_root.as_bytes()
}

fn flip_hash_byte(hash: &mut Hash64, position: usize) -> TestResult {
    let bytes = hash
        .0
        .get_mut(position)
        .ok_or_else(|| format!("hash byte position {position} out of bounds"))?;
    *bytes ^= 1;
    Ok(())
}

fn encoded_is_rejected_or_invalid(encoded: &[u8], root: &[u8; 64]) -> bool {
    match deserialize_merkle_proof(encoded) {
        Ok(proof) => !verify_merkle_proof(&proof, root),
        Err(_) => true,
    }
}

#[test]
fn merkle_001_empty_compute_root_uses_deterministic_dummy_leaf() -> TestResult {
    let (root, levels) = compute_merkle_root(&[]).map_err(debug_err)?;
    let expected = expected_root_from_leaves(&[])?;

    assert_eq!(root, expected);
    assert_level_widths(&levels, &[1])?;
    assert_eq!(levels.first().map(Vec::len), Some(1));

    Ok(())
}

#[test]
fn merkle_002_single_hash_root_equals_single_leaf() -> TestResult {
    let leaf = vector_hash(b"single-leaf");
    let leaves = vec![leaf];
    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_eq!(root, leaf);
    assert_level_widths(&levels, &[1])?;

    Ok(())
}

#[test]
fn merkle_003_two_hash_root_matches_left_right_node_vector() -> TestResult {
    let left = vector_hash(b"left");
    let right = vector_hash(b"right");
    let leaves = vec![left, right];

    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let expected = node_hash64(&left, &right)?;

    assert_eq!(root, expected);
    assert_level_widths(&levels, &[2, 1])?;

    Ok(())
}

#[test]
fn merkle_004_three_hash_root_duplicates_last_leaf() -> TestResult {
    let first = vector_hash(b"first");
    let second = vector_hash(b"second");
    let third = vector_hash(b"third");
    let leaves = vec![first, second, third];

    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let left_parent = node_hash64(&first, &second)?;
    let right_parent = node_hash64(&third, &third)?;
    let expected = node_hash64(&left_parent, &right_parent)?;

    assert_eq!(root, expected);
    assert_level_widths(&levels, &[3, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_005_four_hash_root_matches_balanced_tree_vector() -> TestResult {
    let a = vector_hash(b"a");
    let b = vector_hash(b"b");
    let c = vector_hash(b"c");
    let d = vector_hash(b"d");
    let leaves = vec![a, b, c, d];

    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let left_parent = node_hash64(&a, &b)?;
    let right_parent = node_hash64(&c, &d)?;
    let expected = node_hash64(&left_parent, &right_parent)?;

    assert_eq!(root, expected);
    assert_level_widths(&levels, &[4, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_006_compute_root_is_deterministic_for_same_input() -> TestResult {
    let leaves = vec![
        vector_hash(b"tx-0"),
        vector_hash(b"tx-1"),
        vector_hash(b"tx-2"),
        vector_hash(b"tx-3"),
        vector_hash(b"tx-4"),
    ];

    let (first_root, first_levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let (second_root, second_levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_eq!(first_root, second_root);
    assert_eq!(first_levels.len(), second_levels.len());

    Ok(())
}

#[test]
fn merkle_007_compute_root_is_order_sensitive() -> TestResult {
    let ordered = vec![
        vector_hash(b"tx-a"),
        vector_hash(b"tx-b"),
        vector_hash(b"tx-c"),
    ];
    let reordered = vec![
        vector_hash(b"tx-c"),
        vector_hash(b"tx-b"),
        vector_hash(b"tx-a"),
    ];

    let (ordered_root, _) = compute_merkle_root(&ordered).map_err(debug_err)?;
    let (reordered_root, _) = compute_merkle_root(&reordered).map_err(debug_err)?;

    assert_ne!(ordered_root, reordered_root);

    Ok(())
}

#[test]
fn merkle_008_compute_root_rejects_hash_count_above_config_limit() -> TestResult {
    let count = GlobalConfiguration::MAX_BATCH_ITEMS.saturating_add(1);
    let hashes = vec![[0_u8; 64]; count];

    assert!(compute_merkle_root(&hashes).is_err());

    Ok(())
}

#[test]
fn merkle_009_generate_proof_rejects_empty_batch() -> TestResult {
    assert!(generate_merkle_proof(&[], b"missing").is_err());
    Ok(())
}

#[test]
fn merkle_010_generate_proof_rejects_missing_target() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"one".as_slice(), b"two".as_slice(), b"three".as_slice()];

    assert!(generate_merkle_proof(&batch, b"four").is_err());

    Ok(())
}

#[test]
fn merkle_011_single_transaction_proof_has_empty_path_and_verifies() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"solo".as_slice()];
    let proof = proof_for(&batch, b"solo")?;
    let root = root_from_proof(&proof);

    assert!(proof.sibling_hashes.is_empty());
    assert!(proof.path.is_empty());
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_012_two_transaction_left_proof_has_right_sibling() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"left-tx".as_slice(), b"right-tx".as_slice()];
    let proof = proof_for(&batch, b"left-tx")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.sibling_hashes.len(), 1);
    assert_eq!(proof.path, vec![true]);
    assert_eq!(
        proof.sibling_hashes.first().map(Hash64::as_bytes),
        Some(&leaf_hash64(b"right-tx"))
    );
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_013_two_transaction_right_proof_has_left_sibling() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"left-tx".as_slice(), b"right-tx".as_slice()];
    let proof = proof_for(&batch, b"right-tx")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.sibling_hashes.len(), 1);
    assert_eq!(proof.path, vec![false]);
    assert_eq!(
        proof.sibling_hashes.first().map(Hash64::as_bytes),
        Some(&leaf_hash64(b"left-tx"))
    );
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_014_three_transaction_last_proof_uses_odd_duplicate_rule() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"first".as_slice(),
        b"second".as_slice(),
        b"third".as_slice(),
    ];
    let proof = proof_for(&batch, b"third")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.sibling_hashes.len(), 2);
    assert_eq!(proof.path, vec![true, false]);
    assert_eq!(
        proof.sibling_hashes.first().map(Hash64::as_bytes),
        Some(&leaf_hash64(b"third"))
    );
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_015_all_targets_in_five_transaction_batch_verify() -> TestResult {
    let txs: Vec<&[u8]> = vec![
        b"tx-0".as_slice(),
        b"tx-1".as_slice(),
        b"tx-2".as_slice(),
        b"tx-3".as_slice(),
        b"tx-4".as_slice(),
    ];

    for target in &txs {
        let proof = proof_for(&txs, target)?;
        let root = root_from_proof(&proof);
        assert!(verify_merkle_proof(&proof, &root));
    }

    Ok(())
}

#[test]
fn merkle_016_duplicate_transaction_target_still_generates_valid_proof() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"dup".as_slice(),
        b"middle".as_slice(),
        b"dup".as_slice(),
        b"tail".as_slice(),
    ];
    let proof = proof_for(&batch, b"dup")?;
    let root = root_from_proof(&proof);

    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_017_serialize_deserialize_roundtrip_preserves_proof_fields() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let decoded = deserialize_merkle_proof(&encoded).map_err(debug_err)?;

    assert_eq!(
        decoded.transaction_hash.as_bytes(),
        proof.transaction_hash.as_bytes()
    );
    assert_eq!(decoded.sibling_hashes.len(), proof.sibling_hashes.len());
    assert_eq!(decoded.path, proof.path);
    assert_eq!(decoded.merkle_root.as_bytes(), proof.merkle_root.as_bytes());

    Ok(())
}

#[test]
fn merkle_018_deserialized_proof_verifies_against_embedded_root() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"c")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let decoded = deserialize_merkle_proof(&encoded).map_err(debug_err)?;
    let root = root_from_proof(&decoded);

    assert!(verify_merkle_proof(&decoded, &root));

    Ok(())
}

#[test]
fn merkle_019_deserialize_rejects_empty_bytes() -> TestResult {
    assert!(deserialize_merkle_proof(&[]).is_err());
    Ok(())
}

#[test]
fn merkle_020_deserialize_rejects_random_invalid_bytes() -> TestResult {
    let invalid = b"not a postcard merkle proof";

    assert!(deserialize_merkle_proof(invalid).is_err());

    Ok(())
}

#[test]
fn merkle_021_deserialize_rejects_truncated_encoded_proof() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let proof = proof_for(&batch, b"a")?;
    let mut encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;

    encoded.truncate(encoded.len().saturating_sub(1));

    assert!(deserialize_merkle_proof(&encoded).is_err());

    Ok(())
}

#[test]
fn merkle_022_deserialize_rejects_extra_trailing_byte() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let proof = proof_for(&batch, b"a")?;
    let mut encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;

    encoded.push(0);

    assert!(deserialize_merkle_proof(&encoded).is_err());

    Ok(())
}

#[test]
fn merkle_023_serialize_rejects_mismatched_sibling_and_path_lengths() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;

    proof.path.push(true);

    assert!(serialize_merkle_proof(&proof).is_err());

    Ok(())
}

#[test]
fn merkle_024_deserialize_rejects_mismatched_sibling_and_path_lengths() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;

    proof.path.push(true);

    let encoded = postcard::to_stdvec(&proof).map_err(debug_err)?;
    assert!(deserialize_merkle_proof(&encoded).is_err());

    Ok(())
}

#[test]
fn merkle_025_verify_returns_false_for_mismatched_sibling_and_path_lengths() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    proof.path.push(false);

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_026_verify_returns_false_for_wrong_signed_root() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let proof = proof_for(&batch, b"a")?;
    let mut wrong_root = root_from_proof(&proof);

    let first = wrong_root
        .get_mut(0)
        .ok_or_else(|| "missing root byte".to_string())?;
    *first ^= 1;

    assert!(!verify_merkle_proof(&proof, &wrong_root));

    Ok(())
}

#[test]
fn merkle_027_verify_returns_false_for_tampered_embedded_root() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let signed_root = root_from_proof(&proof);

    flip_hash_byte(&mut proof.merkle_root, 0)?;

    assert!(!verify_merkle_proof(&proof, &signed_root));

    Ok(())
}

#[test]
fn merkle_028_verify_returns_false_for_tampered_transaction_hash() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    flip_hash_byte(&mut proof.transaction_hash, 0)?;

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_029_verify_returns_false_for_tampered_sibling_hash() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    let sibling = proof
        .sibling_hashes
        .get_mut(0)
        .ok_or_else(|| "missing proof sibling".to_string())?;
    flip_hash_byte(sibling, 0)?;

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_030_verify_returns_false_for_tampered_path_direction() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    let first_path = proof
        .path
        .get_mut(0)
        .ok_or_else(|| "missing proof path element".to_string())?;
    *first_path = !*first_path;

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_031_verify_empty_depth_proof_requires_tx_and_root_to_match() -> TestResult {
    let transaction_hash = Hash64::from_bytes(vector_hash(b"transaction"));
    let merkle_root = Hash64::from_bytes(vector_hash(b"different-root"));
    let signed_root = *merkle_root.as_bytes();

    let proof = MerkleProof {
        transaction_hash,
        sibling_hashes: Vec::new(),
        path: Vec::new(),
        merkle_root,
    };

    assert!(!verify_merkle_proof(&proof, &signed_root));

    Ok(())
}

#[test]
fn merkle_032_serialize_rejects_absurd_proof_depth() -> TestResult {
    let transaction_hash = Hash64::from_bytes(vector_hash(b"tx"));
    let merkle_root = Hash64::from_bytes(vector_hash(b"root"));
    let sibling = Hash64::from_bytes(vector_hash(b"sibling"));

    let proof = MerkleProof {
        transaction_hash,
        sibling_hashes: vec![sibling; 4_097],
        path: vec![true; 4_097],
        merkle_root,
    };

    assert!(serialize_merkle_proof(&proof).is_err());

    Ok(())
}

#[test]
fn merkle_033_verify_rejects_absurd_proof_depth() -> TestResult {
    let transaction_hash = Hash64::from_bytes(vector_hash(b"tx"));
    let merkle_root = Hash64::from_bytes(vector_hash(b"root"));
    let sibling = Hash64::from_bytes(vector_hash(b"sibling"));
    let signed_root = *merkle_root.as_bytes();

    let proof = MerkleProof {
        transaction_hash,
        sibling_hashes: vec![sibling; 4_097],
        path: vec![true; 4_097],
        merkle_root,
    };

    assert!(!verify_merkle_proof(&proof, &signed_root));

    Ok(())
}

#[test]
fn merkle_034_generate_rejects_batch_item_larger_than_max_item_bytes() -> TestResult {
    let too_large = vec![7_u8; GlobalConfiguration::MAX_ITEM_BYTES.saturating_add(1)];
    let batch: Vec<&[u8]> = vec![too_large.as_slice()];

    assert!(generate_merkle_proof(&batch, too_large.as_slice()).is_err());

    Ok(())
}

#[test]
fn merkle_035_generate_rejects_target_larger_than_max_item_bytes() -> TestResult {
    let valid = b"valid";
    let target = vec![9_u8; GlobalConfiguration::MAX_ITEM_BYTES.saturating_add(1)];
    let batch: Vec<&[u8]> = vec![valid.as_slice()];

    assert!(generate_merkle_proof(&batch, &target).is_err());

    Ok(())
}

#[test]
fn merkle_036_generate_rejects_batch_count_above_max_items() -> TestResult {
    let item = b"x".as_slice();
    let count = GlobalConfiguration::MAX_BATCH_ITEMS.saturating_add(1);
    let batch: Vec<&[u8]> = vec![item; count];

    assert!(generate_merkle_proof(&batch, item).is_err());

    Ok(())
}

#[test]
fn merkle_037_compute_rejects_hash_count_above_max_items() -> TestResult {
    let count = GlobalConfiguration::MAX_BATCH_ITEMS.saturating_add(1);
    let hashes = vec![[1_u8; 64]; count];

    assert!(compute_merkle_root(&hashes).is_err());

    Ok(())
}

#[test]
fn merkle_038_generate_rejects_total_batch_bytes_above_limit() -> TestResult {
    let one_mib = vec![3_u8; 1024 * 1024];
    let repeat_count = GlobalConfiguration::MAX_TOTAL_BATCH_BYTES
        .div_euclid(one_mib.len())
        .saturating_add(1);
    let batch: Vec<&[u8]> = vec![one_mib.as_slice(); repeat_count];

    assert!(generate_merkle_proof(&batch, one_mib.as_slice()).is_err());

    Ok(())
}

#[test]
fn merkle_039_adversarial_network_reordered_encoded_fragments_do_not_verify() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"network-a".as_slice(),
        b"network-b".as_slice(),
        b"network-c".as_slice(),
        b"network-d".as_slice(),
    ];
    let proof = proof_for(&batch, b"network-c")?;
    let root = root_from_proof(&proof);
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;

    let first = encoded
        .get(..16)
        .ok_or_else(|| "missing first encoded fragment".to_string())?;
    let middle = encoded
        .get(16..64)
        .ok_or_else(|| "missing middle encoded fragment".to_string())?;
    let last = encoded
        .get(64..)
        .ok_or_else(|| "missing last encoded fragment".to_string())?;

    let mut reordered = Vec::with_capacity(encoded.len());
    reordered.extend_from_slice(middle);
    reordered.extend_from_slice(first);
    reordered.extend_from_slice(last);

    assert!(encoded_is_rejected_or_invalid(&reordered, &root));

    Ok(())
}

#[test]
fn merkle_040_load_test_generate_serialize_deserialize_verify_many_small_proofs() -> TestResult {
    let txs: Vec<Vec<u8>> = (0_u8..32_u8).map(|n| vec![b't', b'x', b'-', n]).collect();

    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();

    for tx in &batch {
        let proof = proof_for(&batch, tx)?;
        let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
        let decoded = deserialize_merkle_proof(&encoded).map_err(debug_err)?;
        let root = root_from_proof(&decoded);

        assert!(verify_merkle_proof(&decoded, &root));
    }

    Ok(())
}

#[test]
fn merkle_041_clone_preserves_all_proof_fields() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;
    let cloned = proof.clone();

    assert_eq!(
        cloned.transaction_hash.as_bytes(),
        proof.transaction_hash.as_bytes()
    );
    assert_eq!(cloned.sibling_hashes.len(), proof.sibling_hashes.len());
    assert_eq!(cloned.path, proof.path);
    assert_eq!(cloned.merkle_root.as_bytes(), proof.merkle_root.as_bytes());

    Ok(())
}

#[test]
fn merkle_042_debug_output_identifies_merkle_proof() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let proof = proof_for(&batch, b"a")?;
    let debug_output = format!("{proof:?}");

    assert!(debug_output.contains("MerkleProof"));
    assert!(debug_output.contains("transaction_hash"));
    assert!(debug_output.contains("sibling_hashes"));
    assert!(debug_output.contains("merkle_root"));

    Ok(())
}

#[test]
fn merkle_043_generated_proof_transaction_hash_matches_leaf_hash() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"left".as_slice(),
        b"target".as_slice(),
        b"right".as_slice(),
    ];
    let proof = proof_for(&batch, b"target")?;
    let expected = leaf_hash64(b"target");

    assert_eq!(proof.transaction_hash.as_bytes(), &expected);

    Ok(())
}

#[test]
fn merkle_044_generated_proof_root_matches_compute_root_for_batch() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"root-a".as_slice(),
        b"root-b".as_slice(),
        b"root-c".as_slice(),
        b"root-d".as_slice(),
    ];
    let hashed: Vec<[u8; 64]> = batch.iter().map(|tx| leaf_hash64(tx)).collect();
    let (root, _) = compute_merkle_root(&hashed).map_err(debug_err)?;
    let proof = proof_for(&batch, b"root-c")?;

    assert_eq!(proof.merkle_root.as_bytes(), &root);

    Ok(())
}

#[test]
fn merkle_045_eight_transaction_proof_depth_is_three() -> TestResult {
    let txs: Vec<Vec<u8>> = (0_u8..8_u8).map(|n| vec![b'e', n]).collect();
    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();
    let target = batch
        .get(6)
        .copied()
        .ok_or_else(|| "missing target transaction".to_string())?;
    let proof = proof_for(&batch, target)?;

    assert_eq!(proof.sibling_hashes.len(), 3);
    assert_eq!(proof.path.len(), 3);

    Ok(())
}

#[test]
fn merkle_046_nine_transaction_proof_depth_is_four() -> TestResult {
    let txs: Vec<Vec<u8>> = (0_u8..9_u8).map(|n| vec![b'n', n]).collect();
    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();
    let target = batch
        .get(8)
        .copied()
        .ok_or_else(|| "missing target transaction".to_string())?;
    let proof = proof_for(&batch, target)?;

    assert_eq!(proof.sibling_hashes.len(), 4);
    assert_eq!(proof.path.len(), 4);

    Ok(())
}

#[test]
fn merkle_047_four_transaction_index_zero_path_vector() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"p0".as_slice(),
        b"p1".as_slice(),
        b"p2".as_slice(),
        b"p3".as_slice(),
    ];
    let proof = proof_for(&batch, b"p0")?;

    assert_eq!(proof.path, vec![true, true]);

    Ok(())
}

#[test]
fn merkle_048_four_transaction_index_one_path_vector() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"p0".as_slice(),
        b"p1".as_slice(),
        b"p2".as_slice(),
        b"p3".as_slice(),
    ];
    let proof = proof_for(&batch, b"p1")?;

    assert_eq!(proof.path, vec![false, true]);

    Ok(())
}

#[test]
fn merkle_049_four_transaction_index_two_path_vector() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"p0".as_slice(),
        b"p1".as_slice(),
        b"p2".as_slice(),
        b"p3".as_slice(),
    ];
    let proof = proof_for(&batch, b"p2")?;

    assert_eq!(proof.path, vec![true, false]);

    Ok(())
}

#[test]
fn merkle_050_four_transaction_index_three_path_vector() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"p0".as_slice(),
        b"p1".as_slice(),
        b"p2".as_slice(),
        b"p3".as_slice(),
    ];
    let proof = proof_for(&batch, b"p3")?;

    assert_eq!(proof.path, vec![false, false]);

    Ok(())
}

#[test]
fn merkle_051_duplicate_target_uses_first_matching_leaf_position() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"dup-target".as_slice(),
        b"middle".as_slice(),
        b"dup-target".as_slice(),
        b"tail".as_slice(),
    ];
    let proof = proof_for(&batch, b"dup-target")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.path, vec![true, true]);
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_052_generated_proof_root_matches_manual_expected_root() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"manual-a".as_slice(),
        b"manual-b".as_slice(),
        b"manual-c".as_slice(),
        b"manual-d".as_slice(),
        b"manual-e".as_slice(),
    ];
    let hashed: Vec<[u8; 64]> = batch.iter().map(|tx| leaf_hash64(tx)).collect();
    let expected = expected_root_from_leaves(&hashed)?;
    let proof = proof_for(&batch, b"manual-e")?;

    assert_eq!(proof.merkle_root.as_bytes(), &expected);

    Ok(())
}

#[test]
fn merkle_053_serialize_same_proof_is_stable() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;

    let first = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let second = serialize_merkle_proof(&proof).map_err(debug_err)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn merkle_054_deserialize_then_serialize_preserves_canonical_bytes() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"c")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let decoded = deserialize_merkle_proof(&encoded).map_err(debug_err)?;
    let reencoded = serialize_merkle_proof(&decoded).map_err(debug_err)?;

    assert_eq!(encoded, reencoded);

    Ok(())
}

#[test]
fn merkle_055_small_encoded_proof_is_nonempty_and_reasonable_size() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"a")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;

    assert!(!encoded.is_empty());
    assert!(encoded.len() < 4096);

    Ok(())
}

#[test]
fn merkle_056_verify_rejects_proof_against_root_from_different_batch() -> TestResult {
    let batch_a: Vec<&[u8]> = vec![b"a0".as_slice(), b"a1".as_slice(), b"a2".as_slice()];
    let batch_b: Vec<&[u8]> = vec![b"b0".as_slice(), b"b1".as_slice(), b"b2".as_slice()];
    let proof = proof_for(&batch_a, b"a1")?;

    let hashed_b: Vec<[u8; 64]> = batch_b.iter().map(|tx| leaf_hash64(tx)).collect();
    let (wrong_root, _) = compute_merkle_root(&hashed_b).map_err(debug_err)?;

    assert!(!verify_merkle_proof(&proof, &wrong_root));

    Ok(())
}

#[test]
fn merkle_057_verify_rejects_reversed_sibling_order() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
    ];
    let mut proof = proof_for(&batch, b"d")?;
    let root = root_from_proof(&proof);

    proof.sibling_hashes.reverse();

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_058_verify_rejects_reversed_path_order() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
    ];
    let mut proof = proof_for(&batch, b"b")?;
    let root = root_from_proof(&proof);

    proof.path.reverse();

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_059_verify_rejects_non_root_empty_depth_proof() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    proof.sibling_hashes.clear();
    proof.path.clear();

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_060_single_transaction_serialized_proof_roundtrips_and_verifies() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"only".as_slice()];
    let proof = proof_for(&batch, b"only")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let decoded = deserialize_merkle_proof(&encoded).map_err(debug_err)?;
    let root = root_from_proof(&decoded);

    assert!(decoded.path.is_empty());
    assert!(decoded.sibling_hashes.is_empty());
    assert!(verify_merkle_proof(&decoded, &root));

    Ok(())
}

#[test]
fn merkle_061_seven_hash_tree_level_widths_are_expected() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..7_u8).map(|n| vector_hash(&[b's', n])).collect();
    let (_, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_level_widths(&levels, &[7, 4, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_062_eight_hash_tree_level_widths_are_expected() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..8_u8).map(|n| vector_hash(&[b'e', n])).collect();
    let (_, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_level_widths(&levels, &[8, 4, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_063_nine_hash_tree_level_widths_are_expected() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..9_u8).map(|n| vector_hash(&[b'n', n])).collect();
    let (_, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_level_widths(&levels, &[9, 5, 3, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_064_six_hash_root_matches_manual_expected_root() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..6_u8).map(|n| vector_hash(&[b'm', n])).collect();
    let (root, _) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let expected = expected_root_from_leaves(&leaves)?;

    assert_eq!(root, expected);

    Ok(())
}

#[test]
fn merkle_065_compute_root_changes_when_one_leaf_changes() -> TestResult {
    let original = vec![
        vector_hash(b"a"),
        vector_hash(b"b"),
        vector_hash(b"c"),
        vector_hash(b"d"),
    ];
    let changed = vec![
        vector_hash(b"a"),
        vector_hash(b"b"),
        vector_hash(b"changed-c"),
        vector_hash(b"d"),
    ];

    let (original_root, _) = compute_merkle_root(&original).map_err(debug_err)?;
    let (changed_root, _) = compute_merkle_root(&changed).map_err(debug_err)?;

    assert_ne!(original_root, changed_root);

    Ok(())
}

#[test]
fn merkle_066_empty_transaction_bytes_can_be_proven_when_present() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"prefix".as_slice(), b"".as_slice(), b"suffix".as_slice()];
    let proof = proof_for(&batch, b"")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.transaction_hash.as_bytes(), &leaf_hash64(b""));
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_067_binary_transaction_with_zero_bytes_verifies() -> TestResult {
    let binary_tx = [0_u8, 1, 2, 0, 3, 255, 0, 4];
    let other_tx = [9_u8, 8, 7, 6];
    let batch: Vec<&[u8]> = vec![other_tx.as_slice(), binary_tx.as_slice()];

    let proof = proof_for(&batch, binary_tx.as_slice())?;
    let root = root_from_proof(&proof);

    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_068_large_but_valid_transaction_verifies() -> TestResult {
    let large_tx = vec![42_u8; 1024];
    let other_tx = vec![11_u8; 512];
    let batch: Vec<&[u8]> = vec![other_tx.as_slice(), large_tx.as_slice()];

    let proof = proof_for(&batch, large_tx.as_slice())?;
    let root = root_from_proof(&proof);

    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_069_same_length_absent_target_is_rejected() -> TestResult {
    let tx_a = [1_u8; 16];
    let tx_b = [2_u8; 16];
    let missing = [3_u8; 16];
    let batch: Vec<&[u8]> = vec![tx_a.as_slice(), tx_b.as_slice()];

    assert!(generate_merkle_proof(&batch, missing.as_slice()).is_err());

    Ok(())
}

#[test]
fn merkle_070_serialize_rejects_depth_over_derived_cap_even_below_absolute_cap() -> TestResult {
    let tx = Hash64::from_bytes(vector_hash(b"tx"));
    let root = Hash64::from_bytes(vector_hash(b"root"));
    let sibling = Hash64::from_bytes(vector_hash(b"sibling"));

    let proof = MerkleProof {
        transaction_hash: tx,
        sibling_hashes: vec![sibling; 128],
        path: vec![true; 128],
        merkle_root: root,
    };

    assert!(serialize_merkle_proof(&proof).is_err());

    Ok(())
}

#[test]
fn merkle_071_verify_rejects_depth_over_derived_cap_even_below_absolute_cap() -> TestResult {
    let tx = Hash64::from_bytes(vector_hash(b"tx"));
    let root = Hash64::from_bytes(vector_hash(b"root"));
    let sibling = Hash64::from_bytes(vector_hash(b"sibling"));
    let signed_root = *root.as_bytes();

    let proof = MerkleProof {
        transaction_hash: tx,
        sibling_hashes: vec![sibling; 128],
        path: vec![true; 128],
        merkle_root: root,
    };

    assert!(!verify_merkle_proof(&proof, &signed_root));

    Ok(())
}

#[test]
fn merkle_072_deserialize_rejects_depth_over_derived_cap_even_when_postcard_decodes() -> TestResult
{
    let tx = Hash64::from_bytes(vector_hash(b"tx"));
    let root = Hash64::from_bytes(vector_hash(b"root"));
    let sibling = Hash64::from_bytes(vector_hash(b"sibling"));

    let proof = MerkleProof {
        transaction_hash: tx,
        sibling_hashes: vec![sibling; 128],
        path: vec![true; 128],
        merkle_root: root,
    };

    let encoded = postcard::to_stdvec(&proof).map_err(debug_err)?;

    assert!(deserialize_merkle_proof(&encoded).is_err());

    Ok(())
}

#[test]
fn merkle_073_adversarial_network_duplicate_encoded_frame_is_rejected() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let mut duplicated = Vec::with_capacity(encoded.len().saturating_mul(2));

    duplicated.extend_from_slice(&encoded);
    duplicated.extend_from_slice(&encoded);

    assert!(deserialize_merkle_proof(&duplicated).is_err());

    Ok(())
}

#[test]
fn merkle_074_adversarial_network_missing_first_encoded_byte_is_rejected() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
    let shifted = encoded
        .get(1..)
        .ok_or_else(|| "missing shifted encoded proof".to_string())?;

    assert!(deserialize_merkle_proof(shifted).is_err());

    Ok(())
}

#[test]
fn merkle_075_adversarial_network_flipped_encoded_byte_is_rejected_or_invalid() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;
    let root = root_from_proof(&proof);
    let mut encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;

    let byte = encoded
        .get_mut(0)
        .ok_or_else(|| "missing first encoded byte".to_string())?;
    *byte ^= 1;

    assert!(encoded_is_rejected_or_invalid(&encoded, &root));

    Ok(())
}

#[test]
fn merkle_076_deterministic_fuzz_all_single_byte_payloads_rejected_by_deserializer() -> TestResult {
    for byte in 0_u8..=u8::MAX {
        let payload = [byte];
        assert!(
            deserialize_merkle_proof(&payload).is_err(),
            "single-byte payload {byte} decoded unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn merkle_077_property_all_targets_in_eight_batch_share_same_root_and_verify() -> TestResult {
    let txs: Vec<Vec<u8>> = (0_u8..8_u8).map(|n| vec![b'p', b'-', n]).collect();
    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();

    let first_proof = proof_for(&batch, batch[0])?;
    let expected_root = root_from_proof(&first_proof);

    for tx in &batch {
        let proof = proof_for(&batch, tx)?;
        let root = root_from_proof(&proof);

        assert_eq!(root, expected_root);
        assert!(verify_merkle_proof(&proof, &root));
    }

    Ok(())
}

#[test]
fn merkle_078_load_compute_root_for_sixty_four_leaves() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..64_u8)
        .map(|n| vector_hash(&[b'l', b'o', b'a', b'd', n]))
        .collect();

    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let expected = expected_root_from_leaves(&leaves)?;

    assert_eq!(root, expected);
    assert_level_widths(&levels, &[64, 32, 16, 8, 4, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_079_load_generate_serialize_deserialize_twenty_proofs() -> TestResult {
    let txs: Vec<Vec<u8>> = (0_u8..20_u8)
        .map(|n| vec![b'l', b'o', b'a', b'd', b'-', n])
        .collect();
    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();

    for tx in &batch {
        let proof = proof_for(&batch, tx)?;
        let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;
        let decoded = deserialize_merkle_proof(&encoded).map_err(debug_err)?;
        let root = root_from_proof(&decoded);

        assert!(verify_merkle_proof(&decoded, &root));
    }

    Ok(())
}

#[test]
fn merkle_080_manual_empty_depth_proof_verifies_when_tx_root_and_signed_root_match() -> TestResult {
    let root = vector_hash(b"manual-single-root");
    let proof = MerkleProof {
        transaction_hash: Hash64::from_bytes(root),
        sibling_hashes: Vec::new(),
        path: Vec::new(),
        merkle_root: Hash64::from_bytes(root),
    };

    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_081_final_level_root_matches_returned_root() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..6_u8)
        .map(|n| vector_hash(&[b'r', b'o', b'o', b't', n]))
        .collect();
    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    let final_level = levels
        .last()
        .ok_or_else(|| "missing final merkle level".to_string())?;
    let final_node = final_level
        .first()
        .ok_or_else(|| "missing final merkle root node".to_string())?;

    assert_eq!(final_level.len(), 1);
    assert_eq!(final_node.as_bytes(), &root);

    Ok(())
}

#[test]
fn merkle_082_leaf_level_preserves_input_hash_order() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..5_u8)
        .map(|n| vector_hash(&[b'o', b'r', b'd', n]))
        .collect();
    let (_, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let leaf_level = levels
        .first()
        .ok_or_else(|| "missing leaf level".to_string())?;

    assert_eq!(leaf_level.len(), leaves.len());

    for (stored, original) in leaf_level.iter().zip(leaves.iter()) {
        assert_eq!(stored.as_bytes(), original);
    }

    Ok(())
}

#[test]
fn merkle_083_single_empty_transaction_proof_verifies() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"".as_slice()];
    let proof = proof_for(&batch, b"")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.transaction_hash.as_bytes(), &leaf_hash64(b""));
    assert!(proof.sibling_hashes.is_empty());
    assert!(proof.path.is_empty());
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_084_two_empty_transactions_target_uses_first_match_and_verifies() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"".as_slice(), b"".as_slice()];
    let proof = proof_for(&batch, b"")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.path, vec![true]);
    assert_eq!(
        proof.sibling_hashes.first().map(Hash64::as_bytes),
        Some(&leaf_hash64(b""))
    );
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_085_five_transaction_last_leaf_first_sibling_is_self_duplicate() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"five-0".as_slice(),
        b"five-1".as_slice(),
        b"five-2".as_slice(),
        b"five-3".as_slice(),
        b"five-4".as_slice(),
    ];
    let proof = proof_for(&batch, b"five-4")?;
    let root = root_from_proof(&proof);

    assert_eq!(proof.sibling_hashes.len(), 3);
    assert_eq!(proof.path, vec![true, true, false]);
    assert_eq!(
        proof.sibling_hashes.first().map(Hash64::as_bytes),
        Some(&leaf_hash64(b"five-4"))
    );
    assert!(verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_086_five_transaction_index_three_path_vector() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"path-0".as_slice(),
        b"path-1".as_slice(),
        b"path-2".as_slice(),
        b"path-3".as_slice(),
        b"path-4".as_slice(),
    ];
    let proof = proof_for(&batch, b"path-3")?;

    assert_eq!(proof.path, vec![false, false, true]);

    Ok(())
}

#[test]
fn merkle_087_six_hash_tree_level_widths_are_expected() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..6_u8)
        .map(|n| vector_hash(&[b's', b'i', b'x', n]))
        .collect();
    let (_, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_level_widths(&levels, &[6, 3, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_088_ten_hash_tree_level_widths_are_expected() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..10_u8)
        .map(|n| vector_hash(&[b't', b'e', b'n', n]))
        .collect();
    let (_, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;

    assert_level_widths(&levels, &[10, 5, 3, 2, 1])?;

    Ok(())
}

#[test]
fn merkle_089_eleven_hash_root_matches_manual_expected_root() -> TestResult {
    let leaves: Vec<[u8; 64]> = (0_u8..11_u8)
        .map(|n| vector_hash(&[b'e', b'l', b'e', b'v', n]))
        .collect();
    let (root, _) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let expected = expected_root_from_leaves(&leaves)?;

    assert_eq!(root, expected);

    Ok(())
}

#[test]
fn merkle_090_five_leaf_tree_equals_six_leaf_tree_when_sixth_duplicates_fifth() -> TestResult {
    let a = vector_hash(b"a");
    let b = vector_hash(b"b");
    let c = vector_hash(b"c");
    let d = vector_hash(b"d");
    let e = vector_hash(b"e");

    let five = vec![a, b, c, d, e];
    let six_with_duplicate = vec![a, b, c, d, e, e];

    let (five_root, _) = compute_merkle_root(&five).map_err(debug_err)?;
    let (six_root, _) = compute_merkle_root(&six_with_duplicate).map_err(debug_err)?;

    assert_eq!(five_root, six_root);

    Ok(())
}

#[test]
fn merkle_091_deserialize_rejects_input_above_absolute_encoded_cap() -> TestResult {
    let oversized = vec![0_u8; (256_usize * 1024_usize).saturating_add(1)];

    assert!(deserialize_merkle_proof(&oversized).is_err());

    Ok(())
}

#[test]
fn merkle_092_serialize_rejects_sibling_longer_than_path() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;

    proof
        .sibling_hashes
        .push(Hash64::from_bytes(vector_hash(b"extra-sibling")));

    assert!(serialize_merkle_proof(&proof).is_err());

    Ok(())
}

#[test]
fn merkle_093_deserialize_rejects_sibling_longer_than_path() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;

    proof
        .sibling_hashes
        .push(Hash64::from_bytes(vector_hash(b"extra-sibling")));

    let encoded = postcard::to_stdvec(&proof).map_err(debug_err)?;

    assert!(deserialize_merkle_proof(&encoded).is_err());

    Ok(())
}

#[test]
fn merkle_094_verify_rejects_sibling_longer_than_path() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    proof
        .sibling_hashes
        .push(Hash64::from_bytes(vector_hash(b"extra-sibling")));

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_095_verify_rejects_extra_balanced_fake_level() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice()];
    let mut proof = proof_for(&batch, b"a")?;
    let root = root_from_proof(&proof);

    proof
        .sibling_hashes
        .push(Hash64::from_bytes(vector_hash(b"fake-level")));
    proof.path.push(true);

    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_096_verify_rejects_removed_top_level_from_multi_level_proof() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"a".as_slice(),
        b"b".as_slice(),
        b"c".as_slice(),
        b"d".as_slice(),
    ];
    let mut proof = proof_for(&batch, b"d")?;
    let root = root_from_proof(&proof);

    let removed_sibling = proof.sibling_hashes.pop();
    let removed_path = proof.path.pop();

    assert!(removed_sibling.is_some());
    assert!(removed_path.is_some());
    assert!(!verify_merkle_proof(&proof, &root));

    Ok(())
}

#[test]
fn merkle_097_verify_rejects_spliced_proof_from_same_root() -> TestResult {
    let batch: Vec<&[u8]> = vec![
        b"splice-a".as_slice(),
        b"splice-b".as_slice(),
        b"splice-c".as_slice(),
        b"splice-d".as_slice(),
    ];
    let proof_a = proof_for(&batch, b"splice-a")?;
    let proof_d = proof_for(&batch, b"splice-d")?;
    let root = root_from_proof(&proof_a);

    let spliced = MerkleProof {
        transaction_hash: proof_a.transaction_hash,
        sibling_hashes: proof_d.sibling_hashes,
        path: proof_d.path,
        merkle_root: proof_a.merkle_root,
    };

    assert!(!verify_merkle_proof(&spliced, &root));

    Ok(())
}

#[test]
fn merkle_098_deserialize_rejects_every_truncation_of_valid_encoded_proof() -> TestResult {
    let batch: Vec<&[u8]> = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
    let proof = proof_for(&batch, b"b")?;
    let encoded = serialize_merkle_proof(&proof).map_err(debug_err)?;

    for len in 0..encoded.len() {
        let truncated = encoded
            .get(..len)
            .ok_or_else(|| format!("missing truncation length {len}"))?;
        assert!(
            deserialize_merkle_proof(truncated).is_err(),
            "truncation length {len} decoded unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn merkle_099_property_all_targets_in_thirteen_batch_share_same_root_and_verify() -> TestResult {
    let txs: Vec<Vec<u8>> = (0_u8..13_u8)
        .map(|n| vec![b't', b'h', b'i', b'r', b't', b'e', b'e', b'n', n])
        .collect();
    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();

    let first_target = batch
        .first()
        .copied()
        .ok_or_else(|| "missing first target".to_string())?;
    let first_proof = proof_for(&batch, first_target)?;
    let expected_root = root_from_proof(&first_proof);

    for target in &batch {
        let proof = proof_for(&batch, target)?;
        let root = root_from_proof(&proof);

        assert_eq!(root, expected_root);
        assert!(verify_merkle_proof(&proof, &root));
    }

    Ok(())
}

#[test]
fn merkle_100_load_test_compute_root_and_verify_for_one_hundred_twenty_eight_leaves() -> TestResult
{
    let txs: Vec<Vec<u8>> = (0_u8..128_u8)
        .map(|n| vec![b'l', b'o', b'a', b'd', b'1', b'2', b'8', n])
        .collect();
    let batch: Vec<&[u8]> = txs.iter().map(Vec::as_slice).collect();
    let leaves: Vec<[u8; 64]> = batch.iter().map(|tx| leaf_hash64(tx)).collect();

    let (root, levels) = compute_merkle_root(&leaves).map_err(debug_err)?;
    let expected = expected_root_from_leaves(&leaves)?;

    assert_eq!(root, expected);
    assert_level_widths(&levels, &[128, 64, 32, 16, 8, 4, 2, 1])?;

    for target in batch.iter().take(16) {
        let proof = proof_for(&batch, target)?;
        assert_eq!(proof.merkle_root.as_bytes(), &root);
        assert!(verify_merkle_proof(&proof, &root));
    }

    Ok(())
}
