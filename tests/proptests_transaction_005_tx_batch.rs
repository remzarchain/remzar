use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;
use std::sync::{Mutex, MutexGuard, OnceLock};

use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

fn wallet(tag: u8, seed: u64) -> String {
    format!("r{tag:02x}{seed:0126x}")
}

fn transfer_tx(seed: u64, amount: u64) -> Transaction {
    Transaction::new(
        wallet(0x10, seed),
        wallet(0x20, seed.saturating_add(1)),
        amount.max(1),
    )
    .expect("generated transfer transaction should be valid")
}

fn transfer_kind(seed: u64, amount: u64) -> TxKind {
    TxKind::Transfer(transfer_tx(seed, amount))
}

fn register_kind(seed: u64) -> TxKind {
    TxKind::RegisterNode(
        RegisterNodeTx::new(wallet(0x33, seed))
            .expect("generated register transaction should be valid"),
    )
}

fn reward_amount(seed: u64) -> u64 {
    let max = GlobalConfiguration::MAX_BLOCK_REWARD;

    if max == 0 {
        return 1;
    }

    seed.checked_rem(max)
        .unwrap_or(0)
        .saturating_add(1)
        .min(max)
        .max(1)
}

fn reward_kind(seed: u64, amount_seed: u64, block_height: u64) -> TxKind {
    TxKind::Reward(
        RewardTx::new(
            wallet(0x77, seed),
            reward_amount(amount_seed),
            block_height.max(1),
        )
        .expect("generated reward transaction should be valid"),
    )
}

fn transfer_kinds(amounts: &[u64]) -> Vec<TxKind> {
    amounts
        .iter()
        .enumerate()
        .map(|(index, amount)| {
            let seed = u64::try_from(index)
                .expect("test index should fit into u64")
                .saturating_add(1);

            transfer_kind(seed, (*amount).max(1))
        })
        .collect()
}

fn shared_signing_key() -> MutexGuard<'static, fips204::ml_dsa_65::PrivateKey> {
    static SIGNING_KEY: OnceLock<Mutex<fips204::ml_dsa_65::PrivateKey>> = OnceLock::new();

    SIGNING_KEY
        .get_or_init(|| {
            Mutex::new(
                MlDsa65Keypair::generate()
                    .expect("ML-DSA-65 keypair generation should succeed")
                    .get_signing_key()
                    .expect("generated secret key should parse as signing key"),
            )
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn fixed_hash(seed: u8) -> Hash {
    [seed; 64]
}

fn serialized_kind_len(kind: &TxKind) -> usize {
    match kind {
        TxKind::Transfer(tx) => tx.serialize().expect("transfer should serialize").len(),
        TxKind::RegisterNode(tx) => tx.serialize().expect("register tx should serialize").len(),
        TxKind::Reward(tx) => tx.serialize().expect("reward tx should serialize").len(),
        TxKind::NftMint(tx) => postcard::to_allocvec(tx)
            .expect("nft mint should serialize")
            .len(),
        TxKind::NftTransfer(tx) => postcard::to_allocvec(tx)
            .expect("nft transfer should serialize")
            .len(),
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
    fn test_001_new_preserves_index_timestamp_transactions_and_starts_unsigned(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000_000u64, 0..32),
    ) {
        let transactions = transfer_kinds(&amounts);

        let batch = TransactionBatch::new(index, timestamp, transactions.clone())
            .expect("TransactionBatch::new should succeed for generated transfer list");

        prop_assert_eq!(
            batch.index,
            index,
            "batch must preserve index"
        );

        prop_assert_eq!(
            batch.timestamp,
            timestamp,
            "batch must preserve timestamp"
        );

        prop_assert_eq!(
            &batch.transactions,
            &transactions,
            "batch must preserve transactions"
        );

        prop_assert!(
            batch.guardian_signature.is_none(),
            "new batch must start without guardian signature"
        );
    }

    // 02/25
    #[test]
    fn test_002_total_size_matches_sum_of_inner_transfer_serialized_sizes(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000_000u64, 0..32),
    ) {
        let transactions = transfer_kinds(&amounts);

        let batch = TransactionBatch::new(index, timestamp, transactions.clone())
            .expect("TransactionBatch::new should succeed");

        let expected_size = transactions
            .iter()
            .map(serialized_kind_len)
            .sum::<usize>();

        prop_assert_eq!(
            batch.total_size().expect("batch total_size should succeed"),
            expected_size,
            "total_size must equal sum of serialized inner transaction sizes"
        );
    }

    // 03/25
    #[test]
    fn test_003_serialized_len_matches_actual_postcard_serialized_length(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000_000u64, 0..32),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let encoded = batch
            .serialize()
            .expect("batch serialization should succeed");

        prop_assert_eq!(
            batch.serialized_len().expect("serialized_len should succeed"),
            encoded.len(),
            "serialized_len must equal actual serialized byte length"
        );

        prop_assert_eq!(
            postcard::to_allocvec(&batch)
                .expect("postcard serialization should succeed")
                .len(),
            encoded.len(),
            "batch serialize helper must use postcard encoding"
        );
    }

    // 04/25
    #[test]
    fn test_004_serialize_deserialize_roundtrip_preserves_batch(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000_000u64, 0..32),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let encoded = batch
            .serialize()
            .expect("batch serialization should succeed");

        let decoded = TransactionBatch::deserialize(&encoded)
            .expect("serialized batch should deserialize");

        prop_assert_eq!(
            &decoded,
            &batch,
            "batch serialization roundtrip must preserve all fields"
        );
    }

    // 05/25
    #[test]
    fn test_005_deserialize_rejects_truncated_serialized_batch(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000_000u64, 0..32),
        keep_seed in any::<usize>(),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let encoded = batch
            .serialize()
            .expect("batch serialization should succeed");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            TransactionBatch::deserialize(truncated).is_err(),
            "batch deserializer must reject truncated serialized bytes"
        );
    }

    // 06/25
    #[test]
    fn test_006_serialize_for_storage_matches_serialize_for_small_batches(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..16),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let encoded = batch
            .serialize()
            .expect("batch serialization should succeed");

        let storage_encoded = batch
            .serialize_for_storage()
            .expect("small generated batch should fit storage size limit");

        prop_assert_eq!(
            &storage_encoded,
            &encoded,
            "serialize_for_storage must return canonical serialized bytes for valid small batches"
        );

        prop_assert!(
            storage_encoded.len() <= usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
                .unwrap_or(usize::MAX),
            "storage bytes must fit MAX_BLOCK_SIZE"
        );
    }

    // 07/25
    #[test]
    fn test_007_compute_merkle_root_is_64_bytes_deterministic_and_order_sensitive(
        left_amount in 1u64..=1_000_000_000u64,
        right_amount in 1u64..=1_000_000_000u64,
        index in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        let left = transfer_kind(1, left_amount);
        let right = transfer_kind(2, right_amount);

        let original = TransactionBatch::new(index, timestamp, vec![left.clone(), right.clone()])
            .expect("original batch should construct");

        let reordered = TransactionBatch::new(index, timestamp, vec![right, left])
            .expect("reordered batch should construct");

        let root_a1 = original
            .compute_merkle_root()
            .expect("Merkle root should compute");

        let root_a2 = original
            .compute_merkle_root()
            .expect("Merkle root should be deterministic");

        let root_b = reordered
            .compute_merkle_root()
            .expect("Merkle root should compute for reordered batch");

        prop_assert_eq!(
            root_a1.len(),
            64,
            "batch Merkle root must be exactly 64 bytes"
        );

        prop_assert_eq!(
            root_a1,
            root_a2,
            "Merkle root must be deterministic for unchanged batch"
        );

        prop_assert_ne!(
            root_a1,
            root_b,
            "Merkle root must be order-sensitive for distinct transactions"
        );
    }

    // 08/25
    #[test]
    fn test_008_inclusion_proof_rejects_out_of_bounds_leaf_index(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..32),
        extra in 0usize..32usize,
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let out_of_bounds = batch.transactions.len().saturating_add(extra);

        prop_assert!(
            batch.inclusion_proof(out_of_bounds).is_err(),
            "inclusion_proof must reject leaf index outside transaction list"
        );
    }

    // 09/25
    #[test]
    fn test_009_inclusion_proof_for_valid_leaf_contains_only_64_byte_hashes(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 1..32),
        leaf_seed in any::<usize>(),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let leaf_index = leaf_seed % batch.transactions.len();

        let proof = batch
            .inclusion_proof(leaf_index)
            .expect("valid leaf index should produce inclusion proof");

        prop_assert!(
            proof.iter().all(|hash| hash.as_bytes().len() == 64),
            "every inclusion proof sibling must be 64 bytes"
        );

        prop_assert!(
            proof.len() <= batch.transactions.len(),
            "proof length must stay bounded by transaction count"
        );

        if batch.transactions.len() == 1 {
            prop_assert!(
                proof.is_empty(),
                "single-leaf batch should have empty inclusion proof"
            );
        }
    }

    // 10/25
    #[test]
    fn test_010_from_reward_only_creates_single_reward_batch_without_signature(
        index in 1u64..=1_000_000u64,
        timestamp in any::<u64>(),
        receiver_seed in any::<u64>(),
        reward_amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet(0x77, receiver_seed);
        let amount = reward_amount(reward_amount_seed);

        let reward = RewardTx::new(receiver.clone(), amount, index)
            .expect("generated reward transaction should construct");

        let batch = TransactionBatch::from_reward_only(index, timestamp, reward.clone())
            .expect("reward-only batch should construct");

        prop_assert_eq!(
            batch.index,
            index,
            "reward-only batch must preserve index"
        );

        prop_assert_eq!(
            batch.timestamp,
            timestamp,
            "reward-only batch must preserve timestamp"
        );

        prop_assert_eq!(
            batch.transactions.len(),
            1,
            "reward-only batch must contain exactly one transaction"
        );

        prop_assert!(
            batch.guardian_signature.is_none(),
            "reward-only batch should start unsigned"
        );

        match &batch.transactions[0] {
            TxKind::Reward(decoded_reward) => {
                prop_assert_eq!(
                    decoded_reward,
                    &reward,
                    "reward-only batch must preserve reward transaction"
                );
            }
            other => {
                prop_assert!(
                    false,
                    "reward-only batch must contain TxKind::Reward, got {:?}",
                    other.tag()
                );
            }
        }
    }

    // 11/25
    #[test]
    fn test_011_sign_batch_attaches_exact_ml_dsa_65_signature_length(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..8),
    ) {
        let mut batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let signing_key = shared_signing_key();

        batch
            .sign_batch(&signing_key)
            .expect("signing generated batch should succeed");

        let signature = batch
            .guardian_signature
            .as_ref()
            .expect("sign_batch must attach guardian_signature");

        prop_assert_eq!(
            signature.len(),
            ml_dsa_65::SIG_LEN,
            "guardian signature must be exact ML-DSA-65 signature length"
        );
    }

    // 12/25
    #[test]
    fn test_012_finalize_block_sets_signature_and_returns_matching_metadata(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        prev_seed in any::<u8>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..8),
    ) {
        let mut batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let signing_key = shared_signing_key();
        let previous_hash = fixed_hash(prev_seed);

        let expected_merkle = batch
            .compute_merkle_root()
            .expect("Merkle root should compute before finalization");

        let metadata = batch
            .finalize_block(&signing_key, previous_hash)
            .expect("finalize_block should succeed for small generated batch");

        prop_assert_eq!(
            metadata.index,
            index,
            "finalized metadata must preserve batch index"
        );

        prop_assert_eq!(
            metadata.timestamp,
            timestamp,
            "finalized metadata must preserve batch timestamp"
        );

        prop_assert_eq!(
            metadata.previous_hash,
            previous_hash,
            "finalized metadata must preserve previous hash"
        );

        prop_assert_eq!(
            metadata.merkle_root,
            expected_merkle,
            "finalized metadata Merkle root must match batch Merkle root"
        );

        let signature = batch
            .guardian_signature
            .as_ref()
            .expect("finalize_block must attach guardian signature");

        prop_assert_eq!(
            signature.len(),
            ml_dsa_65::SIG_LEN,
            "finalize_block must attach exact-length ML-DSA-65 guardian signature"
        );
    }

    // 13/25
    #[test]
    fn test_013_serialize_is_deterministic_for_unchanged_batch(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..16),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let encoded_a = batch
            .serialize()
            .expect("first batch serialization should succeed");

        let encoded_b = batch
            .serialize()
            .expect("second batch serialization should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing the same batch twice must produce identical bytes"
        );

        prop_assert!(
            !encoded_a.is_empty(),
            "serialized batch must not be empty"
        );
    }

    // 14/25
    #[test]
    fn test_014_deserialize_rejects_serialized_batch_with_nonzero_trailing_bytes(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..16),
        extra in proptest::collection::vec(1u8..=255u8, 1..32),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let mut encoded = batch
            .serialize()
            .expect("batch serialization should succeed");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            TransactionBatch::deserialize(&encoded).is_err(),
            "batch deserializer must reject nonzero trailing bytes after valid payload"
        );
    }

    // 15/25
    #[test]
    fn test_015_deserialize_rejects_serialized_batch_with_zero_trailing_bytes(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..16),
        extra_len in 1usize..32usize,
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let mut encoded = batch
            .serialize()
            .expect("batch serialization should succeed");

        encoded.extend(std::iter::repeat(0u8).take(extra_len));

        prop_assert!(
            TransactionBatch::deserialize(&encoded).is_err(),
            "batch deserializer must reject zero trailing bytes after valid payload"
        );
    }

    // 16/25
    #[test]
    fn test_016_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            TransactionBatch::deserialize(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "TransactionBatch::deserialize must never panic for arbitrary external bytes"
        );
    }

    // 17/25
    #[test]
    fn test_017_empty_batch_merkle_root_is_64_bytes_and_deterministic(
        index in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        let batch = TransactionBatch::new(index, timestamp, Vec::new())
            .expect("empty batch should construct");

        let root_a = batch
            .compute_merkle_root()
            .expect("empty batch Merkle root should compute");

        let root_b = batch
            .compute_merkle_root()
            .expect("empty batch Merkle root should be deterministic");

        prop_assert_eq!(
            root_a.len(),
            64,
            "empty batch Merkle root must still be 64 bytes"
        );

        prop_assert_eq!(
            root_a,
            root_b,
            "empty batch Merkle root must be deterministic"
        );
    }

    // 18/25
    #[test]
    fn test_018_single_transaction_merkle_root_changes_when_transaction_changes(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amount in 1u64..=1_000_000_000u64,
    ) {
        let batch_a = TransactionBatch::new(
            index,
            timestamp,
            vec![transfer_kind(1, amount)],
        )
        .expect("single transfer batch should construct");

        let batch_b = TransactionBatch::new(
            index,
            timestamp,
            vec![transfer_kind(1, amount.saturating_add(1))],
        )
        .expect("changed single transfer batch should construct");

        let root_a = batch_a
            .compute_merkle_root()
            .expect("first Merkle root should compute");

        let root_b = batch_b
            .compute_merkle_root()
            .expect("changed Merkle root should compute");

        prop_assert_ne!(
            root_a,
            root_b,
            "changing the only transaction must change the Merkle root"
        );
    }

    // 19/25
    #[test]
    fn test_019_single_leaf_inclusion_proof_is_empty(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amount in 1u64..=1_000_000u64,
    ) {
        let batch = TransactionBatch::new(
            index,
            timestamp,
            vec![transfer_kind(1, amount)],
        )
        .expect("single transfer batch should construct");

        let proof = batch
            .inclusion_proof(0)
            .expect("single valid leaf should produce proof");

        prop_assert!(
            proof.is_empty(),
            "single-leaf inclusion proof must be empty"
        );
    }

    // 20/25
    #[test]
    fn test_020_inclusion_proof_length_is_bounded_for_every_valid_leaf(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 1..32),
    ) {
        let batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        for leaf_index in 0..batch.transactions.len() {
            let proof = batch
                .inclusion_proof(leaf_index)
                .expect("valid leaf index should produce proof");

            prop_assert!(
                proof.len() <= batch.transactions.len(),
                "proof length must be bounded by transaction count"
            );

            prop_assert!(
                proof.iter().all(|hash| hash.as_bytes().len() == 64),
                "each sibling hash must be 64 bytes"
            );
        }
    }

    // 21/25
    #[test]
    fn test_021_total_size_matches_sum_for_mixed_transfer_register_reward_batch(
        index in 1u64..=1_000_000u64,
        timestamp in any::<u64>(),
        transfer_amount in 1u64..=1_000_000u64,
        reward_amount_seed in any::<u64>(),
        seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let transactions = vec![
            transfer_kind(seed.saturating_add(1), transfer_amount),
            register_kind(seed.saturating_add(2)),
            reward_kind(seed.saturating_add(3), reward_amount_seed, index),
        ];

        let batch = TransactionBatch::new(index, timestamp, transactions.clone())
            .expect("mixed batch should construct");

        let expected = transactions
            .iter()
            .map(serialized_kind_len)
            .sum::<usize>();

        prop_assert_eq!(
            batch.total_size().expect("mixed batch total_size should compute"),
            expected,
            "total_size must sum serialized sizes for transfer, register, and reward variants"
        );
    }

    // 22/25
    #[test]
    fn test_022_mixed_batch_roundtrip_preserves_variant_order(
        index in 1u64..=1_000_000u64,
        timestamp in any::<u64>(),
        transfer_amount in 1u64..=1_000_000u64,
        reward_amount_seed in any::<u64>(),
        seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let transactions = vec![
            transfer_kind(seed.saturating_add(1), transfer_amount),
            register_kind(seed.saturating_add(2)),
            reward_kind(seed.saturating_add(3), reward_amount_seed, index),
        ];

        let batch = TransactionBatch::new(index, timestamp, transactions)
            .expect("mixed batch should construct");

        let encoded = batch
            .serialize()
            .expect("mixed batch should serialize");

        let decoded = TransactionBatch::deserialize(&encoded)
            .expect("mixed batch should deserialize");

        prop_assert_eq!(
            &decoded,
            &batch,
            "mixed batch roundtrip must preserve variant order and payloads"
        );

        let tags: Vec<&str> = decoded
            .transactions
            .iter()
            .map(|kind| kind.tag())
            .collect();

        prop_assert_eq!(
            tags,
            vec!["transfer", "register_node", "reward"],
            "mixed batch must preserve transaction variant order"
        );
    }

    // 23/25
    #[test]
    fn test_023_sign_batch_overwrites_existing_bad_signature_with_exact_length_signature(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..8),
        bad_sig_len in 0usize..128usize,
    ) {
        prop_assume!(bad_sig_len != ml_dsa_65::SIG_LEN);

        let mut batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        batch.guardian_signature = Some(vec![0x55; bad_sig_len]);

        let signing_key = shared_signing_key();

        batch
            .sign_batch(&signing_key)
            .expect("sign_batch should overwrite bad existing signature");

        let signature = batch
            .guardian_signature
            .as_ref()
            .expect("sign_batch must leave a signature");

        prop_assert_eq!(
            signature.len(),
            ml_dsa_65::SIG_LEN,
            "sign_batch must replace any existing malformed signature with exact-length signature"
        );
    }

    // 24/25
    #[test]
    fn test_024_finalize_block_returns_structurally_valid_non_genesis_metadata(
        index in 1u64..=1_000_000u64,
        timestamp in GlobalConfiguration::MIN_TIMESTAMP_SECS..=4_000_000_000u64,
        prev_seed in 1u8..=255u8,
        amounts in proptest::collection::vec(1u64..=1_000_000u64, 0..8),
    ) {
        let mut batch = TransactionBatch::new(index, timestamp, transfer_kinds(&amounts))
            .expect("TransactionBatch::new should succeed");

        let signing_key = shared_signing_key();
        let previous_hash = fixed_hash(prev_seed);

        let metadata = batch
            .finalize_block(&signing_key, previous_hash)
            .expect("finalize_block should succeed for bounded non-genesis batch");

        prop_assert!(
            metadata.validate_structural().is_ok(),
            "finalize_block must return structurally valid non-genesis metadata"
        );

        prop_assert_ne!(
            metadata.guardian_signature,
            [0u8; ml_dsa_65::SIG_LEN],
            "finalized non-genesis metadata must contain nonzero guardian signature"
        );
    }

    // 25/25
    #[test]
    fn test_025_from_reward_only_matches_manual_single_reward_batch_serialization(
        index in 1u64..=1_000_000u64,
        timestamp in any::<u64>(),
        receiver_seed in any::<u64>(),
        reward_amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let reward = RewardTx::new(
            wallet(0x77, receiver_seed),
            reward_amount(reward_amount_seed),
            index,
        )
        .expect("generated reward transaction should construct");

        let reward_only = TransactionBatch::from_reward_only(
            index,
            timestamp,
            reward.clone(),
        )
        .expect("reward-only batch should construct");

        let manual = TransactionBatch::new(
            index,
            timestamp,
            vec![TxKind::Reward(reward)],
        )
        .expect("manual single reward batch should construct");

        prop_assert_eq!(
            &reward_only,
            &manual,
            "from_reward_only must be equivalent to a manual single Reward batch"
        );

        prop_assert_eq!(
            reward_only.serialize().expect("reward-only should serialize"),
            manual.serialize().expect("manual reward batch should serialize"),
            "from_reward_only and manual single Reward batch must serialize identically"
        );
    }
}
