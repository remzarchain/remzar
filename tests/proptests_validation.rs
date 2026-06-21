use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::validation::BlockchainValidation;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::alpha_003_detection_system::DetectionSystem;

const VALIDATION_TIMESTAMP_FLOOR: u64 = 946_684_800;

fn detection() -> DetectionSystem {
    DetectionSystem::new()
}

fn wallet(seed: u64) -> String {
    format!("r{:0128x}", seed)
}

fn wallet_pair(seed_a: u64, seed_b: u64) -> (String, String) {
    let sender = wallet(seed_a);
    let mut receiver = wallet(seed_b);

    if sender == receiver {
        receiver = wallet(seed_a.wrapping_add(1));
    }

    (sender, receiver)
}

fn valid_index(seed: u64) -> u64 {
    1u64.saturating_add(seed % 10_000_000)
}

fn valid_timestamp(seed: u64) -> u64 {
    VALIDATION_TIMESTAMP_FLOOR.saturating_add(seed % 2_000_000_000)
}

fn valid_metadata_size(seed: u64) -> u64 {
    let max = GlobalConfiguration::MAX_BLOCK_SIZE;

    if max <= 64 {
        return 64;
    }

    64u64.saturating_add(seed % max.saturating_sub(63))
}

fn valid_tx_amount(seed: u64) -> u64 {
    let max = GlobalConfiguration::MAX_TX_AMOUNT;
    1u64.saturating_add(seed % max.max(1))
}

fn valid_reward_amount(seed: u64) -> u64 {
    let max = GlobalConfiguration::MAX_BLOCK_REWARD;
    1u64.saturating_add(seed % max.max(1))
}

fn nonzero_non_ff_hash(tag: u8, seed: u64) -> [u8; 64] {
    let fill = match tag {
        0x00 => 0x01,
        0xFF => 0xFE,
        value => value,
    };

    let mut out = [fill; 64];
    out[..8].copy_from_slice(&seed.to_be_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[63] = 0xFE;
    }

    out
}

fn distinct_hash(tag: u8, seed: u64, other: [u8; 64]) -> [u8; 64] {
    let mut out = nonzero_non_ff_hash(tag, seed);

    if out == other {
        out[63] ^= 0x01;

        if out == [0u8; 64] || out == [0xFFu8; 64] {
            out[63] = 0x7F;
        }
    }

    out
}

fn nonzero_non_ff_signature(seed: u64) -> [u8; ml_dsa_65::SIG_LEN] {
    let byte = u8::try_from(seed % 254)
        .expect("seed modulo 254 must fit into u8")
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
    let previous_hash = nonzero_non_ff_hash(0x11, previous_seed);
    let merkle_root = distinct_hash(0xAA, merkle_seed, previous_hash);

    BlockMetadata::new(
        valid_index(index_seed),
        valid_timestamp(timestamp_seed),
        previous_hash,
        merkle_root,
        nonzero_non_ff_signature(signature_seed),
        None,
        valid_metadata_size(size_seed),
    )
}

fn valid_genesis_metadata(
    timestamp_seed: u64,
    merkle_seed: u64,
    signature_seed: u64,
    size_seed: u64,
) -> BlockMetadata {
    BlockMetadata::new(
        0,
        valid_timestamp(timestamp_seed),
        [0u8; 64],
        nonzero_non_ff_hash(0xBB, merkle_seed),
        nonzero_non_ff_signature(signature_seed),
        None,
        valid_metadata_size(size_seed),
    )
}

fn valid_puzzle_proof(
    height: u64,
    validator_seed: u64,
    previous_hash: [u8; 64],
    output_seed: u128,
) -> BlockPuzzleProof {
    BlockPuzzleProof {
        height,
        validator: wallet(validator_seed),
        prev_block_hash: previous_hash,
        output: output_seed.saturating_add(1),
    }
}

fn err_contains<T>(result: Result<T, ErrorDetection>, needle: &str) -> bool {
    match result {
        Ok(_) => false,
        Err(err) => {
            let text = format!("{err:?}").to_ascii_lowercase();
            text.contains(&needle.to_ascii_lowercase())
        }
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
    fn test_001_valid_non_genesis_metadata_passes_blockchain_validation(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "valid non-genesis metadata must pass BlockchainValidation::validate_block_metadata"
        );
    }

    // 02/25
    #[test]
    fn test_002_valid_genesis_metadata_with_zero_previous_hash_and_nonzero_signature_passes(
        timestamp_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let metadata = valid_genesis_metadata(
            timestamp_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        prop_assert_eq!(metadata.index, 0);
        prop_assert_eq!(metadata.previous_hash, [0u8; 64]);

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "genesis metadata with zero previous_hash, non-sentinel merkle_root, and nonzero guardian signature must pass"
        );
    }

    // 03/25
    #[test]
    fn test_003_genesis_metadata_rejects_nonzero_previous_hash(
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_genesis_metadata(
            timestamp_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.previous_hash = nonzero_non_ff_hash(0x22, previous_seed);

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "Genesis metadata previous_hash must be zero",
            ),
            "genesis metadata must reject nonzero previous_hash"
        );
    }

    // 04/25
    #[test]
    fn test_004_non_genesis_metadata_rejects_zero_previous_hash(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            1,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.previous_hash = [0u8; 64];

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "Non-genesis metadata previous_hash cannot be zero",
            ),
            "non-genesis metadata must reject zero previous_hash"
        );
    }

    // 05/25
    #[test]
    fn test_005_metadata_rejects_all_ff_previous_hash_sentinel(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            2,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.previous_hash = [0xFFu8; 64];

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "previous_hash cannot be all 0xFF",
            ),
            "metadata must reject all-0xFF previous_hash sentinel"
        );
    }

    // 06/25
    #[test]
    fn test_006_metadata_rejects_zero_or_ff_merkle_root_sentinels(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        invalid_case in 0usize..2usize,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            3,
            signature_seed,
            size_seed,
        );

        metadata.merkle_root = if invalid_case == 0 {
            [0u8; 64]
        } else {
            [0xFFu8; 64]
        };

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "merkle_root cannot be zero or all 0xFF",
            ),
            "metadata must reject zero and all-0xFF merkle_root sentinels"
        );
    }

    // 07/25
    #[test]
    fn test_007_metadata_rejects_zero_or_ff_guardian_signature(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        size_seed in any::<u64>(),
        invalid_case in 0usize..2usize,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            4,
            size_seed,
        );

        metadata.guardian_signature = if invalid_case == 0 {
            [0u8; ml_dsa_65::SIG_LEN]
        } else {
            [0xFFu8; ml_dsa_65::SIG_LEN]
        };

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata must reject zero and all-0xFF guardian signatures"
        );
    }

    // 08/25
    #[test]
    fn test_008_metadata_size_accepts_boundaries_and_rejects_outside_plausible_range(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE < u64::MAX);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            0,
        );

        metadata.size = 64;
        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "metadata size exactly 64 must be accepted"
        );

        metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE;
        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "metadata size exactly MAX_BLOCK_SIZE must be accepted"
        );

        metadata.size = 63;
        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata size below 64 must be rejected"
        );

        metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);
        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata size above MAX_BLOCK_SIZE must be rejected"
        );
    }

    // 09/25
    #[test]
    fn test_009_non_genesis_metadata_rejects_merkle_root_equal_previous_hash(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let same = nonzero_non_ff_hash(0x55, previous_seed);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            5,
            signature_seed,
            size_seed,
        );

        metadata.previous_hash = same;
        metadata.merkle_root = same;

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "merkle_root == previous_hash",
            ),
            "non-genesis metadata must reject merkle_root equal to previous_hash"
        );
    }

    // 10/25
    #[test]
    fn test_010_metadata_timestamp_accepts_exact_validation_floor_and_rejects_older_values(
        index_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        old_timestamp in 0u64..VALIDATION_TIMESTAMP_FLOOR,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            0,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.timestamp = VALIDATION_TIMESTAMP_FLOOR;
        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "timestamp exactly at validation floor must pass"
        );

        metadata.timestamp = old_timestamp;
        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "too old",
            ),
            "timestamp below validation floor must fail"
        );
    }

    // 11/25
    #[test]
    fn test_011_metadata_layer_does_not_confuse_full_block_index_gate_with_header_plausibility(
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        excess in 1u64..=1_000_000u64,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            1,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.index = 10_000_000u64.saturating_add(excess);

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "metadata validation must remain a header-plausibility check; full block validation owns the implausibly-large index gate"
        );
    }

    // 12/25
    #[test]
    fn test_012_genesis_metadata_rejects_any_committed_puzzle_proof(
        timestamp_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_genesis_metadata(
            timestamp_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.puzzle_proof = Some(valid_puzzle_proof(
            1,
            validator_seed,
            nonzero_non_ff_hash(0x66, timestamp_seed),
            output_seed,
        ));

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "Genesis metadata must not include puzzle_proof",
            ),
            "genesis metadata must reject committed puzzle proof"
        );
    }

    // 13/25
    #[test]
    fn test_013_non_genesis_metadata_accepts_structurally_valid_aligned_puzzle_proof(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.puzzle_proof = Some(valid_puzzle_proof(
            metadata.index,
            validator_seed,
            metadata.previous_hash,
            output_seed,
        ));

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_ok(),
            "metadata validation must accept structurally valid puzzle proof aligned with index and previous_hash"
        );
    }

    // 14/25
    #[test]
    fn test_014_metadata_rejects_puzzle_proof_height_mismatch(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let wrong_height = if metadata.index == 10_000_000 {
            metadata.index.saturating_sub(1)
        } else {
            metadata.index.saturating_add(1)
        };

        metadata.puzzle_proof = Some(valid_puzzle_proof(
            wrong_height,
            validator_seed,
            metadata.previous_hash,
            output_seed,
        ));

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "does not match metadata.index",
            ),
            "metadata validation must reject puzzle proof height mismatch"
        );
    }

    // 15/25
    #[test]
    fn test_015_metadata_rejects_puzzle_proof_previous_hash_mismatch(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let wrong_previous_hash = distinct_hash(
            0x77,
            previous_seed.saturating_add(1),
            metadata.previous_hash,
        );

        metadata.puzzle_proof = Some(valid_puzzle_proof(
            metadata.index,
            validator_seed,
            wrong_previous_hash,
            output_seed,
        ));

        prop_assert!(
            err_contains(
                BlockchainValidation::validate_block_metadata(&metadata, &detection()),
                "prev_block_hash does not match metadata.previous_hash",
            ),
            "metadata validation must reject puzzle proof previous_hash mismatch"
        );
    }

    // 16/25
    #[test]
    fn test_016_metadata_rejects_noncanonical_puzzle_proof_validator(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.puzzle_proof = Some(BlockPuzzleProof {
            height: metadata.index,
            validator: wallet(validator_seed).replace('r', "R"),
            prev_block_hash: metadata.previous_hash,
            output: output_seed.saturating_add(1),
        });

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata validation must reject noncanonical puzzle proof validator identity"
        );
    }

    // 17/25
    #[test]
    fn test_017_metadata_rejects_puzzle_proof_zero_output(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.puzzle_proof = Some(BlockPuzzleProof {
            height: metadata.index,
            validator: wallet(validator_seed),
            prev_block_hash: metadata.previous_hash,
            output: 0,
        });

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata validation must reject puzzle proof with zero output"
        );
    }

    // 18/25
    #[test]
    fn test_018_metadata_rejects_puzzle_proof_previous_hash_sentinel(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
        invalid_case in 0usize..2usize,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let bad_prev = if invalid_case == 0 {
            [0u8; 64]
        } else {
            [0xFFu8; 64]
        };

        metadata.puzzle_proof = Some(BlockPuzzleProof {
            height: metadata.index,
            validator: wallet(validator_seed),
            prev_block_hash: bad_prev,
            output: output_seed.saturating_add(1),
        });

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata validation must reject puzzle proof with zero or all-0xFF previous hash"
        );
    }

    // 19/25
    #[test]
    fn test_019_metadata_rejects_puzzle_proof_height_above_structural_limit(
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_SIZE >= 64);

        let mut metadata = valid_non_genesis_metadata(
            123,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        metadata.puzzle_proof = Some(BlockPuzzleProof {
            height: 10_000_001,
            validator: wallet(validator_seed),
            prev_block_hash: metadata.previous_hash,
            output: output_seed.saturating_add(1),
        });

        prop_assert!(
            BlockchainValidation::validate_block_metadata(&metadata, &detection()).is_err(),
            "metadata validation must reject structurally impossible puzzle proof height"
        );
    }

    // 20/25
    #[test]
    fn test_020_validate_transaction_accepts_valid_canonical_transfer_at_or_under_max_amount(
        sender_seed in any::<u64>(),
        receiver_seed in any::<u64>(),
        amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_TX_AMOUNT > 0);

        let (sender, receiver) = wallet_pair(sender_seed, receiver_seed);
        let amount = valid_tx_amount(amount_seed);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("generated canonical transfer should construct");

        prop_assert!(
            BlockchainValidation::validate_transaction(&tx).is_ok(),
            "valid canonical transfer at or below MAX_TX_AMOUNT must pass validation"
        );
    }

    // 21/25
    #[test]
    fn test_021_validate_transaction_rejects_amount_above_max_after_external_mutation(
        sender_seed in any::<u64>(),
        receiver_seed in any::<u64>(),
        amount_seed in any::<u64>(),
        extra in 1u64..=1_000_000u64,
    ) {
        prop_assume!(GlobalConfiguration::MAX_TX_AMOUNT > 0);
        prop_assume!(GlobalConfiguration::MAX_TX_AMOUNT < u64::MAX);

        let (sender, receiver) = wallet_pair(sender_seed, receiver_seed);
        let amount = valid_tx_amount(amount_seed);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("generated canonical transfer should construct");

        tx.amount = GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(extra);

        prop_assert!(
            BlockchainValidation::validate_transaction(&tx).is_err(),
            "validation wrapper must reject externally-mutated amount above MAX_TX_AMOUNT"
        );
    }

    // 22/25
    #[test]
    fn test_022_validate_transaction_rejects_sender_equal_receiver_after_external_mutation(
        sender_seed in any::<u64>(),
        receiver_seed in any::<u64>(),
        amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_TX_AMOUNT > 0);

        let (sender, receiver) = wallet_pair(sender_seed, receiver_seed);
        let amount = valid_tx_amount(amount_seed);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("generated canonical transfer should construct");

        tx.receiver = tx.sender;

        prop_assert!(
            BlockchainValidation::validate_transaction(&tx).is_err(),
            "transaction validation must reject stored transfer whose sender and receiver bytes are identical"
        );
    }

    // 23/25
    #[test]
    fn test_023_validate_transaction_rejects_noncanonical_stored_receiver_bytes(
        sender_seed in any::<u64>(),
        receiver_seed in any::<u64>(),
        amount_seed in any::<u64>(),
        byte_index in 0usize..129usize,
    ) {
        prop_assume!(GlobalConfiguration::MAX_TX_AMOUNT > 0);

        let (sender, receiver) = wallet_pair(sender_seed, receiver_seed);
        let amount = valid_tx_amount(amount_seed);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("generated canonical transfer should construct");

        tx.receiver[byte_index] = b'Z';

        prop_assert!(
            BlockchainValidation::validate_transaction(&tx).is_err(),
            "transaction validation must reject noncanonical stored receiver address bytes"
        );
    }

    // 24/25
    #[test]
    fn test_024_validate_reward_transaction_accepts_valid_reward_transaction(
        receiver_seed in any::<u64>(),
        amount_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet(receiver_seed);
        let amount = valid_reward_amount(amount_seed);
        let block_height = height_seed.saturating_add(1);

        let reward = RewardTx::new(receiver, amount, block_height)
            .expect("generated valid reward transaction should construct");

        prop_assert!(
            BlockchainValidation::validate_reward_transaction(&reward).is_ok(),
            "valid reward transaction must pass BlockchainValidation::validate_reward_transaction"
        );
    }

    // 25/25
    #[test]
    fn test_025_validate_reward_transaction_rejects_mutated_zero_amount_above_max_or_zero_height(
        receiver_seed in any::<u64>(),
        amount_seed in any::<u64>(),
        height_seed in any::<u64>(),
        extra in 1u64..=1_000_000u64,
        invalid_case in 0usize..3usize,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD < u64::MAX);

        let receiver = wallet(receiver_seed);
        let amount = valid_reward_amount(amount_seed);
        let block_height = height_seed.saturating_add(1);

        let mut reward = RewardTx::new(receiver, amount, block_height)
            .expect("generated valid reward transaction should construct");

        match invalid_case {
            0 => reward.amount = 0,
            1 => reward.amount = GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(extra),
            _ => reward.block_height = 0,
        }

        prop_assert!(
            BlockchainValidation::validate_reward_transaction(&reward).is_err(),
            "reward validation must reject zero amount, above-max amount, or zero block height after mutation"
        );
    }
}
