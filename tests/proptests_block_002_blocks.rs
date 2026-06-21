use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

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
        1u64.saturating_add(index_seed % 10_000_000),
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

fn fresh_signing_key() -> fips204::ml_dsa_65::PrivateKey {
    MlDsa65Keypair::generate()
        .expect("ML-DSA-65 keypair generation should succeed")
        .get_signing_key()
        .expect("generated secret key should parse as signing key")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_accepts_valid_non_genesis_block_and_sets_64_byte_hash(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
        batch_key_tail in "[A-Za-z0-9_-]{0,128}",
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let miner = wallet(miner_seed);
        let batch_key = Some(format!("tx_batch_{batch_key_tail}"));

        let block = Block::new(
            metadata.clone(),
            batch_key.clone(),
            miner.clone(),
            reward,
        )
        .expect("valid non-genesis block should construct");

        prop_assert_eq!(
            &block.metadata,
            &metadata,
            "block must preserve metadata"
        );

        prop_assert_eq!(
            &block.batch_key,
            &batch_key,
            "block must preserve batch key"
        );

        prop_assert_eq!(
            block.miner_wallet(),
            miner,
            "block must preserve canonical miner wallet"
        );

        prop_assert_eq!(
            block.block_hash.len(),
            64,
            "block hash must be exactly 64 bytes"
        );

        prop_assert_ne!(
            block.block_hash,
            [0u8; 64],
            "non-genesis block hash must not be all zeros"
        );

        prop_assert!(
            block.verify_block_hash().expect("block hash verification should run"),
            "freshly constructed block must verify its own hash"
        );

        prop_assert!(
            block.validate(None).is_ok(),
            "freshly constructed valid block must validate"
        );
    }

    // 02/25
    #[test]
    fn test_002_genesis_block_allows_empty_miner_and_validates(
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        size_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_genesis_metadata(
            timestamp_seed,
            previous_seed,
            merkle_seed,
            size_seed,
        );

        let block = Block::new(metadata, None, String::new(), reward)
            .expect("genesis block should allow empty miner");

        prop_assert_eq!(
            block.metadata.index,
            0,
            "genesis block index must be zero"
        );

        prop_assert_eq!(
            block.miner_wallet(),
            "",
            "genesis block may have empty miner"
        );

        prop_assert!(
            block.verify_block_hash().expect("genesis hash verification should run"),
            "genesis block must verify its own hash"
        );

        prop_assert!(
            block.validate(None).is_ok(),
            "valid genesis block must validate"
        );
    }

    // 03/25
    #[test]
    fn test_003_new_rejects_non_genesis_empty_miner(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        reward in any::<u64>(),
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
            Block::new(metadata, None, String::new(), reward).is_err(),
            "non-genesis block constructor must reject empty miner"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_canonicalizes_uppercase_or_whitespace_miner(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let canonical = wallet(miner_seed);
        let messy = format!(" \t{}\n", canonical.to_ascii_uppercase());

        let block = Block::new(metadata, None, messy, reward)
            .expect("constructor should canonicalize valid miner wallet input");

        prop_assert_eq!(
            block.miner_wallet(),
            canonical,
            "constructor must trim/lowercase valid miner wallet"
        );

        prop_assert!(
            block.validate(None).is_ok(),
            "canonicalized block must validate"
        );
    }

    // 05/25
    #[test]
    fn test_005_new_rejects_malformed_miner_and_overlong_batch_key(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let malformed_miner = "rz".repeat(65);

        prop_assert!(
            Block::new(
                metadata.clone(),
                None,
                malformed_miner,
                reward,
            )
            .is_err(),
            "constructor must reject malformed miner wallet"
        );

        let overlong_batch_key = Some("x".repeat(4097));

        prop_assert!(
            Block::new(
                metadata,
                overlong_batch_key,
                wallet(1),
                reward,
            )
            .is_err(),
            "constructor must reject overlong batch key"
        );
    }

    // 06/25
    #[test]
    fn test_006_compute_block_hash_is_deterministic_and_sensitive_to_reward_and_batch_key(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
        batch_key_tail in "[A-Za-z0-9_-]{1,128}",
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let miner = wallet(miner_seed);

        let block_a = Block::new(
            metadata.clone(),
            Some(format!("batch_a_{batch_key_tail}")),
            miner.clone(),
            reward,
        )
        .expect("block A should construct");

        let block_a_again = Block::new(
            metadata.clone(),
            Some(format!("batch_a_{batch_key_tail}")),
            miner.clone(),
            reward,
        )
        .expect("block A duplicate should construct");

        let block_reward_changed = Block::new(
            metadata.clone(),
            Some(format!("batch_a_{batch_key_tail}")),
            miner.clone(),
            reward.wrapping_add(1),
        )
        .expect("reward-changed block should construct");

        let block_key_changed = Block::new(
            metadata,
            Some(format!("batch_b_{batch_key_tail}")),
            miner,
            reward,
        )
        .expect("batch-key-changed block should construct");

        prop_assert_eq!(
            block_a.block_hash,
            block_a_again.block_hash,
            "same critical block fields must produce deterministic block hash"
        );

        prop_assert_ne!(
            block_a.block_hash,
            block_reward_changed.block_hash,
            "changing reward must change block hash"
        );

        prop_assert_ne!(
            block_a.block_hash,
            block_key_changed.block_hash,
            "changing non-empty batch key must change block hash"
        );

        prop_assert_eq!(
            block_a.hash_hex(),
            hex::encode(block_a.block_hash),
            "hash_hex must encode stored block_hash"
        );

        prop_assert_eq!(
            block_a.hash_hex().len(),
            128,
            "hash_hex must be 128 lowercase hex chars"
        );
    }

    // 07/25
    #[test]
    fn test_007_none_and_empty_batch_key_hash_identically(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let miner = wallet(miner_seed);

        let none_key = Block::new(
            metadata.clone(),
            None,
            miner.clone(),
            reward,
        )
        .expect("None batch key block should construct");

        let empty_key = Block::new(
            metadata,
            Some(String::new()),
            miner,
            reward,
        )
        .expect("empty batch key block should construct");

        prop_assert_eq!(
            none_key.block_hash,
            empty_key.block_hash,
            "None and Some(\"\") batch keys must hash identically"
        );

        prop_assert!(
            none_key.verify_block_hash().expect("None-key hash verification should run")
        );

        prop_assert!(
            empty_key.verify_block_hash().expect("empty-key hash verification should run")
        );
    }

    // 08/25
    #[test]
    fn test_008_serialize_deserialize_from_storage_roundtrip_preserves_valid_block(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
        batch_key_tail in "[A-Za-z0-9_-]{0,128}",
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let block = Block::new(
            metadata,
            Some(format!("tx_batch_{batch_key_tail}")),
            wallet(miner_seed),
            reward,
        )
        .expect("valid block should construct");

        let encoded = block
            .serialize_for_storage()
            .expect("valid block should serialize for storage");

        let decoded = Block::deserialize_from_storage(&encoded)
            .expect("valid stored block should deserialize");

        prop_assert_eq!(
            &decoded,
            &block,
            "storage serialization roundtrip must preserve block"
        );

        prop_assert!(
            decoded.validate(None).is_ok(),
            "decoded block must validate"
        );
    }

    // 09/25
    #[test]
    fn test_009_deserialize_with_sizes_reports_actual_and_stored_sizes_for_canonical_and_padded_blocks(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
        pad_len in 1usize..64usize,
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let block = Block::new(
            metadata,
            Some("tx_batch_size_test".to_owned()),
            wallet(miner_seed),
            reward,
        )
        .expect("valid block should construct");

        let encoded = block
            .serialize_for_storage()
            .expect("valid block should serialize");

        let (decoded, actual, stored) = Block::deserialize_with_sizes(&encoded)
            .expect("canonical stored block should decode with sizes");

        prop_assert_eq!(
            &decoded,
            &block,
            "canonical decode must preserve block"
        );

        prop_assert_eq!(
            actual,
            encoded.len(),
            "canonical actual size must equal encoded length"
        );

        prop_assert_eq!(
            stored,
            encoded.len(),
            "canonical stored size must equal encoded length"
        );

        let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .unwrap_or(usize::MAX);

        prop_assume!(encoded.len().saturating_add(pad_len) <= max_block_size);

        let mut padded = encoded.clone();
        padded.extend(vec![0u8; pad_len]);

        let (decoded_padded, actual_padded, stored_padded) = Block::deserialize_with_sizes(&padded)
            .expect("legacy padded stored block should decode with sizes");

        prop_assert_eq!(
            &decoded_padded,
            &block,
            "padded decode must preserve block"
        );

        prop_assert_eq!(
            actual_padded,
            encoded.len(),
            "padded actual size must equal original postcard length"
        );

        prop_assert_eq!(
            stored_padded,
            padded.len(),
            "padded stored size must include trailing padding"
        );

        let decoded_from_padded = Block::deserialize_from_storage(&padded)
            .expect("deserialize_from_storage must accept legacy padded block bytes");

        prop_assert_eq!(
            &decoded_from_padded,
            &block,
            "padded deserialize_from_storage must preserve block"
        );
    }

    // 10/25
    #[test]
    fn test_010_deserialize_from_storage_rejects_truncated_and_oversized_data(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let min_block_size = usize::try_from(GlobalConfiguration::MIN_BLOCK_SIZE)
            .unwrap_or(usize::MAX);

        let short_len = data.len().min(min_block_size.saturating_sub(1));
        let short = &data[..short_len];

        prop_assert!(
            Block::deserialize_from_storage(short).is_err(),
            "deserialize_from_storage must reject data shorter than MIN_BLOCK_SIZE"
        );

        prop_assert!(
            Block::deserialize_with_sizes(short).is_err(),
            "deserialize_with_sizes must reject data shorter than MIN_BLOCK_SIZE"
        );

        let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .unwrap_or(usize::MAX);

        if max_block_size <= 1_000_000 {
            let oversized = vec![0u8; max_block_size.saturating_add(1)];

            prop_assert!(
                Block::deserialize_from_storage(&oversized).is_err(),
                "deserialize_from_storage must reject data larger than MAX_BLOCK_SIZE"
            );

            prop_assert!(
                Block::deserialize_with_sizes(&oversized).is_err(),
                "deserialize_with_sizes must reject data larger than MAX_BLOCK_SIZE"
            );
        }
    }

    // 11/25
    #[test]
    fn test_011_validate_rejects_block_hash_mismatch_after_mutating_consensus_field(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(
            metadata,
            Some("tx_batch_mutation".to_owned()),
            wallet(miner_seed),
            reward,
        )
        .expect("valid block should construct");

        prop_assert!(
            block.validate(None).is_ok(),
            "block must validate before mutation"
        );

        block.reward = block.reward.wrapping_add(1);

        prop_assert!(
            !block.verify_block_hash().expect("hash verification should run after mutation"),
            "mutating reward must make stored block hash stale"
        );

        prop_assert!(
            block.validate(None).is_err(),
            "block validation must reject stale block_hash after consensus field mutation"
        );
    }

    // 12/25
    #[test]
    fn test_012_validate_rejects_noncanonical_miner_after_manual_mutation(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(
            metadata,
            None,
            wallet(miner_seed),
            reward,
        )
        .expect("valid block should construct");

        block.miner = block.miner.to_ascii_uppercase();

        prop_assert!(
            block.validate(None).is_err(),
            "validate must reject noncanonical miner mutation"
        );
    }

    // 13/25
    #[test]
    fn test_013_encoded_length_helpers_match_actual_storage_serialization_length(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let block = Block::new(
            metadata,
            Some("tx_batch_len".to_owned()),
            wallet(miner_seed),
            reward,
        )
        .expect("valid block should construct");

        let encoded = block
            .serialize_for_storage()
            .expect("valid block should serialize");

        prop_assert_eq!(
            block.encoded_len_unpadded()
                .expect("encoded_len_unpadded should succeed"),
            encoded.len(),
            "encoded_len_unpadded must equal actual serialized length"
        );

        prop_assert_eq!(
            block.encoded_len_padded(),
            encoded.len(),
            "encoded_len_padded now returns actual variable-length storage size"
        );
    }

    // 14/25
    #[test]
    fn test_014_sign_block_attaches_nonzero_guardian_signature_and_refreshes_hash(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(
            metadata,
            Some("tx_batch_sign".to_owned()),
            wallet(miner_seed),
            reward,
        )
        .expect("structurally valid non-genesis block should construct");

        let old_hash = block.block_hash;
        let old_signature = block.metadata.guardian_signature;
        let signing_key = fresh_signing_key();

        block
            .sign_block(&signing_key)
            .expect("sign_block should attach guardian signature and refresh hash");

        prop_assert_ne!(
            block.metadata.guardian_signature,
            [0u8; ml_dsa_65::SIG_LEN],
            "sign_block must leave guardian signature nonzero"
        );

        prop_assert_ne!(
            block.metadata.guardian_signature,
            old_signature,
            "sign_block should replace the previous placeholder guardian signature"
        );

        prop_assert_ne!(
            block.block_hash,
            old_hash,
            "sign_block must refresh block hash after embedding the new signature"
        );

        prop_assert!(
            block.verify_block_hash().expect("signed block hash verification should run"),
            "signed block must verify its refreshed hash"
        );

        prop_assert!(
            block.validate(None).is_ok(),
            "signed block should pass block validation"
        );
    }

    // 15/25
    #[test]
    fn test_015_block_hash_changes_when_previous_hash_changes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata_a = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut metadata_b = metadata_a.clone();
        metadata_b.previous_hash = nonzero_hash(0x33, previous_seed.wrapping_add(1));

        let miner = wallet(miner_seed);

        let block_a = Block::new(metadata_a, None, miner.clone(), reward)
            .expect("first block should construct");

        let block_b = Block::new(metadata_b, None, miner, reward)
            .expect("previous-hash-mutated block should construct");

        prop_assert_ne!(
            block_a.block_hash,
            block_b.block_hash,
            "changing metadata.previous_hash must change block_hash"
        );
    }

    // 16/25
    #[test]
    fn test_016_block_hash_changes_when_merkle_root_changes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata_a = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut metadata_b = metadata_a.clone();
        metadata_b.merkle_root = nonzero_hash(0xCC, merkle_seed.wrapping_add(1));

        let miner = wallet(miner_seed);

        let block_a = Block::new(metadata_a, None, miner.clone(), reward)
            .expect("first block should construct");

        let block_b = Block::new(metadata_b, None, miner, reward)
            .expect("merkle-root-mutated block should construct");

        prop_assert_ne!(
            block_a.block_hash,
            block_b.block_hash,
            "changing metadata.merkle_root must change block_hash"
        );
    }

    // 17/25
    #[test]
    fn test_017_block_hash_changes_when_guardian_signature_changes(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata_a = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut metadata_b = metadata_a.clone();
        metadata_b.guardian_signature = nonzero_signature(signature_seed.wrapping_add(1));

        let miner = wallet(miner_seed);

        let block_a = Block::new(metadata_a, None, miner.clone(), reward)
            .expect("first block should construct");

        let block_b = Block::new(metadata_b, None, miner, reward)
            .expect("guardian-signature-mutated block should construct");

        prop_assert_ne!(
            block_a.block_hash,
            block_b.block_hash,
            "changing metadata.guardian_signature must change block_hash"
        );
    }

    // 18/25
    #[test]
    fn test_018_validate_rejects_all_zero_block_hash_for_non_genesis(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(metadata, None, wallet(miner_seed), reward)
            .expect("valid block should construct");

        block.block_hash = [0u8; 64];

        prop_assert!(
            block.validate(None).is_err(),
            "non-genesis block with all-zero block_hash must fail validation"
        );
    }

    // 19/25
    #[test]
    fn test_019_storage_decode_preserves_stale_hash_and_validate_rejects_after_reward_mutation(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(metadata, None, wallet(miner_seed), reward)
            .expect("valid block should construct");

        block.reward = block.reward.wrapping_add(1);

        let encoded = postcard::to_allocvec(&block)
            .expect("direct postcard serialization of stale-hash block should succeed");

        let decoded = Block::deserialize_from_storage(&encoded)
            .expect("storage decoder should decode structurally sane stale-hash block");

        prop_assert!(
            decoded.validate(None).is_err(),
            "full validation must reject decoded block whose stored hash is stale"
        );
    }

    // 20/25
    #[test]
    fn test_020_deserialize_from_storage_rejects_directly_serialized_overlong_batch_key(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(metadata, None, wallet(miner_seed), reward)
            .expect("valid block should construct");

        block.batch_key = Some("x".repeat(4097));

        let encoded = postcard::to_allocvec(&block)
            .expect("direct postcard serialization should allow malformed test object");

        prop_assert!(
            Block::deserialize_from_storage(&encoded).is_err(),
            "storage decoder must reject overlong batch_key even if bytes deserialize"
        );
    }

    // 21/25
    #[test]
    fn test_021_deserialize_from_storage_canonicalizes_messy_miner_from_legacy_storage(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let canonical_miner = wallet(miner_seed);

        let mut block = Block::new(
            metadata,
            None,
            canonical_miner.clone(),
            reward,
        )
        .expect("valid block should construct");

        block.miner = format!(" \t{}\n", canonical_miner.to_ascii_uppercase());

        let encoded = postcard::to_allocvec(&block)
            .expect("direct postcard serialization should allow messy miner test object");

        let decoded = Block::deserialize_from_storage(&encoded)
            .expect("storage decoder should canonicalize valid messy miner");

        prop_assert_eq!(
            decoded.miner_wallet(),
            canonical_miner.as_str(),
            "storage decoder must trim/lowercase miner wallet into canonical form"
        );

        prop_assert!(
            decoded.validate(None).is_ok(),
            "decoded canonicalized block must validate"
        );
    }

    // 22/25
    #[test]
    fn test_022_deserialize_from_storage_rejects_manual_non_genesis_empty_miner(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let mut block = Block::new(metadata, None, wallet(miner_seed), reward)
            .expect("valid block should construct");

        block.miner.clear();

        let encoded = postcard::to_allocvec(&block)
            .expect("direct postcard serialization should allow empty miner test object");

        prop_assert!(
            Block::deserialize_from_storage(&encoded).is_err(),
            "storage decoder must reject non-genesis block with empty miner"
        );
    }

    // 23/25
    #[test]
    fn test_023_encoded_len_unpadded_matches_reencoded_length_after_storage_roundtrip(
        index_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        previous_seed in any::<u64>(),
        merkle_seed in any::<u64>(),
        signature_seed in any::<u64>(),
        size_seed in any::<u64>(),
        miner_seed in any::<u64>(),
        reward in any::<u64>(),
        batch_key_tail in "[A-Za-z0-9_-]{0,128}",
    ) {
        let metadata = valid_non_genesis_metadata(
            index_seed,
            timestamp_seed,
            previous_seed,
            merkle_seed,
            signature_seed,
            size_seed,
        );

        let block = Block::new(
            metadata,
            Some(format!("roundtrip_{batch_key_tail}")),
            wallet(miner_seed),
            reward,
        )
        .expect("valid block should construct");

        let encoded = block
            .serialize_for_storage()
            .expect("valid block should serialize");

        let decoded = Block::deserialize_from_storage(&encoded)
            .expect("valid stored block should decode");

        let decoded_len = decoded
            .encoded_len_unpadded()
            .expect("decoded block should report encoded length");

        prop_assert_eq!(
            decoded_len,
            encoded.len(),
            "decoded encoded_len_unpadded must match original canonical storage length"
        );

        prop_assert_eq!(
            decoded.encoded_len_padded(),
            decoded_len,
            "encoded_len_padded must match actual variable-length storage size"
        );
    }

    // 24/25
    #[test]
    fn test_024_deserialize_from_storage_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Block::deserialize_from_storage(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "deserialize_from_storage must never panic for arbitrary external bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_deserialize_with_sizes_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Block::deserialize_with_sizes(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "deserialize_with_sizes must never panic for arbitrary external bytes"
        );
    }
}
