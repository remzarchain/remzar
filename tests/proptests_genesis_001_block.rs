// tests/proptests_genesis_001_block.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_FILE_ID: AtomicU64 = AtomicU64::new(1);

fn valid_timestamp(seed: u64) -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(seed % 1_000_000_000)
}

fn valid_genesis_data(tail: &str) -> String {
    format!("Remzar genesis {tail}")
}

fn valid_wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

fn is_lower_hex_128(s: &str) -> bool {
    s.len() == 128
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn max_block_size_usize() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .expect("MAX_BLOCK_SIZE must fit into usize on this test platform")
}

struct TempJsonPath {
    path: PathBuf,
}

impl TempJsonPath {
    fn new(label: &str) -> Self {
        let id = NEXT_TEST_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "remzar_proptest_genesis_{label}_{}_{}.json",
            std::process::id(),
            id
        ));

        if path.exists() {
            let _ = fs::remove_file(&path);
        }

        Self { path }
    }

    fn as_str(&self) -> &str {
        self.path
            .to_str()
            .expect("temporary genesis json path must be valid UTF-8")
    }
}

impl Drop for TempJsonPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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
    fn test_001_new_with_timestamp_accepts_valid_data_and_preserves_public_fields(
        tail in "[A-Za-z0-9_. -]{0,128}",
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis data and valid timestamp should construct");

        prop_assert!(
            genesis.validate().is_ok(),
            "freshly constructed genesis block must validate"
        );

        prop_assert_eq!(
            genesis.timestamp,
            ts,
            "genesis constructor must preserve timestamp"
        );

        prop_assert_eq!(
            genesis.data.as_str(),
            data.as_str(),
            "genesis constructor must preserve data"
        );

        prop_assert!(
            genesis.founder_wallet().is_none(),
            "new_with_timestamp without miner must not set founder_wallet"
        );

        prop_assert_eq!(
            genesis.miner_for_genesis_block(),
            "",
            "genesis miner string must be empty when founder_wallet is absent"
        );

        prop_assert_eq!(
            genesis.genesis_hash_hex(),
            hex::encode(genesis.genesis_hash),
            "genesis_hash_hex must expose the canonical genesis_hash bytes"
        );

        prop_assert!(
            is_lower_hex_128(&genesis.genesis_hash_hex()),
            "genesis hash hex must be 128 lowercase hex chars"
        );
    }

    // 02/25
    #[test]
    fn test_002_new_with_timestamp_accepts_data_at_all_valid_lengths(
        len in 1usize..=1024usize,
        ts_seed in any::<u64>(),
    ) {
        let data = "g".repeat(len);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("non-empty genesis data up to 1024 bytes should construct");

        prop_assert_eq!(
            genesis.data.len(),
            len,
            "constructor must preserve valid data length"
        );

        prop_assert!(
            genesis.validate().is_ok(),
            "genesis with valid bounded data length must validate"
        );
    }

    // 03/25
    #[test]
    fn test_003_new_with_timestamp_rejects_blank_and_oversized_data(
        blank_len in 0usize..128usize,
        extra_len in 1usize..256usize,
        ts_seed in any::<u64>(),
    ) {
        let ts = valid_timestamp(ts_seed);

        let blank = " ".repeat(blank_len);

        prop_assert!(
            GenesisBlock::new_with_timestamp(&blank, ts).is_err(),
            "blank or whitespace-only genesis data must be rejected"
        );

        let oversized = "x".repeat(1024 + extra_len);

        prop_assert!(
            GenesisBlock::new_with_timestamp(&oversized, ts).is_err(),
            "genesis data larger than 1024 bytes must be rejected"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_with_timestamp_rejects_timestamp_below_minimum(
        seed in any::<u64>(),
    ) {
        let min = GlobalConfiguration::MIN_TIMESTAMP_SECS;

        if min > 0 {
            let ts = seed % min;

            prop_assert!(
                GenesisBlock::new_with_timestamp("valid genesis data", ts).is_err(),
                "timestamp below MIN_TIMESTAMP_SECS must be rejected"
            );
        } else {
            prop_assert!(
                GenesisBlock::new_with_timestamp("valid genesis data", 0).is_ok(),
                "when MIN_TIMESTAMP_SECS is zero, timestamp zero is allowed"
            );
        }
    }

    // 05/25
    #[test]
    fn test_005_valid_founder_wallet_is_preserved_and_used_as_genesis_miner(
        wallet_tail in "[0-9a-f]{128}",
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        ts_seed in any::<u64>(),
    ) {
        let wallet = valid_wallet_from_tail(&wallet_tail);
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
            .expect("canonical founder wallet should be accepted");

        prop_assert_eq!(
            genesis.founder_wallet(),
            Some(wallet.as_str()),
            "founder_wallet getter must expose the canonical founder wallet"
        );

        prop_assert_eq!(
            genesis.miner_for_genesis_block(),
            wallet,
            "miner_for_genesis_block must return founder_wallet when configured"
        );

        prop_assert!(
            genesis.validate().is_ok(),
            "genesis block with canonical founder wallet must validate"
        );
    }

    // 06/25
    #[test]
    fn test_006_invalid_founder_wallets_are_rejected(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
        ts_seed in any::<u64>(),
    ) {
        let ts = valid_timestamp(ts_seed);
        let data = "valid genesis data";

        let short_wallet = valid_wallet_from_tail(&short_tail);
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert!(
            GenesisBlock::new_with_timestamp_and_miner(data, ts, &short_wallet).is_err(),
            "short founder wallet must be rejected"
        );

        prop_assert!(
            GenesisBlock::new_with_timestamp_and_miner(data, ts, &wrong_prefix).is_err(),
            "wrong founder wallet prefix must be rejected"
        );

        prop_assert!(
            GenesisBlock::new_with_timestamp_and_miner(data, ts, &non_hex).is_err(),
            "non-hex founder wallet body must be rejected"
        );
    }

    // 07/25
    #[test]
    fn test_007_genesis_hash_is_deterministic_and_independent_of_data_timestamp_and_founder_wallet(
        tail_a in "[A-Za-z0-9_. -]{0,128}",
        tail_b in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in "[0-9a-f]{128}",
        ts_seed_a in any::<u64>(),
        ts_seed_b in any::<u64>(),
    ) {
        let data_a = valid_genesis_data(&tail_a);
        let data_b = valid_genesis_data(&tail_b);
        let wallet = valid_wallet_from_tail(&wallet_tail);

        let ts_a = valid_timestamp(ts_seed_a);
        let ts_b = valid_timestamp(ts_seed_b);

        let without_founder = GenesisBlock::new_with_timestamp(&data_a, ts_a)
            .expect("valid genesis should construct");

        let with_founder = GenesisBlock::new_with_timestamp_and_miner(&data_b, ts_b, &wallet)
            .expect("valid genesis with founder should construct");

        prop_assert_eq!(
            without_founder.genesis_hash,
            with_founder.genesis_hash,
            "genesis hash must not depend on data, timestamp, or founder_wallet"
        );

        prop_assert_eq!(
            without_founder.prev_hash,
            with_founder.prev_hash,
            "prev_hash must come from deterministic genesis configuration"
        );

        prop_assert_eq!(
            without_founder.merkle_root,
            with_founder.merkle_root,
            "merkle_root must come from deterministic genesis configuration"
        );
    }

    // 08/25
    #[test]
    fn test_008_serialize_deserialize_roundtrip_preserves_valid_genesis(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let encoded = genesis.serialize()
            .expect("valid genesis should serialize");

        let decoded = GenesisBlock::deserialize(&encoded)
            .expect("serialized valid genesis should deserialize");

        prop_assert_eq!(
            &decoded,
            &genesis,
            "postcard serialization roundtrip must preserve genesis block"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized genesis block must validate"
        );
    }

    // 09/25
    #[test]
    fn test_009_deserialize_rejects_truncated_serialized_genesis(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        ts_seed in any::<u64>(),
        keep_seed in any::<usize>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis should construct");

        let encoded = genesis.serialize()
            .expect("valid genesis should serialize");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            GenesisBlock::deserialize(truncated).is_err(),
            "genesis deserializer must reject truncated postcard bytes"
        );
    }

    // 10/25
    #[test]
    fn test_010_deserialize_rejects_tampered_wire_genesis_hash(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        ts_seed in any::<u64>(),
        flip_index in 0usize..64usize,
        flip_byte in 1u8..=255u8,
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis should construct");

        let mut encoded = genesis
            .serialize()
            .expect("valid genesis should serialize");

        prop_assert!(
            encoded.len() > flip_index,
            "encoded genesis wire bytes must contain the raw genesis_hash field"
        );

        encoded[flip_index] ^= flip_byte;

        prop_assert!(
            GenesisBlock::deserialize(&encoded).is_err(),
            "deserializer must validate and reject tampered wire genesis_hash"
        );
    }

    // 11/25
    #[test]
    fn test_011_json_roundtrip_preserves_block_and_uses_lowercase_128_hex_hashes(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let json = genesis.to_json()
            .expect("valid genesis should convert to JSON");

        let value: Value = serde_json::from_str(&json)
            .expect("genesis JSON should parse as serde_json::Value");

        for field in ["genesis_hash", "merkle_root", "prev_hash"] {
            let s = value
                .get(field)
                .and_then(Value::as_str)
                .expect("hash field must be a JSON string");

            prop_assert!(
                is_lower_hex_128(s),
                "{field} must be serialized as 128 lowercase hex chars"
            );
        }

        if genesis.founder_wallet.is_none() {
            prop_assert!(
                value.get("founder_wallet").is_none(),
                "founder_wallet must be skipped in JSON when absent"
            );
        }

        let decoded = GenesisBlock::from_json(&json)
            .expect("valid genesis JSON should parse and validate");

        prop_assert_eq!(
            decoded,
            genesis,
            "JSON roundtrip must preserve genesis block"
        );
    }

    // 12/25
    #[test]
    fn test_012_from_json_rejects_bad_hash_hex_shape(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis should construct");

        let json = genesis.to_json()
            .expect("valid genesis should serialize to JSON");

        let mut short_hash_value: Value = serde_json::from_str(&json)
            .expect("valid genesis JSON should parse");

        short_hash_value["genesis_hash"] = Value::String("0".repeat(127));

        let short_hash_json = serde_json::to_string(&short_hash_value)
            .expect("mutated JSON value should serialize");

        prop_assert!(
            GenesisBlock::from_json(&short_hash_json).is_err(),
            "from_json must reject hash fields that are not exactly 128 hex chars"
        );

        let mut non_hex_value: Value = serde_json::from_str(&json)
            .expect("valid genesis JSON should parse");

        non_hex_value["merkle_root"] = Value::String("g".repeat(128));

        let non_hex_json = serde_json::to_string(&non_hex_value)
            .expect("mutated JSON value should serialize");

        prop_assert!(
            GenesisBlock::from_json(&non_hex_json).is_err(),
            "from_json must reject non-hex 128-char hash fields"
        );
    }

    // 13/25
    #[test]
    fn test_013_from_json_rejects_noncanonical_founder_wallet(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        valid_tail in "[0-9a-f]{128}",
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis should construct");

        let json = genesis.to_json()
            .expect("valid genesis should serialize to JSON");

        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        let mut wrong_prefix_value: Value = serde_json::from_str(&json)
            .expect("valid genesis JSON should parse");

        wrong_prefix_value["founder_wallet"] = Value::String(wrong_prefix);

        let wrong_prefix_json = serde_json::to_string(&wrong_prefix_value)
            .expect("mutated JSON value should serialize");

        prop_assert!(
            GenesisBlock::from_json(&wrong_prefix_json).is_err(),
            "from_json must reject founder_wallet with wrong prefix"
        );

        let mut non_hex_value: Value = serde_json::from_str(&json)
            .expect("valid genesis JSON should parse");

        non_hex_value["founder_wallet"] = Value::String(non_hex);

        let non_hex_json = serde_json::to_string(&non_hex_value)
            .expect("mutated JSON value should serialize");

        prop_assert!(
            GenesisBlock::from_json(&non_hex_json).is_err(),
            "from_json must reject founder_wallet with non-hex body"
        );
    }

    // 14/25
    #[test]
    fn test_014_validate_rejects_tampered_hash_fields_zero_hashes_and_duplicate_fields(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        ts_seed in any::<u64>(),
        flip_index in 0usize..64usize,
        flip_byte in 1u8..=255u8,
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis should construct");

        let mut bad_genesis_hash = genesis.clone();
        bad_genesis_hash.genesis_hash[flip_index] ^= flip_byte;

        prop_assert!(
            bad_genesis_hash.validate().is_err(),
            "validate must reject mutated genesis_hash"
        );

        let mut bad_prev_hash = genesis.clone();
        bad_prev_hash.prev_hash[flip_index] ^= flip_byte;

        prop_assert!(
            bad_prev_hash.validate().is_err(),
            "validate must reject mutated prev_hash because recomputed genesis_hash will mismatch"
        );

        let mut bad_merkle_root = genesis.clone();
        bad_merkle_root.merkle_root[flip_index] ^= flip_byte;

        prop_assert!(
            bad_merkle_root.validate().is_err(),
            "validate must reject mutated merkle_root because recomputed genesis_hash will mismatch"
        );

        let mut zero_genesis_hash = genesis.clone();
        zero_genesis_hash.genesis_hash = [0u8; 64];

        prop_assert!(
            zero_genesis_hash.validate().is_err(),
            "validate must reject all-zero genesis_hash"
        );

        let mut zero_merkle_root = genesis.clone();
        zero_merkle_root.merkle_root = [0u8; 64];

        prop_assert!(
            zero_merkle_root.validate().is_err(),
            "validate must reject all-zero merkle_root"
        );

        let mut duplicate_fields = genesis.clone();
        duplicate_fields.prev_hash = duplicate_fields.merkle_root;

        prop_assert!(
            duplicate_fields.validate().is_err(),
            "validate must reject duplicate genesis hash-domain fields"
        );
    }

    // 15/25
    #[test]
    fn test_015_validate_against_now_accepts_within_future_drift_and_rejects_beyond(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        now_seed in any::<u64>(),
        accepted_delta_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);

        let bounded_now_offset = now_seed % 1_000_000_000;
        let now = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(bounded_now_offset);

        prop_assume!(
            now <= u64::MAX
                .saturating_sub(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS)
                .saturating_sub(1)
        );

        let max_accepted_delta =
            GlobalConfiguration::MAX_FUTURE_DRIFT_SECS.min(1_000_000);

        let accepted_delta =
            accepted_delta_seed % max_accepted_delta.saturating_add(1);

        let accepted_ts = now.saturating_add(accepted_delta);

        let accepted = GenesisBlock::new_with_timestamp(&data, accepted_ts)
            .expect("genesis with valid timestamp should construct");

        prop_assert!(
            accepted.validate_against_now(now).is_ok(),
            "validate_against_now must accept timestamps within MAX_FUTURE_DRIFT_SECS"
        );

        let too_far_ts = now
            .saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS)
            .saturating_add(1);

        let too_far = GenesisBlock::new_with_timestamp(&data, too_far_ts)
            .expect("constructor does not enforce future drift; validate_against_now does");

        prop_assert!(
            too_far.validate_against_now(now).is_err(),
            "validate_against_now must reject timestamps beyond MAX_FUTURE_DRIFT_SECS"
        );
    }

    // 16/25
    #[test]
    fn test_016_serialize_for_storage_stays_within_max_block_size(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let storage = genesis.serialize_for_storage()
            .expect("valid genesis should serialize for storage");

        prop_assert!(
            storage.len() <= max_block_size_usize(),
            "serialize_for_storage must never exceed MAX_BLOCK_SIZE"
        );

        let decoded = GenesisBlock::deserialize(&storage)
            .expect("storage serialization should deserialize");

        prop_assert_eq!(
            decoded,
            genesis,
            "storage serialization must preserve genesis block"
        );
    }

    // 17/25
    #[test]
    fn test_017_pad_to_max_size_deserializes_back_to_original_genesis(
        data_tail in "[A-Za-z0-9_. -]{0,64}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let padded = genesis.pad_to_max_size()
            .expect("valid genesis should pad to MAX_BLOCK_SIZE");

        prop_assert_eq!(
            padded.len(),
            max_block_size_usize(),
            "pad_to_max_size must return exactly MAX_BLOCK_SIZE bytes"
        );

        let decoded = GenesisBlock::deserialize(&padded)
            .expect("deserializer must accept padded genesis storage bytes");

        prop_assert_eq!(
            decoded,
            genesis,
            "padded genesis bytes must deserialize back to original genesis block"
        );
    }

    // 18/25
    #[test]
    fn test_018_json_file_roundtrip_preserves_valid_genesis(
        data_tail in "[A-Za-z0-9_. -]{0,64}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let temp = TempJsonPath::new("roundtrip");

        genesis
            .to_json_file(temp.as_str())
            .expect("valid genesis should write to JSON file");

        let loaded = GenesisBlock::from_json_file(temp.as_str())
            .expect("valid genesis JSON file should load");

        prop_assert_eq!(
            loaded,
            genesis,
            "to_json_file/from_json_file roundtrip must preserve genesis block"
        );
    }

    // 19/25
    #[test]
    fn test_019_deserialize_rejects_nonzero_trailing_bytes_after_valid_serialized_genesis(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
        extra in proptest::collection::vec(1u8..=255u8, 1..64),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let mut encoded = genesis.serialize()
            .expect("valid genesis should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            GenesisBlock::deserialize(&encoded).is_err(),
            "genesis deserializer must reject valid postcard payload followed by nonzero trailing bytes"
        );
    }

    // 20/25
    #[test]
    fn test_020_deserialize_accepts_zero_trailing_padding_after_valid_serialized_genesis(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
        zero_padding_len in 1usize..256usize,
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let mut encoded = genesis.serialize()
            .expect("valid genesis should serialize");

        encoded.extend(std::iter::repeat(0u8).take(zero_padding_len));

        let decoded = GenesisBlock::deserialize(&encoded)
            .expect("zero padding after valid genesis payload should be accepted");

        prop_assert_eq!(
            decoded,
            genesis,
            "zero-padded genesis payload must decode to the original genesis block"
        );
    }

    // 21/25
    #[test]
    fn test_021_serialize_is_deterministic_and_storage_encoding_matches_canonical_serialize(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in proptest::option::of("[0-9a-f]{128}"),
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);

        let genesis = match wallet_tail {
            Some(tail) => {
                let wallet = valid_wallet_from_tail(&tail);
                GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
                    .expect("valid genesis with founder should construct")
            }
            None => GenesisBlock::new_with_timestamp(&data, ts)
                .expect("valid genesis without founder should construct"),
        };

        let encoded_a = genesis.serialize()
            .expect("first serialize should succeed");

        let encoded_b = genesis.serialize()
            .expect("second serialize should succeed");

        let storage = genesis.serialize_for_storage()
            .expect("serialize_for_storage should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing the same genesis block twice must produce identical bytes"
        );

        prop_assert_eq!(
            &storage,
            &encoded_a,
            "serialize_for_storage must use the same canonical bytes as serialize when below MAX_BLOCK_SIZE"
        );
    }

    // 22/25
    #[test]
    fn test_022_json_omits_founder_wallet_when_none_and_includes_exact_canonical_when_some(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in "[0-9a-f]{128}",
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);
        let wallet = valid_wallet_from_tail(&wallet_tail);

        let without_founder = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis without founder should construct");

        let without_json = without_founder.to_json()
            .expect("genesis without founder should serialize to JSON");

        let without_value: Value = serde_json::from_str(&without_json)
            .expect("JSON without founder should parse");

        prop_assert!(
            without_value.get("founder_wallet").is_none(),
            "founder_wallet must be omitted from JSON when None"
        );

        let with_founder = GenesisBlock::new_with_timestamp_and_miner(&data, ts, &wallet)
            .expect("valid genesis with founder should construct");

        let with_json = with_founder.to_json()
            .expect("genesis with founder should serialize to JSON");

        let with_value: Value = serde_json::from_str(&with_json)
            .expect("JSON with founder should parse");

        prop_assert_eq!(
            with_value.get("founder_wallet").and_then(Value::as_str),
            Some(wallet.as_str()),
            "founder_wallet must be included exactly as canonical lowercase wallet when Some"
        );
    }

    // 23/25
    #[test]
    fn test_023_from_json_rejects_uppercase_or_whitespace_founder_wallet(
        data_tail in "[A-Za-z0-9_. -]{0,128}",
        wallet_tail in "[0-9a-f]{128}",
        ts_seed in any::<u64>(),
    ) {
        let data = valid_genesis_data(&data_tail);
        let ts = valid_timestamp(ts_seed);
        let canonical_wallet = valid_wallet_from_tail(&wallet_tail);

        let genesis = GenesisBlock::new_with_timestamp(&data, ts)
            .expect("valid genesis should construct");

        let json = genesis.to_json()
            .expect("valid genesis should serialize to JSON");

        let mut uppercase_value: Value = serde_json::from_str(&json)
            .expect("valid genesis JSON should parse");

        uppercase_value["founder_wallet"] = Value::String(canonical_wallet.to_ascii_uppercase());

        let uppercase_json = serde_json::to_string(&uppercase_value)
            .expect("uppercase founder JSON should serialize");

        prop_assert!(
            GenesisBlock::from_json(&uppercase_json).is_err(),
            "from_json must reject noncanonical uppercase founder_wallet"
        );

        let mut whitespace_value: Value = serde_json::from_str(&json)
            .expect("valid genesis JSON should parse");

        whitespace_value["founder_wallet"] = Value::String(format!(" {canonical_wallet} "));

        let whitespace_json = serde_json::to_string(&whitespace_value)
            .expect("whitespace founder JSON should serialize");

        prop_assert!(
            GenesisBlock::from_json(&whitespace_json).is_err(),
            "from_json must reject founder_wallet with surrounding whitespace"
        );
    }

    // 24/25
    #[test]
    fn test_024_from_json_file_rejects_missing_file_and_malformed_json_file(
        garbage in ".{0,512}",
    ) {
        let missing = TempJsonPath::new("missing");

        prop_assert!(
            GenesisBlock::from_json_file(missing.as_str()).is_err(),
            "from_json_file must reject missing files"
        );

        let malformed = TempJsonPath::new("malformed");

        fs::write(malformed.as_str(), format!("not-json-{garbage}"))
            .expect("test should write malformed JSON file");

        prop_assert!(
            GenesisBlock::from_json_file(malformed.as_str()).is_err(),
            "from_json_file must reject malformed JSON file contents"
        );
    }

    // 25/25
    #[test]
    fn test_025_public_genesis_entrypoints_never_panic_for_arbitrary_external_inputs(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        json_text in ".{0,4096}",
        data_text in ".{0,2048}",
        ts in any::<u64>(),
        now in any::<u64>(),
        wallet_text in ".{0,256}",
    ) {
        let deserialize_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            GenesisBlock::deserialize(&bytes)
        }));

        prop_assert!(
            deserialize_result.is_ok(),
            "GenesisBlock::deserialize must return Ok/Err, not panic, for arbitrary bytes"
        );

        let json_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            GenesisBlock::from_json(&json_text)
        }));

        prop_assert!(
            json_result.is_ok(),
            "GenesisBlock::from_json must return Ok/Err, not panic, for arbitrary strings"
        );

        let constructor_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            GenesisBlock::new_with_timestamp_and_miner(&data_text, ts, &wallet_text)
        }));

        prop_assert!(
            constructor_result.is_ok(),
            "GenesisBlock constructor must return Ok/Err, not panic, for arbitrary public inputs"
        );

        if let Ok(Ok(genesis)) = constructor_result {
            let method_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = genesis.validate();
                let _ = genesis.validate_against_now(now);
                let _ = genesis.serialize();
                let _ = genesis.serialize_for_storage();
                let _ = genesis.to_json();
                let _ = genesis.genesis_hash_hex();
                let _ = genesis.miner_for_genesis_block();
                let _ = genesis.founder_wallet();
            }));

            prop_assert!(
                method_result.is_ok(),
                "valid constructed genesis public methods must not panic"
            );
        }
    }
}
