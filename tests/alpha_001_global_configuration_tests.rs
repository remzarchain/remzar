use fips204::ml_dsa_65;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, UNIT_DIVISOR, canon_wallet_id_checked, decode_hex_to_64,
};
use std::collections::BTreeSet;

type TestResult = Result<(), String>;

fn checked_add_u64(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or_else(|| "checked_add_u64 overflow".to_string())
}

fn checked_mul_u64(a: u64, b: u64) -> Result<u64, String> {
    a.checked_mul(b)
        .ok_or_else(|| "checked_mul_u64 overflow".to_string())
}

fn checked_mul_usize(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b)
        .ok_or_else(|| "checked_mul_usize overflow".to_string())
}

fn usize_to_u64(value: usize) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| "usize_to_u64 conversion failed".to_string())
}

fn assert_condition(condition: bool) {
    assert!(condition);
}

fn next_deterministic_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn is_lower_hex_ascii(s: &str) -> bool {
    s.as_bytes()
        .iter()
        .all(|b| matches!(*b, b'0'..=b'9' | b'a'..=b'f'))
}

fn db_dirs() -> Vec<&'static str> {
    vec![
        GlobalConfiguration::WALLETS_DIR,
        GlobalConfiguration::DATABASE_DIR_NAME,
        GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR,
        GlobalConfiguration::REGISTRY_DIR_NAME,
        GlobalConfiguration::LOG_DATABASE_DIR,
        GlobalConfiguration::AUDIT_REPORTS_DIR,
        GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR,
        GlobalConfiguration::PEER_LIST_DIR,
        GlobalConfiguration::SIDECHAIN_DATABASE_DIR,
    ]
}

fn column_ids() -> Vec<u8> {
    vec![
        GlobalConfiguration::META_DATA_COLUMN,
        GlobalConfiguration::GLOBAL_COLUMN,
        GlobalConfiguration::ACCOUNT_COLUMN,
        GlobalConfiguration::NETWORK_COLUMN,
        GlobalConfiguration::SIDECHAIN_COLUMN,
        GlobalConfiguration::STATE_COLUMN,
        GlobalConfiguration::TRANSACTION_COLUMN,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN,
        GlobalConfiguration::REWARD_COLUMN,
        GlobalConfiguration::REWARD_BATCH_COLUMN,
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN,
        GlobalConfiguration::LOGS_COLUMN,
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN,
        GlobalConfiguration::TX_TO_HASH_COLUMN,
        GlobalConfiguration::IDENTITY_COLUMN,
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN,
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN,
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN,
    ]
}

fn column_names() -> Vec<&'static str> {
    vec![
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        GlobalConfiguration::GLOBAL_COLUMN_NAME,
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME,
        GlobalConfiguration::STATE_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        GlobalConfiguration::LOGS_COLUMN_NAME,
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::IDENTITY_COLUMN_NAME,
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ]
}

fn column_pairs() -> Vec<(u8, &'static str)> {
    column_ids().into_iter().zip(column_names()).collect()
}

#[test]
fn global_config_001_version_and_identity_vectors_are_stable() -> TestResult {
    assert_eq!(GlobalConfiguration::VERSION, 1);
    assert_eq!(GlobalConfiguration::COIN_NAME, "remzar");
    assert_eq!(GlobalConfiguration::SYMBOL, "remzar");
    assert_eq!(GlobalConfiguration::START_DATE, "2026-06-26");
    assert_eq!(GlobalConfiguration::DEFAULT_PORT, 36_213);
    Ok(())
}

#[test]
fn global_config_002_directory_vector_has_expected_entries() -> TestResult {
    let dirs = db_dirs();
    let expected = [
        "000.wallets",
        "001.database_db",
        "002.blockchain_db",
        "003.registry_db",
        "004.log_db",
        "005.audit_reports",
        "006.accountmodel_db",
        "007.peerlist",
        "008.sidechain_db",
    ];

    assert_eq!(dirs.as_slice(), expected);
    Ok(())
}

#[test]
fn global_config_003_database_directories_are_unique_and_count_matches_total() -> TestResult {
    let dirs = db_dirs();
    let unique: BTreeSet<&str> = dirs.iter().copied().collect();

    assert_eq!(dirs.len(), GlobalConfiguration::TOTAL_DB_DIRS);
    assert_eq!(unique.len(), dirs.len());
    Ok(())
}

#[test]
fn global_config_004_database_directory_numbering_is_contiguous_and_ordered() -> TestResult {
    let dirs = db_dirs();

    for (index, dir) in dirs.iter().enumerate() {
        let expected = format!("{index:03}.");
        assert!(
            dir.starts_with(&expected),
            "directory `{dir}` must start with `{expected}`"
        );
    }

    Ok(())
}

#[test]
fn global_config_005_genesis_file_path_is_relative_and_json() -> TestResult {
    assert_eq!(
        GlobalConfiguration::GENESIS_JSON_PATH,
        "blockchain/genesis.json"
    );
    assert_condition(!GlobalConfiguration::GENESIS_JSON_PATH.starts_with('/'));
    assert_condition(GlobalConfiguration::GENESIS_JSON_PATH.ends_with(".json"));
    Ok(())
}

#[test]
fn global_config_006_genesis_prev_hash_byte_vector_is_zeroed() -> TestResult {
    assert_eq!(GlobalConfiguration::GENESIS_PREV_HASH_BYTES.len(), 64);
    assert_condition(
        GlobalConfiguration::GENESIS_PREV_HASH_BYTES
            .iter()
            .all(|b| *b == 0),
    );
    Ok(())
}

#[test]
fn global_config_007_genesis_prev_hash_hex_decodes_to_same_64_bytes() -> TestResult {
    let decoded = decode_hex_to_64(GlobalConfiguration::GENESIS_PREV_HASH_HEX)
        .map_err(|e| format!("GENESIS_PREV_HASH_HEX decode failed: {e:?}"))?;

    assert_eq!(decoded, GlobalConfiguration::GENESIS_PREV_HASH_BYTES);
    assert_eq!(GlobalConfiguration::GENESIS_PREV_HASH_HEX.len(), 128);
    assert!(is_lower_hex_ascii(
        GlobalConfiguration::GENESIS_PREV_HASH_HEX
    ));
    Ok(())
}

#[test]
fn global_config_008_genesis_merkle_root_hex_is_canonical_64_bytes() -> TestResult {
    let decoded = decode_hex_to_64(GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX)
        .map_err(|e| format!("GENESIS_MERKLE_ROOT_HEX decode failed: {e:?}"))?;

    assert_eq!(decoded.len(), 64);
    assert_eq!(GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX.len(), 128);
    assert!(is_lower_hex_ascii(
        GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX
    ));
    Ok(())
}

#[test]
fn global_config_009_genesis_merkle_root_is_repeated_32_byte_vector() -> TestResult {
    let first_half = GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX.get(..64);
    let second_half = GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX.get(64..128);

    assert_eq!(first_half, second_half);
    Ok(())
}

#[test]
fn global_config_010_genesis_hash_hex_is_canonical_64_byte_nonzero() -> TestResult {
    let decoded = decode_hex_to_64(GlobalConfiguration::GENESIS_HASH_HEX)
        .map_err(|e| format!("GENESIS_HASH_HEX decode failed: {e:?}"))?;

    assert_eq!(decoded.len(), 64);
    assert_eq!(GlobalConfiguration::GENESIS_HASH_HEX.len(), 128);
    assert!(is_lower_hex_ascii(GlobalConfiguration::GENESIS_HASH_HEX));
    assert!(decoded.iter().any(|b| *b != 0));
    assert_ne!(
        GlobalConfiguration::GENESIS_HASH_HEX,
        GlobalConfiguration::GENESIS_PREV_HASH_HEX
    );
    Ok(())
}

#[test]
fn global_config_011_genesis_nonce_validator_reward_vectors_are_stable() -> TestResult {
    assert_eq!(GlobalConfiguration::GENESIS_NONCE, 299_792_458);
    assert_eq!(GlobalConfiguration::GENESIS_REWARD, 0);
    assert_eq!(
        GlobalConfiguration::GENESIS_VALIDATOR.len(),
        REMZAR_WALLET_LEN
    );
    Ok(())
}

#[test]
fn global_config_012_genesis_and_burn_wallets_are_helper_canonical() -> TestResult {
    canon_wallet_id_checked(GlobalConfiguration::GENESIS_VALIDATOR)
        .map_err(|e| format!("GENESIS_VALIDATOR is not canonical: {e:?}"))?;

    canon_wallet_id_checked(GlobalConfiguration::BURN_ADDRESS)
        .map_err(|e| format!("BURN_ADDRESS is not canonical: {e:?}"))?;

    Ok(())
}

#[test]
fn global_config_013_base58_alphabet_is_canonical_unique_vector() -> TestResult {
    let alphabet = GlobalConfiguration::BASE58_ALPHABET.as_bytes();
    let unique: BTreeSet<u8> = alphabet.iter().copied().collect();

    assert_eq!(alphabet.len(), 58);
    assert_eq!(unique.len(), alphabet.len());

    for forbidden in [b'0', b'O', b'I', b'l'] {
        assert!(!alphabet.contains(&forbidden));
    }

    Ok(())
}

#[test]
fn global_config_014_block_size_and_buffer_vectors_are_exact() -> TestResult {
    assert_eq!(GlobalConfiguration::MAX_BLOCK_SIZE, 2_097_152);
    assert_eq!(GlobalConfiguration::TRANSACTION_BUFFER_LIMIT, 2_097_152);
    assert_eq!(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE, 16_384);
    assert_eq!(GlobalConfiguration::MAX_TXS_PER_BLOCK, 7_500);
    assert_eq!(GlobalConfiguration::MAX_BATCH_SERIALIZED_OVERHEAD, 2_048);

    let max_block_size_usize = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| "MAX_BLOCK_SIZE does not fit usize".to_string())?;

    assert_condition(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE < max_block_size_usize);
    Ok(())
}

#[test]
fn global_config_015_mldsa_and_encryption_size_vectors_are_consistent() -> TestResult {
    assert_eq!(GlobalConfiguration::MLDSA65_SECRET_BYTES, ml_dsa_65::SK_LEN);
    assert_eq!(
        GlobalConfiguration::MLDSA65_SECRET_HEX_LEN,
        checked_mul_usize(GlobalConfiguration::MLDSA65_SECRET_BYTES, 2)?
    );
    assert_eq!(
        GlobalConfiguration::MAX_PRIVKEY_HEX_INPUT_LEN,
        GlobalConfiguration::MLDSA65_SECRET_HEX_LEN
    );
    assert_eq!(GlobalConfiguration::GUARDIAN_SIG_LEN, ml_dsa_65::SIG_LEN);

    assert_eq!(GlobalConfiguration::NONCE_SIZE, 12);
    assert_eq!(GlobalConfiguration::AES_KEY_SIZE, 32);
    assert_eq!(GlobalConfiguration::SALT_SIZE, 16);
    Ok(())
}

#[test]
fn global_config_016_economic_supply_vectors_are_consistent() -> TestResult {
    assert_eq!(
        GlobalConfiguration::MAX_REWARD_SUPPLY,
        checked_mul_u64(200_000_000, UNIT_DIVISOR)?
    );
    assert_eq!(
        GlobalConfiguration::MAX_SUPPLY,
        GlobalConfiguration::MAX_REWARD_SUPPLY
    );
    assert_eq!(
        GlobalConfiguration::MAX_TX_AMOUNT,
        checked_mul_u64(100_000_000, UNIT_DIVISOR)?
    );
    assert_condition(GlobalConfiguration::MAX_TX_AMOUNT <= GlobalConfiguration::MAX_SUPPLY);
    Ok(())
}

#[test]
fn global_config_017_reward_reduction_sequence_exact_vector() -> TestResult {
    let expected = [
        checked_mul_u64(20, UNIT_DIVISOR)?,
        checked_mul_u64(10, UNIT_DIVISOR)?,
        checked_mul_u64(5, UNIT_DIVISOR)?,
        checked_mul_u64(2, UNIT_DIVISOR)?,
        UNIT_DIVISOR,
    ];

    assert_eq!(GlobalConfiguration::REWARD_REDUCTION_SEQUENCE, expected);

    assert_eq!(
        GlobalConfiguration::INITIAL_BLOCK_REWARD,
        checked_mul_u64(20, UNIT_DIVISOR)?
    );
    assert_eq!(GlobalConfiguration::STABILIZED_BLOCK_REWARD, UNIT_DIVISOR);
    assert_eq!(
        GlobalConfiguration::MAX_BLOCK_REWARD,
        GlobalConfiguration::INITIAL_BLOCK_REWARD
    );
    Ok(())
}

#[test]
fn global_config_018_cumulative_reward_sequence_matches_formula() -> TestResult {
    let mut reward_sum = 0_u64;

    for reward in GlobalConfiguration::REWARD_REDUCTION_SEQUENCE {
        reward_sum = checked_add_u64(reward_sum, *reward)?;
    }

    let expected = checked_mul_u64(reward_sum, GlobalConfiguration::HALVING_INTERVAL_BLOCKS)?;

    assert_eq!(GlobalConfiguration::CUMULATIVE_REWARD_SEQUENCE, expected);
    assert_eq!(
        GlobalConfiguration::CUMULATIVE_REWARD_SEQUENCE,
        checked_mul_u64(
            checked_mul_u64(38, GlobalConfiguration::HALVING_INTERVAL_BLOCKS)?,
            UNIT_DIVISOR,
        )?
    );
    Ok(())
}

#[test]
fn global_config_019_effective_cumulative_sequence_accounts_for_rewardless_prefix() -> TestResult {
    let expected_nominal = checked_mul_u64(
        GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS,
        GlobalConfiguration::INITIAL_BLOCK_REWARD,
    )?;

    assert_eq!(
        GlobalConfiguration::REWARDLESS_PREFIX_NOMINAL_ISSUANCE,
        expected_nominal
    );

    assert_eq!(
        GlobalConfiguration::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE,
        GlobalConfiguration::CUMULATIVE_REWARD_SEQUENCE
            .saturating_sub(GlobalConfiguration::REWARDLESS_PREFIX_NOMINAL_ISSUANCE)
    );
    Ok(())
}

#[test]
fn global_config_020_stabilized_blocks_cover_exact_remaining_supply() -> TestResult {
    let remaining = GlobalConfiguration::MAX_REWARD_SUPPLY
        .saturating_sub(GlobalConfiguration::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE);

    let expected_blocks =
        GlobalConfiguration::ceil_div(remaining, GlobalConfiguration::STABILIZED_BLOCK_REWARD);

    let final_issued = checked_add_u64(
        GlobalConfiguration::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE,
        checked_mul_u64(
            GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD,
            GlobalConfiguration::STABILIZED_BLOCK_REWARD,
        )?,
    )?;

    assert_eq!(
        GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD,
        expected_blocks
    );
    assert_eq!(final_issued, GlobalConfiguration::MAX_REWARD_SUPPLY);
    Ok(())
}

#[test]
fn global_config_021_total_reward_blocks_matches_formula() -> TestResult {
    let ladder_blocks = checked_mul_u64(
        usize_to_u64(GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len())?,
        GlobalConfiguration::HALVING_INTERVAL_BLOCKS,
    )?;

    let expected = checked_add_u64(
        checked_add_u64(GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS, ladder_blocks)?,
        GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD,
    )?;

    assert_eq!(GlobalConfiguration::TOTAL_REWARD_BLOCKS, expected);
    Ok(())
}

#[test]
fn global_config_022_ceil_div_handles_edge_vectors() -> TestResult {
    assert_eq!(GlobalConfiguration::ceil_div(0, 1), 0);
    assert_eq!(GlobalConfiguration::ceil_div(1, 1), 1);
    assert_eq!(GlobalConfiguration::ceil_div(1, 2), 1);
    assert_eq!(GlobalConfiguration::ceil_div(2, 2), 1);
    assert_eq!(GlobalConfiguration::ceil_div(3, 2), 2);
    assert_eq!(GlobalConfiguration::ceil_div(24, 7), 4);
    assert_eq!(GlobalConfiguration::ceil_div(30, 30), 1);
    Ok(())
}

#[test]
fn global_config_023_validator_activation_delay_matches_seconds_formula() -> TestResult {
    let expected = GlobalConfiguration::ceil_div(
        GlobalConfiguration::ACTIVATION_WARMUP_SECS,
        GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
    );

    assert_eq!(
        GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS,
        expected
    );
    assert_eq!(GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS, 1);
    Ok(())
}

#[test]
fn global_config_024_heartbeat_and_dead_peer_timing_derivations_match() -> TestResult {
    assert_eq!(
        GlobalConfiguration::HEARTBEAT_TX_INTERVAL_SECS,
        checked_mul_u64(
            GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS,
            GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
        )?
    );

    assert_eq!(
        GlobalConfiguration::DEAD_PEER_EVICTION_SECS,
        checked_mul_u64(
            GlobalConfiguration::DEAD_PEER_EVICTION_BLOCKS,
            GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
        )?
    );

    assert_condition(
        GlobalConfiguration::DEAD_PEER_EVICTION_BLOCKS
            < GlobalConfiguration::CANONICAL_LEASE_BLOCKS,
    );
    assert_eq!(GlobalConfiguration::HEARTBEAT_GRACE_SECS, 0);
    Ok(())
}

#[test]
fn global_config_025_failover_slack_window_and_deadline_match_formulas() -> TestResult {
    assert_eq!(
        GlobalConfiguration::FAILOVER_SLACK_SECS,
        checked_add_u64(
            GlobalConfiguration::FAILOVER_BUILD_SLACK_SECS,
            GlobalConfiguration::FAILOVER_LEADER_GRACE_SECS,
        )?
    );

    assert_eq!(
        GlobalConfiguration::FAILOVER_WINDOW_SECS,
        checked_add_u64(
            GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS,
            GlobalConfiguration::FAILOVER_SLACK_SECS,
        )?
    );

    let expected_deadline = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS
        .saturating_sub(GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS);

    assert_eq!(
        GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS,
        expected_deadline
    );
    Ok(())
}

#[test]
fn global_config_026_failover_max_rounds_matches_floor_with_minimum_one() -> TestResult {
    let raw_rounds = GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS
        .div_euclid(GlobalConfiguration::FAILOVER_WINDOW_SECS);

    let expected = if raw_rounds == 0 { 1 } else { raw_rounds };

    assert_eq!(GlobalConfiguration::FAILOVER_MAX_ROUNDS, expected);
    assert_eq!(GlobalConfiguration::FAILOVER_MAX_ROUNDS, 2);
    Ok(())
}

#[test]
fn global_config_027_slot_gate_and_future_skew_bounds_are_sane() -> TestResult {
    assert_eq!(GlobalConfiguration::MAX_FUTURE_SKEW_SECS, 7_200);
    assert_eq!(GlobalConfiguration::SLOT_GATE_DRIFT_SECS, 2);
    assert_condition(
        GlobalConfiguration::SLOT_GATE_DRIFT_SECS < GlobalConfiguration::FAILOVER_WINDOW_SECS,
    );
    assert_condition(
        GlobalConfiguration::SLOT_GATE_DRIFT_SECS < GlobalConfiguration::MAX_FUTURE_SKEW_SECS,
    );
    Ok(())
}

#[test]
fn global_config_028_column_ids_are_exact_contiguous_vectors() -> TestResult {
    let ids = column_ids();

    assert_eq!(ids.len(), GlobalConfiguration::TOTAL_COLUMNS);

    for (index, id) in ids.iter().copied().enumerate() {
        let expected =
            u8::try_from(index).map_err(|_| "column index conversion failed".to_string())?;
        assert_eq!(id, expected);
    }

    Ok(())
}

#[test]
fn global_config_029_column_names_are_unique_and_counted() -> TestResult {
    let names = column_names();
    let unique: BTreeSet<&str> = names.iter().copied().collect();

    assert_eq!(names.len(), GlobalConfiguration::TOTAL_COLUMNS);
    assert_eq!(unique.len(), names.len());

    for name in names {
        assert!(!name.is_empty());
        assert!(!name.contains(' '));
        assert!(
            name.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
        );
    }

    Ok(())
}

#[test]
fn global_config_030_column_id_name_pairs_are_complete() -> TestResult {
    let pairs = column_pairs();

    assert_eq!(pairs.len(), GlobalConfiguration::TOTAL_COLUMNS);

    for (id, name) in pairs {
        assert!(usize::from(id) < GlobalConfiguration::TOTAL_COLUMNS);
        assert!(!name.is_empty());
    }

    Ok(())
}

#[test]
fn global_config_031_governance_and_security_thresholds_are_sane() -> TestResult {
    assert_eq!(GlobalConfiguration::ATTACK_THRESHOLD, 51);
    assert_eq!(GlobalConfiguration::MAJORITY_THRESHOLD, 75);
    assert_eq!(GlobalConfiguration::TRANSACTION_CONFIRMATION_COUNT, 6);
    assert_eq!(GlobalConfiguration::MIN_REWARD_THRESHOLD, 1_000_000);
    assert_eq!(
        GlobalConfiguration::GOVERNANCE_PROPOSAL_THRESHOLD,
        1_000_000
    );

    assert_condition(
        GlobalConfiguration::ATTACK_THRESHOLD < GlobalConfiguration::MAJORITY_THRESHOLD,
    );
    assert_condition(GlobalConfiguration::TRANSACTION_CONFIRMATION_COUNT > 0);
    Ok(())
}

#[test]
fn global_config_032_user_chain_inheritance_vectors_match_mainchain() -> TestResult {
    assert_condition(GlobalConfiguration::ENABLE_MULTI_CHAIN);
    assert_condition(GlobalConfiguration::ENABLE_MULTI_DATABASE);
    assert_condition(GlobalConfiguration::INHERIT_MAINCHAIN_SNAPSHOTS);

    assert_eq!(
        GlobalConfiguration::USER_CHAIN_MAX_SUPPLY,
        GlobalConfiguration::MAX_REWARD_SUPPLY
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_ZAR_SUPPLY,
        GlobalConfiguration::MAX_REWARD_SUPPLY
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_GOVERNANCE_PROPOSAL_THRESHOLD,
        GlobalConfiguration::GOVERNANCE_PROPOSAL_THRESHOLD
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_MAJORITY_THRESHOLD,
        GlobalConfiguration::MAJORITY_THRESHOLD
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_ATTACK_THRESHOLD,
        GlobalConfiguration::ATTACK_THRESHOLD
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_STABILIZED_BLOCK_REWARD,
        GlobalConfiguration::STABILIZED_BLOCK_REWARD
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_INITIAL_BLOCK_REWARD,
        GlobalConfiguration::INITIAL_BLOCK_REWARD
    );
    Ok(())
}

#[test]
fn global_config_033_metadata_timestamp_and_batch_dos_bounds_are_sane() -> TestResult {
    assert_eq!(GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES, 8_192);
    assert_eq!(GlobalConfiguration::MIN_BLOCK_SIZE, 64);
    assert_eq!(GlobalConfiguration::MIN_TIMESTAMP_SECS, 946_684_800);
    assert_eq!(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS, 315_360_000);

    assert_eq!(GlobalConfiguration::MAX_BATCH_ITEMS, 50_000);
    assert_eq!(GlobalConfiguration::MAX_ITEM_BYTES, 4_194_304);
    assert_eq!(GlobalConfiguration::MAX_TOTAL_BATCH_BYTES, 67_108_864);

    let default_user_chain_buffer =
        usize::try_from(GlobalConfiguration::DEFAULT_USER_CHAIN_TX_BUFFER_LIMIT)
            .map_err(|_| "DEFAULT_USER_CHAIN_TX_BUFFER_LIMIT does not fit usize".to_string())?;

    assert_condition(GlobalConfiguration::MAX_ITEM_BYTES <= default_user_chain_buffer);
    assert_condition(
        GlobalConfiguration::MAX_TOTAL_BATCH_BYTES > GlobalConfiguration::MAX_ITEM_BYTES,
    );
    Ok(())
}

#[test]
fn global_config_034_input_retry_and_identity_limits_are_sane() -> TestResult {
    assert_eq!(GlobalConfiguration::MAX_ATTEMPTS, 5);
    assert_eq!(GlobalConfiguration::RETRY_DELAY_SECS, 2);
    assert_eq!(GlobalConfiguration::JOIN_TIMEOUT_SECS, 5);

    assert_eq!(GlobalConfiguration::MAX_INPUT_BYTES, 256);
    assert_eq!(GlobalConfiguration::MAX_IDENTITY_KEY_BYTES, 2_097_152);
    assert_eq!(GlobalConfiguration::MAX_GENESIS_JSON_BYTES, 52_428_800);

    assert_eq!(GlobalConfiguration::MAX_YN_INPUT_LEN, 16);
    assert_eq!(GlobalConfiguration::MAX_MODE_INPUT_LEN, 16);
    assert_eq!(GlobalConfiguration::MAX_BATCH_INPUT_LEN, 16);
    assert_eq!(GlobalConfiguration::MAX_BATCH_WALLETS, 10);
    assert_eq!(GlobalConfiguration::MAX_PASS_PROMPTS, 5);
    Ok(())
}

#[test]
fn global_config_035_deterministic_property_ceil_div_matches_reference_formula() -> TestResult {
    let mut state = 0xA11C_EE55_D15C_0DED_u64;

    for _ in 0..4_096 {
        let a = next_deterministic_u64(&mut state);
        let b = next_deterministic_u64(&mut state)
            .rem_euclid(1_000_000)
            .saturating_add(1);

        let expected = if a == 0 {
            0
        } else {
            checked_add_u64(
                a.checked_sub(1)
                    .ok_or_else(|| "ceil_div reference subtraction failed".to_string())?
                    .checked_div(b)
                    .ok_or_else(|| "ceil_div reference division failed".to_string())?,
                1,
            )?
        };

        assert_eq!(GlobalConfiguration::ceil_div(a, b), expected);
    }

    Ok(())
}

#[test]
fn global_config_036_deterministic_fuzz_hex_decoding_rejects_bad_lengths_and_bad_chars()
-> TestResult {
    for len in [0_usize, 1, 2, 63, 126, 127, 129, 130, 256] {
        let candidate = "0".repeat(len);
        assert!(
            decode_hex_to_64(&candidate).is_err(),
            "hex string with length {len} must be rejected"
        );
    }

    let invalid_hex = "g".repeat(128);
    assert!(decode_hex_to_64(&invalid_hex).is_err());

    let uppercase_valid_hex = "A".repeat(128);
    assert!(
        decode_hex_to_64(&uppercase_valid_hex).is_ok(),
        "hex decoder accepts uppercase hex even though config constants should remain lowercase"
    );

    Ok(())
}

#[test]
fn global_config_037_deterministic_fuzz_reward_sequence_is_positive_and_nonincreasing() -> TestResult
{
    let mut previous: Option<u64> = None;

    for reward in GlobalConfiguration::REWARD_REDUCTION_SEQUENCE {
        assert!(*reward > 0);
        assert_eq!(*reward % UNIT_DIVISOR, 0);

        if let Some(prev) = previous {
            assert!(*reward <= prev);
        }

        previous = Some(*reward);
    }

    assert_eq!(previous, Some(GlobalConfiguration::STABILIZED_BLOCK_REWARD));
    Ok(())
}

#[test]
fn global_config_038_adversarial_failover_round_sim_never_selects_out_of_range_round() -> TestResult
{
    let mut state = 0x5151_5151_DEAD_BEEFu64;
    let max_round_start = checked_mul_u64(
        GlobalConfiguration::FAILOVER_MAX_ROUNDS,
        GlobalConfiguration::FAILOVER_WINDOW_SECS,
    )?;

    assert!(max_round_start <= GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS);

    for _ in 0..8_192 {
        let offset = next_deterministic_u64(&mut state)
            .rem_euclid(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS);

        if offset < GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS {
            let round = offset.div_euclid(GlobalConfiguration::FAILOVER_WINDOW_SECS);

            if offset < max_round_start {
                assert!(round < GlobalConfiguration::FAILOVER_MAX_ROUNDS);
            } else {
                assert!(round >= GlobalConfiguration::FAILOVER_MAX_ROUNDS);
            }
        } else {
            assert!(offset >= GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS);
        }
    }

    Ok(())
}

#[test]
fn global_config_039_adversarial_network_timing_sim_rejects_late_or_drifted_proposals() -> TestResult
{
    fn proposal_is_admissible(offset_secs: u64, drift_secs: u64) -> bool {
        offset_secs < GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS
            && drift_secs <= GlobalConfiguration::SLOT_GATE_DRIFT_SECS
    }

    let before_deadline = GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS.saturating_sub(1);
    let at_deadline = GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS;
    let after_deadline = GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS.saturating_add(1);
    let excessive_drift = GlobalConfiguration::SLOT_GATE_DRIFT_SECS.saturating_add(1);

    assert!(proposal_is_admissible(0, 0));
    assert!(proposal_is_admissible(
        before_deadline,
        GlobalConfiguration::SLOT_GATE_DRIFT_SECS
    ));
    assert!(!proposal_is_admissible(at_deadline, 0));
    assert!(!proposal_is_admissible(after_deadline, 0));
    assert!(!proposal_is_admissible(
        GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS,
        excessive_drift
    ));

    Ok(())
}

#[test]
fn global_config_040_load_repeated_config_invariants_remain_stable() -> TestResult {
    let names = column_names();
    let dirs = db_dirs();
    let mut accumulator = 0_u64;

    for _ in 0..10_000 {
        assert_eq!(names.len(), GlobalConfiguration::TOTAL_COLUMNS);
        assert_eq!(dirs.len(), GlobalConfiguration::TOTAL_DB_DIRS);
        assert_eq!(
            GlobalConfiguration::DEFAULT_USER_CHAIN_BLOCK_SIZE,
            GlobalConfiguration::MAX_BLOCK_SIZE
        );
        assert_eq!(
            GlobalConfiguration::USER_CHAIN_REWARD_REDUCTION_SEQUENCE,
            GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
        );

        accumulator = accumulator.wrapping_add(GlobalConfiguration::MAX_BLOCK_SIZE);
        accumulator = accumulator.wrapping_add(GlobalConfiguration::FAILOVER_MAX_ROUNDS);
        accumulator = accumulator.wrapping_add(GlobalConfiguration::TOTAL_REWARD_BLOCKS);
    }

    assert!(accumulator > 0);
    Ok(())
}

#[test]
fn global_config_041_database_directories_are_relative_ascii_safe_names() -> TestResult {
    for dir in db_dirs() {
        assert!(!dir.is_empty());
        assert!(!dir.starts_with('/'));
        assert!(!dir.starts_with('\\'));
        assert!(!dir.contains('/'));
        assert!(!dir.contains('\\'));
        assert!(!dir.contains(' '));
        assert!(
            dir.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_'))
        );
    }

    Ok(())
}

#[test]
fn global_config_042_database_directories_have_expected_storage_suffixes() -> TestResult {
    assert_condition(GlobalConfiguration::DATABASE_DIR_NAME.ends_with("_db"));
    assert_condition(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR.ends_with("_db"));
    assert_condition(GlobalConfiguration::REGISTRY_DIR_NAME.ends_with("_db"));
    assert_condition(GlobalConfiguration::LOG_DATABASE_DIR.ends_with("_db"));
    assert_condition(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR.ends_with("_db"));
    assert_condition(GlobalConfiguration::SIDECHAIN_DATABASE_DIR.ends_with("_db"));

    assert_condition(GlobalConfiguration::WALLETS_DIR.contains("wallets"));
    assert_condition(GlobalConfiguration::AUDIT_REPORTS_DIR.contains("audit"));
    assert_condition(GlobalConfiguration::PEER_LIST_DIR.contains("peerlist"));

    Ok(())
}

#[test]
fn global_config_043_database_directory_numeric_prefixes_match_indexes() -> TestResult {
    for (index, dir) in db_dirs().iter().enumerate() {
        let prefix = dir
            .split_once('.')
            .map(|parts| parts.0)
            .ok_or_else(|| format!("directory `{dir}` is missing numeric prefix separator"))?;

        let parsed = prefix
            .parse::<usize>()
            .map_err(|e| format!("directory prefix parse failed for `{dir}`: {e}"))?;

        assert_eq!(parsed, index);
    }

    Ok(())
}

#[test]
fn global_config_044_genesis_hex_constants_reject_single_bad_character_mutations() -> TestResult {
    for original in [
        GlobalConfiguration::GENESIS_PREV_HASH_HEX,
        GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX,
        GlobalConfiguration::GENESIS_HASH_HEX,
    ] {
        let mut mutated = original.to_string();
        let removed = mutated
            .pop()
            .ok_or_else(|| "cannot mutate empty hex string".to_string())?;

        assert_ne!(removed, 'z');
        mutated.push('z');

        assert!(
            decode_hex_to_64(&mutated).is_err(),
            "mutated hex must be rejected"
        );
    }

    Ok(())
}

#[test]
fn global_config_045_all_genesis_hex_constants_are_128_lower_hex_chars() -> TestResult {
    for hex_value in [
        GlobalConfiguration::GENESIS_PREV_HASH_HEX,
        GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX,
        GlobalConfiguration::GENESIS_HASH_HEX,
    ] {
        assert_eq!(hex_value.len(), 128);
        assert!(is_lower_hex_ascii(hex_value));
    }

    Ok(())
}

#[test]
fn global_config_046_genesis_validator_has_r_prefix_and_128_hex_body() -> TestResult {
    assert_eq!(
        GlobalConfiguration::GENESIS_VALIDATOR
            .as_bytes()
            .first()
            .copied(),
        Some(b'r')
    );

    let body = GlobalConfiguration::GENESIS_VALIDATOR
        .get(1..)
        .ok_or_else(|| "GENESIS_VALIDATOR missing wallet body".to_string())?;

    assert_eq!(body.len(), 128);
    assert!(is_lower_hex_ascii(body));
    Ok(())
}

#[test]
fn global_config_047_burn_address_has_r_prefix_and_128_hex_body() -> TestResult {
    assert_eq!(
        GlobalConfiguration::BURN_ADDRESS
            .as_bytes()
            .first()
            .copied(),
        Some(b'r')
    );

    let body = GlobalConfiguration::BURN_ADDRESS
        .get(1..)
        .ok_or_else(|| "BURN_ADDRESS missing wallet body".to_string())?;

    assert_eq!(body.len(), 128);
    assert!(is_lower_hex_ascii(body));
    Ok(())
}

#[test]
fn global_config_048_genesis_validator_and_burn_address_are_distinct_canonical_wallets()
-> TestResult {
    let genesis = canon_wallet_id_checked(GlobalConfiguration::GENESIS_VALIDATOR)
        .map_err(|e| format!("GENESIS_VALIDATOR is not canonical: {e:?}"))?;

    let burn = canon_wallet_id_checked(GlobalConfiguration::BURN_ADDRESS)
        .map_err(|e| format!("BURN_ADDRESS is not canonical: {e:?}"))?;

    assert_ne!(genesis, burn);
    Ok(())
}

#[test]
fn global_config_049_wallet_constants_remain_valid_when_boundary_trimmed() -> TestResult {
    let genesis_with_spaces = format!(" {} ", GlobalConfiguration::GENESIS_VALIDATOR);
    let burn_with_spaces = format!(" {} ", GlobalConfiguration::BURN_ADDRESS);

    let genesis = canon_wallet_id_checked(&genesis_with_spaces)
        .map_err(|e| format!("trimmed GENESIS_VALIDATOR failed canonicalization: {e:?}"))?;

    let burn = canon_wallet_id_checked(&burn_with_spaces)
        .map_err(|e| format!("trimmed BURN_ADDRESS failed canonicalization: {e:?}"))?;

    assert_eq!(genesis, GlobalConfiguration::GENESIS_VALIDATOR);
    assert_eq!(burn, GlobalConfiguration::BURN_ADDRESS);
    Ok(())
}

#[test]
fn global_config_050_block_payload_capacity_after_overhead_is_positive() -> TestResult {
    let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| "MAX_BLOCK_SIZE does not fit usize".to_string())?;

    let payload_capacity = max_block_size
        .checked_sub(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE)
        .ok_or_else(|| "BLOCK_OVERHEAD_RESERVE exceeds MAX_BLOCK_SIZE".to_string())?;

    assert!(payload_capacity > 0);
    assert!(payload_capacity < max_block_size);
    assert_eq!(payload_capacity, 2_080_768);
    Ok(())
}

#[test]
fn global_config_051_transaction_count_limit_fits_inside_block_byte_limit_floor() -> TestResult {
    assert_condition(GlobalConfiguration::MAX_TXS_PER_BLOCK > 0);
    assert_condition(GlobalConfiguration::MAX_TXS_PER_BLOCK <= GlobalConfiguration::MAX_BLOCK_SIZE);
    assert_condition(
        GlobalConfiguration::MAX_TXS_PER_BLOCK <= GlobalConfiguration::TRANSACTION_BUFFER_LIMIT,
    );
    Ok(())
}

#[test]
fn global_config_052_batch_serialized_overhead_is_bounded_by_block_overhead_reserve() -> TestResult
{
    assert_condition(
        GlobalConfiguration::MAX_BATCH_SERIALIZED_OVERHEAD
            <= GlobalConfiguration::BLOCK_OVERHEAD_RESERVE,
    );
    assert_eq!(
        GlobalConfiguration::BLOCK_OVERHEAD_RESERVE
            .checked_div(GlobalConfiguration::MAX_BATCH_SERIALIZED_OVERHEAD)
            .ok_or_else(|| "division by zero in overhead ratio".to_string())?,
        8
    );
    Ok(())
}

#[test]
fn global_config_053_max_future_skew_is_exactly_two_hours() -> TestResult {
    let expected = checked_mul_u64(checked_mul_u64(2, 60)?, 60)?;
    assert_eq!(GlobalConfiguration::MAX_FUTURE_SKEW_SECS, expected);
    Ok(())
}

#[test]
fn global_config_054_block_and_puzzle_intervals_are_sane_for_fast_failover() -> TestResult {
    assert_condition(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS > 0);
    assert_condition(GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS > 0);
    assert_condition(
        GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS
            < GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
    );
    Ok(())
}

#[test]
fn global_config_055_activation_warmup_matches_single_block_slot() -> TestResult {
    assert_eq!(
        GlobalConfiguration::ACTIVATION_WARMUP_SECS,
        GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS
    );
    assert_eq!(GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS, 1);
    Ok(())
}

#[test]
fn global_config_056_quarantine_and_epoch_slot_bounds_are_sane() -> TestResult {
    assert_condition(GlobalConfiguration::QUARANTINE_BLOCKS > 0);
    assert_condition(GlobalConfiguration::EPOCH_SLOTS > 0);
    assert_condition(GlobalConfiguration::QUARANTINE_BLOCKS < GlobalConfiguration::EPOCH_SLOTS);
    assert_eq!(GlobalConfiguration::QUARANTINE_BLOCKS, 4);
    assert_eq!(GlobalConfiguration::EPOCH_SLOTS, 60);
    Ok(())
}

#[test]
fn global_config_057_heartbeat_interval_and_canonical_lease_are_aggressive_vectors() -> TestResult {
    assert_eq!(GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS, 10);
    assert_eq!(
        GlobalConfiguration::CANONICAL_LEASE_BLOCKS,
        GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS
    );
    assert_eq!(GlobalConfiguration::HEARTBEAT_TX_INTERVAL_SECS, 300);
    Ok(())
}

#[test]
fn global_config_058_failover_timing_exact_vector_values_match_design() -> TestResult {
    assert_eq!(GlobalConfiguration::FAILOVER_BUILD_SLACK_SECS, 5);
    assert_eq!(GlobalConfiguration::FAILOVER_LEADER_GRACE_SECS, 5);
    assert_eq!(GlobalConfiguration::FAILOVER_SLACK_SECS, 10);
    assert_eq!(GlobalConfiguration::FAILOVER_WINDOW_SECS, 12);
    assert_eq!(GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS, 6);
    assert_eq!(GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS, 24);
    Ok(())
}

#[test]
fn global_config_059_failover_rounds_fit_exactly_before_gossip_tail() -> TestResult {
    let consumed_round_secs = checked_mul_u64(
        GlobalConfiguration::FAILOVER_MAX_ROUNDS,
        GlobalConfiguration::FAILOVER_WINDOW_SECS,
    )?;

    assert!(consumed_round_secs <= GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS);

    let proposal_margin = GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS
        .checked_sub(consumed_round_secs)
        .ok_or_else(|| "failover consumed more than proposal deadline".to_string())?;

    assert_eq!(proposal_margin, 0);
    assert_eq!(GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS, 6);
    assert_eq!(
        checked_add_u64(
            GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS,
            GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS,
        )?,
        GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS
    );

    Ok(())
}

#[test]
fn global_config_060_slot_gossip_buffer_is_smaller_than_block_slot() -> TestResult {
    assert_condition(GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS > 0);
    assert_condition(
        GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS
            < GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
    );
    Ok(())
}

#[test]
fn global_config_061_rewardless_prefix_and_reward_delay_only_skip_genesis() -> TestResult {
    assert_eq!(GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS, 1);
    assert_eq!(GlobalConfiguration::REWARD_DELAY_BLOCKS, 1);
    Ok(())
}

#[test]
fn global_config_062_reward_sequence_sum_is_exactly_38_remzar() -> TestResult {
    let mut reward_sum_micro = 0_u64;

    for reward in GlobalConfiguration::REWARD_REDUCTION_SEQUENCE {
        reward_sum_micro = checked_add_u64(reward_sum_micro, *reward)?;
    }

    assert_eq!(reward_sum_micro.rem_euclid(UNIT_DIVISOR), 0);
    assert_eq!(reward_sum_micro.div_euclid(UNIT_DIVISOR), 38);
    Ok(())
}

#[test]
fn global_config_063_total_reward_blocks_exceeds_ladder_block_count() -> TestResult {
    let ladder_blocks = checked_mul_u64(
        usize_to_u64(GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len())?,
        GlobalConfiguration::HALVING_INTERVAL_BLOCKS,
    )?;

    assert_condition(GlobalConfiguration::TOTAL_REWARD_BLOCKS > ladder_blocks);
    assert_condition(
        GlobalConfiguration::TOTAL_REWARD_BLOCKS
            > GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD,
    );
    Ok(())
}

#[test]
fn global_config_064_max_reward_supply_is_exactly_200_million_whole_remzar() -> TestResult {
    assert_eq!(
        GlobalConfiguration::MAX_REWARD_SUPPLY.rem_euclid(UNIT_DIVISOR),
        0
    );
    assert_eq!(
        GlobalConfiguration::MAX_REWARD_SUPPLY.div_euclid(UNIT_DIVISOR),
        200_000_000
    );
    Ok(())
}

#[test]
fn global_config_065_max_transaction_amount_is_half_of_max_supply() -> TestResult {
    let doubled_max_tx = checked_mul_u64(GlobalConfiguration::MAX_TX_AMOUNT, 2)?;
    assert_eq!(doubled_max_tx, GlobalConfiguration::MAX_SUPPLY);
    Ok(())
}

#[test]
fn global_config_066_min_reward_threshold_is_one_hundredth_remzar() -> TestResult {
    assert_eq!(
        GlobalConfiguration::MIN_REWARD_THRESHOLD,
        UNIT_DIVISOR
            .checked_div(100)
            .ok_or_else(|| "UNIT_DIVISOR division by 100 failed".to_string())?
    );
    Ok(())
}

#[test]
fn global_config_067_governance_proposal_threshold_matches_min_reward_threshold() -> TestResult {
    assert_eq!(
        GlobalConfiguration::GOVERNANCE_PROPOSAL_THRESHOLD,
        GlobalConfiguration::MIN_REWARD_THRESHOLD
    );
    Ok(())
}

#[test]
fn global_config_068_column_ids_are_unique_as_storage_discriminants() -> TestResult {
    let ids = column_ids();
    let unique: BTreeSet<u8> = ids.iter().copied().collect();

    assert_eq!(ids.len(), GlobalConfiguration::TOTAL_COLUMNS);
    assert_eq!(unique.len(), ids.len());
    Ok(())
}

#[test]
fn global_config_069_column_name_first_and_last_vectors_are_stable() -> TestResult {
    let pairs = column_pairs();

    let first = pairs
        .first()
        .copied()
        .ok_or_else(|| "missing first column pair".to_string())?;

    let last = pairs
        .last()
        .copied()
        .ok_or_else(|| "missing last column pair".to_string())?;

    assert_eq!(first, (0, "meta_data"));
    assert_eq!(last, (18, "canonical_chain_view"));
    Ok(())
}

#[test]
fn global_config_070_column_names_do_not_have_leading_trailing_or_duplicate_underscores()
-> TestResult {
    for name in column_names() {
        assert!(!name.starts_with('_'));
        assert!(!name.ends_with('_'));
        assert!(!name.contains("__"));
    }

    Ok(())
}

#[test]
fn global_config_071_critical_canonical_column_names_are_exact_vectors() -> TestResult {
    assert_eq!(
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
        "block_meta_by_hash"
    );
    assert_eq!(
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        "batch_by_block_hash"
    );
    assert_eq!(
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        "canonical_height_to_hash"
    );
    assert_eq!(
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
        "canonical_chain_view"
    );
    Ok(())
}

#[test]
fn global_config_072_multichain_capacity_limits_are_consistent() -> TestResult {
    assert_eq!(
        GlobalConfiguration::MAX_CONCURRENT_DATABASES,
        GlobalConfiguration::MAX_USER_CHAINS
    );
    assert_condition(
        GlobalConfiguration::MAX_CONCURRENT_ROCKSDB_INSTANCES
            >= GlobalConfiguration::MAX_CONCURRENT_DATABASES,
    );
    assert_eq!(GlobalConfiguration::MAX_USER_CHAINS, 1_000);
    assert_eq!(
        GlobalConfiguration::MAX_CONCURRENT_ROCKSDB_INSTANCES,
        10_000
    );
    Ok(())
}

#[test]
fn global_config_073_user_chain_directory_and_format_vectors_are_stable() -> TestResult {
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_DATABASE_DIR,
        "user_chains_db"
    );
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_SNAPSHOT_DIR,
        "user_chain_snapshots"
    );
    assert_eq!(
        GlobalConfiguration::DEFAULT_USER_CHAIN_PREFIX,
        "Remzar_Chain_"
    );
    assert_eq!(
        GlobalConfiguration::DEFAULT_USER_COIN_NAME_FORMAT,
        "Remzar_Chain_{id}"
    );
    assert_eq!(
        GlobalConfiguration::DEFAULT_USER_COIN_SYMBOL_FORMAT,
        "REMZAR{id}"
    );
    Ok(())
}

#[test]
fn global_config_074_default_user_chain_buffer_is_twice_main_block_size() -> TestResult {
    assert_eq!(
        GlobalConfiguration::DEFAULT_USER_CHAIN_TX_BUFFER_LIMIT,
        checked_mul_u64(2, GlobalConfiguration::MAX_BLOCK_SIZE)?
    );
    assert_eq!(
        GlobalConfiguration::DEFAULT_USER_CHAIN_BLOCK_SIZE,
        GlobalConfiguration::MAX_BLOCK_SIZE
    );
    Ok(())
}

#[test]
fn global_config_075_user_chain_network_magic_is_exact_nonzero_vector() -> TestResult {
    assert_eq!(
        GlobalConfiguration::USER_CHAIN_NETWORK_MAGIC_BASE,
        [137, 29, 3, 7]
    );
    assert_condition(
        GlobalConfiguration::USER_CHAIN_NETWORK_MAGIC_BASE
            .iter()
            .any(|b| *b != 0),
    );
    Ok(())
}

#[test]
fn global_config_076_domain_separation_defaults_are_stable() -> TestResult {
    assert_condition(!GlobalConfiguration::DOMAIN_SEPARATION_ON);
    assert_eq!(
        GlobalConfiguration::DOMAIN_TAG,
        b"REMZAR_GUARDIAN_BATCH_SHAKE256_V1"
    );
    assert_condition(!GlobalConfiguration::DOMAIN_TAG.is_empty());
    Ok(())
}

#[test]
fn global_config_077_argon2_parameter_vectors_are_sane() -> TestResult {
    assert_eq!(GlobalConfiguration::ARGON2_MEMORY_KIB, 65_536);
    assert_eq!(GlobalConfiguration::ARGON2_TIME_COST, 3);
    assert_eq!(GlobalConfiguration::ARGON2_LANES, 1);

    assert_condition(GlobalConfiguration::ARGON2_MEMORY_KIB >= 64 * 1024);
    assert_condition(GlobalConfiguration::ARGON2_TIME_COST > 0);
    assert_condition(GlobalConfiguration::ARGON2_LANES > 0);
    Ok(())
}

#[test]
fn global_config_078_private_key_and_encrypted_blob_caps_are_ordered() -> TestResult {
    assert_eq!(GlobalConfiguration::MAX_PRIVATE_KEY_BYTES, 1_048_576);
    assert_eq!(GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES, 16_777_216);
    assert_condition(
        GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES > GlobalConfiguration::MAX_PRIVATE_KEY_BYTES,
    );
    Ok(())
}

#[test]
fn global_config_079_consensus_participation_limits_are_ordered() -> TestResult {
    assert_eq!(
        GlobalConfiguration::MAX_ZAR_PARTICIPANTS,
        usize_to_u64(GlobalConfiguration::MAX_VALIDATORS)?
    );
    assert_condition(GlobalConfiguration::MAX_IDENTITIES >= GlobalConfiguration::MAX_VALIDATORS);
    assert_condition(
        GlobalConfiguration::MAX_SNAPSHOT_ENTRIES >= GlobalConfiguration::MAX_IDENTITIES,
    );
    assert_condition(
        GlobalConfiguration::MAX_VERIFYING_KEYS <= GlobalConfiguration::MAX_VALIDATORS,
    );
    assert_eq!(GlobalConfiguration::MAX_PEER_ID_B58_LEN, 128);
    Ok(())
}

#[test]
fn global_config_080_load_scan_all_directory_and_column_constants_repeatedly() -> TestResult {
    let dirs = db_dirs();
    let pairs = column_pairs();
    let mut checksum = 0_usize;

    for _ in 0..10_000 {
        for dir in &dirs {
            checksum = checksum.wrapping_add(dir.len());
            assert!(!dir.is_empty());
        }

        for (id, name) in &pairs {
            checksum = checksum.wrapping_add(usize::from(*id));
            checksum = checksum.wrapping_add(name.len());
            assert!(usize::from(*id) < GlobalConfiguration::TOTAL_COLUMNS);
            assert!(!name.is_empty());
        }
    }

    assert!(checksum > 0);
    Ok(())
}

#[test]
fn global_config_081_start_date_uses_strict_yyyy_mm_dd_vector_shape() -> TestResult {
    let start_date = GlobalConfiguration::START_DATE;

    assert_eq!(start_date.len(), 10);
    assert_eq!(start_date.get(4..5), Some("-"));
    assert_eq!(start_date.get(7..8), Some("-"));

    let year = start_date
        .get(0..4)
        .ok_or_else(|| "START_DATE missing year".to_string())?;
    let month = start_date
        .get(5..7)
        .ok_or_else(|| "START_DATE missing month".to_string())?;
    let day = start_date
        .get(8..10)
        .ok_or_else(|| "START_DATE missing day".to_string())?;

    assert!(year.bytes().all(|b| b.is_ascii_digit()));
    assert!(month.bytes().all(|b| b.is_ascii_digit()));
    assert!(day.bytes().all(|b| b.is_ascii_digit()));

    assert_eq!(year, "2026");
    assert_eq!(month, "06");
    assert_eq!(day, "26");
    Ok(())
}

#[test]
fn global_config_082_default_port_is_valid_non_reserved_tcp_port() -> TestResult {
    assert_condition(GlobalConfiguration::DEFAULT_PORT > 1_024);
    assert_condition(GlobalConfiguration::DEFAULT_PORT <= 65_535);
    assert_eq!(GlobalConfiguration::DEFAULT_PORT, 36_213);
    Ok(())
}

#[test]
fn global_config_083_genesis_prev_hash_hex_is_exact_zero_vector() -> TestResult {
    assert_eq!(GlobalConfiguration::GENESIS_PREV_HASH_HEX.len(), 128);

    for byte in GlobalConfiguration::GENESIS_PREV_HASH_HEX.bytes() {
        assert_eq!(byte, b'0');
    }

    Ok(())
}

#[test]
fn global_config_084_genesis_merkle_and_genesis_hash_are_not_zero_vectors() -> TestResult {
    let merkle = decode_hex_to_64(GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX)
        .map_err(|e| format!("GENESIS_MERKLE_ROOT_HEX decode failed: {e:?}"))?;
    let genesis_hash = decode_hex_to_64(GlobalConfiguration::GENESIS_HASH_HEX)
        .map_err(|e| format!("GENESIS_HASH_HEX decode failed: {e:?}"))?;

    assert!(merkle.iter().any(|b| *b != 0));
    assert!(genesis_hash.iter().any(|b| *b != 0));
    assert_ne!(merkle, GlobalConfiguration::GENESIS_PREV_HASH_BYTES);
    assert_ne!(genesis_hash, GlobalConfiguration::GENESIS_PREV_HASH_BYTES);
    Ok(())
}

#[test]
fn global_config_085_genesis_hash_merkle_and_prev_hash_are_distinct_vectors() -> TestResult {
    assert_ne!(
        GlobalConfiguration::GENESIS_HASH_HEX,
        GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX
    );
    assert_ne!(
        GlobalConfiguration::GENESIS_HASH_HEX,
        GlobalConfiguration::GENESIS_PREV_HASH_HEX
    );
    assert_ne!(
        GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX,
        GlobalConfiguration::GENESIS_PREV_HASH_HEX
    );
    Ok(())
}

#[test]
fn global_config_086_wallet_constants_have_no_uppercase_or_whitespace() -> TestResult {
    for wallet in [
        GlobalConfiguration::GENESIS_VALIDATOR,
        GlobalConfiguration::BURN_ADDRESS,
    ] {
        assert_eq!(wallet.trim(), wallet);
        assert!(!wallet.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(!wallet.bytes().any(|b| b.is_ascii_whitespace()));
    }

    Ok(())
}

#[test]
fn global_config_087_invalid_wallet_prefix_mutations_are_rejected() -> TestResult {
    for wallet in [
        GlobalConfiguration::GENESIS_VALIDATOR,
        GlobalConfiguration::BURN_ADDRESS,
    ] {
        let body = wallet
            .get(1..)
            .ok_or_else(|| "wallet constant missing body".to_string())?;
        let mutated = format!("p{body}");

        assert!(
            canon_wallet_id_checked(&mutated).is_err(),
            "non-r wallet prefix must be rejected"
        );
    }

    Ok(())
}

#[test]
fn global_config_088_reward_sequence_len_and_halving_interval_are_exact_vectors() -> TestResult {
    assert_eq!(GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len(), 5);
    assert_eq!(GlobalConfiguration::HALVING_INTERVAL_BLOCKS, 500_000);
    assert_condition(
        GlobalConfiguration::HALVING_INTERVAL_BLOCKS > GlobalConfiguration::EPOCH_SLOTS,
    );
    Ok(())
}

#[test]
fn global_config_089_each_reward_tier_is_between_stabilized_and_max_reward() -> TestResult {
    for reward in GlobalConfiguration::REWARD_REDUCTION_SEQUENCE {
        assert!(*reward >= GlobalConfiguration::STABILIZED_BLOCK_REWARD);
        assert!(*reward <= GlobalConfiguration::MAX_BLOCK_REWARD);
        assert_eq!(reward.rem_euclid(UNIT_DIVISOR), 0);
    }

    Ok(())
}

#[test]
fn global_config_090_stabilized_remaining_supply_is_exactly_divisible_by_stabilized_reward()
-> TestResult {
    let remaining = GlobalConfiguration::MAX_REWARD_SUPPLY
        .saturating_sub(GlobalConfiguration::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE);

    assert_eq!(
        remaining.rem_euclid(GlobalConfiguration::STABILIZED_BLOCK_REWARD),
        0
    );

    assert_eq!(
        remaining.div_euclid(GlobalConfiguration::STABILIZED_BLOCK_REWARD),
        GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD
    );

    Ok(())
}

#[test]
fn global_config_091_total_reward_blocks_has_expected_exact_vector_value() -> TestResult {
    assert_eq!(GlobalConfiguration::TOTAL_REWARD_BLOCKS, 183_500_021);
    assert_eq!(
        GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD,
        181_000_020
    );
    Ok(())
}

#[test]
fn global_config_092_min_block_size_and_block_max_bounds_are_ordered() -> TestResult {
    assert_condition(GlobalConfiguration::MIN_BLOCK_SIZE > 0);
    assert_condition(GlobalConfiguration::MIN_BLOCK_SIZE < GlobalConfiguration::MAX_BLOCK_SIZE);
    assert_condition(
        GlobalConfiguration::MIN_BLOCK_SIZE
            < u64::try_from(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE)
                .map_err(|_| "BLOCK_OVERHEAD_RESERVE does not fit u64".to_string())?,
    );
    Ok(())
}

#[test]
fn global_config_093_min_sized_batch_items_fit_total_batch_byte_limit() -> TestResult {
    let min_item_total = checked_mul_usize(
        GlobalConfiguration::MAX_BATCH_ITEMS,
        usize::try_from(GlobalConfiguration::MIN_BLOCK_SIZE)
            .map_err(|_| "MIN_BLOCK_SIZE does not fit usize".to_string())?,
    )?;

    assert!(min_item_total <= GlobalConfiguration::MAX_TOTAL_BATCH_BYTES);
    Ok(())
}

#[test]
fn global_config_094_batch_item_limit_is_at_least_default_user_chain_buffer() -> TestResult {
    assert_eq!(
        u64::try_from(GlobalConfiguration::MAX_ITEM_BYTES)
            .map_err(|_| "MAX_ITEM_BYTES does not fit u64".to_string())?,
        GlobalConfiguration::DEFAULT_USER_CHAIN_TX_BUFFER_LIMIT
    );

    Ok(())
}

#[test]
fn global_config_095_default_user_chain_genesis_timestamp_is_after_min_timestamp() -> TestResult {
    assert_eq!(
        GlobalConfiguration::DEFAULT_USER_CHAIN_GENESIS_TIMESTAMP,
        1782435600
    );
    assert_condition(
        GlobalConfiguration::DEFAULT_USER_CHAIN_GENESIS_TIMESTAMP
            > GlobalConfiguration::MIN_TIMESTAMP_SECS,
    );
    Ok(())
}

#[test]
fn global_config_096_crypto_size_bounds_are_ordered_for_nonce_salt_key() -> TestResult {
    assert_condition(GlobalConfiguration::NONCE_SIZE > 0);
    assert_condition(GlobalConfiguration::SALT_SIZE > GlobalConfiguration::NONCE_SIZE);
    assert_condition(GlobalConfiguration::AES_KEY_SIZE > GlobalConfiguration::SALT_SIZE);
    Ok(())
}

#[test]
fn global_config_097_private_key_hex_input_len_matches_secret_byte_expansion() -> TestResult {
    let expected_hex_len = checked_mul_usize(GlobalConfiguration::MLDSA65_SECRET_BYTES, 2)?;

    assert_eq!(
        GlobalConfiguration::MLDSA65_SECRET_HEX_LEN,
        expected_hex_len
    );
    assert_eq!(
        GlobalConfiguration::MAX_PRIVKEY_HEX_INPUT_LEN,
        expected_hex_len
    );
    assert_condition(
        GlobalConfiguration::MAX_PRIVKEY_HEX_INPUT_LEN > GlobalConfiguration::GUARDIAN_SIG_LEN,
    );
    Ok(())
}

#[test]
fn global_config_098_retry_total_wait_window_covers_join_timeout() -> TestResult {
    let retry_window = checked_mul_u64(
        u64::from(GlobalConfiguration::MAX_ATTEMPTS),
        GlobalConfiguration::RETRY_DELAY_SECS,
    )?;

    assert_eq!(retry_window, 10);
    assert!(retry_window >= GlobalConfiguration::JOIN_TIMEOUT_SECS);
    Ok(())
}

#[test]
fn global_config_099_user_chain_paths_do_not_collide_with_main_database_dirs() -> TestResult {
    let dirs: BTreeSet<&str> = db_dirs().into_iter().collect();

    assert!(!dirs.contains(GlobalConfiguration::USER_CHAIN_DATABASE_DIR));
    assert!(!dirs.contains(GlobalConfiguration::USER_CHAIN_SNAPSHOT_DIR));
    assert_ne!(
        GlobalConfiguration::USER_CHAIN_DATABASE_DIR,
        GlobalConfiguration::USER_CHAIN_SNAPSHOT_DIR
    );
    Ok(())
}

#[test]
fn global_config_100_all_fixed_string_vectors_are_non_empty_and_ascii() -> TestResult {
    let fixed_strings = [
        GlobalConfiguration::COIN_NAME,
        GlobalConfiguration::SYMBOL,
        GlobalConfiguration::START_DATE,
        GlobalConfiguration::GENESIS_JSON_PATH,
        GlobalConfiguration::BASE58_ALPHABET,
        GlobalConfiguration::USER_CHAIN_DATABASE_DIR,
        GlobalConfiguration::USER_CHAIN_SNAPSHOT_DIR,
        GlobalConfiguration::DEFAULT_USER_CHAIN_PREFIX,
        GlobalConfiguration::DEFAULT_USER_COIN_NAME_FORMAT,
        GlobalConfiguration::DEFAULT_USER_COIN_SYMBOL_FORMAT,
    ];

    for value in fixed_strings {
        assert!(!value.is_empty());
        assert!(value.is_ascii());
    }

    Ok(())
}
