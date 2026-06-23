use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::validatorstate::ValidatorState;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const UNIX_2000: u64 = 946_684_800;

static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(UNIX_2000)
}

fn valid_timestamp(seed: u64) -> u64 {
    let now = now_secs().max(UNIX_2000);
    let span = now.saturating_sub(UNIX_2000).saturating_add(1);
    UNIX_2000.saturating_add(seed % span)
}

fn valid_join_height(seed: u64) -> u64 {
    1u64.saturating_add(seed % 100_000)
}

fn wallet(seed: u64) -> String {
    format!("r{:0128x}", seed)
}

fn distinct_wallets(seed_a: u64, seed_b: u64) -> (String, String) {
    let first = wallet(seed_a);
    let mut second = wallet(seed_b);

    if first == second {
        second = wallet(seed_a.wrapping_add(1));
    }

    (first, second)
}

fn wallet_array(wallet: &str) -> [u8; REMZAR_WALLET_LEN] {
    let bytes = wallet.as_bytes();
    assert_eq!(bytes.len(), REMZAR_WALLET_LEN);

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    out
}

fn manual_register(wallet: &str, timestamp: u64) -> RegisterNodeTx {
    RegisterNodeTx {
        wallet_address: wallet_array(wallet),
        timestamp,
    }
}

fn apply_register_at_block_time(
    state: &mut ValidatorState,
    block_height: u64,
    tx: &RegisterNodeTx,
) -> Result<(), ErrorDetection> {
    state.apply_register_tx_at_block_time(block_height, tx.timestamp, tx)
}

fn register_wallet_string(tx: &RegisterNodeTx) -> String {
    std::str::from_utf8(&tx.wallet_address)
        .expect("generated RegisterNodeTx wallet bytes must be valid UTF-8")
        .to_string()
}

fn test_root_path() -> PathBuf {
    let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "remzar_validatorstate_prop_{}_{}",
        std::process::id(),
        id
    ));

    let _ = std::fs::remove_dir_all(&root);
    root
}

fn make_node_opts(root: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: root.join("identity.key").to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: root.to_string_lossy().to_string(),
        wallet_address: String::new(),
        founder: false,
    }
}

fn fresh_manager() -> RockDBManager {
    let root = test_root_path();
    let db_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let opts = make_node_opts(&root);

    RockDBManager::new_blockchain(
        &opts,
        db_path
            .to_str()
            .expect("temporary blockchain path should be valid UTF-8"),
    )
    .expect("fresh temporary RocksDB manager should open")
}

fn fresh_state() -> ValidatorState {
    ValidatorState::with_manager(fresh_manager())
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_validator_state_starts_empty_and_unknown_wallets_are_not_known(
        wallet_seed in any::<u64>(),
    ) {
        let state = fresh_state();
        let wallet = wallet(wallet_seed);

        prop_assert!(
            state.is_empty(),
            "fresh ValidatorState must start empty"
        );

        prop_assert_eq!(
            state.len(),
            0,
            "fresh ValidatorState length must be zero"
        );

        prop_assert!(
            state.all().is_empty(),
            "fresh ValidatorState::all must return an empty map"
        );

        prop_assert_eq!(
            state.is_canonically_known(&wallet).expect("valid wallet query should not error"),
            false,
            "unknown valid wallet must not be canonically known"
        );

        prop_assert_eq!(
            state.meta_for(&wallet),
            None,
            "unknown valid wallet must not have metadata"
        );

        prop_assert_eq!(
            state.join_height(&wallet),
            None,
            "unknown valid wallet must not have join height"
        );
    }

    // 02/25
    #[test]
    fn test_002_load_state_on_empty_database_returns_not_found_without_creating_state(
        _case in any::<u8>(),
    ) {
        let manager = fresh_manager();

        prop_assert!(
            ValidatorState::load_state(manager).is_err(),
            "load_state on an empty database must fail instead of inventing validator state"
        );
    }

    // 03/25
    #[test]
    fn test_003_load_or_new_on_empty_database_returns_empty_state_and_false_multi_validator_latch(
        _case in any::<u8>(),
    ) {
        let manager = fresh_manager();

        let state = ValidatorState::load_or_new(manager)
            .expect("load_or_new should create empty ValidatorState when snapshot is missing");

        prop_assert!(state.is_empty());
        prop_assert_eq!(state.len(), 0);

        prop_assert!(
            !state
                .multi_validator_ever_seen()
                .expect("multi-validator latch read should succeed"),
            "fresh state must not claim multi-validator era was seen"
        );
    }

    // 04/25
    #[test]
    fn test_004_seed_genesis_founder_inserts_canonical_founder_at_height_zero(
        founder_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let founder = wallet(founder_seed);
        let timestamp = valid_timestamp(timestamp_seed);

        state
            .seed_genesis_founder(&founder, timestamp)
            .expect("valid founder seed should succeed");

        prop_assert_eq!(state.len(), 1);
        prop_assert!(!state.is_empty());

        prop_assert!(
            state
                .is_canonically_known(&founder)
                .expect("known founder query should succeed"),
            "seeded founder must be canonically known"
        );

        prop_assert_eq!(
            state.join_height(&founder),
            Some(0),
            "genesis founder must always have join_height zero"
        );

        let meta = state
            .meta_for(&founder)
            .expect("seeded founder must have metadata");

        prop_assert_eq!(meta.join_height, 0);
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, 0);
        prop_assert_eq!(meta.last_renew_timestamp, timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 05/25
    #[test]
    fn test_005_seed_genesis_founder_canonicalizes_uppercase_prefix_hex_and_outer_whitespace(
        tail in "[0-9A-F]{128}",
        timestamp_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let raw = format!(" \n\tR{tail}\r\n ");
        let expected = format!("r{}", tail.to_ascii_lowercase());

        state
            .seed_genesis_founder(&raw, valid_timestamp(timestamp_seed))
            .expect("canonicalizable founder wallet should seed");

        prop_assert!(
            state
                .is_canonically_known(&expected)
                .expect("canonical founder query should succeed"),
            "founder must be stored under canonical lowercase wallet"
        );

        prop_assert_eq!(
            state.join_height(&expected),
            Some(0),
            "canonicalized founder must preserve join_height zero"
        );

        prop_assert!(
            state.all().contains_key(&expected),
            "all() map must contain canonical founder key"
        );
    }

    // 06/25
    #[test]
    fn test_006_seed_genesis_founder_rejects_invalid_wallet_without_mutating_state(
        bad_tail in "[0-9a-f]{0,127}",
        timestamp_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let invalid = format!("r{bad_tail}");

        prop_assert!(
            state
                .seed_genesis_founder(&invalid, valid_timestamp(timestamp_seed))
                .is_err(),
            "invalid founder wallet must be rejected"
        );

        prop_assert_eq!(
            state.len(),
            0,
            "failed founder seed must not mutate validator state"
        );

        prop_assert!(state.is_empty());
    }

    // 07/25
    #[test]
    fn test_007_seed_genesis_founder_rejects_implausibly_old_timestamp_without_mutating_state(
        founder_seed in any::<u64>(),
        old_timestamp in 0u64..UNIX_2000,
    ) {
        let mut state = fresh_state();
        let founder = wallet(founder_seed);

        prop_assert!(
            state.seed_genesis_founder(&founder, old_timestamp).is_err(),
            "founder timestamp before year 2000 must be rejected"
        );

        prop_assert_eq!(
            state.len(),
            0,
            "failed timestamp validation must not insert founder"
        );
    }

    // 08/25
    #[test]
    fn test_008_seed_genesis_founder_is_idempotent_for_same_founder_and_preserves_original_metadata(
        founder_seed in any::<u64>(),
        first_ts_seed in any::<u64>(),
        second_ts_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let founder = wallet(founder_seed);
        let first_ts = valid_timestamp(first_ts_seed);
        let second_ts = valid_timestamp(second_ts_seed);

        state
            .seed_genesis_founder(&founder, first_ts)
            .expect("first founder seed should succeed");

        let before = state
            .meta_for(&founder)
            .expect("founder metadata should exist after first seed");

        state
            .seed_genesis_founder(&founder, second_ts)
            .expect("second same-founder seed should be idempotent");

        let after = state
            .meta_for(&founder)
            .expect("founder metadata should still exist after second seed");

        prop_assert_eq!(
            state.len(),
            1,
            "idempotent founder seed must not duplicate founder"
        );

        prop_assert_eq!(
            after,
            before,
            "idempotent founder seed must preserve original founder metadata"
        );
    }

    // 09/25
    #[test]
    fn test_009_commit_and_load_state_roundtrip_preserves_seeded_founder_snapshot(
        founder_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
    ) {
        let manager = fresh_manager();
        let founder = wallet(founder_seed);
        let timestamp = valid_timestamp(timestamp_seed);

        let mut state = ValidatorState::with_manager(manager.clone());

        state
            .seed_genesis_founder(&founder, timestamp)
            .expect("seeded founder should commit");

        let loaded = ValidatorState::load_state(manager)
            .expect("load_state should reload committed ValidatorState snapshot");

        prop_assert_eq!(loaded.len(), 1);
        prop_assert_eq!(loaded.join_height(&founder), Some(0));

        let loaded_meta = loaded
            .meta_for(&founder)
            .expect("loaded founder metadata must exist");

        prop_assert_eq!(loaded_meta.join_timestamp, timestamp);
        prop_assert_eq!(loaded_meta.exit_height, None);
    }

    // 10/25
    #[test]
    fn test_010_single_founder_does_not_trip_multi_validator_ever_seen_latch(
        founder_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();

        state
            .seed_genesis_founder(&wallet(founder_seed), valid_timestamp(timestamp_seed))
            .expect("single founder seed should succeed");

        prop_assert_eq!(state.len(), 1);

        prop_assert!(
            !state
                .multi_validator_ever_seen()
                .expect("latch read should succeed"),
            "single-validator state must not persist multi-validator latch"
        );
    }

    // 11/25
    #[test]
    fn test_011_second_validator_registration_trips_and_persists_multi_validator_latch(
        founder_seed in any::<u64>(),
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        let (founder, validator) = distinct_wallets(founder_seed, validator_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let join_height = valid_join_height(height_seed);

        let manager = fresh_manager();
        let mut state = ValidatorState::with_manager(manager.clone());

        state
            .seed_genesis_founder(&founder, timestamp)
            .expect("founder seed should succeed");

        let reg = manual_register(&validator, timestamp);

        apply_register_at_block_time(&mut state, join_height, &reg)
            .expect("second validator registration should succeed");

        prop_assert_eq!(state.len(), 2);

        prop_assert!(
            state
                .multi_validator_ever_seen()
                .expect("multi-validator latch read should succeed"),
            "adding a second validator must persist multi-validator latch"
        );

        let loaded = ValidatorState::load_state(manager)
            .expect("committed two-validator state should reload");

        prop_assert!(
            loaded
                .multi_validator_ever_seen()
                .expect("loaded latch read should succeed"),
            "multi-validator latch must survive reload"
        );
    }

    // 12/25
    #[test]
    fn test_012_apply_register_tx_inserts_new_validator_with_exact_join_height_and_timestamp(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let join_height = valid_join_height(height_seed);
        let reg = manual_register(&validator, timestamp);

        apply_register_at_block_time(&mut state, join_height, &reg)
            .expect("valid RegisterNodeTx should insert validator");

        prop_assert_eq!(state.len(), 1);
        prop_assert_eq!(state.join_height(&validator), Some(join_height));

        let meta = state
            .meta_for(&validator)
            .expect("inserted validator metadata must exist");

        prop_assert_eq!(meta.join_height, join_height);
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, join_height);
        prop_assert_eq!(meta.last_renew_timestamp, timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 13/25
    #[test]
    fn test_013_apply_register_tx_canonicalizes_register_wallet_before_storage(
        upper_tail in "[0-9A-F]{128}",
        height_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let raw_wallet = format!("R{upper_tail}");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let reg = RegisterNodeTx::new(raw_wallet)
            .expect("RegisterNodeTx::new should canonicalize uppercase wallet");

        apply_register_at_block_time(&mut state, valid_join_height(height_seed), &reg)
            .expect("canonicalized register tx should apply");

        let stored_wallet = register_wallet_string(&reg);

        prop_assert_eq!(
            &stored_wallet,
            &expected,
            "RegisterNodeTx helper must store canonical lowercase wallet bytes"
        );

        prop_assert!(
            state.all().contains_key(&expected),
            "ValidatorState must store register tx under canonical wallet key"
        );

        prop_assert!(
            state
                .is_canonically_known(&expected)
                .expect("canonical wallet lookup should succeed")
        );
    }

    // 14/25
    #[test]
    fn test_014_duplicate_register_at_same_height_is_no_change_and_preserves_metadata(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let height = valid_join_height(height_seed);
        let reg = manual_register(&validator, timestamp);

        apply_register_at_block_time(&mut state, height, &reg)
            .expect("first registration should insert");

        let before = state
            .meta_for(&validator)
            .expect("metadata should exist after first registration");

        apply_register_at_block_time(&mut state, height, &reg)
            .expect("duplicate registration should not error");

        let after = state
            .meta_for(&validator)
            .expect("metadata should still exist after duplicate registration");

        prop_assert_eq!(state.len(), 1);
        prop_assert_eq!(
            after,
            before,
            "duplicate same-height same-timestamp register must be a no-change renewal"
        );
    }

    // 15/25
    #[test]
    fn test_015_later_register_for_same_active_validator_renews_without_rewriting_join_height(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
        renew_gap in 1u64..=1000u64,
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let first_ts = valid_timestamp(timestamp_seed);
        let second_ts = first_ts.saturating_add(1);
        let join_height = valid_join_height(height_seed);
        let renew_height = join_height.saturating_add(renew_gap);

        let first = manual_register(&validator, first_ts);
        let second = manual_register(&validator, second_ts);

        apply_register_at_block_time(&mut state, join_height, &first)
            .expect("initial registration should insert");

        apply_register_at_block_time(&mut state, renew_height, &second)
            .expect("later registration should renew");

        let meta = state
            .meta_for(&validator)
            .expect("renewed validator metadata must exist");

        prop_assert_eq!(
            meta.join_height,
            join_height,
            "renewal must not rewrite original join_height for active validator"
        );

        prop_assert_eq!(
            meta.last_renew_height,
            renew_height,
            "renewal must update last_renew_height"
        );

        prop_assert_eq!(
            meta.last_renew_timestamp,
            second_ts,
            "renewal must update last_renew_timestamp when timestamp increases"
        );
    }

    // 16/25
    #[test]
    fn test_016_out_of_order_older_register_does_not_decrease_last_renew_height(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
        renew_gap in 2u64..=1000u64,
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let first_ts = valid_timestamp(timestamp_seed);
        let join_height = valid_join_height(height_seed);
        let later_height = join_height.saturating_add(renew_gap);
        let middle_height = join_height.saturating_add(1);

        let first = manual_register(&validator, first_ts);
        let later = manual_register(&validator, first_ts.saturating_add(2));
        let older = manual_register(&validator, first_ts.saturating_add(1));

        apply_register_at_block_time(&mut state, join_height, &first)
            .expect("insert should succeed");
        apply_register_at_block_time(&mut state, later_height, &later)
            .expect("later renew should succeed");

        let before = state
            .meta_for(&validator)
            .expect("metadata should exist before out-of-order renew");

        apply_register_at_block_time(&mut state, middle_height, &older)
            .expect("out-of-order older register should not error");

        let after = state
            .meta_for(&validator)
            .expect("metadata should exist after out-of-order renew");

        prop_assert_eq!(
            after.last_renew_height,
            before.last_renew_height,
            "out-of-order older register must not decrease last_renew_height"
        );

        prop_assert_eq!(
            after.join_height,
            before.join_height,
            "out-of-order older register must not rewrite join_height"
        );
    }

    // 17/25
    #[test]
    fn test_017_active_at_excludes_before_join_includes_at_join_and_returns_sorted_wallets(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let timestamp = valid_timestamp(timestamp_seed);
        let join_height = valid_join_height(height_seed);

        let mut state = fresh_state();

        let reg_b = manual_register(&wallet_b, timestamp);
        apply_register_at_block_time(&mut state, join_height, &reg_b)
            .expect("wallet_b registration should succeed");

        let reg_a = manual_register(&wallet_a, timestamp);
        apply_register_at_block_time(&mut state, join_height, &reg_a)
            .expect("wallet_a registration should succeed");

        if join_height > 0 {
            prop_assert!(
                !state.is_active_at(&wallet_a, join_height.saturating_sub(1)),
                "validator must not be active before join_height"
            );
        }

        prop_assert!(
            state.is_active_at(&wallet_a, join_height),
            "validator must be active at join_height"
        );

        let active = state.active_at(join_height);
        let mut sorted = active.clone();
        sorted.sort_unstable();

        prop_assert_eq!(
            &active,
            &sorted,
            "active_at must return wallets in deterministic sorted order"
        );

        prop_assert!(active.contains(&wallet_a));
        prop_assert!(active.contains(&wallet_b));
    }

    // 18/25
    #[test]
    fn test_018_active_at_expires_validator_after_canonical_lease_boundary(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let join_height = valid_join_height(height_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let lease_blocks = GlobalConfiguration::CANONICAL_LEASE_BLOCKS.max(1);

        let reg = manual_register(&validator, timestamp);
        apply_register_at_block_time(&mut state, join_height, &reg)
            .expect("registration should succeed");

        let last_active_height = join_height.saturating_add(lease_blocks);
        let expired_height = last_active_height.saturating_add(1);

        prop_assert!(
            state.is_active_at(&validator, last_active_height),
            "validator must remain active through lease expiry boundary"
        );

        prop_assert!(
            !state.is_active_at(&validator, expired_height),
            "validator must be inactive after canonical lease expires"
        );

        prop_assert!(
            !state.active_at(expired_height).contains(&validator),
            "active_at must exclude expired validator"
        );
    }

    // 19/25
    #[test]
    fn test_019_invalid_wallet_queries_return_false_or_none_without_panicking(
        bad_tail in "[0-9a-f]{0,127}",
        query_height in any::<u64>(),
    ) {
        let state = fresh_state();
        let invalid_wallet = format!("r{bad_tail}");

        prop_assert!(
            state.is_canonically_known(&invalid_wallet).is_err(),
            "is_canonically_known must reject malformed wallet query"
        );

        prop_assert_eq!(
            state.meta_for(&invalid_wallet),
            None,
            "meta_for must return None for malformed wallet query"
        );

        prop_assert_eq!(
            state.join_height(&invalid_wallet),
            None,
            "join_height must return None for malformed wallet query"
        );

        prop_assert!(
            !state.is_active_at(&invalid_wallet, query_height),
            "is_active_at must return false for malformed wallet query"
        );

        prop_assert!(
            !state.reward_eligible_at(&invalid_wallet, query_height),
            "reward_eligible_at must return false for malformed wallet query"
        );
    }

    // 20/25
    #[test]
    fn test_020_proposable_at_respects_explicit_activation_delay_for_non_founder_validator(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
        delay in 0u64..=GlobalConfiguration::CANONICAL_LEASE_BLOCKS,
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let join_height = valid_join_height(height_seed);
        let timestamp = valid_timestamp(timestamp_seed);

        let reg = manual_register(&validator, timestamp);
        apply_register_at_block_time(&mut state, join_height, &reg)
            .expect("registration should succeed");

        let eligible_height = join_height.saturating_add(delay);

        if delay > 0 {
            prop_assert!(
                !state
                    .proposable_at(eligible_height.saturating_sub(1), delay)
                    .contains(&validator),
                "non-founder validator must not be proposable before join_height + activation delay"
            );
        }

        prop_assert!(
            state.proposable_at(eligible_height, delay).contains(&validator),
            "non-founder validator must be proposable at join_height + activation delay"
        );
    }

    // 21/25
    #[test]
    fn test_021_founder_is_immediately_proposable_even_with_large_activation_delay(
        founder_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        delay in 1u64..=10_000u64,
    ) {
        let mut state = fresh_state();
        let founder = wallet(founder_seed);

        state
            .seed_genesis_founder(&founder, valid_timestamp(timestamp_seed))
            .expect("founder seed should succeed");

        prop_assert!(
            state.proposable_at(0, delay).contains(&founder),
            "genesis founder must be immediately proposable at height zero"
        );

        prop_assert!(
            state.is_active_at(&founder, 0),
            "genesis founder must be active at height zero"
        );
    }

    // 22/25
    #[test]
    fn test_022_reward_eligible_at_respects_reward_delay_for_non_founder_validator(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let join_height = valid_join_height(height_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let reward_delay = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;

        let reg = manual_register(&validator, timestamp);
        apply_register_at_block_time(&mut state, join_height, &reg)
            .expect("registration should succeed");

        let eligible_height = join_height.saturating_add(reward_delay);

        if reward_delay > 0 {
            prop_assert!(
                !state.reward_eligible_at(&validator, eligible_height.saturating_sub(1)),
                "validator must not be reward eligible before reward delay boundary"
            );
        }

        prop_assert!(
            state.reward_eligible_at(&validator, eligible_height),
            "validator must be reward eligible at reward delay boundary"
        );
    }

    // 23/25
    #[test]
    fn test_023_mark_exit_makes_validator_inactive_at_exit_height_but_not_before(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
        exit_gap in 1u64..=GlobalConfiguration::CANONICAL_LEASE_BLOCKS,
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let join_height = valid_join_height(height_seed);
        let exit_height = join_height.saturating_add(exit_gap);
        let timestamp = valid_timestamp(timestamp_seed);

        let reg = manual_register(&validator, timestamp);
        apply_register_at_block_time(&mut state, join_height, &reg)
            .expect("registration should succeed");

        state
            .mark_exit(&validator, exit_height)
            .expect("mark_exit after join height should succeed");

        prop_assert!(
            state.is_active_at(&validator, exit_height.saturating_sub(1)),
            "validator must remain active before explicit exit height when exit is inside canonical lease"
        );

        prop_assert!(
            !state.is_active_at(&validator, exit_height),
            "validator must be inactive at explicit exit height"
        );

        let meta = state
            .meta_for(&validator)
            .expect("exited validator metadata should remain queryable");

        prop_assert_eq!(meta.exit_height, Some(exit_height));
    }

    // 24/25
    #[test]
    fn test_024_mark_exit_for_unknown_validator_is_noop_and_keeps_state_empty(
        unknown_seed in any::<u64>(),
        exit_height in 1u64..=100_000u64,
    ) {
        let mut state = fresh_state();
        let unknown = wallet(unknown_seed);

        state
            .mark_exit(&unknown, exit_height)
            .expect("mark_exit for unknown valid wallet should be a no-op");

        prop_assert_eq!(
            state.len(),
            0,
            "mark_exit for unknown validator must not create metadata"
        );

        prop_assert_eq!(
            state.meta_for(&unknown),
            None,
            "unknown validator must remain absent after mark_exit"
        );
    }

    // 25/25
    #[test]
    fn test_025_register_after_explicit_exit_reactivates_non_founder_with_new_join_height(
        validator_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        height_seed in any::<u64>(),
        exit_gap in 1u64..=1000u64,
        reactivate_gap in 1u64..=1000u64,
    ) {
        let mut state = fresh_state();
        let validator = wallet(validator_seed);
        let first_ts = valid_timestamp(timestamp_seed);
        let second_ts = first_ts.saturating_add(1);
        let join_height = valid_join_height(height_seed);
        let exit_height = join_height.saturating_add(exit_gap);
        let reactivate_height = exit_height.saturating_add(reactivate_gap);

        let first_reg = manual_register(&validator, first_ts);
        apply_register_at_block_time(&mut state, join_height, &first_reg)
            .expect("initial registration should succeed");

        state
            .mark_exit(&validator, exit_height)
            .expect("exit should succeed");

        prop_assert!(
            !state.is_active_at(&validator, exit_height),
            "validator must be inactive at exit height before reactivation"
        );

        let second_reg = manual_register(&validator, second_ts);
        apply_register_at_block_time(&mut state, reactivate_height, &second_reg)
            .expect("post-exit register should reactivate validator");

        let meta = state
            .meta_for(&validator)
            .expect("reactivated validator metadata must exist");

        prop_assert_eq!(
            meta.join_height,
            reactivate_height,
            "reactivated non-founder must receive new join_height"
        );

        prop_assert_eq!(
            meta.exit_height,
            None,
            "reactivated validator must clear exit_height"
        );

        prop_assert!(
            state.is_active_at(&validator, reactivate_height),
            "reactivated validator must be active at new join height"
        );
    }
}
