use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_008_validator_lifecycle::{
    RegisterOutcome, ValidatorLifecycle, ValidatorLifecycleConfig, ValidatorMeta,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::collections::BTreeMap;

const UNIX_2000: u64 = 946_684_800;

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp())
        .unwrap_or(UNIX_2000)
        .max(UNIX_2000)
}

fn max_valid_timestamp() -> u64 {
    now_secs().saturating_add(GlobalConfiguration::MAX_FUTURE_SKEW_SECS)
}

fn valid_timestamp(seed: u64) -> u64 {
    let max = max_valid_timestamp();
    let span = max.saturating_sub(UNIX_2000).saturating_add(1);

    UNIX_2000.saturating_add(seed % span)
}

fn valid_timestamp_with_room(seed: u64, room: u64) -> u64 {
    let max = max_valid_timestamp().saturating_sub(room).max(UNIX_2000);
    let span = max.saturating_sub(UNIX_2000).saturating_add(1);

    UNIX_2000.saturating_add(seed % span)
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

fn three_distinct_wallets(seed_a: u64, seed_b: u64, seed_c: u64) -> (String, String, String) {
    let first = wallet(seed_a);

    let mut second_seed = seed_b;
    let mut second = wallet(second_seed);
    while second == first {
        second_seed = second_seed.wrapping_add(1);
        second = wallet(second_seed);
    }

    let mut third_seed = seed_c;
    let mut third = wallet(third_seed);
    while third == first || third == second {
        third_seed = third_seed.wrapping_add(1);
        third = wallet(third_seed);
    }

    (first, second, third)
}

fn joined_meta(height: u64, timestamp: u64) -> ValidatorMeta {
    ValidatorMeta::joined(height, timestamp).expect("generated joined metadata should be valid")
}

fn founder_meta(timestamp: u64) -> ValidatorMeta {
    ValidatorMeta::founder(timestamp).expect("generated founder metadata should be valid")
}

fn custom_cfg(
    activation_delay_blocks: u64,
    reward_delay_blocks: u64,
    lease_blocks: u64,
) -> ValidatorLifecycleConfig {
    ValidatorLifecycleConfig {
        activation_delay_blocks,
        reward_delay_blocks,
        lease_blocks: lease_blocks.max(1),
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
    fn test_001_default_and_global_lifecycle_config_are_valid_and_match_expected_globals(
        _case in any::<u8>(),
    ) {
        let cfg = ValidatorLifecycle::config();
        let default_cfg = ValidatorLifecycleConfig::default();
        let global_cfg = ValidatorLifecycleConfig::from_globals();

        prop_assert_eq!(
            cfg,
            default_cfg,
            "ValidatorLifecycle::config must use the default global-derived lifecycle config"
        );

        prop_assert_eq!(
            cfg,
            global_cfg,
            "ValidatorLifecycle::config must match ValidatorLifecycleConfig::from_globals"
        );

        prop_assert!(
            cfg.validate().is_ok(),
            "global-derived lifecycle config must validate"
        );

        prop_assert_eq!(
            cfg.activation_delay_blocks,
            GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS,
            "activation delay must come from GlobalConfiguration"
        );

        prop_assert_eq!(
            cfg.reward_delay_blocks,
            GlobalConfiguration::REWARD_DELAY_BLOCKS as u64,
            "reward delay must come from GlobalConfiguration"
        );

        prop_assert!(
            cfg.lease_blocks >= 1,
            "canonical lease must be clamped to at least one block"
        );

        prop_assert!(
            cfg.lease_blocks <= 1_000_000,
            "canonical lease must respect the hard defensive cap"
        );
    }

    // 02/25
    #[test]
    fn test_002_lifecycle_config_rejects_zero_or_above_hard_cap_lease_and_accepts_boundaries(
        activation_delay in 0u64..10_000u64,
        reward_delay in 0u64..10_000u64,
    ) {
        let zero_lease = ValidatorLifecycleConfig {
            activation_delay_blocks: activation_delay,
            reward_delay_blocks: reward_delay,
            lease_blocks: 0,
        };

        prop_assert!(
            zero_lease.validate().is_err(),
            "lease_blocks=0 must be rejected"
        );

        let min_valid = ValidatorLifecycleConfig {
            activation_delay_blocks: activation_delay,
            reward_delay_blocks: reward_delay,
            lease_blocks: 1,
        };

        prop_assert!(
            min_valid.validate().is_ok(),
            "lease_blocks=1 must be accepted"
        );

        let max_valid = ValidatorLifecycleConfig {
            activation_delay_blocks: activation_delay,
            reward_delay_blocks: reward_delay,
            lease_blocks: 1_000_000,
        };

        prop_assert!(
            max_valid.validate().is_ok(),
            "lease_blocks at hard cap must be accepted"
        );

        let above_cap = ValidatorLifecycleConfig {
            activation_delay_blocks: activation_delay,
            reward_delay_blocks: reward_delay,
            lease_blocks: 1_000_001,
        };

        prop_assert!(
            above_cap.validate().is_err(),
            "lease_blocks above hard cap must be rejected"
        );
    }

    // 03/25
    #[test]
    fn test_003_founder_meta_sets_height_zero_renewal_zero_timestamp_and_no_exit(
        timestamp_seed in any::<u64>(),
    ) {
        let timestamp = valid_timestamp(timestamp_seed);
        let meta = ValidatorLifecycle::founder_meta(timestamp)
            .expect("valid founder timestamp must construct founder metadata");

        prop_assert_eq!(meta.join_height, 0);
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, 0);
        prop_assert_eq!(meta.last_renew_timestamp, timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 04/25
    #[test]
    fn test_004_new_validator_meta_canonicalizes_wallet_and_sets_join_and_renew_fields(
        wallet_tail in "[0-9A-F]{128}",
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
    ) {
        let raw_wallet = format!(" \n\tR{wallet_tail}\r\n ");
        let timestamp = valid_timestamp(timestamp_seed);

        let meta = ValidatorLifecycle::new_validator_meta(&raw_wallet, height, timestamp)
            .expect("canonicalizable wallet and plausible timestamp must construct validator metadata");

        prop_assert_eq!(meta.join_height, height);
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, height);
        prop_assert_eq!(meta.last_renew_timestamp, timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 05/25
    #[test]
    fn test_005_metadata_constructors_reject_timestamp_before_2000_but_do_not_apply_wall_clock_future_skew(
        old_timestamp in 0u64..UNIX_2000,
        future_extra in 1u64..10_000u64,
        height in 1u64..1_000_000u64,
    ) {
        let structural_future = max_valid_timestamp().saturating_add(future_extra);

        prop_assert!(
            ValidatorMeta::founder(old_timestamp).is_err(),
            "founder metadata must reject timestamps before UNIX_2000"
        );

        prop_assert!(
            ValidatorMeta::joined(height, old_timestamp).is_err(),
            "joined metadata must reject timestamps before UNIX_2000"
        );

        prop_assert!(
            ValidatorMeta::founder(structural_future).is_ok(),
            "founder metadata should accept structurally valid future timestamps"
        );

        prop_assert!(
            ValidatorMeta::joined(height, structural_future).is_ok(),
            "joined metadata should accept structurally valid future timestamps"
        );
    }

    // 06/25
    #[test]
    fn test_006_validate_invariants_rejects_invalid_wallet_even_when_metadata_is_structurally_valid(
        bad_tail in "[0-9a-f]{0,127}",
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
    ) {
        let invalid_wallet = format!("r{bad_tail}");
        let meta = joined_meta(height, valid_timestamp(timestamp_seed));

        prop_assert!(
            meta.validate_invariants(&invalid_wallet).is_err(),
            "validate_invariants must reject malformed wallet ids"
        );
    }

    // 07/25
    #[test]
    fn test_007_validate_invariants_rejects_renewal_height_or_timestamp_going_backwards(
        wallet_seed in any::<u64>(),
        height in 2u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        invalid_case in 0usize..2usize,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp_with_room(timestamp_seed, 10);
        let later_timestamp = timestamp.saturating_add(1);

        let meta = if invalid_case == 0 {
            ValidatorMeta {
                join_height: height,
                join_timestamp: timestamp,
                last_renew_height: height.saturating_sub(1),
                last_renew_timestamp: later_timestamp,
                exit_height: None,
            }
        } else {
            ValidatorMeta {
                join_height: height,
                join_timestamp: later_timestamp,
                last_renew_height: height,
                last_renew_timestamp: timestamp,
                exit_height: None,
            }
        };

        prop_assert!(
            meta.validate_invariants(&wallet).is_err(),
            "metadata invariants must reject last_renew fields going backward from join fields"
        );
    }

    // 08/25
    #[test]
    fn test_008_validate_invariants_rejects_invalid_exit_height_boundaries(
        wallet_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        invalid_case in 0usize..2usize,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp(timestamp_seed);

        let meta = if invalid_case == 0 {
            ValidatorMeta {
                join_height: height,
                join_timestamp: timestamp,
                last_renew_height: height,
                last_renew_timestamp: timestamp,
                exit_height: Some(0),
            }
        } else {
            ValidatorMeta {
                join_height: height,
                join_timestamp: timestamp,
                last_renew_height: height,
                last_renew_timestamp: timestamp,
                exit_height: Some(height),
            }
        };

        prop_assert!(
            meta.validate_invariants(&wallet).is_err(),
            "non-founder metadata must reject exit_height=0 and exit_height <= join_height"
        );
    }

    // 09/25
    #[test]
    fn test_009_not_explicitly_exited_at_is_true_before_exit_and_false_at_exit_boundary(
        height in 1u64..1_000_000u64,
        exit_gap in 1u64..10_000u64,
        timestamp_seed in any::<u64>(),
    ) {
        let exit_height = height.saturating_add(exit_gap);
        let mut meta = joined_meta(height, valid_timestamp(timestamp_seed));
        meta.exit_height = Some(exit_height);

        prop_assert!(
            meta.not_explicitly_exited_at(exit_height.saturating_sub(1)),
            "validator must not be explicitly exited before exit_height"
        );

        prop_assert!(
            !meta.not_explicitly_exited_at(exit_height),
            "validator must be explicitly exited at exit_height"
        );

        prop_assert!(
            !meta.not_explicitly_exited_at(exit_height.saturating_add(1)),
            "validator must remain explicitly exited after exit_height"
        );
    }

    // 10/25
    #[test]
    fn test_010_lease_expiry_and_within_lease_are_inclusive_at_expiry_and_false_after(
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        lease in 1u64..10_000u64,
    ) {
        let meta = joined_meta(height, valid_timestamp(timestamp_seed));
        let cfg = custom_cfg(0, 0, lease);
        let expiry = height.saturating_add(lease);

        prop_assert_eq!(
            meta.lease_expiry_height(cfg),
            expiry,
            "lease expiry must be last_renew_height + lease_blocks"
        );

        prop_assert!(
            meta.within_lease_at(expiry, cfg),
            "lease must be inclusive at expiry height"
        );

        prop_assert!(
            !meta.within_lease_at(expiry.saturating_add(1), cfg),
            "validator must be outside lease after expiry height"
        );
    }

    // 11/25
    #[test]
    fn test_011_is_active_at_requires_join_height_and_canonical_lease(
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        lease in 1u64..10_000u64,
    ) {
        let meta = joined_meta(height, valid_timestamp(timestamp_seed));
        let cfg = custom_cfg(0, 0, lease);

        prop_assert!(
            !meta.is_active_at(height.saturating_sub(1), cfg),
            "validator must not be active before join_height"
        );

        prop_assert!(
            meta.is_active_at(height, cfg),
            "validator must be active at join_height"
        );

        prop_assert!(
            meta.is_active_at(height.saturating_add(lease), cfg),
            "validator must remain active at lease expiry boundary"
        );

        prop_assert!(
            !meta.is_active_at(height.saturating_add(lease).saturating_add(1), cfg),
            "validator must be inactive after canonical lease expires"
        );
    }

    // 12/25
    #[test]
    fn test_012_is_active_at_respects_explicit_exit_before_lease_expiry(
        height in 1u64..1_000_000u64,
        exit_gap in 1u64..1_000u64,
        timestamp_seed in any::<u64>(),
    ) {
        let exit_height = height.saturating_add(exit_gap);
        let lease = exit_gap.saturating_add(100);
        let cfg = custom_cfg(0, 0, lease);
        let mut meta = joined_meta(height, valid_timestamp(timestamp_seed));

        meta.exit_height = Some(exit_height);

        prop_assert!(
            meta.is_active_at(exit_height.saturating_sub(1), cfg),
            "validator must be active before explicit exit when still inside lease"
        );

        prop_assert!(
            !meta.is_active_at(exit_height, cfg),
            "validator must be inactive at explicit exit height"
        );
    }

    // 13/25
    #[test]
    fn test_013_founder_is_immediately_proposable_even_with_activation_delay(
        timestamp_seed in any::<u64>(),
        activation_delay in 1u64..10_000u64,
        extra_lease in 1u64..10_000u64,
    ) {
        let meta = founder_meta(valid_timestamp(timestamp_seed));
        let lease = activation_delay.saturating_add(extra_lease);
        let cfg = custom_cfg(activation_delay, 0, lease);

        prop_assert!(
            meta.is_proposable_at(0, cfg),
            "founder must be immediately proposable at height zero"
        );

        prop_assert!(
            meta.is_proposable_at(activation_delay.saturating_sub(1), cfg),
            "founder must not wait for activation delay while still inside canonical lease"
        );

        prop_assert!(
            !meta.is_proposable_at(lease.saturating_add(1), cfg),
            "founder must still obey canonical lease expiry"
        );
    }

    // 14/25
    #[test]
    fn test_014_non_founder_proposable_only_after_activation_delay_while_active(
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        activation_delay in 0u64..1_000u64,
    ) {
        let meta = joined_meta(height, valid_timestamp(timestamp_seed));
        let cfg = custom_cfg(
            activation_delay,
            0,
            activation_delay.saturating_add(100),
        );

        let eligible_height = height.saturating_add(activation_delay);

        if activation_delay > 0 {
            prop_assert!(
                !meta.is_proposable_at(eligible_height.saturating_sub(1), cfg),
                "non-founder must not be proposable before join_height + activation_delay"
            );
        }

        prop_assert!(
            meta.is_proposable_at(eligible_height, cfg),
            "non-founder must be proposable at join_height + activation_delay when still active"
        );
    }

    // 15/25
    #[test]
    fn test_015_founder_is_reward_eligible_at_every_height(
        timestamp_seed in any::<u64>(),
        reward_delay in 0u64..10_000u64,
        query_height in any::<u64>(),
    ) {
        let meta = founder_meta(valid_timestamp(timestamp_seed));
        let cfg = custom_cfg(0, reward_delay, 10_000);

        prop_assert!(
            meta.reward_eligible_at(query_height, cfg),
            "founder must always be reward-eligible under current lifecycle semantics"
        );
    }

    // 16/25
    #[test]
    fn test_016_non_founder_reward_eligibility_starts_at_reward_delay_boundary(
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        reward_delay in 0u64..1_000u64,
    ) {
        let meta = joined_meta(height, valid_timestamp(timestamp_seed));
        let cfg = custom_cfg(0, reward_delay, 10_000);
        let eligible_height = height.saturating_add(reward_delay);

        if reward_delay > 0 {
            prop_assert!(
                !meta.reward_eligible_at(eligible_height.saturating_sub(1), cfg),
                "non-founder must not be reward-eligible before reward delay boundary"
            );
        }

        prop_assert!(
            meta.reward_eligible_at(eligible_height, cfg),
            "non-founder must be reward-eligible at reward delay boundary"
        );
    }

    // 17/25
    #[test]
    fn test_017_renew_or_reactivate_on_active_validator_updates_newer_height_and_timestamp(
        wallet_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        height_gap in 1u64..10_000u64,
        timestamp_gap in 1u64..1_000u64,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp_with_room(timestamp_seed, timestamp_gap);
        let mut meta = joined_meta(height, timestamp);

        let renewed_height = height.saturating_add(height_gap);
        let renewed_timestamp = timestamp.saturating_add(timestamp_gap);

        let outcome = meta
            .renew_or_reactivate(&wallet, renewed_height, renewed_timestamp)
            .expect("renewal with newer height and timestamp should succeed");

        prop_assert_eq!(outcome, RegisterOutcome::Renewed);
        prop_assert_eq!(meta.join_height, height);
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, renewed_height);
        prop_assert_eq!(meta.last_renew_timestamp, renewed_timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 18/25
    #[test]
    fn test_018_renew_or_reactivate_on_active_validator_is_no_change_for_duplicate_or_older_height_same_timestamp(
        wallet_seed in any::<u64>(),
        height in 2u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        older_gap in 0u64..2u64,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let mut meta = joined_meta(height, timestamp);
        let renew_height = height.saturating_sub(older_gap);

        let before = meta.clone();

        let outcome = meta
            .renew_or_reactivate(&wallet, renew_height, timestamp)
            .expect("duplicate or older-height renewal with same timestamp should not error");

        prop_assert_eq!(outcome, RegisterOutcome::NoChange);
        prop_assert_eq!(
            meta,
            before,
            "NoChange renewal must preserve metadata exactly"
        );
    }

    // 19/25
    #[test]
    fn test_019_mark_exit_sets_first_exit_ignores_later_exit_and_lowers_to_earlier_exit(
        wallet_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let mut meta = joined_meta(height, timestamp);

        let first_exit = height.saturating_add(100);
        let later_exit = first_exit.saturating_add(100);
        let earlier_exit = height.saturating_add(50);

        prop_assert!(
            meta.mark_exit(&wallet, first_exit)
                .expect("first valid exit should succeed"),
            "first exit must change metadata"
        );

        prop_assert_eq!(meta.exit_height, Some(first_exit));

        prop_assert!(
            !meta.mark_exit(&wallet, later_exit)
                .expect("later exit after existing exit should not error"),
            "later exit must not loosen an earlier exit"
        );

        prop_assert_eq!(meta.exit_height, Some(first_exit));

        prop_assert!(
            meta.mark_exit(&wallet, earlier_exit)
                .expect("earlier valid exit should succeed"),
            "earlier exit must tighten exit height"
        );

        prop_assert_eq!(meta.exit_height, Some(earlier_exit));
    }

    // 20/25
    #[test]
    fn test_020_renew_before_recorded_future_exit_is_no_change_and_preserves_exit(
        wallet_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        timestamp_gap in 1u64..1_000u64,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp_with_room(timestamp_seed, timestamp_gap);
        let mut meta = joined_meta(height, timestamp);

        let exit_height = height.saturating_add(100);
        meta.mark_exit(&wallet, exit_height)
            .expect("valid exit should mark metadata");

        let before = meta.clone();

        let outcome = meta
            .renew_or_reactivate(
                &wallet,
                exit_height.saturating_sub(1),
                timestamp.saturating_add(timestamp_gap),
            )
            .expect("out-of-order renewal before recorded exit should not error");

        prop_assert_eq!(outcome, RegisterOutcome::NoChange);
        prop_assert_eq!(
            meta,
            before,
            "renewal before a stricter future exit must preserve existing metadata"
        );
    }

    // 21/25
    #[test]
    fn test_021_renew_after_exit_reactivates_non_founder_with_fresh_join_era(
        wallet_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        timestamp_gap in 1u64..1_000u64,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp_with_room(timestamp_seed, timestamp_gap);
        let mut meta = joined_meta(height, timestamp);

        let exit_height = height.saturating_add(10);
        let reactivate_height = exit_height.saturating_add(5);
        let reactivate_timestamp = timestamp.saturating_add(timestamp_gap);

        meta.mark_exit(&wallet, exit_height)
            .expect("valid exit should mark metadata");

        let outcome = meta
            .renew_or_reactivate(&wallet, reactivate_height, reactivate_timestamp)
            .expect("register after exit should reactivate non-founder");

        prop_assert_eq!(outcome, RegisterOutcome::Reactivated);
        prop_assert_eq!(meta.join_height, reactivate_height);
        prop_assert_eq!(meta.join_timestamp, reactivate_timestamp);
        prop_assert_eq!(meta.last_renew_height, reactivate_height);
        prop_assert_eq!(meta.last_renew_timestamp, reactivate_timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 22/25
    #[test]
    fn test_022_renew_after_exit_reactivates_founder_without_rewriting_join_height_zero(
        wallet_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        timestamp_gap in 1u64..1_000u64,
        renew_height in 2u64..1_000_000u64,
    ) {
        let wallet = wallet(wallet_seed);
        let timestamp = valid_timestamp_with_room(timestamp_seed, timestamp_gap);
        let mut meta = founder_meta(timestamp);

        meta.mark_exit(&wallet, 1)
            .expect("founder exit at height 1 should be structurally valid");

        let renew_timestamp = timestamp.saturating_add(timestamp_gap);

        let outcome = meta
            .renew_or_reactivate(&wallet, renew_height, renew_timestamp)
            .expect("founder register after exit should reactivate founder");

        prop_assert_eq!(outcome, RegisterOutcome::Reactivated);
        prop_assert_eq!(
            meta.join_height,
            0,
            "founder reactivation must preserve join_height=0"
        );
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, renew_height);
        prop_assert_eq!(meta.last_renew_timestamp, renew_timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 23/25
    #[test]
    fn test_023_apply_register_or_renew_inserts_canonical_wallet_key_and_metadata(
        tail in "[0-9A-F]{128}",
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
    ) {
        let raw_wallet = format!(" \n\tR{tail}\r\n ");
        let expected_wallet = format!("r{}", tail.to_ascii_lowercase());
        let timestamp = valid_timestamp(timestamp_seed);
        let mut map = BTreeMap::new();

        let outcome = ValidatorLifecycle::apply_register_or_renew(
            &mut map,
            &raw_wallet,
            height,
            timestamp,
        )
        .expect("canonicalizable wallet should insert");

        prop_assert_eq!(outcome, RegisterOutcome::Inserted);
        prop_assert_eq!(map.len(), 1);
        prop_assert!(map.contains_key(&expected_wallet));

        let meta = map
            .get(&expected_wallet)
            .expect("inserted canonical wallet metadata must exist");

        prop_assert_eq!(meta.join_height, height);
        prop_assert_eq!(meta.join_timestamp, timestamp);
        prop_assert_eq!(meta.last_renew_height, height);
        prop_assert_eq!(meta.last_renew_timestamp, timestamp);
        prop_assert_eq!(meta.exit_height, None);
    }

    // 24/25
    #[test]
    fn test_024_apply_exit_handles_known_unknown_and_invalid_wallets_without_unwanted_insertions(
        wallet_seed in any::<u64>(),
        unknown_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        timestamp_seed in any::<u64>(),
        bad_tail in "[0-9a-f]{0,127}",
    ) {
        let (known_wallet, mut unknown_wallet) = distinct_wallets(wallet_seed, unknown_seed);
        if known_wallet == unknown_wallet {
            unknown_wallet = wallet(wallet_seed.wrapping_add(999));
        }

        let timestamp = valid_timestamp(timestamp_seed);
        let mut map = BTreeMap::new();

        map.insert(known_wallet.clone(), joined_meta(height, timestamp));

        let unknown_result = ValidatorLifecycle::apply_exit(
            &mut map,
            &unknown_wallet,
            height.saturating_add(1),
        )
        .expect("apply_exit for unknown valid wallet should not error");

        prop_assert!(
            !unknown_result,
            "apply_exit for unknown wallet must return false"
        );

        prop_assert_eq!(
            map.len(),
            1,
            "apply_exit for unknown wallet must not insert metadata"
        );

        let changed = ValidatorLifecycle::apply_exit(
            &mut map,
            &known_wallet,
            height.saturating_add(1),
        )
        .expect("apply_exit for known wallet at valid exit height should succeed");

        prop_assert!(changed);

        prop_assert_eq!(
            map.get(&known_wallet)
                .expect("known wallet metadata must remain")
                .exit_height,
            Some(height.saturating_add(1))
        );

        let invalid_wallet = format!("r{bad_tail}");

        prop_assert!(
            ValidatorLifecycle::apply_exit(&mut map, &invalid_wallet, height.saturating_add(2)).is_err(),
            "apply_exit must reject malformed wallet"
        );

        prop_assert_eq!(
            map.len(),
            1,
            "failed invalid-wallet apply_exit must not insert metadata"
        );
    }

    // 25/25
    #[test]
    fn test_025_active_and_proposable_wallet_queries_are_sorted_and_validate_map_rejects_bad_keys(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
        timestamp_seed in any::<u64>(),
    ) {
        let (wallet_a, wallet_b, wallet_c) = three_distinct_wallets(seed_a, seed_b, seed_c);
        let timestamp = valid_timestamp(timestamp_seed);
        let cfg = ValidatorLifecycle::config();
        let join_height = 5u64;
        let query_height = join_height;

        let mut map = BTreeMap::new();
        map.insert(wallet_b.clone(), joined_meta(join_height, timestamp));
        map.insert(wallet_a.clone(), founder_meta(timestamp));
        map.insert(wallet_c.clone(), joined_meta(join_height.saturating_add(1), timestamp));

        prop_assert!(
            ValidatorLifecycle::validate_map(&map).is_ok(),
            "valid canonical wallet map must validate"
        );

        let active = ValidatorLifecycle::active_wallets_at(&map, query_height)
            .expect("active wallet query over valid map should succeed");

        let mut sorted_active = active.clone();
        sorted_active.sort_unstable();

        prop_assert_eq!(
            &active,
            &sorted_active,
            "active_wallets_at must return sorted wallets"
        );

        prop_assert!(
            active.contains(&wallet_a),
            "founder must be active at query height"
        );

        prop_assert!(
            active.contains(&wallet_b),
            "joined wallet at query height must be active"
        );

        prop_assert!(
            !active.contains(&wallet_c),
            "wallet joining after query height must not be active yet"
        );

        let proposable = ValidatorLifecycle::proposable_wallets_at(&map, query_height)
            .expect("proposable wallet query over valid map should succeed");

        let mut sorted_proposable = proposable.clone();
        sorted_proposable.sort_unstable();

        prop_assert_eq!(
            &proposable,
            &sorted_proposable,
            "proposable_wallets_at must return sorted wallets"
        );

        prop_assert!(
            proposable.contains(&wallet_a),
            "founder must be immediately proposable"
        );

        if cfg.activation_delay_blocks == 0 {
            prop_assert!(
                proposable.contains(&wallet_b),
                "non-founder with zero activation delay must be proposable at join height"
            );
        } else {
            prop_assert!(
                !proposable.contains(&wallet_b),
                "non-founder with nonzero activation delay must not be proposable at join height"
            );
        }

        let mut bad_map = map.clone();
        bad_map.insert("not-a-wallet".to_string(), founder_meta(timestamp));

        prop_assert!(
            ValidatorLifecycle::validate_map(&bad_map).is_err(),
            "validate_map must reject malformed wallet keys"
        );
    }
}
