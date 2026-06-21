use remzar::consensus::por_008_validator_lifecycle::{
    RegisterOutcome, ValidatorLifecycle, ValidatorLifecycleConfig, ValidatorMeta,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::collections::BTreeMap;
use std::error::Error;
use std::io;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const VALID_TS: u64 = 1_700_000_000;
const VALID_TS_LATER: u64 = 1_700_000_100;
const VALID_TS_EVEN_LATER: u64 = 1_700_000_200;
const UNIX_2000_MINUS_ONE: u64 = 946_684_799;
const HARD_CAP_PLUS_ONE: u64 = 1_000_001;

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn test_cfg() -> ValidatorLifecycleConfig {
    ValidatorLifecycleConfig {
        activation_delay_blocks: 3,
        reward_delay_blocks: 5,
        lease_blocks: 10,
    }
}

fn validation_message<T>(result: Result<T, ErrorDetection>) -> TestResult<String> {
    match result {
        Ok(_) => Err(test_error("expected validation error but got Ok")),
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert_eq!(tx_id, None);
            Ok(message)
        }
        Err(other) => Err(Box::new(io::Error::other(format!(
            "unexpected error variant: {other:?}"
        )))),
    }
}

#[test]
fn test_01_config_from_globals_validates() {
    let cfg = ValidatorLifecycleConfig::from_globals();

    assert!(cfg.validate().is_ok());
    assert!(cfg.lease_blocks >= 1);
    assert!(cfg.lease_blocks <= 1_000_000);
}

#[test]
fn test_02_default_config_matches_from_globals() {
    assert_eq!(
        ValidatorLifecycleConfig::default(),
        ValidatorLifecycleConfig::from_globals()
    );
}

#[test]
fn test_03_config_from_globals_uses_expected_global_fields() {
    let cfg = ValidatorLifecycleConfig::from_globals();

    assert_eq!(
        cfg.activation_delay_blocks,
        GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS
    );
    assert_eq!(
        cfg.reward_delay_blocks,
        GlobalConfiguration::REWARD_DELAY_BLOCKS as u64
    );
    assert_eq!(
        cfg.lease_blocks,
        GlobalConfiguration::CANONICAL_LEASE_BLOCKS.clamp(1, 1_000_000)
    );
}

#[test]
fn test_04_config_validate_rejects_zero_lease_blocks() -> TestResult {
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 0,
        lease_blocks: 0,
    };

    let message = validation_message(cfg.validate())?;

    assert!(message.contains("lease_blocks must be >= 1"));
    Ok(())
}

#[test]
fn test_05_config_validate_rejects_lease_blocks_above_hard_cap() -> TestResult {
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 0,
        lease_blocks: HARD_CAP_PLUS_ONE,
    };

    let message = validation_message(cfg.validate())?;

    assert!(message.contains("exceeds hard cap"));
    Ok(())
}

#[test]
fn test_06_founder_meta_has_bootstrap_fields() -> TestResult {
    let meta = ValidatorMeta::founder(VALID_TS)?;

    assert_eq!(meta.join_height, 0);
    assert_eq!(meta.join_timestamp, VALID_TS);
    assert_eq!(meta.last_renew_height, 0);
    assert_eq!(meta.last_renew_timestamp, VALID_TS);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_07_founder_meta_rejects_timestamp_before_year_2000() -> TestResult {
    let message = validation_message(ValidatorMeta::founder(UNIX_2000_MINUS_ONE))?;

    assert!(message.contains("ValidatorMeta.founder.join_timestamp"));
    assert!(message.contains("timestamp below UNIX_2000_SECS"));
    Ok(())
}

#[test]
fn test_08_joined_meta_has_join_and_renew_fields_at_same_height() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;

    assert_eq!(meta.join_height, 10);
    assert_eq!(meta.join_timestamp, VALID_TS);
    assert_eq!(meta.last_renew_height, 10);
    assert_eq!(meta.last_renew_timestamp, VALID_TS);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_09_joined_meta_rejects_timestamp_before_year_2000() -> TestResult {
    let message = validation_message(ValidatorMeta::joined(10, UNIX_2000_MINUS_ONE))?;

    assert!(message.contains("ValidatorMeta.joined.join_timestamp"));
    assert!(message.contains("timestamp below UNIX_2000_SECS"));
    Ok(())
}

#[test]
fn test_10_validate_invariants_accepts_valid_meta_and_wallet() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;

    meta.validate_invariants(&wallet(10))?;

    Ok(())
}

#[test]
fn test_11_validate_invariants_rejects_invalid_wallet() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;

    let message = validation_message(meta.validate_invariants("bad-wallet"))?;

    assert!(message.contains("ValidatorMeta invalid wallet"));
    Ok(())
}

#[test]
fn test_12_validate_invariants_rejects_last_renew_height_before_join_height() -> TestResult {
    let meta = ValidatorMeta {
        join_height: 10,
        join_timestamp: VALID_TS,
        last_renew_height: 9,
        last_renew_timestamp: VALID_TS,
        exit_height: None,
    };

    let message = validation_message(meta.validate_invariants(&wallet(12)))?;

    assert!(message.contains("last_renew_height=9 < join_height=10"));
    Ok(())
}

#[test]
fn test_13_validate_invariants_rejects_last_renew_timestamp_before_join_timestamp() -> TestResult {
    let meta = ValidatorMeta {
        join_height: 10,
        join_timestamp: VALID_TS_LATER,
        last_renew_height: 10,
        last_renew_timestamp: VALID_TS,
        exit_height: None,
    };

    let message = validation_message(meta.validate_invariants(&wallet(13)))?;

    assert!(message.contains("last_renew_timestamp"));
    Ok(())
}

#[test]
fn test_14_validate_invariants_rejects_exit_height_zero() -> TestResult {
    let meta = ValidatorMeta {
        join_height: 10,
        join_timestamp: VALID_TS,
        last_renew_height: 10,
        last_renew_timestamp: VALID_TS,
        exit_height: Some(0),
    };

    let message = validation_message(meta.validate_invariants(&wallet(14)))?;

    assert!(message.contains("exit_height=0 is invalid"));
    Ok(())
}

#[test]
fn test_15_validate_invariants_rejects_nonfounder_exit_at_or_before_join_height() -> TestResult {
    let meta = ValidatorMeta {
        join_height: 10,
        join_timestamp: VALID_TS,
        last_renew_height: 10,
        last_renew_timestamp: VALID_TS,
        exit_height: Some(10),
    };

    let message = validation_message(meta.validate_invariants(&wallet(15)))?;

    assert!(message.contains("exit_height=10 <= join_height=10"));
    Ok(())
}

#[test]
fn test_16_not_explicitly_exited_at_is_false_at_exit_height_and_after() -> TestResult {
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;
    meta.exit_height = Some(20);

    assert!(meta.not_explicitly_exited_at(19));
    assert!(!meta.not_explicitly_exited_at(20));
    assert!(!meta.not_explicitly_exited_at(21));
    Ok(())
}

#[test]
fn test_17_lease_expiry_height_adds_lease_blocks() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;
    let cfg = test_cfg();

    assert_eq!(meta.lease_expiry_height(cfg), 20);
    Ok(())
}

#[test]
fn test_18_lease_expiry_height_saturates_near_u64_max() {
    let meta = ValidatorMeta {
        join_height: u64::MAX.saturating_sub(5),
        join_timestamp: VALID_TS,
        last_renew_height: u64::MAX.saturating_sub(5),
        last_renew_timestamp: VALID_TS,
        exit_height: None,
    };
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 0,
        lease_blocks: 10,
    };

    assert_eq!(meta.lease_expiry_height(cfg), u64::MAX);
}

#[test]
fn test_19_within_lease_at_is_inclusive_at_expiry_height() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;
    let cfg = test_cfg();

    assert!(meta.within_lease_at(20, cfg));
    assert!(!meta.within_lease_at(21, cfg));
    Ok(())
}

#[test]
fn test_20_is_active_at_requires_join_height_not_future_and_lease_not_expired() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;
    let cfg = test_cfg();

    assert!(!meta.is_active_at(9, cfg));
    assert!(meta.is_active_at(10, cfg));
    assert!(meta.is_active_at(20, cfg));
    assert!(!meta.is_active_at(21, cfg));
    Ok(())
}

#[test]
fn test_21_is_active_at_respects_explicit_exit_height() -> TestResult {
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;
    meta.exit_height = Some(15);
    let cfg = test_cfg();

    assert!(meta.is_active_at(14, cfg));
    assert!(!meta.is_active_at(15, cfg));
    Ok(())
}

#[test]
fn test_22_founder_is_proposable_immediately_at_height_zero() -> TestResult {
    let meta = ValidatorMeta::founder(VALID_TS)?;
    let cfg = test_cfg();

    assert!(meta.is_proposable_at(0, cfg));
    assert!(meta.is_proposable_at(1, cfg));
    Ok(())
}

#[test]
fn test_23_nonfounder_is_proposable_only_after_activation_delay() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;
    let cfg = test_cfg();

    assert!(!meta.is_proposable_at(12, cfg));
    assert!(meta.is_proposable_at(13, cfg));
    Ok(())
}

#[test]
fn test_24_founder_is_reward_eligible_immediately() -> TestResult {
    let meta = ValidatorMeta::founder(VALID_TS)?;
    let cfg = test_cfg();

    assert!(meta.reward_eligible_at(0, cfg));
    assert!(meta.reward_eligible_at(1, cfg));
    Ok(())
}

#[test]
fn test_25_nonfounder_reward_eligibility_respects_reward_delay() -> TestResult {
    let meta = ValidatorMeta::joined(10, VALID_TS)?;
    let cfg = test_cfg();

    assert!(!meta.reward_eligible_at(14, cfg));
    assert!(meta.reward_eligible_at(15, cfg));
    Ok(())
}

#[test]
fn test_26_renew_or_reactivate_active_validator_updates_newer_height_and_timestamp() -> TestResult {
    let wallet_a = wallet(26);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 12, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::Renewed);
    assert_eq!(meta.join_height, 10);
    assert_eq!(meta.join_timestamp, VALID_TS);
    assert_eq!(meta.last_renew_height, 12);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_27_renew_or_reactivate_active_validator_no_change_for_same_height_and_timestamp()
-> TestResult {
    let wallet_a = wallet(27);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 10, VALID_TS)?;

    assert_eq!(outcome, RegisterOutcome::NoChange);
    assert_eq!(meta.last_renew_height, 10);
    assert_eq!(meta.last_renew_timestamp, VALID_TS);
    Ok(())
}

#[test]
fn test_28_renew_or_reactivate_rejects_invalid_wallet() -> TestResult {
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;

    let message = validation_message(meta.renew_or_reactivate("bad-wallet", 11, VALID_TS_LATER))?;

    assert!(message.contains("ValidatorMeta invalid wallet"));
    Ok(())
}

#[test]
fn test_29_renew_or_reactivate_ignores_out_of_order_before_existing_exit() -> TestResult {
    let wallet_a = wallet(29);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;
    assert!(meta.mark_exit(&wallet_a, 20)?);

    let outcome = meta.renew_or_reactivate(&wallet_a, 19, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::NoChange);
    assert_eq!(meta.exit_height, Some(20));
    Ok(())
}

#[test]
fn test_30_renew_or_reactivate_nonfounder_after_exit_starts_fresh_active_era() -> TestResult {
    let wallet_a = wallet(30);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;
    assert!(meta.mark_exit(&wallet_a, 20)?);

    let outcome = meta.renew_or_reactivate(&wallet_a, 20, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::Reactivated);
    assert_eq!(meta.join_height, 20);
    assert_eq!(meta.join_timestamp, VALID_TS_LATER);
    assert_eq!(meta.last_renew_height, 20);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_31_renew_or_reactivate_founder_preserves_join_height_zero_after_exit() -> TestResult {
    let wallet_a = wallet(31);
    let mut meta = ValidatorMeta::founder(VALID_TS)?;
    assert!(meta.mark_exit(&wallet_a, 5)?);

    let outcome = meta.renew_or_reactivate(&wallet_a, 10, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::Reactivated);
    assert_eq!(meta.join_height, 0);
    assert_eq!(meta.join_timestamp, VALID_TS);
    assert_eq!(meta.last_renew_height, 10);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_32_mark_exit_first_time_sets_exit_height_and_returns_true() -> TestResult {
    let wallet_a = wallet(32);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;

    assert!(meta.mark_exit(&wallet_a, 20)?);
    assert_eq!(meta.exit_height, Some(20));
    Ok(())
}

#[test]
fn test_33_mark_exit_same_or_later_height_returns_false() -> TestResult {
    let wallet_a = wallet(33);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;

    assert!(meta.mark_exit(&wallet_a, 20)?);
    assert!(!meta.mark_exit(&wallet_a, 20)?);
    assert!(!meta.mark_exit(&wallet_a, 21)?);
    assert_eq!(meta.exit_height, Some(20));
    Ok(())
}

#[test]
fn test_34_mark_exit_earlier_height_updates_exit_height() -> TestResult {
    let wallet_a = wallet(34);
    let mut meta = ValidatorMeta::joined(10, VALID_TS)?;

    assert!(meta.mark_exit(&wallet_a, 30)?);
    assert!(meta.mark_exit(&wallet_a, 20)?);
    assert_eq!(meta.exit_height, Some(20));
    Ok(())
}

#[test]
fn test_35_new_validator_meta_validates_wallet_and_constructs_joined_meta() -> TestResult {
    let wallet_a = wallet(35);
    let meta = ValidatorLifecycle::new_validator_meta(&wallet_a, 35, VALID_TS)?;

    assert_eq!(meta.join_height, 35);
    assert_eq!(meta.last_renew_height, 35);
    assert_eq!(meta.join_timestamp, VALID_TS);
    Ok(())
}

#[test]
fn test_36_new_validator_meta_rejects_invalid_wallet() -> TestResult {
    let message = validation_message(ValidatorLifecycle::new_validator_meta(
        "bad-wallet",
        36,
        VALID_TS,
    ))?;

    assert!(message.contains("new_validator_meta invalid wallet"));
    Ok(())
}

#[test]
fn test_37_apply_register_or_renew_inserts_new_canonical_wallet() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(37);

    let outcome = ValidatorLifecycle::apply_register_or_renew(
        &mut map,
        &wallet_a.to_ascii_uppercase(),
        37,
        VALID_TS,
    )?;

    assert_eq!(outcome, RegisterOutcome::Inserted);
    assert!(map.contains_key(&wallet_a));
    assert_eq!(map.len(), 1);
    Ok(())
}

#[test]
fn test_38_apply_register_or_renew_renews_existing_wallet() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(38);

    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 38, VALID_TS)?,
        RegisterOutcome::Inserted
    );
    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 40, VALID_TS_LATER)?,
        RegisterOutcome::Renewed
    );

    let meta = map
        .get(&wallet_a)
        .ok_or_else(|| test_error("validator missing after renewal"))?;

    assert_eq!(meta.join_height, 38);
    assert_eq!(meta.last_renew_height, 40);
    Ok(())
}

#[test]
fn test_39_active_and_proposable_wallets_are_sorted() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(39);
    let wallet_b = wallet(40);
    let wallet_c = wallet(41);
    let check_height = 1_000_u64;

    let renewed_meta = |join_height: u64| ValidatorMeta {
        join_height,
        join_timestamp: VALID_TS,
        last_renew_height: check_height,
        last_renew_timestamp: VALID_TS_LATER,
        exit_height: None,
    };

    map.insert(wallet_c.clone(), renewed_meta(1));
    map.insert(wallet_a.clone(), renewed_meta(1));
    map.insert(wallet_b.clone(), renewed_meta(1));

    ValidatorLifecycle::validate_map(&map)?;

    let active = ValidatorLifecycle::active_wallets_at(&map, check_height)?;
    let proposable = ValidatorLifecycle::proposable_wallets_at(&map, check_height)?;

    assert_eq!(
        active,
        vec![wallet_a.clone(), wallet_b.clone(), wallet_c.clone()]
    );
    assert_eq!(proposable, vec![wallet_a, wallet_b, wallet_c]);
    Ok(())
}

#[test]
fn test_40_apply_exit_missing_wallet_returns_false_and_validate_map_checks_keys() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(40);

    assert!(!ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 50)?);

    map.insert(wallet_a, ValidatorMeta::joined(10, VALID_TS)?);
    ValidatorLifecycle::validate_map(&map)?;

    map.insert(
        "bad-wallet".to_string(),
        ValidatorMeta::joined(10, VALID_TS)?,
    );
    assert!(ValidatorLifecycle::validate_map(&map).is_err());

    Ok(())
}

#[test]
fn test_41_register_outcome_copy_debug_and_equality() {
    let inserted = RegisterOutcome::Inserted;
    let copied = inserted;
    let debug_text = format!("{inserted:?}");

    assert_eq!(inserted, copied);
    assert_eq!(debug_text, "Inserted");
    assert_ne!(RegisterOutcome::Inserted, RegisterOutcome::Renewed);
    assert_ne!(RegisterOutcome::Reactivated, RegisterOutcome::NoChange);
}

#[test]
fn test_42_validator_lifecycle_config_copy_debug_and_equality() {
    let cfg = test_cfg();
    let copied = cfg;
    let debug_text = format!("{cfg:?}");

    assert_eq!(cfg, copied);
    assert!(debug_text.contains("ValidatorLifecycleConfig"));
    assert!(debug_text.contains("lease_blocks"));
}

#[test]
fn test_43_validator_meta_clone_eq_and_debug_preserve_fields() -> TestResult {
    let meta = ValidatorMeta::joined(43, VALID_TS)?;
    let cloned = meta.clone();
    let debug_text = format!("{meta:?}");

    assert_eq!(cloned, meta);
    assert!(debug_text.contains("ValidatorMeta"));
    assert!(debug_text.contains("join_height"));
    assert!(debug_text.contains("last_renew_height"));
    Ok(())
}

#[test]
fn test_44_validator_lifecycle_unit_struct_default_copy_and_debug() {
    let lifecycle = ValidatorLifecycle;
    let defaulted = ValidatorLifecycle;
    let copied = lifecycle;
    let debug_text = format!("{lifecycle:?}");

    assert_eq!(format!("{copied:?}"), format!("{defaulted:?}"));
    assert!(debug_text.contains("ValidatorLifecycle"));
}

#[test]
fn test_45_founder_meta_helper_matches_validator_meta_founder() -> TestResult {
    let direct = ValidatorMeta::founder(VALID_TS)?;
    let helper = ValidatorLifecycle::founder_meta(VALID_TS)?;

    assert_eq!(helper, direct);
    Ok(())
}

#[test]
fn test_46_founder_validate_invariants_accepts_valid_wallet() -> TestResult {
    let meta = ValidatorMeta::founder(VALID_TS)?;

    meta.validate_invariants(&wallet(46))?;

    Ok(())
}

#[test]
fn test_47_founder_mark_exit_at_zero_rejects_invalid_exit_height() -> TestResult {
    let wallet_a = wallet(47);
    let mut meta = ValidatorMeta::founder(VALID_TS)?;

    let message = validation_message(meta.mark_exit(&wallet_a, 0))?;

    assert!(message.contains("exit_height=0 is invalid"));
    Ok(())
}

#[test]
fn test_48_nonfounder_mark_exit_at_join_height_rejects() -> TestResult {
    let wallet_a = wallet(48);
    let mut meta = ValidatorMeta::joined(48, VALID_TS)?;

    let message = validation_message(meta.mark_exit(&wallet_a, 48))?;

    assert!(message.contains("exit_height=48 <= join_height=48"));
    Ok(())
}

#[test]
fn test_49_nonfounder_mark_exit_before_join_height_rejects() -> TestResult {
    let wallet_a = wallet(49);
    let mut meta = ValidatorMeta::joined(49, VALID_TS)?;

    let message = validation_message(meta.mark_exit(&wallet_a, 48))?;

    assert!(message.contains("exit_height=48 <= join_height=49"));
    Ok(())
}

#[test]
fn test_50_mark_exit_rejects_invalid_wallet_before_setting_valid_exit() -> TestResult {
    let mut meta = ValidatorMeta::joined(50, VALID_TS)?;

    let message = validation_message(meta.mark_exit("bad-wallet", 60))?;

    assert!(message.contains("ValidatorMeta invalid wallet"));
    Ok(())
}

#[test]
fn test_51_renew_active_validator_newer_height_same_timestamp_updates_height_only() -> TestResult {
    let wallet_a = wallet(51);
    let mut meta = ValidatorMeta::joined(51, VALID_TS)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 52, VALID_TS)?;

    assert_eq!(outcome, RegisterOutcome::Renewed);
    assert_eq!(meta.join_height, 51);
    assert_eq!(meta.last_renew_height, 52);
    assert_eq!(meta.last_renew_timestamp, VALID_TS);
    Ok(())
}

#[test]
fn test_52_renew_active_validator_same_height_newer_timestamp_updates_timestamp_only() -> TestResult
{
    let wallet_a = wallet(52);
    let mut meta = ValidatorMeta::joined(52, VALID_TS)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 52, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::Renewed);
    assert_eq!(meta.join_height, 52);
    assert_eq!(meta.last_renew_height, 52);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    Ok(())
}

#[test]
fn test_53_renew_active_validator_older_height_newer_timestamp_updates_timestamp_only() -> TestResult
{
    let wallet_a = wallet(53);
    let mut meta = ValidatorMeta::joined(53, VALID_TS)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 52, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::Renewed);
    assert_eq!(meta.join_height, 53);
    assert_eq!(meta.last_renew_height, 53);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    Ok(())
}

#[test]
fn test_54_renew_active_validator_newer_height_older_but_valid_timestamp_keeps_timestamp()
-> TestResult {
    let wallet_a = wallet(54);
    let mut meta = ValidatorMeta::joined(54, VALID_TS_LATER)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 55, VALID_TS)?;

    assert_eq!(outcome, RegisterOutcome::Renewed);
    assert_eq!(meta.last_renew_height, 55);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    Ok(())
}

#[test]
fn test_55_renew_or_reactivate_rejects_timestamp_before_year_2000() -> TestResult {
    let wallet_a = wallet(55);
    let mut meta = ValidatorMeta::joined(55, VALID_TS)?;

    let message = validation_message(meta.renew_or_reactivate(&wallet_a, 56, UNIX_2000_MINUS_ONE))?;

    assert!(message.contains("ValidatorMeta.renew_or_reactivate.timestamp"));
    assert!(message.contains("timestamp below UNIX_2000_SECS"));
    Ok(())
}

#[test]
fn test_56_reactivate_founder_after_exit_with_older_valid_timestamp_preserves_latest_timestamp()
-> TestResult {
    let wallet_a = wallet(56);
    let mut meta = ValidatorMeta::founder(VALID_TS_LATER)?;

    assert!(meta.mark_exit(&wallet_a, 5)?);

    let outcome = meta.renew_or_reactivate(&wallet_a, 10, VALID_TS)?;

    assert_eq!(outcome, RegisterOutcome::Reactivated);
    assert_eq!(meta.join_height, 0);
    assert_eq!(meta.join_timestamp, VALID_TS_LATER);
    assert_eq!(meta.last_renew_height, 10);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_57_reactivate_nonfounder_after_exit_replaces_join_timestamp_with_new_timestamp()
-> TestResult {
    let wallet_a = wallet(57);
    let mut meta = ValidatorMeta::joined(57, VALID_TS)?;

    assert!(meta.mark_exit(&wallet_a, 60)?);

    let outcome = meta.renew_or_reactivate(&wallet_a, 61, VALID_TS_LATER)?;

    assert_eq!(outcome, RegisterOutcome::Reactivated);
    assert_eq!(meta.join_height, 61);
    assert_eq!(meta.join_timestamp, VALID_TS_LATER);
    assert_eq!(meta.last_renew_height, 61);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_58_apply_register_or_renew_duplicate_same_height_timestamp_is_no_change() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(58);

    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 58, VALID_TS)?,
        RegisterOutcome::Inserted
    );
    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 58, VALID_TS)?,
        RegisterOutcome::NoChange
    );

    assert_eq!(map.len(), 1);
    Ok(())
}

#[test]
fn test_59_apply_register_or_renew_reactivates_exited_nonfounder_in_map() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(59);

    map.insert(wallet_a.clone(), ValidatorMeta::joined(59, VALID_TS)?);

    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 60)?);
    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 61, VALID_TS_LATER)?,
        RegisterOutcome::Reactivated
    );

    let meta = map
        .get(&wallet_a)
        .ok_or_else(|| test_error("validator missing after reactivation"))?;

    assert_eq!(meta.join_height, 61);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_60_apply_register_or_renew_preserves_founder_join_height_after_reactivation() -> TestResult
{
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(60);

    map.insert(wallet_a.clone(), ValidatorMeta::founder(VALID_TS)?);

    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 5)?);
    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 10, VALID_TS_LATER)?,
        RegisterOutcome::Reactivated
    );

    let meta = map
        .get(&wallet_a)
        .ok_or_else(|| test_error("founder missing after reactivation"))?;

    assert_eq!(meta.join_height, 0);
    assert_eq!(meta.last_renew_height, 10);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_61_apply_register_or_renew_rejects_invalid_wallet_without_inserting() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();

    let message = validation_message(ValidatorLifecycle::apply_register_or_renew(
        &mut map,
        "bad-wallet",
        61,
        VALID_TS,
    ))?;

    assert!(message.contains("apply_register_or_renew invalid wallet"));
    assert!(map.is_empty());
    Ok(())
}

#[test]
fn test_62_apply_register_or_renew_rejects_invalid_timestamp_without_inserting() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(62);

    let message = validation_message(ValidatorLifecycle::apply_register_or_renew(
        &mut map,
        &wallet_a,
        62,
        UNIX_2000_MINUS_ONE,
    ))?;

    assert!(message.contains("ValidatorLifecycle.apply_register_or_renew.timestamp"));
    assert!(message.contains("timestamp below UNIX_2000_SECS"));
    assert!(map.is_empty());
    Ok(())
}

#[test]
fn test_63_apply_exit_invalid_wallet_returns_validation_error() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();

    let message = validation_message(ValidatorLifecycle::apply_exit(&mut map, "bad-wallet", 63))?;

    assert!(message.contains("apply_exit invalid wallet"));
    Ok(())
}

#[test]
fn test_64_apply_exit_existing_wallet_sets_exit_and_active_wallets_exclude_at_exit() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(64);

    map.insert(wallet_a.clone(), ValidatorMeta::joined(64, VALID_TS)?);

    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 70)?);

    assert_eq!(
        ValidatorLifecycle::active_wallets_at(&map, 69)?,
        vec![wallet_a]
    );
    assert!(ValidatorLifecycle::active_wallets_at(&map, 70)?.is_empty());
    Ok(())
}

#[test]
fn test_65_apply_exit_same_or_later_height_returns_false() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(65);

    map.insert(wallet_a.clone(), ValidatorMeta::joined(65, VALID_TS)?);

    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 70)?);
    assert!(!ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 70)?);
    assert!(!ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 71)?);

    assert_eq!(
        map.get(&wallet_a)
            .ok_or_else(|| test_error("validator missing"))?
            .exit_height,
        Some(70)
    );
    Ok(())
}

#[test]
fn test_66_apply_exit_earlier_height_updates_exit_height_in_map() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(66);

    map.insert(wallet_a.clone(), ValidatorMeta::joined(66, VALID_TS)?);

    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 80)?);
    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 70)?);

    assert_eq!(
        map.get(&wallet_a)
            .ok_or_else(|| test_error("validator missing"))?
            .exit_height,
        Some(70)
    );
    Ok(())
}

#[test]
fn test_67_active_wallets_at_excludes_expired_lease() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(67);

    map.insert(wallet_a, ValidatorMeta::joined(1, VALID_TS)?);

    let cfg = ValidatorLifecycle::config();
    let active_at_join = ValidatorLifecycle::active_wallets_at(&map, 1)?;
    let active_after_expiry =
        ValidatorLifecycle::active_wallets_at(&map, 1_u64.saturating_add(cfg.lease_blocks + 1))?;

    assert_eq!(active_at_join.len(), 1);
    assert!(active_after_expiry.is_empty());
    Ok(())
}

#[test]
fn test_68_proposable_wallets_at_excludes_nonfounder_before_activation_delay() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(68);
    let cfg = ValidatorLifecycle::config();

    map.insert(wallet_a.clone(), ValidatorMeta::joined(10, VALID_TS)?);

    let before = 10_u64.saturating_add(cfg.activation_delay_blocks.saturating_sub(1));
    let at = 10_u64.saturating_add(cfg.activation_delay_blocks);

    if cfg.activation_delay_blocks > 0 {
        assert!(ValidatorLifecycle::proposable_wallets_at(&map, before)?.is_empty());
    }

    assert_eq!(
        ValidatorLifecycle::proposable_wallets_at(&map, at)?,
        vec![wallet_a]
    );
    Ok(())
}

#[test]
fn test_69_founder_remains_proposable_immediately_through_namespace_helper() -> TestResult {
    let founder = ValidatorMeta::founder(VALID_TS)?;

    assert!(ValidatorLifecycle::is_proposable_at(&founder, 0));
    assert!(ValidatorLifecycle::is_proposable_at(&founder, 1));
    Ok(())
}

#[test]
fn test_70_reward_eligible_namespace_helper_matches_meta_method() -> TestResult {
    let meta = ValidatorMeta::joined(70, VALID_TS)?;
    let cfg = ValidatorLifecycle::config();

    for height in [70_u64, 71, 75, 100] {
        assert_eq!(
            ValidatorLifecycle::reward_eligible_at(&meta, height),
            meta.reward_eligible_at(height, cfg)
        );
    }

    Ok(())
}

#[test]
fn test_71_is_active_namespace_helper_matches_meta_method() -> TestResult {
    let meta = ValidatorMeta::joined(71, VALID_TS)?;
    let cfg = ValidatorLifecycle::config();

    for height in [70_u64, 71, 72, 100] {
        assert_eq!(
            ValidatorLifecycle::is_active_at(&meta, height),
            meta.is_active_at(height, cfg)
        );
    }

    Ok(())
}

#[test]
fn test_72_validator_meta_postcard_round_trip_preserves_fields() -> TestResult {
    let mut meta = ValidatorMeta::joined(72, VALID_TS)?;
    meta.last_renew_height = 73;
    meta.last_renew_timestamp = VALID_TS_LATER;
    meta.exit_height = Some(80);

    let bytes = postcard::to_allocvec(&meta)?;
    let decoded = postcard::from_bytes::<ValidatorMeta>(&bytes)?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_73_validator_meta_json_round_trip_preserves_fields() -> TestResult {
    let mut meta = ValidatorMeta::joined(73, VALID_TS)?;
    meta.last_renew_height = 74;
    meta.last_renew_timestamp = VALID_TS_LATER;
    meta.exit_height = Some(80);

    let encoded = serde_json::to_string(&meta)?;
    let decoded = serde_json::from_str::<ValidatorMeta>(&encoded)?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_74_validator_meta_json_contains_expected_field_names() -> TestResult {
    let meta = ValidatorMeta::joined(74, VALID_TS)?;
    let encoded = serde_json::to_string(&meta)?;

    assert!(encoded.contains("join_height"));
    assert!(encoded.contains("join_timestamp"));
    assert!(encoded.contains("last_renew_height"));
    assert!(encoded.contains("last_renew_timestamp"));
    assert!(encoded.contains("exit_height"));
    Ok(())
}

#[test]
fn test_75_validate_map_accepts_empty_map() -> TestResult {
    let map = BTreeMap::<String, ValidatorMeta>::new();

    ValidatorLifecycle::validate_map(&map)?;

    Ok(())
}

#[test]
fn test_76_validate_map_rejects_bad_metadata_under_valid_wallet() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(76);

    map.insert(
        wallet_a,
        ValidatorMeta {
            join_height: 76,
            join_timestamp: VALID_TS,
            last_renew_height: 75,
            last_renew_timestamp: VALID_TS,
            exit_height: None,
        },
    );

    assert!(ValidatorLifecycle::validate_map(&map).is_err());
    Ok(())
}

#[test]
fn test_77_load_many_inserted_validators_active_wallets_are_sorted() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let mut expected = Vec::new();

    for seed in (77_u64..109_u64).rev() {
        let wallet_addr = wallet(seed);
        expected.push(wallet_addr.clone());
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_addr, 1, VALID_TS)?;
    }

    expected.sort();

    assert_eq!(ValidatorLifecycle::active_wallets_at(&map, 1)?, expected);
    Ok(())
}

#[test]
fn test_78_load_many_inserted_validators_proposable_wallets_are_sorted_after_activation()
-> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let cfg = ValidatorLifecycle::config();
    let mut expected = Vec::new();

    for seed in (78_u64..110_u64).rev() {
        let wallet_addr = wallet(seed);
        expected.push(wallet_addr.clone());
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_addr, 10, VALID_TS)?;
    }

    expected.sort();

    assert_eq!(
        ValidatorLifecycle::proposable_wallets_at(
            &map,
            10_u64.saturating_add(cfg.activation_delay_blocks),
        )?,
        expected
    );
    Ok(())
}

#[test]
fn test_79_load_alternating_exits_filter_active_wallets() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let mut expected_active = Vec::new();

    for seed in 79_u64..95_u64 {
        let wallet_addr = wallet(seed);
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_addr, 10, VALID_TS)?;

        if seed % 2 == 0 {
            ValidatorLifecycle::apply_exit(&mut map, &wallet_addr, 20)?;
        } else {
            expected_active.push(wallet_addr);
        }
    }

    expected_active.sort();

    assert_eq!(
        ValidatorLifecycle::active_wallets_at(&map, 20)?,
        expected_active
    );
    Ok(())
}

#[test]
fn test_80_adversarial_map_with_mixed_invalid_keys_and_valid_meta_fails_validation() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();

    map.insert(wallet(80), ValidatorMeta::joined(80, VALID_TS)?);
    map.insert(
        "bad-wallet".to_string(),
        ValidatorMeta::joined(80, VALID_TS)?,
    );

    assert!(ValidatorLifecycle::validate_map(&map).is_err());

    Ok(())
}

#[test]
fn test_81_edge_config_validate_accepts_hard_cap_exactly() {
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 0,
        lease_blocks: 1_000_000,
    };

    assert!(cfg.validate().is_ok());
}

#[test]
fn test_82_edge_zero_activation_delay_makes_nonfounder_immediately_proposable() -> TestResult {
    let meta = ValidatorMeta::joined(82, VALID_TS)?;
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 5,
        lease_blocks: 10,
    };

    assert!(meta.is_proposable_at(82, cfg));
    assert!(!meta.is_proposable_at(81, cfg));
    Ok(())
}

#[test]
fn test_83_edge_zero_reward_delay_makes_nonfounder_immediately_reward_eligible() -> TestResult {
    let meta = ValidatorMeta::joined(83, VALID_TS)?;
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 3,
        reward_delay_blocks: 0,
        lease_blocks: 10,
    };

    assert!(meta.reward_eligible_at(83, cfg));
    assert!(!meta.reward_eligible_at(82, cfg));
    Ok(())
}

#[test]
fn test_84_edge_one_block_lease_is_active_at_join_and_expiry_only() -> TestResult {
    let meta = ValidatorMeta::joined(84, VALID_TS)?;
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 0,
        lease_blocks: 1,
    };

    assert!(meta.is_active_at(84, cfg));
    assert!(meta.is_active_at(85, cfg));
    assert!(!meta.is_active_at(86, cfg));
    Ok(())
}

#[test]
fn test_85_vector_validate_invariants_accepts_uppercase_and_trimmed_wallet() -> TestResult {
    let meta = ValidatorMeta::joined(85, VALID_TS)?;
    let canonical = wallet(85);
    let input = format!(" \n{}\t ", canonical.to_ascii_uppercase());

    meta.validate_invariants(&input)?;

    Ok(())
}

#[test]
fn test_86_edge_founder_explicit_exit_height_one_is_valid_and_deactivates_at_one() -> TestResult {
    let wallet_a = wallet(86);
    let mut meta = ValidatorMeta::founder(VALID_TS)?;
    let cfg = test_cfg();

    assert!(meta.mark_exit(&wallet_a, 1)?);
    assert!(meta.is_active_at(0, cfg));
    assert!(!meta.is_active_at(1, cfg));
    assert_eq!(meta.exit_height, Some(1));
    Ok(())
}

#[test]
fn test_87_edge_nonfounder_exit_height_join_plus_one_is_valid() -> TestResult {
    let wallet_a = wallet(87);
    let mut meta = ValidatorMeta::joined(87, VALID_TS)?;

    assert!(meta.mark_exit(&wallet_a, 88)?);
    assert_eq!(meta.exit_height, Some(88));
    meta.validate_invariants(&wallet_a)?;
    Ok(())
}

#[test]
fn test_88_vector_active_at_join_exit_and_lease_boundaries() -> TestResult {
    let mut meta = ValidatorMeta::joined(88, VALID_TS)?;
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 0,
        lease_blocks: 10,
    };

    assert!(meta.is_active_at(88, cfg));
    assert!(meta.is_active_at(98, cfg));
    assert!(!meta.is_active_at(99, cfg));

    meta.mark_exit(&wallet(88), 95)?;

    assert!(meta.is_active_at(94, cfg));
    assert!(!meta.is_active_at(95, cfg));
    Ok(())
}

#[test]
fn test_89_vector_proposable_at_join_activation_and_expiry_boundaries() -> TestResult {
    let meta = ValidatorMeta::joined(89, VALID_TS)?;
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 3,
        reward_delay_blocks: 0,
        lease_blocks: 10,
    };

    assert!(!meta.is_proposable_at(89, cfg));
    assert!(!meta.is_proposable_at(91, cfg));
    assert!(meta.is_proposable_at(92, cfg));
    assert!(meta.is_proposable_at(99, cfg));
    assert!(!meta.is_proposable_at(100, cfg));
    Ok(())
}

#[test]
fn test_90_vector_reward_eligibility_boundaries() -> TestResult {
    let meta = ValidatorMeta::joined(90, VALID_TS)?;
    let cfg = ValidatorLifecycleConfig {
        activation_delay_blocks: 0,
        reward_delay_blocks: 5,
        lease_blocks: 10,
    };

    assert!(!meta.reward_eligible_at(94, cfg));
    assert!(meta.reward_eligible_at(95, cfg));
    assert!(meta.reward_eligible_at(100, cfg));
    Ok(())
}

#[test]
fn test_91_edge_renew_active_validator_with_older_height_and_older_timestamp_is_no_change()
-> TestResult {
    let wallet_a = wallet(91);
    let mut meta = ValidatorMeta::joined(91, VALID_TS_LATER)?;

    let outcome = meta.renew_or_reactivate(&wallet_a, 90, VALID_TS)?;

    assert_eq!(outcome, RegisterOutcome::NoChange);
    assert_eq!(meta.join_height, 91);
    assert_eq!(meta.last_renew_height, 91);
    assert_eq!(meta.last_renew_timestamp, VALID_TS_LATER);
    Ok(())
}

#[test]
fn test_92_edge_out_of_order_renewal_before_exit_with_larger_timestamp_is_ignored() -> TestResult {
    let wallet_a = wallet(92);
    let mut meta = ValidatorMeta::joined(92, VALID_TS)?;

    assert!(meta.mark_exit(&wallet_a, 100)?);

    let outcome = meta.renew_or_reactivate(&wallet_a, 99, VALID_TS_EVEN_LATER)?;

    assert_eq!(outcome, RegisterOutcome::NoChange);
    assert_eq!(meta.exit_height, Some(100));
    assert_eq!(meta.last_renew_timestamp, VALID_TS);
    Ok(())
}

#[test]
fn test_93_vector_apply_register_or_renew_uppercase_and_trimmed_forms_share_one_entry() -> TestResult
{
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let canonical = wallet(93);
    let uppercase = canonical.to_ascii_uppercase();
    let trimmed = format!(" \n{uppercase}\t ");

    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &canonical, 93, VALID_TS)?,
        RegisterOutcome::Inserted
    );
    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &trimmed, 94, VALID_TS_LATER)?,
        RegisterOutcome::Renewed
    );

    assert_eq!(map.len(), 1);
    assert!(map.contains_key(&canonical));
    assert_eq!(
        map.get(&canonical)
            .ok_or_else(|| test_error("canonical entry missing"))?
            .last_renew_height,
        94
    );
    Ok(())
}

#[test]
fn test_94_vector_apply_exit_uppercase_wallet_updates_canonical_entry() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let canonical = wallet(94);

    ValidatorLifecycle::apply_register_or_renew(&mut map, &canonical, 94, VALID_TS)?;

    assert!(ValidatorLifecycle::apply_exit(
        &mut map,
        &canonical.to_ascii_uppercase(),
        100
    )?);

    assert_eq!(
        map.get(&canonical)
            .ok_or_else(|| test_error("canonical entry missing"))?
            .exit_height,
        Some(100)
    );
    Ok(())
}

#[test]
fn test_95_vector_active_wallets_at_filters_join_future_expired_and_exited() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let active = wallet(950);
    let future = wallet(951);
    let exited = wallet(952);
    let expired = wallet(953);
    let cfg = ValidatorLifecycle::config();

    map.insert(active.clone(), ValidatorMeta::joined(10, VALID_TS)?);
    map.insert(future, ValidatorMeta::joined(1_000, VALID_TS)?);

    let mut exited_meta = ValidatorMeta::joined(10, VALID_TS)?;
    exited_meta.mark_exit(&exited, 20)?;
    map.insert(exited, exited_meta);

    map.insert(expired, ValidatorMeta::joined(1, VALID_TS)?);

    let height = 10_u64.saturating_add(cfg.lease_blocks.min(100));
    let active_wallets = ValidatorLifecycle::active_wallets_at(&map, height)?;

    assert!(active_wallets.contains(&active));
    assert!(
        !active_wallets
            .iter()
            .any(|wallet_addr| wallet_addr == &wallet(951))
    );
    assert!(
        !active_wallets
            .iter()
            .any(|wallet_addr| wallet_addr == &wallet(952))
    );

    if height > 1_u64.saturating_add(cfg.lease_blocks) {
        assert!(
            !active_wallets
                .iter()
                .any(|wallet_addr| wallet_addr == &wallet(953))
        );
    }

    Ok(())
}

#[test]
fn test_96_vector_proposable_wallets_at_filters_activation_delay_but_active_wallets_include_joined()
-> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(960);
    let cfg = ValidatorLifecycle::config();

    map.insert(wallet_a.clone(), ValidatorMeta::joined(100, VALID_TS)?);

    let before_activation = 100_u64.saturating_add(cfg.activation_delay_blocks.saturating_sub(1));
    let at_activation = 100_u64.saturating_add(cfg.activation_delay_blocks);

    if cfg.activation_delay_blocks > 0 {
        assert_eq!(
            ValidatorLifecycle::active_wallets_at(&map, before_activation)?,
            vec![wallet_a.clone()]
        );
        assert!(ValidatorLifecycle::proposable_wallets_at(&map, before_activation)?.is_empty());
    }

    assert_eq!(
        ValidatorLifecycle::proposable_wallets_at(&map, at_activation)?,
        vec![wallet_a]
    );
    Ok(())
}

#[test]
fn test_97_vector_json_missing_field_is_rejected() {
    let json_text = format!(
        r#"{{
            "join_height": 97,
            "join_timestamp": {VALID_TS},
            "last_renew_height": 97,
            "exit_height": null
        }}"#
    );

    let result = serde_json::from_str::<ValidatorMeta>(&json_text);

    assert!(result.is_err());
}

#[test]
fn test_98_vector_json_unknown_field_is_ignored_by_default_serde_behavior() -> TestResult {
    let json_text = format!(
        r#"{{
            "join_height": 98,
            "join_timestamp": {VALID_TS},
            "last_renew_height": 98,
            "last_renew_timestamp": {VALID_TS},
            "exit_height": null,
            "extra_field": "ignored"
        }}"#
    );

    let decoded = serde_json::from_str::<ValidatorMeta>(&json_text)?;

    assert_eq!(decoded.join_height, 98);
    assert_eq!(decoded.last_renew_height, 98);
    decoded.validate_invariants(&wallet(98))?;
    Ok(())
}

#[test]
fn test_99_load_vector_repeated_renewals_are_monotonic_for_height_and_timestamp() -> TestResult {
    let wallet_a = wallet(99);
    let mut meta = ValidatorMeta::joined(99, VALID_TS)?;

    for offset in 0_u64..64_u64 {
        let height = 99_u64.saturating_add(offset);
        let timestamp = VALID_TS.saturating_add(offset);
        let _outcome = meta.renew_or_reactivate(&wallet_a, height, timestamp)?;
        assert!(meta.last_renew_height >= 99);
        assert!(meta.last_renew_timestamp >= VALID_TS);
        meta.validate_invariants(&wallet_a)?;
    }

    assert_eq!(meta.last_renew_height, 162);
    assert_eq!(meta.last_renew_timestamp, VALID_TS.saturating_add(63));
    Ok(())
}

#[test]
fn test_100_adversarial_vector_map_register_exit_reactivate_and_validate() -> TestResult {
    let mut map = BTreeMap::<String, ValidatorMeta>::new();
    let wallet_a = wallet(100);
    let wallet_b = wallet(101);

    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 100, VALID_TS)?,
        RegisterOutcome::Inserted
    );
    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_b, 101, VALID_TS)?,
        RegisterOutcome::Inserted
    );

    assert!(ValidatorLifecycle::apply_exit(&mut map, &wallet_a, 110)?);

    assert_eq!(
        ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet_a, 111, VALID_TS_LATER)?,
        RegisterOutcome::Reactivated
    );

    ValidatorLifecycle::validate_map(&map)?;

    let meta_a = map
        .get(&wallet_a)
        .ok_or_else(|| test_error("wallet_a missing"))?;
    let meta_b = map
        .get(&wallet_b)
        .ok_or_else(|| test_error("wallet_b missing"))?;

    assert_eq!(meta_a.join_height, 111);
    assert_eq!(meta_a.exit_height, None);
    assert_eq!(meta_b.join_height, 101);
    assert_eq!(map.len(), 2);
    Ok(())
}
