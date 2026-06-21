//! tests/time_policy_tests.rs

use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::time_policy::{
    ChainTimePolicyConfig, MAX_BLOCK_INTERVAL_SECS, MAX_SLOT_GATE_DRIFT_SECS, TimePolicy,
    UNIX_2000_MILLIS, UNIX_2000_SECS, UNIX_9999_MILLIS, UNIX_9999_SECS,
};

const GOOD_GENESIS: u64 = UNIX_2000_SECS + 3_600;
const GOOD_INTERVAL: u64 = 30;
const GOOD_DRIFT: u64 = 5;

fn cfg() -> ChainTimePolicyConfig {
    ChainTimePolicyConfig::new(GOOD_GENESIS, GOOD_INTERVAL, GOOD_DRIFT)
}

fn assert_ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("expected Ok(..), got Err({err:?})"),
    }
}

fn assert_err<T: core::fmt::Debug, E: core::fmt::Debug>(result: Result<T, E>) {
    if let Ok(value) = result {
        panic!("expected Err(..), got Ok({value:?})");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 001-005: UNIX seconds structural bounds.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_001_seconds_below_unix_2000_secs_is_rejected() {
    assert_err(TimePolicy::validate_unix_secs_structural(
        "case.001.seconds_below_2000",
        UNIX_2000_SECS - 1,
    ));
}

#[test]
fn test_002_seconds_exactly_unix_2000_secs_is_accepted() {
    assert_ok(TimePolicy::validate_unix_secs_structural(
        "case.002.seconds_at_2000",
        UNIX_2000_SECS,
    ));
}

#[test]
fn test_003_ordinary_unix_seconds_value_is_accepted() {
    assert_ok(TimePolicy::validate_unix_secs_structural(
        "case.003.good_genesis",
        GOOD_GENESIS,
    ));
}

#[test]
fn test_004_seconds_exactly_unix_9999_secs_is_accepted() {
    assert_ok(TimePolicy::validate_unix_secs_structural(
        "case.004.seconds_at_9999",
        UNIX_9999_SECS,
    ));
}

#[test]
fn test_005_seconds_above_unix_9999_secs_is_rejected() {
    assert_err(TimePolicy::validate_unix_secs_structural(
        "case.005.seconds_above_9999",
        UNIX_9999_SECS + 1,
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 006-009: UNIX milliseconds structural bounds.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_006_millis_below_unix_2000_millis_is_rejected() {
    assert_err(TimePolicy::validate_unix_millis_structural(
        "case.006.millis_below_2000",
        UNIX_2000_MILLIS - 1,
    ));
}

#[test]
fn test_007_millis_exactly_unix_2000_millis_is_accepted() {
    assert_ok(TimePolicy::validate_unix_millis_structural(
        "case.007.millis_at_2000",
        UNIX_2000_MILLIS,
    ));
}

#[test]
fn test_008_millis_exactly_unix_9999_millis_is_accepted() {
    assert_ok(TimePolicy::validate_unix_millis_structural(
        "case.008.millis_at_9999",
        UNIX_9999_MILLIS,
    ));
}

#[test]
fn test_009_millis_above_unix_9999_millis_is_rejected() {
    assert_err(TimePolicy::validate_unix_millis_structural(
        "case.009.millis_above_9999",
        UNIX_9999_MILLIS + 1,
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 010-016: ChainTimePolicyConfig validation.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_010_valid_config_is_accepted() {
    assert_ok(cfg().validate());
}

#[test]
fn test_011_config_with_pre_2000_genesis_is_rejected() {
    let bad = ChainTimePolicyConfig::new(UNIX_2000_SECS - 1, GOOD_INTERVAL, GOOD_DRIFT);
    assert_err(bad.validate());
}

#[test]
fn test_012_config_with_zero_block_interval_is_rejected() {
    let bad = ChainTimePolicyConfig::new(GOOD_GENESIS, 0, GOOD_DRIFT);
    assert_err(bad.validate());
}

#[test]
fn test_013_config_with_max_allowed_block_interval_is_accepted() {
    let good = ChainTimePolicyConfig::new(GOOD_GENESIS, MAX_BLOCK_INTERVAL_SECS, GOOD_DRIFT);
    assert_ok(good.validate());
}

#[test]
fn test_014_config_above_max_block_interval_is_rejected() {
    let bad = ChainTimePolicyConfig::new(GOOD_GENESIS, MAX_BLOCK_INTERVAL_SECS + 1, GOOD_DRIFT);
    assert_err(bad.validate());
}

#[test]
fn test_015_config_with_max_slot_gate_drift_is_accepted() {
    let good = ChainTimePolicyConfig::new(GOOD_GENESIS, GOOD_INTERVAL, MAX_SLOT_GATE_DRIFT_SECS);
    assert_ok(good.validate());
}

#[test]
fn test_016_config_above_max_slot_gate_drift_is_rejected() {
    let bad = ChainTimePolicyConfig::new(GOOD_GENESIS, GOOD_INTERVAL, MAX_SLOT_GATE_DRIFT_SECS + 1);
    assert_err(bad.validate());
}

// ─────────────────────────────────────────────────────────────────────────────
// 017-022: Slot start and overflow/upper-bound behavior.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_017_slot_0_start_returns_genesis() {
    assert_eq!(assert_ok(cfg().slot_start_unix_checked(0)), GOOD_GENESIS);
}

#[test]
fn test_018_slot_1_start_returns_genesis_plus_interval() {
    assert_eq!(
        assert_ok(cfg().slot_start_unix_checked(1)),
        GOOD_GENESIS + GOOD_INTERVAL
    );
}

#[test]
fn test_019_slot_10_start_returns_exact_value() {
    assert_eq!(
        assert_ok(cfg().slot_start_unix_checked(10)),
        GOOD_GENESIS + (10 * GOOD_INTERVAL)
    );
}

#[test]
fn test_020_slot_start_saturating_is_display_only_checked_path_rejects() {
    let bad = ChainTimePolicyConfig::new(UNIX_9999_SECS, u64::MAX, 0);

    let display_value = bad.slot_start_unix_saturating(u64::MAX);
    assert_eq!(display_value, u64::MAX);

    assert_err(bad.slot_start_unix_checked(u64::MAX));
}

#[test]
fn test_021_large_slot_multiplication_overflow_is_rejected() {
    let config = ChainTimePolicyConfig::new(GOOD_GENESIS, MAX_BLOCK_INTERVAL_SECS, GOOD_DRIFT);
    assert_err(config.slot_start_unix_checked(u64::MAX));
}

#[test]
fn test_022_slot_start_above_unix_9999_secs_is_rejected() {
    let config = ChainTimePolicyConfig::new(UNIX_9999_SECS - 10, GOOD_INTERVAL, GOOD_DRIFT);
    assert_err(config.slot_start_unix_checked(1));
}

// ─────────────────────────────────────────────────────────────────────────────
// 023-027: Slot derivation from timestamps.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_023_slot_for_timestamp_at_genesis_returns_slot_0() {
    assert_eq!(assert_ok(cfg().slot_for_timestamp_checked(GOOD_GENESIS)), 0);
}

#[test]
fn test_024_slot_for_timestamp_at_end_of_slot_0_returns_slot_0() {
    assert_eq!(
        assert_ok(cfg().slot_for_timestamp_checked(GOOD_GENESIS + GOOD_INTERVAL - 1)),
        0
    );
}

#[test]
fn test_025_slot_for_timestamp_at_slot_1_boundary_returns_slot_1() {
    assert_eq!(
        assert_ok(cfg().slot_for_timestamp_checked(GOOD_GENESIS + GOOD_INTERVAL)),
        1
    );
}

#[test]
fn test_026_timestamp_before_genesis_drift_window_is_rejected() {
    assert_err(cfg().slot_for_timestamp_checked(GOOD_GENESIS - GOOD_DRIFT - 1));
}

#[test]
fn test_027_timestamp_inside_genesis_drift_window_is_accepted_as_slot_0() {
    assert_eq!(
        assert_ok(cfg().slot_for_timestamp_checked(GOOD_GENESIS - GOOD_DRIFT)),
        0
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 028-030: Seconds into slot and derived slot output.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_028_seconds_into_slot_at_slot_start_is_zero() {
    assert_eq!(assert_ok(cfg().secs_into_slot_checked(0, GOOD_GENESIS)), 0);
}

#[test]
fn test_029_seconds_into_slot_returns_expected_offset_and_saturates_before_slot() {
    let config = cfg();

    assert_eq!(
        assert_ok(config.secs_into_slot_checked(4, GOOD_GENESIS + (4 * GOOD_INTERVAL) + 29)),
        29
    );

    assert_eq!(
        assert_ok(config.secs_into_slot_checked(10, GOOD_GENESIS + 1)),
        0
    );

    assert_err(config.secs_into_slot_checked(10, UNIX_2000_SECS - 1));
}

#[test]
fn test_030_derive_slot_from_block_timestamp_returns_slot_and_offset() {
    let block_ts = GOOD_GENESIS + (12 * GOOD_INTERVAL) + 9;
    let (slot, into) = assert_ok(TimePolicy::derive_slot_from_block_timestamp(
        cfg(),
        block_ts,
    ));

    assert_eq!(slot, 12);
    assert_eq!(into, 9);
}

// ─────────────────────────────────────────────────────────────────────────────
// 031-033: Declared slot windows.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_031_declared_slot_earliest_drift_boundary_is_accepted() {
    let config = cfg();
    let slot = 10;
    let slot_start = assert_ok(config.slot_start_unix_checked(slot));

    assert_ok(TimePolicy::validate_block_timestamp_for_declared_slot(
        config,
        slot,
        slot_start - GOOD_DRIFT,
    ));
}

#[test]
fn test_032_declared_slot_latest_drift_boundary_is_accepted() {
    let config = cfg();
    let slot = 10;
    let slot_start = assert_ok(config.slot_start_unix_checked(slot));

    assert_ok(TimePolicy::validate_block_timestamp_for_declared_slot(
        config,
        slot,
        slot_start + GOOD_INTERVAL + GOOD_DRIFT,
    ));
}

#[test]
fn test_033_declared_slot_values_outside_window_are_rejected() {
    let config = cfg();
    let slot = 10;
    let slot_start = assert_ok(config.slot_start_unix_checked(slot));

    assert_err(TimePolicy::validate_block_timestamp_for_declared_slot(
        config,
        slot,
        slot_start - GOOD_DRIFT - 1,
    ));

    assert_err(TimePolicy::validate_block_timestamp_for_declared_slot(
        config,
        slot,
        slot_start + GOOD_INTERVAL + GOOD_DRIFT + 1,
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 034-037: Parent/block timestamp policy.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_034_block_parent_timestamp_monotonic_mode_allows_equal_timestamps() {
    let parent = GOOD_GENESIS;

    assert_ok(TimePolicy::validate_block_timestamp_against_parent(
        parent, parent, 0,
    ));
}

#[test]
fn test_035_block_parent_timestamp_strict_spacing_rejects_too_early_block() {
    let parent = GOOD_GENESIS;

    assert_err(TimePolicy::validate_block_timestamp_against_parent(
        parent, parent, 1,
    ));

    assert_err(TimePolicy::validate_block_timestamp_against_parent(
        parent + 29,
        parent,
        30,
    ));
}

#[test]
fn test_036_block_parent_timestamp_strict_spacing_accepts_exact_delta() {
    let parent = GOOD_GENESIS;

    assert_ok(TimePolicy::validate_block_timestamp_against_parent(
        parent + 1,
        parent,
        1,
    ));

    assert_ok(TimePolicy::validate_block_timestamp_against_parent(
        parent + 30,
        parent,
        30,
    ));
}

#[test]
fn test_037_block_parent_delta_overflow_is_rejected() {
    assert_err(TimePolicy::validate_block_timestamp_against_parent(
        UNIX_9999_SECS,
        UNIX_9999_SECS,
        1,
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 038-040: Runtime/off-chain/canonical-event/tx-window helpers.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_038_runtime_future_skew_edges_default_and_overflow() {
    let now = GOOD_GENESIS + 10_000;

    assert_ok(TimePolicy::validate_runtime_future_skew_secs(
        "case.038.runtime.equal_now",
        now,
        now,
        10,
    ));

    assert_ok(TimePolicy::validate_runtime_future_skew_secs(
        "case.038.runtime.at_limit",
        now + 10,
        now,
        10,
    ));

    assert_err(TimePolicy::validate_runtime_future_skew_secs(
        "case.038.runtime.beyond_limit",
        now + 11,
        now,
        10,
    ));

    assert_err(TimePolicy::validate_runtime_future_skew_secs(
        "case.038.runtime.overflow",
        UNIX_9999_SECS,
        UNIX_9999_SECS,
        1,
    ));

    assert_ok(TimePolicy::validate_runtime_future_skew_secs_default(
        "case.038.runtime.default",
        now,
        now,
    ));
}

#[test]
fn test_039_offchain_timestamp_ms_edges_past_age_and_overflow() {
    let now = GOOD_GENESIS + 10_000;
    let now_ms = now * 1_000;

    assert_ok(TimePolicy::validate_offchain_timestamp_ms(
        "case.039.offchain.equal_now",
        now_ms,
        now_ms,
        1_000,
        Some(60_000),
    ));

    assert_ok(TimePolicy::validate_offchain_timestamp_ms(
        "case.039.offchain.at_future_limit",
        now_ms + 1_000,
        now_ms,
        1_000,
        Some(60_000),
    ));

    assert_err(TimePolicy::validate_offchain_timestamp_ms(
        "case.039.offchain.beyond_future_limit",
        now_ms + 1_001,
        now_ms,
        1_000,
        Some(60_000),
    ));

    assert_err(TimePolicy::validate_offchain_timestamp_ms(
        "case.039.offchain.too_old",
        now_ms - 60_001,
        now_ms,
        1_000,
        Some(60_000),
    ));

    assert_ok(TimePolicy::validate_offchain_timestamp_ms(
        "case.039.offchain.no_past_limit",
        UNIX_2000_MILLIS,
        now_ms,
        0,
        None,
    ));

    assert_err(TimePolicy::validate_offchain_timestamp_ms(
        "case.039.offchain.future_skew_overflow",
        UNIX_9999_MILLIS,
        UNIX_9999_MILLIS,
        1,
        None,
    ));
}

#[test]
fn test_040_canonical_event_tx_window_and_runtime_clock_helpers() {
    let block_ts = GOOD_GENESIS + 10_000;
    let delta = 120;

    let event_ts = assert_ok(TimePolicy::canonical_event_timestamp_from_block(
        "case.040.canonical_event",
        block_ts,
    ));
    assert_eq!(event_ts, block_ts);

    assert_ok(TimePolicy::validate_tx_timestamp_within_block_window(
        "case.040.tx.earliest",
        block_ts - delta,
        block_ts,
        delta,
    ));

    assert_ok(TimePolicy::validate_tx_timestamp_within_block_window(
        "case.040.tx.center",
        block_ts,
        block_ts,
        delta,
    ));

    assert_ok(TimePolicy::validate_tx_timestamp_within_block_window(
        "case.040.tx.latest",
        block_ts + delta,
        block_ts,
        delta,
    ));

    assert_err(TimePolicy::validate_tx_timestamp_within_block_window(
        "case.040.tx.before_window",
        block_ts - delta - 1,
        block_ts,
        delta,
    ));

    assert_err(TimePolicy::validate_tx_timestamp_within_block_window(
        "case.040.tx.after_window",
        block_ts + delta + 1,
        block_ts,
        delta,
    ));

    let secs = assert_ok(TimePolicy::now_unix_secs_runtime());
    let millis = assert_ok(TimePolicy::now_unix_millis_runtime());

    assert!(secs >= UNIX_2000_SECS, "secs={secs}");
    assert!(secs <= UNIX_9999_SECS, "secs={secs}");
    assert!(millis >= UNIX_2000_MILLIS, "millis={millis}");
    assert!(millis <= UNIX_9999_MILLIS, "millis={millis}");

    let secs_as_ms = secs.saturating_mul(1_000);
    assert!(
        millis >= secs_as_ms.saturating_sub(2_000),
        "millis={millis} secs_as_ms={secs_as_ms}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 041-050: Final edge corners for globals, invalid configs, overflow windows,
//          and deterministic reject/accept behavior not covered above.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_041_from_genesis_and_globals_uses_project_global_time_settings() {
    let config = ChainTimePolicyConfig::from_genesis_and_globals(GOOD_GENESIS);

    assert_eq!(config.genesis_time_unix, GOOD_GENESIS);
    assert_eq!(
        config.block_interval_secs,
        GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS
    );
    assert_eq!(
        config.slot_gate_drift_secs,
        GlobalConfiguration::SLOT_GATE_DRIFT_SECS
    );
    assert_ok(config.validate());
}

#[test]
fn test_042_derive_slot_rejects_timestamp_before_genesis_drift_window() {
    let config = cfg();
    let too_early = GOOD_GENESIS - GOOD_DRIFT - 1;

    assert_err(TimePolicy::derive_slot_from_block_timestamp(
        config, too_early,
    ));
}

#[test]
fn test_043_derive_slot_rejects_structurally_invalid_future_timestamp() {
    assert_err(TimePolicy::derive_slot_from_block_timestamp(
        cfg(),
        UNIX_9999_SECS + 1,
    ));
}

#[test]
fn test_044_declared_slot_rejects_window_that_runs_past_unix_9999() {
    let config = ChainTimePolicyConfig::new(UNIX_9999_SECS - 10, 30, 5);

    assert_err(TimePolicy::validate_block_timestamp_for_declared_slot(
        config,
        0,
        UNIX_9999_SECS - 1,
    ));
}

#[test]
fn test_045_declared_slot_rejects_invalid_zero_interval_config() {
    let bad_config = ChainTimePolicyConfig::new(GOOD_GENESIS, 0, GOOD_DRIFT);

    assert_err(TimePolicy::validate_block_timestamp_for_declared_slot(
        bad_config,
        0,
        GOOD_GENESIS,
    ));
}

#[test]
fn test_046_runtime_future_skew_rejects_structurally_invalid_now_or_timestamp() {
    assert_err(TimePolicy::validate_runtime_future_skew_secs(
        "case.046.invalid_now",
        GOOD_GENESIS,
        UNIX_2000_SECS - 1,
        10,
    ));

    assert_err(TimePolicy::validate_runtime_future_skew_secs(
        "case.046.invalid_ts",
        UNIX_2000_SECS - 1,
        GOOD_GENESIS,
        10,
    ));
}

#[test]
fn test_047_runtime_future_skew_allows_old_structural_timestamp() {
    let now = GOOD_GENESIS + 1_000_000;
    let old_but_structural = UNIX_2000_SECS;

    assert_ok(TimePolicy::validate_runtime_future_skew_secs(
        "case.047.old_but_structural",
        old_but_structural,
        now,
        0,
    ));
}

#[test]
fn test_048_offchain_timestamp_rejects_structurally_invalid_inputs() {
    let now_ms = (GOOD_GENESIS + 10_000) * 1_000;

    assert_err(TimePolicy::validate_offchain_timestamp_ms(
        "case.048.invalid_ts_ms",
        UNIX_2000_MILLIS - 1,
        now_ms,
        0,
        None,
    ));

    assert_err(TimePolicy::validate_offchain_timestamp_ms(
        "case.048.invalid_now_ms",
        now_ms,
        UNIX_2000_MILLIS - 1,
        0,
        None,
    ));
}

#[test]
fn test_049_tx_timestamp_window_rejects_latest_overflow_past_unix_9999() {
    assert_err(TimePolicy::validate_tx_timestamp_within_block_window(
        "case.049.tx_window_latest_overflow",
        UNIX_9999_SECS,
        UNIX_9999_SECS,
        1,
    ));
}

#[test]
fn test_050_canonical_event_timestamp_rejects_structurally_invalid_block_times() {
    assert_err(TimePolicy::canonical_event_timestamp_from_block(
        "case.050.canonical_event_below_2000",
        UNIX_2000_SECS - 1,
    ));

    assert_err(TimePolicy::canonical_event_timestamp_from_block(
        "case.050.canonical_event_above_9999",
        UNIX_9999_SECS + 1,
    ));
}
