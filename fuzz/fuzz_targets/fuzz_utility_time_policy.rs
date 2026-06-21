#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;
        }
    }

    pub mod alpha_002_error_detection_system {
        #[derive(Debug)]
        pub enum ErrorDetection {
            TimestampError {
                message: String,
                details: String,
                source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
            },
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

use real_time_policy::{
    ChainTimePolicyConfig, TimePolicy, MAX_BLOCK_INTERVAL_SECS, MAX_SLOT_GATE_DRIFT_SECS,
    UNIX_2000_MILLIS, UNIX_2000_SECS, UNIX_9999_MILLIS, UNIX_9999_SECS,
};

use utility::alpha_001_global_configuration::GlobalConfiguration;
use utility::alpha_002_error_detection_system::ErrorDetection;

const LABEL: &str = "fuzz_time_policy";

static EDGE_CASES: Once = Once::new();

const SECS_EDGE_VALUES: &[u64] = &[
    0,
    1,
    UNIX_2000_SECS - 2,
    UNIX_2000_SECS - 1,
    UNIX_2000_SECS,
    UNIX_2000_SECS + 1,
    1_756_617_600,
    1_776_000_000,
    UNIX_9999_SECS - 1,
    UNIX_9999_SECS,
    UNIX_9999_SECS + 1,
    u32::MAX as u64,
    u64::MAX / 2,
    u64::MAX - 1,
    u64::MAX,
];

const MILLIS_EDGE_VALUES: &[u64] = &[
    0,
    1,
    UNIX_2000_MILLIS - 1_001,
    UNIX_2000_MILLIS - 1,
    UNIX_2000_MILLIS,
    UNIX_2000_MILLIS + 1,
    1_756_617_600_000,
    1_776_000_000_000,
    UNIX_9999_MILLIS - 1,
    UNIX_9999_MILLIS,
    UNIX_9999_MILLIS + 1,
    u32::MAX as u64,
    u64::MAX / 2,
    u64::MAX - 1,
    u64::MAX,
];

const SPAN_EDGE_VALUES: &[u64] = &[
    0,
    1,
    2,
    29,
    30,
    31,
    59,
    60,
    61,
    999,
    1_000,
    GlobalConfiguration::MAX_FUTURE_SKEW_SECS - 1,
    GlobalConfiguration::MAX_FUTURE_SKEW_SECS,
    GlobalConfiguration::MAX_FUTURE_SKEW_SECS + 1,
    MAX_SLOT_GATE_DRIFT_SECS - 1,
    MAX_SLOT_GATE_DRIFT_SECS,
    MAX_SLOT_GATE_DRIFT_SECS + 1,
    MAX_BLOCK_INTERVAL_SECS - 1,
    MAX_BLOCK_INTERVAL_SECS,
    MAX_BLOCK_INTERVAL_SECS + 1,
    u32::MAX as u64,
    u64::MAX / 2,
    u64::MAX - 1,
    u64::MAX,
];

const SLOT_EDGE_VALUES: &[u64] = &[
    0,
    1,
    2,
    3,
    10,
    100,
    8_192,
    (UNIX_9999_SECS - UNIX_2000_SECS) / 30,
    u32::MAX as u64,
    u64::MAX / 30,
    u64::MAX - 1,
    u64::MAX,
];

fuzz_target!(|data: &[u8]| {
    EDGE_CASES.call_once(run_fixed_edge_suite);

    let mut r = Reader::new(data);
    let rounds = 1 + usize::from(r.byte() & 0x07);

    for _ in 0..rounds {
        run_fuzz_case(&mut r);
    }
});

fn run_fixed_edge_suite() {
    for &ts in SECS_EDGE_VALUES {
        check_unix_secs_structural(ts);
        check_canonical_event_timestamp(ts);
        check_from_genesis_and_globals(ts);
        check_runtime_future_skew_secs_default(ts, UNIX_2000_SECS);
        check_runtime_future_skew_secs_default(ts, UNIX_9999_SECS);
    }

    for &ts_ms in MILLIS_EDGE_VALUES {
        check_unix_millis_structural(ts_ms);
    }

    let configs = [
        ChainTimePolicyConfig::new(UNIX_2000_SECS, 1, 0),
        ChainTimePolicyConfig::new(UNIX_2000_SECS, 30, 2),
        ChainTimePolicyConfig::new(UNIX_2000_SECS + 30, 30, 2),
        ChainTimePolicyConfig::new(
            UNIX_2000_SECS + 30,
            MAX_BLOCK_INTERVAL_SECS,
            MAX_SLOT_GATE_DRIFT_SECS,
        ),
        ChainTimePolicyConfig::new(UNIX_2000_SECS - 1, 30, 2),
        ChainTimePolicyConfig::new(UNIX_2000_SECS, 0, 2),
        ChainTimePolicyConfig::new(UNIX_2000_SECS, MAX_BLOCK_INTERVAL_SECS + 1, 2),
        ChainTimePolicyConfig::new(UNIX_2000_SECS, 30, MAX_SLOT_GATE_DRIFT_SECS + 1),
        ChainTimePolicyConfig::new(UNIX_9999_SECS, 1, 0),
        ChainTimePolicyConfig::new(UNIX_9999_SECS - 30, 30, 2),
    ];

    for cfg in configs {
        check_config_validate(cfg);

        for &slot in SLOT_EDGE_VALUES {
            check_slot_start(cfg, slot);

            for &ts in SECS_EDGE_VALUES {
                check_slot_for_timestamp(cfg, ts);
                check_secs_into_slot(cfg, slot, ts);
                check_declared_slot(cfg, slot, ts);
                check_derive_slot(cfg, ts);
            }
        }
    }

    for &parent_ts in SECS_EDGE_VALUES {
        for &min_delta in SPAN_EDGE_VALUES {
            let exact = parent_ts.saturating_add(min_delta);
            let early = exact.saturating_sub(1);
            let late = exact.saturating_add(1);

            check_block_against_parent(exact, parent_ts, min_delta);
            check_block_against_parent(early, parent_ts, min_delta);
            check_block_against_parent(late, parent_ts, min_delta);
        }
    }

    for &block_ts in SECS_EDGE_VALUES {
        for &tx_ts in SECS_EDGE_VALUES {
            for &delta in &[
                0,
                1,
                30,
                GlobalConfiguration::MAX_FUTURE_SKEW_SECS,
                u64::MAX,
            ] {
                check_tx_within_block_window(tx_ts, block_ts, delta);
            }
        }
    }

    for &now in SECS_EDGE_VALUES {
        for &ts in SECS_EDGE_VALUES {
            for &skew in &[
                0,
                1,
                GlobalConfiguration::MAX_FUTURE_SKEW_SECS,
                u64::MAX,
            ] {
                check_runtime_future_skew_secs(ts, now, skew);
            }
        }
    }

    for &now_ms in MILLIS_EDGE_VALUES {
        for &ts_ms in MILLIS_EDGE_VALUES {
            for &future_skew_ms in &[0, 1, 1_000, 7_200_000, u64::MAX] {
                check_offchain_timestamp_ms(ts_ms, now_ms, future_skew_ms, None);
                check_offchain_timestamp_ms(ts_ms, now_ms, future_skew_ms, Some(0));
                check_offchain_timestamp_ms(ts_ms, now_ms, future_skew_ms, Some(1_000));
                check_offchain_timestamp_ms(ts_ms, now_ms, future_skew_ms, Some(u64::MAX));
            }
        }
    }
}

fn run_fuzz_case(r: &mut Reader<'_>) {
    let genesis = r.pick(SECS_EDGE_VALUES);
    let interval = r.pick(SPAN_EDGE_VALUES);
    let drift = r.pick(SPAN_EDGE_VALUES);
    let cfg = ChainTimePolicyConfig::new(genesis, interval, drift);

    let slot = r.pick(SLOT_EDGE_VALUES);
    let ts_a = r.pick(SECS_EDGE_VALUES);
    let ts_b = r.pick(SECS_EDGE_VALUES);
    let span = r.pick(SPAN_EDGE_VALUES);

    let slot_near_ts = timestamp_near_declared_slot(cfg, slot, r);
    let parent_near_ts = timestamp_near_parent(ts_b, span, r);

    check_config_validate(cfg);
    check_from_genesis_and_globals(genesis);

    check_unix_secs_structural(ts_a);
    check_unix_secs_structural(ts_b);

    check_slot_start(cfg, slot);
    check_slot_for_timestamp(cfg, ts_a);
    check_slot_for_timestamp(cfg, slot_near_ts);
    check_secs_into_slot(cfg, slot, ts_a);
    check_secs_into_slot(cfg, slot, slot_near_ts);

    check_declared_slot(cfg, slot, ts_a);
    check_declared_slot(cfg, slot, slot_near_ts);

    check_derive_slot(cfg, ts_a);
    check_derive_slot(cfg, slot_near_ts);

    check_canonical_event_timestamp(ts_a);

    check_block_against_parent(ts_a, ts_b, span);
    check_block_against_parent(parent_near_ts, ts_b, span);

    check_tx_within_block_window(ts_a, ts_b, span);
    check_tx_within_block_window(parent_near_ts, ts_b, span);

    check_runtime_future_skew_secs(ts_a, ts_b, span);
    check_runtime_future_skew_secs(timestamp_near_now_secs(ts_b, span, r), ts_b, span);
    check_runtime_future_skew_secs_default(ts_a, ts_b);

    let now_ms = r.pick(MILLIS_EDGE_VALUES);
    let ts_ms = r.pick(MILLIS_EDGE_VALUES);
    let future_skew_ms = r.pick(SPAN_EDGE_VALUES).saturating_mul(1_000);
    let max_past_age_ms = r.option_u64(MILLIS_EDGE_VALUES);

    check_unix_millis_structural(now_ms);
    check_unix_millis_structural(ts_ms);
    check_offchain_timestamp_ms(ts_ms, now_ms, future_skew_ms, max_past_age_ms);
    check_offchain_timestamp_ms(
        timestamp_near_now_millis(now_ms, future_skew_ms, r),
        now_ms,
        future_skew_ms,
        max_past_age_ms,
    );
}

fn check_config_validate(cfg: ChainTimePolicyConfig) {
    assert_unit_result(cfg.validate(), expected_config_ok(cfg), "config validate");
}

fn check_from_genesis_and_globals(genesis_time_unix: u64) {
    let cfg = ChainTimePolicyConfig::from_genesis_and_globals(genesis_time_unix);

    assert_eq!(cfg.genesis_time_unix, genesis_time_unix);
    assert_eq!(
        cfg.block_interval_secs,
        GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS
    );
    assert_eq!(
        cfg.slot_gate_drift_secs,
        GlobalConfiguration::SLOT_GATE_DRIFT_SECS
    );

    check_config_validate(cfg);
}

fn check_unix_secs_structural(ts: u64) {
    assert_unit_result(
        TimePolicy::validate_unix_secs_structural(LABEL, ts),
        unix_secs_ok(ts),
        "validate_unix_secs_structural",
    );
}

fn check_unix_millis_structural(ts_ms: u64) {
    assert_unit_result(
        TimePolicy::validate_unix_millis_structural(LABEL, ts_ms),
        unix_millis_ok(ts_ms),
        "validate_unix_millis_structural",
    );
}

fn check_slot_start(cfg: ChainTimePolicyConfig, slot: u64) {
    assert_u64_result(
        cfg.slot_start_unix_checked(slot),
        expected_slot_start(cfg, slot),
        "slot_start_unix_checked",
    );

    let expected_saturating = cfg
        .genesis_time_unix
        .saturating_add(slot.saturating_mul(cfg.block_interval_secs.max(1)));

    assert_eq!(
        cfg.slot_start_unix_saturating(slot),
        expected_saturating,
        "slot_start_unix_saturating mismatch"
    );
}

fn check_slot_for_timestamp(cfg: ChainTimePolicyConfig, ts_unix: u64) {
    assert_u64_result(
        cfg.slot_for_timestamp_checked(ts_unix),
        expected_slot_for_timestamp(cfg, ts_unix),
        "slot_for_timestamp_checked",
    );
}

fn check_secs_into_slot(cfg: ChainTimePolicyConfig, slot: u64, ts_unix: u64) {
    assert_u64_result(
        cfg.secs_into_slot_checked(slot, ts_unix),
        expected_secs_into_slot(cfg, slot, ts_unix),
        "secs_into_slot_checked",
    );
}

fn check_runtime_future_skew_secs(ts: u64, now_unix: u64, max_future_skew_secs: u64) {
    assert_unit_result(
        TimePolicy::validate_runtime_future_skew_secs(
            LABEL,
            ts,
            now_unix,
            max_future_skew_secs,
        ),
        expected_runtime_future_skew_secs(ts, now_unix, max_future_skew_secs),
        "validate_runtime_future_skew_secs",
    );
}

fn check_runtime_future_skew_secs_default(ts: u64, now_unix: u64) {
    assert_unit_result(
        TimePolicy::validate_runtime_future_skew_secs_default(LABEL, ts, now_unix),
        expected_runtime_future_skew_secs(
            ts,
            now_unix,
            GlobalConfiguration::MAX_FUTURE_SKEW_SECS,
        ),
        "validate_runtime_future_skew_secs_default",
    );
}

fn check_offchain_timestamp_ms(
    ts_ms: u64,
    now_ms: u64,
    max_future_skew_ms: u64,
    max_past_age_ms: Option<u64>,
) {
    assert_unit_result(
        TimePolicy::validate_offchain_timestamp_ms(
            LABEL,
            ts_ms,
            now_ms,
            max_future_skew_ms,
            max_past_age_ms,
        ),
        expected_offchain_timestamp_ms(ts_ms, now_ms, max_future_skew_ms, max_past_age_ms),
        "validate_offchain_timestamp_ms",
    );
}

fn check_block_against_parent(block_ts: u64, parent_ts: u64, min_delta_secs: u64) {
    assert_unit_result(
        TimePolicy::validate_block_timestamp_against_parent(block_ts, parent_ts, min_delta_secs),
        expected_block_against_parent(block_ts, parent_ts, min_delta_secs),
        "validate_block_timestamp_against_parent",
    );
}

fn check_declared_slot(cfg: ChainTimePolicyConfig, declared_slot: u64, block_ts: u64) {
    assert_unit_result(
        TimePolicy::validate_block_timestamp_for_declared_slot(cfg, declared_slot, block_ts),
        expected_declared_slot_ok(cfg, declared_slot, block_ts),
        "validate_block_timestamp_for_declared_slot",
    );
}

fn check_derive_slot(cfg: ChainTimePolicyConfig, block_ts: u64) {
    assert_pair_result(
        TimePolicy::derive_slot_from_block_timestamp(cfg, block_ts),
        expected_derive_slot(cfg, block_ts),
        "derive_slot_from_block_timestamp",
    );
}

fn check_canonical_event_timestamp(containing_block_ts: u64) {
    assert_u64_result(
        TimePolicy::canonical_event_timestamp_from_block(LABEL, containing_block_ts),
        if unix_secs_ok(containing_block_ts) {
            Some(containing_block_ts)
        } else {
            None
        },
        "canonical_event_timestamp_from_block",
    );
}

fn check_tx_within_block_window(tx_ts: u64, block_ts: u64, allowed_delta_secs: u64) {
    assert_unit_result(
        TimePolicy::validate_tx_timestamp_within_block_window(
            LABEL,
            tx_ts,
            block_ts,
            allowed_delta_secs,
        ),
        expected_tx_within_block_window(tx_ts, block_ts, allowed_delta_secs),
        "validate_tx_timestamp_within_block_window",
    );
}

fn unix_secs_ok(ts: u64) -> bool {
    (UNIX_2000_SECS..=UNIX_9999_SECS).contains(&ts)
}

fn unix_millis_ok(ts_ms: u64) -> bool {
    (UNIX_2000_MILLIS..=UNIX_9999_MILLIS).contains(&ts_ms)
}

fn expected_config_ok(cfg: ChainTimePolicyConfig) -> bool {
    unix_secs_ok(cfg.genesis_time_unix)
        && cfg.block_interval_secs >= 1
        && cfg.block_interval_secs <= MAX_BLOCK_INTERVAL_SECS
        && cfg.slot_gate_drift_secs <= MAX_SLOT_GATE_DRIFT_SECS
}

fn expected_slot_start(cfg: ChainTimePolicyConfig, slot: u64) -> Option<u64> {
    if !expected_config_ok(cfg) {
        return None;
    }

    let offset = slot.checked_mul(cfg.block_interval_secs)?;
    let start = cfg.genesis_time_unix.checked_add(offset)?;

    unix_secs_ok(start).then_some(start)
}

fn expected_slot_for_timestamp(cfg: ChainTimePolicyConfig, ts_unix: u64) -> Option<u64> {
    if !expected_config_ok(cfg) || !unix_secs_ok(ts_unix) {
        return None;
    }

    if ts_unix < cfg.genesis_time_unix.saturating_sub(cfg.slot_gate_drift_secs) {
        return None;
    }

    let elapsed = ts_unix.saturating_sub(cfg.genesis_time_unix);
    Some(elapsed.div_euclid(cfg.block_interval_secs))
}

fn expected_secs_into_slot(
    cfg: ChainTimePolicyConfig,
    slot: u64,
    ts_unix: u64,
) -> Option<u64> {
    if !expected_config_ok(cfg) || !unix_secs_ok(ts_unix) {
        return None;
    }

    let slot_start = expected_slot_start(cfg, slot)?;
    Some(ts_unix.saturating_sub(slot_start))
}

fn expected_runtime_future_skew_secs(
    ts: u64,
    now_unix: u64,
    max_future_skew_secs: u64,
) -> bool {
    if !unix_secs_ok(ts) || !unix_secs_ok(now_unix) {
        return false;
    }

    let Some(max_allowed) = now_unix.checked_add(max_future_skew_secs) else {
        return false;
    };

    if !unix_secs_ok(max_allowed) {
        return false;
    }

    ts <= max_allowed
}

fn expected_offchain_timestamp_ms(
    ts_ms: u64,
    now_ms: u64,
    max_future_skew_ms: u64,
    max_past_age_ms: Option<u64>,
) -> bool {
    if !unix_millis_ok(ts_ms) || !unix_millis_ok(now_ms) {
        return false;
    }

    let Some(max_allowed) = now_ms.checked_add(max_future_skew_ms) else {
        return false;
    };

    if !unix_millis_ok(max_allowed) {
        return false;
    }

    if ts_ms > max_allowed {
        return false;
    }

    if let Some(max_past) = max_past_age_ms {
        let min_allowed = now_ms.saturating_sub(max_past);

        if ts_ms < min_allowed {
            return false;
        }
    }

    true
}

fn expected_block_against_parent(block_ts: u64, parent_ts: u64, min_delta_secs: u64) -> bool {
    if !unix_secs_ok(block_ts) || !unix_secs_ok(parent_ts) {
        return false;
    }

    let Some(min_allowed) = parent_ts.checked_add(min_delta_secs) else {
        return false;
    };

    unix_secs_ok(min_allowed) && block_ts >= min_allowed
}

fn expected_declared_slot_ok(
    cfg: ChainTimePolicyConfig,
    declared_slot: u64,
    block_ts: u64,
) -> bool {
    if !expected_config_ok(cfg) || !unix_secs_ok(block_ts) {
        return false;
    }

    let Some(slot_start) = expected_slot_start(cfg, declared_slot) else {
        return false;
    };

    let earliest = slot_start.saturating_sub(cfg.slot_gate_drift_secs);

    let Some(latest) = slot_start
        .checked_add(cfg.block_interval_secs)
        .and_then(|v| v.checked_add(cfg.slot_gate_drift_secs))
    else {
        return false;
    };

    unix_secs_ok(latest) && block_ts >= earliest && block_ts <= latest
}

fn expected_derive_slot(cfg: ChainTimePolicyConfig, block_ts: u64) -> Option<(u64, u64)> {
    let slot = expected_slot_for_timestamp(cfg, block_ts)?;
    let into = expected_secs_into_slot(cfg, slot, block_ts)?;

    Some((slot, into))
}

fn expected_tx_within_block_window(tx_ts: u64, block_ts: u64, allowed_delta_secs: u64) -> bool {
    if !unix_secs_ok(tx_ts) || !unix_secs_ok(block_ts) {
        return false;
    }

    let earliest = block_ts.saturating_sub(allowed_delta_secs);

    let Some(latest) = block_ts.checked_add(allowed_delta_secs) else {
        return false;
    };

    unix_secs_ok(latest) && tx_ts >= earliest && tx_ts <= latest
}

fn timestamp_near_declared_slot(
    cfg: ChainTimePolicyConfig,
    slot: u64,
    r: &mut Reader<'_>,
) -> u64 {
    let Some(start) = expected_slot_start(cfg, slot) else {
        return r.pick(SECS_EDGE_VALUES);
    };

    match r.byte() % 9 {
        0 => start
            .saturating_sub(cfg.slot_gate_drift_secs)
            .saturating_sub(1),
        1 => start.saturating_sub(cfg.slot_gate_drift_secs),
        2 => start.saturating_sub(1),
        3 => start,
        4 => start.saturating_add(1),
        5 => start.saturating_add(cfg.block_interval_secs),
        6 => start
            .saturating_add(cfg.block_interval_secs)
            .saturating_add(cfg.slot_gate_drift_secs),
        7 => start
            .saturating_add(cfg.block_interval_secs)
            .saturating_add(cfg.slot_gate_drift_secs)
            .saturating_add(1),
        _ => r.pick(SECS_EDGE_VALUES),
    }
}

fn timestamp_near_parent(parent_ts: u64, min_delta_secs: u64, r: &mut Reader<'_>) -> u64 {
    match r.byte() % 6 {
        0 => parent_ts,
        1 => parent_ts.saturating_add(min_delta_secs).saturating_sub(1),
        2 => parent_ts.saturating_add(min_delta_secs),
        3 => parent_ts.saturating_add(min_delta_secs).saturating_add(1),
        4 => parent_ts.checked_add(min_delta_secs).unwrap_or(u64::MAX),
        _ => r.pick(SECS_EDGE_VALUES),
    }
}

fn timestamp_near_now_secs(now_unix: u64, max_future_skew_secs: u64, r: &mut Reader<'_>) -> u64 {
    match r.byte() % 6 {
        0 => now_unix.saturating_sub(1),
        1 => now_unix,
        2 => now_unix.saturating_add(1),
        3 => now_unix.saturating_add(max_future_skew_secs),
        4 => now_unix
            .saturating_add(max_future_skew_secs)
            .saturating_add(1),
        _ => r.pick(SECS_EDGE_VALUES),
    }
}

fn timestamp_near_now_millis(now_ms: u64, max_future_skew_ms: u64, r: &mut Reader<'_>) -> u64 {
    match r.byte() % 6 {
        0 => now_ms.saturating_sub(1),
        1 => now_ms,
        2 => now_ms.saturating_add(1),
        3 => now_ms.saturating_add(max_future_skew_ms),
        4 => now_ms
            .saturating_add(max_future_skew_ms)
            .saturating_add(1),
        _ => r.pick(MILLIS_EDGE_VALUES),
    }
}

fn assert_unit_result(
    got: Result<(), ErrorDetection>,
    expected_ok: bool,
    context: &'static str,
) {
    match got {
        Ok(()) => {
            assert!(expected_ok, "{context}: expected Err, got Ok");
        }
        Err(error) => {
            touch_error(&error);
            assert!(!expected_ok, "{context}: expected Ok, got Err: {:?}", error);
        }
    }
}

fn assert_u64_result(
    got: Result<u64, ErrorDetection>,
    expected: Option<u64>,
    context: &'static str,
) {
    match (got, expected) {
        (Ok(actual), Some(expected_value)) => {
            assert_eq!(actual, expected_value, "{context}: value mismatch");
        }
        (Ok(actual), None) => {
            panic!("{context}: expected Err, got Ok({actual})");
        }
        (Err(error), Some(expected_value)) => {
            touch_error(&error);
            panic!(
                "{context}: expected Ok({expected_value}), got Err: {:?}",
                error
            );
        }
        (Err(error), None) => {
            touch_error(&error);
        }
    }
}

fn assert_pair_result(
    got: Result<(u64, u64), ErrorDetection>,
    expected: Option<(u64, u64)>,
    context: &'static str,
) {
    match (got, expected) {
        (Ok(actual), Some(expected_value)) => {
            assert_eq!(actual, expected_value, "{context}: pair mismatch");
        }
        (Ok(actual), None) => {
            panic!("{context}: expected Err, got Ok({actual:?})");
        }
        (Err(error), Some(expected_value)) => {
            touch_error(&error);
            panic!(
                "{context}: expected Ok({expected_value:?}), got Err: {:?}",
                error
            );
        }
        (Err(error), None) => {
            touch_error(&error);
        }
    }
}

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::TimestampError {
            message,
            details,
            source,
        } => {
            let _ = message.len();
            let _ = details.len();
            let _ = source.is_some();
        }
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(|s| s.len());
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }

        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for byte in &mut out {
            *byte = self.byte();
        }

        u64::from_le_bytes(out)
    }

    fn pick(&mut self, edges: &[u64]) -> u64 {
        let raw = self.u64();

        if edges.is_empty() {
            return raw;
        }

        match self.byte() % 6 {
            0 => raw,
            1 => edges[usize::from(self.byte()) % edges.len()],
            2 => {
                let base = edges[(raw as usize) % edges.len()];
                base.saturating_sub(1)
            }
            3 => {
                let base = edges[(raw as usize) % edges.len()];
                base
            }
            4 => {
                let base = edges[(raw as usize) % edges.len()];
                base.saturating_add(1)
            }
            _ => {
                let base = edges[(raw as usize) % edges.len()];
                base.saturating_add(u64::from(self.byte() & 0x0f))
            }
        }
    }

    fn option_u64(&mut self, edges: &[u64]) -> Option<u64> {
        if self.byte() & 1 == 0 {
            None
        } else {
            Some(self.pick(edges))
        }
    }
}