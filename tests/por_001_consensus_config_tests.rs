use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::error::Error;
use std::io;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn expected_puzzle_secs() -> u64 {
    let slot_secs = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
    let raw_puzzle_secs = GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS.max(1);
    raw_puzzle_secs.min(slot_secs)
}

fn expected_soft_ms() -> u64 {
    expected_puzzle_secs()
        .saturating_mul(1_000)
        .clamp(1_000, 3_600_000)
}

fn slot_secs() -> u64 {
    GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1)
}

fn slot_plus_one() -> TestResult<u64> {
    slot_secs()
        .checked_add(1)
        .ok_or_else(|| test_error("slot seconds overflowed in test"))
}

fn valid_config_with_secs(secs: u64) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(secs),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    }
}

fn invalid_kind_config() -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1,
    }
}

fn validation_message(result: Result<(), ErrorDetection>) -> TestResult<String> {
    match result {
        Ok(()) => Err(test_error(
            "expected validation error but validation succeeded",
        )),
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
fn test_01_default_config_validates() {
    let config = PorConsensusConfig::default();

    assert!(config.validate().is_ok());
}

#[test]
fn test_02_from_globals_config_validates() {
    let config = PorConsensusConfig::from_globals();

    assert!(config.validate().is_ok());
}

#[test]
fn test_03_default_matches_from_globals_field_for_field() {
    let default_config = PorConsensusConfig::default();
    let globals_config = PorConsensusConfig::from_globals();

    assert_eq!(
        default_config.target_block_time,
        globals_config.target_block_time
    );
    assert_eq!(default_config.puzzle_kind, globals_config.puzzle_kind);
    assert_eq!(
        default_config.max_local_puzzle_ms,
        globals_config.max_local_puzzle_ms
    );
}

#[test]
fn test_04_from_globals_uses_mandatory_fibonacci_delay_puzzle() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(config.puzzle_kind, PorPuzzleKind::FibonacciDelayDev);
}

#[test]
fn test_05_from_globals_target_block_time_matches_effective_puzzle_seconds() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(
        config.target_block_time,
        Duration::from_secs(expected_puzzle_secs())
    );
}

#[test]
fn test_06_from_globals_soft_cap_matches_expected_milliseconds() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(config.max_local_puzzle_ms, expected_soft_ms());
}

#[test]
fn test_07_from_globals_target_block_time_is_never_zero() {
    let config = PorConsensusConfig::from_globals();

    assert!(config.target_block_time.as_secs() >= 1);
}

#[test]
fn test_08_from_globals_target_block_time_never_exceeds_block_slot() {
    let config = PorConsensusConfig::from_globals();

    assert!(config.target_block_time.as_secs() <= slot_secs());
}

#[test]
fn test_09_from_globals_soft_cap_is_never_zero() {
    let config = PorConsensusConfig::from_globals();

    assert!(config.max_local_puzzle_ms >= 1);
}

#[test]
fn test_10_from_globals_soft_cap_is_at_least_one_second_in_ms() {
    let config = PorConsensusConfig::from_globals();

    assert!(config.max_local_puzzle_ms >= 1_000);
}

#[test]
fn test_11_from_globals_soft_cap_is_no_more_than_one_hour_in_ms() {
    let config = PorConsensusConfig::from_globals();

    assert!(config.max_local_puzzle_ms <= 3_600_000);
}

#[test]
fn test_12_validate_rejects_zero_target_block_time() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(0),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_13_validate_rejects_zero_max_local_puzzle_ms() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 0,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("max_local_puzzle_ms is 0"));
    Ok(())
}

#[test]
fn test_14_validate_rejects_target_block_time_above_slot() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_plus_one()?),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_15_validate_rejects_factorization_puzzle_kind() -> TestResult {
    let message = validation_message(invalid_kind_config().validate())?;

    assert!(message.contains("puzzle_kind"));
    assert!(message.contains("FactorizationDelayDev"));
    assert!(message.contains("FibonacciDelayDev"));
    Ok(())
}

#[test]
fn test_16_validate_error_order_prefers_zero_target_before_zero_soft_cap() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(0),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 0,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    assert!(!message.contains("max_local_puzzle_ms is 0"));
    assert!(!message.contains("puzzle_kind"));
    Ok(())
}

#[test]
fn test_17_validate_error_order_prefers_zero_soft_cap_before_wrong_kind() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 0,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("max_local_puzzle_ms is 0"));
    assert!(!message.contains("puzzle_kind"));
    Ok(())
}

#[test]
fn test_18_validate_error_order_prefers_slot_exceeded_before_wrong_kind() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_plus_one()?),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    assert!(!message.contains("does not match mandatory network kind"));
    Ok(())
}

#[test]
fn test_19_validate_accepts_one_second_target_with_nonzero_soft_cap() {
    let config = valid_config_with_secs(1);

    assert!(config.validate().is_ok());
}

#[test]
fn test_20_validate_accepts_target_equal_to_slot_boundary() {
    let config = valid_config_with_secs(slot_secs());

    assert!(config.validate().is_ok());
}

#[test]
fn test_21_validate_accepts_large_nonzero_soft_cap_when_other_invariants_hold() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: u64::MAX,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_22_validate_accepts_soft_cap_one_ms_when_other_invariants_hold() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_23_validate_uses_as_secs_so_subsecond_target_is_invalid() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_millis(999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_24_validate_accepts_one_second_plus_subsecond_target() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_millis(1_999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_25_validate_rejects_slot_plus_subsecond_target_because_as_secs_exceeds_slot() -> TestResult
{
    let millis = slot_plus_one()?
        .checked_mul(1_000)
        .ok_or_else(|| test_error("millisecond calculation overflowed in test"))?;
    let config = PorConsensusConfig {
        target_block_time: Duration::from_millis(millis),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_26_clone_preserves_all_config_fields() {
    let config = PorConsensusConfig::from_globals();
    let cloned = config.clone();

    assert_eq!(cloned.target_block_time, config.target_block_time);
    assert_eq!(cloned.puzzle_kind, config.puzzle_kind);
    assert_eq!(cloned.max_local_puzzle_ms, config.max_local_puzzle_ms);
}

#[test]
fn test_27_debug_config_contains_struct_name_and_fields() {
    let config = PorConsensusConfig::from_globals();
    let debug_text = format!("{config:?}");

    assert!(debug_text.contains("PorConsensusConfig"));
    assert!(debug_text.contains("target_block_time"));
    assert!(debug_text.contains("puzzle_kind"));
    assert!(debug_text.contains("max_local_puzzle_ms"));
}

#[test]
fn test_28_debug_puzzle_kind_fibonacci_contains_variant_name() {
    let debug_text = format!("{:?}", PorPuzzleKind::FibonacciDelayDev);

    assert_eq!(debug_text, "FibonacciDelayDev");
}

#[test]
fn test_29_debug_puzzle_kind_factorization_contains_variant_name() {
    let debug_text = format!("{:?}", PorPuzzleKind::FactorizationDelayDev);

    assert_eq!(debug_text, "FactorizationDelayDev");
}

#[test]
fn test_30_puzzle_kind_copy_clone_equality_for_fibonacci() {
    let first = PorPuzzleKind::FibonacciDelayDev;
    let copied = first;
    let cloned = first.clone();

    assert_eq!(first, copied);
    assert_eq!(first, cloned);
}

#[test]
fn test_31_puzzle_kind_copy_clone_equality_for_factorization() {
    let first = PorPuzzleKind::FactorizationDelayDev;
    let copied = first;
    let cloned = first.clone();

    assert_eq!(first, copied);
    assert_eq!(first, cloned);
}

#[test]
fn test_32_puzzle_kind_variants_are_not_equal() {
    assert_ne!(
        PorPuzzleKind::FibonacciDelayDev,
        PorPuzzleKind::FactorizationDelayDev
    );
}

#[test]
fn test_33_vector_valid_targets_from_one_to_slot_all_validate() -> TestResult {
    let cases = [1_u64, expected_puzzle_secs(), slot_secs()];

    for secs in cases {
        let config = valid_config_with_secs(secs);
        config.validate()?;
    }

    Ok(())
}

#[test]
fn test_34_vector_invalid_targets_zero_and_above_slot_fail() -> TestResult {
    let cases = [0_u64, slot_plus_one()?];

    for secs in cases {
        let config = valid_config_with_secs(secs);
        assert!(config.validate().is_err());
    }

    Ok(())
}

#[test]
fn test_35_vector_valid_soft_caps_with_mandatory_kind_validate() -> TestResult {
    let cases = [1_u64, 999_u64, 1_000_u64, expected_soft_ms(), u64::MAX];

    for soft_cap in cases {
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: soft_cap,
        };
        config.validate()?;
    }

    Ok(())
}

#[test]
fn test_36_vector_wrong_kind_rejected_for_multiple_valid_timing_values() -> TestResult {
    let cases = [1_u64, expected_puzzle_secs(), slot_secs()];

    for secs in cases {
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(secs),
            puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
            max_local_puzzle_ms: 1,
        };
        let message = validation_message(config.validate())?;
        assert!(message.contains("does not match mandatory network kind"));
    }

    Ok(())
}

#[test]
fn test_37_property_from_globals_soft_cap_is_target_seconds_times_1000_for_current_bounds()
-> TestResult {
    let config = PorConsensusConfig::from_globals();
    let target_ms = config
        .target_block_time
        .as_secs()
        .checked_mul(1_000)
        .ok_or_else(|| test_error("target ms overflowed in test"))?;

    assert_eq!(
        config.max_local_puzzle_ms,
        target_ms.clamp(1_000, 3_600_000)
    );
    Ok(())
}

#[test]
fn test_38_property_default_remains_stable_across_repeated_construction() {
    let first = PorConsensusConfig::default();

    for _ in 0_u64..128_u64 {
        let next = PorConsensusConfig::default();
        assert_eq!(next.target_block_time, first.target_block_time);
        assert_eq!(next.puzzle_kind, first.puzzle_kind);
        assert_eq!(next.max_local_puzzle_ms, first.max_local_puzzle_ms);
    }
}

#[test]
fn test_39_load_repeated_from_globals_validation_does_not_mutate_config() -> TestResult {
    let config = PorConsensusConfig::from_globals();
    let target = config.target_block_time;
    let kind = config.puzzle_kind;
    let soft_cap = config.max_local_puzzle_ms;

    for _ in 0_u64..1_000_u64 {
        config.validate()?;
        assert_eq!(config.target_block_time, target);
        assert_eq!(config.puzzle_kind, kind);
        assert_eq!(config.max_local_puzzle_ms, soft_cap);
    }

    Ok(())
}

#[test]
fn test_40_adversarial_config_matrix_only_mandatory_nonzero_within_slot_accepts() -> TestResult {
    let target_cases = [
        Duration::from_secs(0),
        Duration::from_secs(1),
        Duration::from_secs(slot_secs()),
        Duration::from_secs(slot_plus_one()?),
    ];
    let kind_cases = [
        PorPuzzleKind::FibonacciDelayDev,
        PorPuzzleKind::FactorizationDelayDev,
    ];
    let soft_cap_cases = [0_u64, 1_u64, expected_soft_ms()];

    for target in target_cases {
        for kind in kind_cases {
            for soft_cap in soft_cap_cases {
                let config = PorConsensusConfig {
                    target_block_time: target,
                    puzzle_kind: kind,
                    max_local_puzzle_ms: soft_cap,
                };

                let should_accept = target.as_secs() > 0
                    && target.as_secs() <= slot_secs()
                    && kind == PorPuzzleKind::FibonacciDelayDev
                    && soft_cap > 0;

                assert_eq!(config.validate().is_ok(), should_accept);
            }
        }
    }

    Ok(())
}

#[test]
fn test_41_cloned_from_globals_config_still_validates() {
    let config = PorConsensusConfig::from_globals();
    let cloned = config.clone();

    assert!(cloned.validate().is_ok());
}

#[test]
fn test_42_manual_config_at_slot_with_expected_soft_cap_validates() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_secs()),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: expected_soft_ms(),
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_43_target_equal_to_slot_plus_subsecond_nanos_validates_because_as_secs_is_slot() {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(slot_secs(), 999_999_999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_44_one_nanosecond_target_rejects_because_as_secs_is_zero() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_nanos(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_45_just_under_one_second_target_rejects_because_as_secs_is_zero() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_micros(999_999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_46_exactly_one_second_from_millis_validates() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_millis(1_000),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_47_slot_plus_one_second_target_rejects() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_plus_one()?),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_48_slot_plus_one_second_with_extra_nanos_still_rejects() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(slot_plus_one()?, 1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_49_u64_max_soft_cap_validates_when_consensus_fields_are_valid() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_secs()),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: u64::MAX,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_50_wrong_kind_rejects_even_with_u64_max_soft_cap() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: u64::MAX,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("does not match mandatory network kind"));
    Ok(())
}

#[test]
fn test_51_zero_soft_cap_is_reported_before_slot_exceeded() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_plus_one()?),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 0,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("max_local_puzzle_ms is 0"));
    assert!(!message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_52_zero_target_is_reported_before_wrong_kind_with_large_soft_cap() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(0),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: u64::MAX,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    assert!(!message.contains("puzzle_kind"));
    Ok(())
}

#[test]
fn test_53_from_globals_has_no_subsecond_component() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(config.target_block_time.subsec_nanos(), 0);
}

#[test]
fn test_54_default_debug_contains_mandatory_puzzle_variant() {
    let config = PorConsensusConfig::default();
    let debug_text = format!("{config:?}");

    assert!(debug_text.contains("FibonacciDelayDev"));
}

#[test]
fn test_55_validation_error_display_contains_validation_error_prefix() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(0),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let error = config
        .validate()
        .err()
        .ok_or_else(|| test_error("expected validation error"))?;
    let display_text = format!("{error}");

    assert!(display_text.contains("Validation error"));
    assert!(display_text.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_56_validation_error_debug_contains_validation_variant_name() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(0),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let error = config
        .validate()
        .err()
        .ok_or_else(|| test_error("expected validation error"))?;
    let debug_text = format!("{error:?}");

    assert!(debug_text.contains("ValidationError"));
    assert!(debug_text.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_57_soft_cap_below_target_milliseconds_is_allowed_because_it_is_monitoring_only() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_secs()),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_58_soft_cap_above_one_hour_is_allowed_for_manual_config() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 3_600_001,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_59_validate_does_not_normalize_valid_config_fields() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 777,
    };

    config.validate()?;

    assert_eq!(config.target_block_time, Duration::from_secs(1));
    assert_eq!(config.puzzle_kind, PorPuzzleKind::FibonacciDelayDev);
    assert_eq!(config.max_local_puzzle_ms, 777);
    Ok(())
}

#[test]
fn test_60_validate_does_not_mutate_invalid_config_fields() {
    let config = invalid_kind_config();

    assert!(config.validate().is_err());
    assert_eq!(config.target_block_time, Duration::from_secs(1));
    assert_eq!(config.puzzle_kind, PorPuzzleKind::FactorizationDelayDev);
    assert_eq!(config.max_local_puzzle_ms, 1);
}

#[test]
fn test_61_vector_sampled_valid_targets_inside_slot_validate() -> TestResult {
    let midpoint = slot_secs().div_euclid(2).max(1);
    let cases = [1_u64, midpoint, expected_puzzle_secs(), slot_secs()];

    for secs in cases {
        let config = valid_config_with_secs(secs);
        config.validate()?;
    }

    Ok(())
}

#[test]
fn test_62_vector_sampled_invalid_targets_above_slot_reject() -> TestResult {
    let slot_plus_two = slot_plus_one()?
        .checked_add(1)
        .ok_or_else(|| test_error("slot plus two overflowed in test"))?;
    let cases = [slot_plus_one()?, slot_plus_two, u64::MAX];

    for secs in cases {
        let config = valid_config_with_secs(secs);
        assert!(config.validate().is_err());
    }

    Ok(())
}

#[test]
fn test_63_u64_max_duration_target_rejects_as_above_slot() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(u64::MAX),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_64_cloned_config_can_be_modified_without_changing_original() {
    let original = PorConsensusConfig::from_globals();
    let mut altered = original.clone();
    altered.max_local_puzzle_ms = altered.max_local_puzzle_ms.saturating_add(999);

    assert_ne!(altered.max_local_puzzle_ms, original.max_local_puzzle_ms);
    assert_eq!(altered.target_block_time, original.target_block_time);
    assert_eq!(altered.puzzle_kind, original.puzzle_kind);
}

#[test]
fn test_65_puzzle_kind_vector_contains_exactly_two_known_variants() {
    let variants = [
        PorPuzzleKind::FibonacciDelayDev,
        PorPuzzleKind::FactorizationDelayDev,
    ];

    assert_eq!(variants.len(), 2);
    assert!(variants.contains(&PorPuzzleKind::FibonacciDelayDev));
    assert!(variants.contains(&PorPuzzleKind::FactorizationDelayDev));
}

#[test]
fn test_66_wrong_kind_error_message_names_actual_and_expected_kind() -> TestResult {
    let message = validation_message(invalid_kind_config().validate())?;

    assert!(message.contains("FactorizationDelayDev"));
    assert!(message.contains("FibonacciDelayDev"));
    Ok(())
}

#[test]
fn test_67_from_globals_soft_cap_matches_target_duration_millis_after_clamp() {
    let config = PorConsensusConfig::from_globals();
    let target_ms = config.target_block_time.as_millis();

    assert_eq!(
        u128::from(config.max_local_puzzle_ms),
        target_ms.clamp(1_000, 3_600_000)
    );
}

#[test]
fn test_68_from_globals_target_seconds_match_duration_object() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(
        Duration::from_secs(config.target_block_time.as_secs()),
        config.target_block_time
    );
}

#[test]
fn test_69_manual_duration_with_nanos_keeps_nanos_after_successful_validate() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(1, 123),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    config.validate()?;

    assert_eq!(config.target_block_time.subsec_nanos(), 123);
    Ok(())
}

#[test]
fn test_70_default_config_has_same_fields_after_validate() -> TestResult {
    let config = PorConsensusConfig::default();
    let target = config.target_block_time;
    let kind = config.puzzle_kind;
    let soft_cap = config.max_local_puzzle_ms;

    config.validate()?;

    assert_eq!(config.target_block_time, target);
    assert_eq!(config.puzzle_kind, kind);
    assert_eq!(config.max_local_puzzle_ms, soft_cap);
    Ok(())
}

#[test]
fn test_71_manual_soft_cap_not_equal_to_expected_soft_ms_can_still_validate() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: expected_soft_ms().saturating_add(123),
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_72_subsecond_target_with_zero_soft_cap_reports_zero_target_first() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_millis(999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 0,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    assert!(!message.contains("max_local_puzzle_ms is 0"));
    Ok(())
}

#[test]
fn test_73_subsecond_target_with_wrong_kind_reports_zero_target_first() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_millis(999),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    assert!(!message.contains("puzzle_kind"));
    Ok(())
}

#[test]
fn test_74_invalid_config_matrix_never_panics_and_always_returns_validation_error() -> TestResult {
    let targets = [
        Duration::from_secs(0),
        Duration::from_millis(999),
        Duration::from_secs(slot_plus_one()?),
    ];
    let kinds = [
        PorPuzzleKind::FibonacciDelayDev,
        PorPuzzleKind::FactorizationDelayDev,
    ];
    let soft_caps = [0_u64, 1_u64];

    for target in targets {
        for kind in kinds {
            for soft_cap in soft_caps {
                let config = PorConsensusConfig {
                    target_block_time: target,
                    puzzle_kind: kind,
                    max_local_puzzle_ms: soft_cap,
                };

                if config.validate().is_err() {
                    continue;
                }

                assert!(
                    target.as_secs() > 0
                        && target.as_secs() <= slot_secs()
                        && kind == PorPuzzleKind::FibonacciDelayDev
                        && soft_cap > 0
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_75_repeated_invalid_validation_is_stable() -> TestResult {
    let config = invalid_kind_config();
    let first = validation_message(config.validate())?;

    for _ in 0_u64..128_u64 {
        let next = validation_message(config.validate())?;
        assert_eq!(next, first);
    }

    Ok(())
}

#[test]
fn test_76_vector_kind_validation_accepts_only_mandatory_kind_for_same_timing() {
    let valid = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };
    let invalid = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(valid.validate().is_ok());
    assert!(invalid.validate().is_err());
}

#[test]
fn test_77_fuzz_style_generated_targets_match_validation_predicate() {
    let mut state = 17_u64;

    for _ in 0_u64..256_u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let bounded = state.rem_euclid(slot_secs().saturating_add(3));
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(bounded),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 1,
        };
        let should_validate = bounded > 0 && bounded <= slot_secs();

        assert_eq!(config.validate().is_ok(), should_validate);
    }
}

#[test]
fn test_78_fuzz_style_generated_soft_caps_match_nonzero_predicate() {
    let mut state = 29_u64;

    for _ in 0_u64..256_u64 {
        state = state
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);
        let soft_cap = state.rem_euclid(5);
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: soft_cap,
        };
        let should_validate = soft_cap > 0;

        assert_eq!(config.validate().is_ok(), should_validate);
    }
}

#[test]
fn test_79_load_repeated_wrong_kind_validation_keeps_returning_error() {
    let config = invalid_kind_config();

    for _ in 0_u64..1_000_u64 {
        assert!(config.validate().is_err());
    }
}

#[test]
fn test_80_adversarial_large_matrix_validates_exactly_expected_cases() -> TestResult {
    let targets = [
        Duration::from_secs(0),
        Duration::from_nanos(1),
        Duration::from_secs(1),
        Duration::new(slot_secs(), 999_999_999),
        Duration::from_secs(slot_plus_one()?),
        Duration::from_secs(u64::MAX),
    ];
    let kinds = [
        PorPuzzleKind::FibonacciDelayDev,
        PorPuzzleKind::FactorizationDelayDev,
    ];
    let soft_caps = [0_u64, 1_u64, expected_soft_ms(), u64::MAX];

    for target in targets {
        for kind in kinds {
            for soft_cap in soft_caps {
                let config = PorConsensusConfig {
                    target_block_time: target,
                    puzzle_kind: kind,
                    max_local_puzzle_ms: soft_cap,
                };
                let should_accept = target.as_secs() > 0
                    && target.as_secs() <= slot_secs()
                    && kind == PorPuzzleKind::FibonacciDelayDev
                    && soft_cap > 0;

                assert_eq!(config.validate().is_ok(), should_accept);
            }
        }
    }

    Ok(())
}

#[test]
fn test_81_edge_duration_at_slot_with_max_nanos_still_validates() {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(slot_secs(), 999_999_999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_82_edge_duration_one_second_with_max_nanos_validates() {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(1, 999_999_999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_83_edge_duration_zero_seconds_with_max_nanos_rejects() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(0, 999_999_999),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("target_block_time is 0s"));
    Ok(())
}

#[test]
fn test_84_edge_duration_slot_plus_one_with_zero_nanos_rejects() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::new(slot_plus_one()?, 0),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("exceeds block slot"));
    Ok(())
}

#[test]
fn test_85_vector_target_duration_boundaries_match_expected_validity() -> TestResult {
    let cases = [
        (Duration::from_secs(0), false),
        (Duration::from_nanos(1), false),
        (Duration::from_millis(999), false),
        (Duration::from_secs(1), true),
        (Duration::new(1, 1), true),
        (Duration::from_secs(slot_secs()), true),
        (Duration::new(slot_secs(), 999_999_999), true),
        (Duration::from_secs(slot_plus_one()?), false),
    ];

    for (target_block_time, should_validate) in cases {
        let config = PorConsensusConfig {
            target_block_time,
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 1,
        };

        assert_eq!(config.validate().is_ok(), should_validate);
    }

    Ok(())
}

#[test]
fn test_86_vector_soft_cap_boundaries_match_expected_validity() {
    let cases = [
        (0_u64, false),
        (1_u64, true),
        (999_u64, true),
        (1_000_u64, true),
        (3_600_000_u64, true),
        (3_600_001_u64, true),
        (u64::MAX, true),
    ];

    for (max_local_puzzle_ms, should_validate) in cases {
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms,
        };

        assert_eq!(config.validate().is_ok(), should_validate);
    }
}

#[test]
fn test_87_vector_puzzle_kind_validation_matrix() {
    let cases = [
        (PorPuzzleKind::FibonacciDelayDev, true),
        (PorPuzzleKind::FactorizationDelayDev, false),
    ];

    for (puzzle_kind, should_validate) in cases {
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind,
            max_local_puzzle_ms: 1,
        };

        assert_eq!(config.validate().is_ok(), should_validate);
    }
}

#[test]
fn test_88_edge_error_message_for_above_slot_includes_actual_and_slot_seconds() -> TestResult {
    let above_slot = slot_plus_one()?;
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(above_slot),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains(&format!("target_block_time={above_slot}s")));
    assert!(message.contains(&format!("block slot={}s", slot_secs())));
    Ok(())
}

#[test]
fn test_89_edge_error_message_for_wrong_kind_includes_both_debug_variants() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("FactorizationDelayDev"));
    assert!(message.contains("FibonacciDelayDev"));
    Ok(())
}

#[test]
fn test_90_edge_error_message_for_zero_soft_cap_mentions_mandatory_puzzle_mode() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 0,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("max_local_puzzle_ms is 0"));
    assert!(message.contains("mandatory puzzle mode"));
    Ok(())
}

#[test]
fn test_91_vector_from_globals_matches_current_global_constants() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(
        config.target_block_time.as_secs(),
        GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS
            .max(1)
            .min(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1))
    );
    assert_eq!(config.max_local_puzzle_ms, expected_soft_ms());
    assert_eq!(config.puzzle_kind, PorPuzzleKind::FibonacciDelayDev);
}

#[test]
fn test_92_edge_from_globals_target_ms_matches_duration_as_millis() {
    let config = PorConsensusConfig::from_globals();

    assert_eq!(
        u128::from(config.max_local_puzzle_ms),
        config.target_block_time.as_millis().clamp(1_000, 3_600_000)
    );
}

#[test]
fn test_93_edge_validate_accepts_target_slot_even_when_soft_cap_is_one() {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_secs()),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_94_edge_validate_rejects_wrong_kind_at_slot_boundary() -> TestResult {
    let config = PorConsensusConfig {
        target_block_time: Duration::from_secs(slot_secs()),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1,
    };

    let message = validation_message(config.validate())?;

    assert!(message.contains("does not match mandatory network kind"));
    Ok(())
}

#[test]
fn test_95_vector_valid_configs_with_different_soft_caps_all_preserve_fields() -> TestResult {
    let soft_caps = [1_u64, 500_u64, 1_000_u64, expected_soft_ms(), u64::MAX];

    for max_local_puzzle_ms in soft_caps {
        let config = PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms,
        };

        config.validate()?;

        assert_eq!(config.target_block_time, Duration::from_secs(1));
        assert_eq!(config.puzzle_kind, PorPuzzleKind::FibonacciDelayDev);
        assert_eq!(config.max_local_puzzle_ms, max_local_puzzle_ms);
    }

    Ok(())
}

#[test]
fn test_96_vector_invalid_zero_target_cases_all_return_same_error_family() -> TestResult {
    let targets = [
        Duration::from_secs(0),
        Duration::from_nanos(1),
        Duration::from_micros(999_999),
        Duration::from_millis(999),
    ];

    for target_block_time in targets {
        let config = PorConsensusConfig {
            target_block_time,
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 1,
        };

        let message = validation_message(config.validate())?;
        assert!(message.contains("target_block_time is 0s"));
    }

    Ok(())
}

#[test]
fn test_97_vector_invalid_above_slot_cases_all_return_slot_error() -> TestResult {
    let slot_plus_two = slot_plus_one()?
        .checked_add(1)
        .ok_or_else(|| test_error("slot plus two overflowed in test"))?;
    let targets = [
        Duration::from_secs(slot_plus_one()?),
        Duration::new(slot_plus_one()?, 999_999_999),
        Duration::from_secs(slot_plus_two),
        Duration::from_secs(u64::MAX),
    ];

    for target_block_time in targets {
        let config = PorConsensusConfig {
            target_block_time,
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 1,
        };

        let message = validation_message(config.validate())?;
        assert!(message.contains("exceeds block slot"));
    }

    Ok(())
}

#[test]
fn test_98_edge_default_and_from_globals_validate_repeatedly_with_same_debug_text() -> TestResult {
    let default_config = PorConsensusConfig::default();
    let globals_config = PorConsensusConfig::from_globals();
    let default_debug = format!("{default_config:?}");
    let globals_debug = format!("{globals_config:?}");

    for _ in 0_u64..256_u64 {
        default_config.validate()?;
        globals_config.validate()?;
        assert_eq!(format!("{default_config:?}"), default_debug);
        assert_eq!(format!("{globals_config:?}"), globals_debug);
    }

    Ok(())
}

#[test]
fn test_99_adversarial_all_invalid_reasons_are_reachable() -> TestResult {
    let zero_target_message = validation_message(
        PorConsensusConfig {
            target_block_time: Duration::from_secs(0),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 1,
        }
        .validate(),
    )?;
    let zero_soft_cap_message = validation_message(
        PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 0,
        }
        .validate(),
    )?;
    let above_slot_message = validation_message(
        PorConsensusConfig {
            target_block_time: Duration::from_secs(slot_plus_one()?),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: 1,
        }
        .validate(),
    )?;
    let wrong_kind_message = validation_message(
        PorConsensusConfig {
            target_block_time: Duration::from_secs(1),
            puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
            max_local_puzzle_ms: 1,
        }
        .validate(),
    )?;

    assert!(zero_target_message.contains("target_block_time is 0s"));
    assert!(zero_soft_cap_message.contains("max_local_puzzle_ms is 0"));
    assert!(above_slot_message.contains("exceeds block slot"));
    assert!(wrong_kind_message.contains("puzzle_kind"));
    Ok(())
}

#[test]
fn test_100_vector_full_consensus_config_acceptance_table() -> TestResult {
    let cases = [
        (
            Duration::from_secs(0),
            PorPuzzleKind::FibonacciDelayDev,
            1_u64,
            false,
        ),
        (
            Duration::from_secs(1),
            PorPuzzleKind::FibonacciDelayDev,
            0_u64,
            false,
        ),
        (
            Duration::from_secs(slot_plus_one()?),
            PorPuzzleKind::FibonacciDelayDev,
            1_u64,
            false,
        ),
        (
            Duration::from_secs(1),
            PorPuzzleKind::FactorizationDelayDev,
            1_u64,
            false,
        ),
        (
            Duration::from_secs(1),
            PorPuzzleKind::FibonacciDelayDev,
            1_u64,
            true,
        ),
        (
            Duration::from_secs(slot_secs()),
            PorPuzzleKind::FibonacciDelayDev,
            expected_soft_ms(),
            true,
        ),
        (
            Duration::new(slot_secs(), 999_999_999),
            PorPuzzleKind::FibonacciDelayDev,
            u64::MAX,
            true,
        ),
    ];

    for (target_block_time, puzzle_kind, max_local_puzzle_ms, should_validate) in cases {
        let config = PorConsensusConfig {
            target_block_time,
            puzzle_kind,
            max_local_puzzle_ms,
        };

        assert_eq!(config.validate().is_ok(), should_validate);
    }

    Ok(())
}
