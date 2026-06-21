use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::time::Duration;

const MAX_SOFT_PUZZLE_MS_TEST: u64 = 60 * 60 * 1_000;

fn slot_secs() -> u64 {
    GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1)
}

fn raw_puzzle_secs() -> u64 {
    GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS.max(1)
}

fn expected_effective_puzzle_secs() -> u64 {
    raw_puzzle_secs().min(slot_secs())
}

fn expected_soft_ms() -> u64 {
    expected_effective_puzzle_secs()
        .saturating_mul(1_000)
        .clamp(1_000, MAX_SOFT_PUZZLE_MS_TEST)
}

fn mandatory_config(target_secs: u64, max_local_puzzle_ms: u64) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(target_secs),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms,
    }
}

fn factorization_config(target_secs: u64, max_local_puzzle_ms: u64) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(target_secs),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms,
    }
}

fn valid_target_from_seed(seed: u64) -> u64 {
    let slot = slot_secs();
    seed.checked_rem(slot).unwrap_or(0).saturating_add(1)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_from_globals_returns_valid_config(
        _probe in any::<u8>(),
    ) {
        let cfg = PorConsensusConfig::from_globals();

        prop_assert!(
            cfg.validate().is_ok(),
            "from_globals must produce a valid mandatory POR config"
        );
    }

    // 02/25
    #[test]
    fn test_002_default_matches_from_globals(
        _probe in any::<u8>(),
    ) {
        let default_cfg = PorConsensusConfig::default();
        let global_cfg = PorConsensusConfig::from_globals();

        prop_assert_eq!(
            default_cfg.target_block_time,
            global_cfg.target_block_time,
            "Default target_block_time must match from_globals"
        );

        prop_assert_eq!(
            default_cfg.puzzle_kind,
            global_cfg.puzzle_kind,
            "Default puzzle_kind must match from_globals"
        );

        prop_assert_eq!(
            default_cfg.max_local_puzzle_ms,
            global_cfg.max_local_puzzle_ms,
            "Default max_local_puzzle_ms must match from_globals"
        );
    }

    // 03/25
    #[test]
    fn test_003_from_globals_uses_mandatory_fibonacci_puzzle_kind(
        _probe in any::<u8>(),
    ) {
        let cfg = PorConsensusConfig::from_globals();

        prop_assert_eq!(
            cfg.puzzle_kind,
            PorPuzzleKind::FibonacciDelayDev,
            "production config must use mandatory FibonacciDelayDev puzzle kind"
        );

        prop_assert_ne!(
            cfg.puzzle_kind,
            PorPuzzleKind::FactorizationDelayDev,
            "production config must not use FactorizationDelayDev without protocol upgrade"
        );
    }

    // 04/25
    #[test]
    fn test_004_from_globals_target_seconds_equal_clamped_global_interval(
        _probe in any::<u8>(),
    ) {
        let cfg = PorConsensusConfig::from_globals();

        prop_assert_eq!(
            cfg.target_block_time.as_secs(),
            expected_effective_puzzle_secs(),
            "from_globals target seconds must clamp puzzle interval to the block slot"
        );

        prop_assert!(
            cfg.target_block_time.as_secs() >= 1,
            "effective puzzle target must never be below one second"
        );

        prop_assert!(
            cfg.target_block_time.as_secs() <= slot_secs(),
            "effective puzzle target must never exceed block slot"
        );
    }

    // 05/25
    #[test]
    fn test_005_from_globals_soft_cap_matches_effective_target_ms_with_observability_bound(
        _probe in any::<u8>(),
    ) {
        let cfg = PorConsensusConfig::from_globals();

        prop_assert_eq!(
            cfg.max_local_puzzle_ms,
            expected_soft_ms(),
            "from_globals soft cap must be target seconds in ms clamped to observability bound"
        );

        prop_assert!(
            cfg.max_local_puzzle_ms >= 1_000,
            "soft puzzle cap must be at least one second in mandatory puzzle mode"
        );

        prop_assert!(
            cfg.max_local_puzzle_ms <= MAX_SOFT_PUZZLE_MS_TEST,
            "soft puzzle cap must be bounded to one hour for observability safety"
        );
    }

    // 06/25
    #[test]
    fn test_006_validate_accepts_mandatory_kind_with_positive_target_inside_slot(
        target_seed in any::<u64>(),
        max_ms in 1u64..=u64::MAX,
    ) {
        let target_secs = valid_target_from_seed(target_seed);
        let cfg = mandatory_config(target_secs, max_ms);

        prop_assert!(
            cfg.validate().is_ok(),
            "mandatory Fibonacci config with target inside slot and positive soft cap must validate"
        );
    }

    // 07/25
    #[test]
    fn test_007_validate_accepts_target_equal_block_slot_boundary(
        max_ms in 1u64..=u64::MAX,
    ) {
        let cfg = mandatory_config(slot_secs(), max_ms);

        prop_assert!(
            cfg.validate().is_ok(),
            "target_block_time exactly equal to block slot must be accepted"
        );
    }

    // 08/25
    #[test]
    fn test_008_validate_accepts_one_second_target_boundary(
        max_ms in 1u64..=u64::MAX,
    ) {
        let cfg = mandatory_config(1, max_ms);

        prop_assert!(
            cfg.validate().is_ok(),
            "one-second target is the minimum valid mandatory puzzle delay"
        );
    }

    // 09/25
    #[test]
    fn test_009_validate_rejects_zero_target_time(
        max_ms in 1u64..=u64::MAX,
    ) {
        let cfg = mandatory_config(0, max_ms);

        prop_assert!(
            cfg.validate().is_err(),
            "zero-second target_block_time must be rejected"
        );
    }

    // 10/25
    #[test]
    fn test_010_validate_rejects_zero_soft_cap(
        target_seed in any::<u64>(),
    ) {
        let target_secs = valid_target_from_seed(target_seed);
        let cfg = mandatory_config(target_secs, 0);

        prop_assert!(
            cfg.validate().is_err(),
            "zero max_local_puzzle_ms must be rejected in mandatory puzzle mode"
        );
    }

    // 11/25
    #[test]
    fn test_011_validate_rejects_target_above_block_slot(
        extra in 1u64..=1_000_000u64,
        max_ms in 1u64..=u64::MAX,
    ) {
        let target_secs = slot_secs().saturating_add(extra);

        prop_assume!(target_secs > slot_secs());

        let cfg = mandatory_config(target_secs, max_ms);

        prop_assert!(
            cfg.validate().is_err(),
            "target_block_time above block slot must be rejected for liveness"
        );
    }

    // 12/25
    #[test]
    fn test_012_validate_rejects_factorization_kind_even_when_timing_is_valid(
        target_seed in any::<u64>(),
        max_ms in 1u64..=u64::MAX,
    ) {
        let target_secs = valid_target_from_seed(target_seed);
        let cfg = factorization_config(target_secs, max_ms);

        prop_assert!(
            cfg.validate().is_err(),
            "FactorizationDelayDev must be rejected because network kind is mandatory FibonacciDelayDev"
        );
    }

    // 13/25
    #[test]
    fn test_013_validate_rejects_factorization_at_all_valid_boundaries(
        boundary_case in 0usize..2usize,
        max_ms in 1u64..=u64::MAX,
    ) {
        let target_secs = if boundary_case == 0 {
            1
        } else {
            slot_secs()
        };

        let cfg = factorization_config(target_secs, max_ms);

        prop_assert!(
            cfg.validate().is_err(),
            "wrong puzzle kind must be rejected even at valid timing boundaries"
        );
    }

    // 14/25
    #[test]
    fn test_014_mandatory_validate_result_matches_expected_predicate_for_random_shapes(
        target_secs in any::<u64>(),
        max_ms in any::<u64>(),
    ) {
        let cfg = mandatory_config(target_secs, max_ms);

        let expected_ok =
            target_secs > 0
                && target_secs <= slot_secs()
                && max_ms > 0;

        prop_assert_eq!(
            cfg.validate().is_ok(),
            expected_ok,
            "mandatory Fibonacci validate result must match public invariant predicate"
        );
    }

    // 15/25
    #[test]
    fn test_015_factorization_validate_is_never_accepted_for_random_shapes(
        target_secs in any::<u64>(),
        max_ms in any::<u64>(),
    ) {
        let cfg = factorization_config(target_secs, max_ms);

        prop_assert!(
            cfg.validate().is_err(),
            "FactorizationDelayDev must never validate under mandatory Fibonacci network config"
        );
    }

    // 16/25
    #[test]
    fn test_016_validate_never_panics_for_arbitrary_manual_configs(
        target_secs in any::<u64>(),
        max_ms in any::<u64>(),
        kind_choice in 0usize..2usize,
    ) {
        let puzzle_kind = if kind_choice == 0 {
            PorPuzzleKind::FibonacciDelayDev
        } else {
            PorPuzzleKind::FactorizationDelayDev
        };

        let cfg = PorConsensusConfig {
            target_block_time: Duration::from_secs(target_secs),
            puzzle_kind,
            max_local_puzzle_ms: max_ms,
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cfg.validate()
        }));

        prop_assert!(
            result.is_ok(),
            "PorConsensusConfig::validate must return Ok/Err, not panic, for arbitrary public config fields"
        );
    }

    // 17/25
    #[test]
    fn test_017_clone_preserves_all_config_fields(
        target_seed in any::<u64>(),
        max_ms in 1u64..=u64::MAX,
    ) {
        let cfg = mandatory_config(valid_target_from_seed(target_seed), max_ms);
        let cloned = cfg.clone();

        prop_assert_eq!(
            cloned.target_block_time,
            cfg.target_block_time,
            "clone must preserve target_block_time"
        );

        prop_assert_eq!(
            cloned.puzzle_kind,
            cfg.puzzle_kind,
            "clone must preserve puzzle_kind"
        );

        prop_assert_eq!(
            cloned.max_local_puzzle_ms,
            cfg.max_local_puzzle_ms,
            "clone must preserve max_local_puzzle_ms"
        );

        prop_assert_eq!(
            cloned.validate().is_ok(),
            cfg.validate().is_ok(),
            "clone must preserve validation result"
        );
    }

    // 18/25
    #[test]
    fn test_018_default_clone_remains_valid_and_field_equal(
        _probe in any::<u8>(),
    ) {
        let cfg = PorConsensusConfig::default();
        let cloned = cfg.clone();

        prop_assert!(
            cloned.validate().is_ok(),
            "cloned default config must remain valid"
        );

        prop_assert_eq!(
            cloned.target_block_time,
            cfg.target_block_time,
            "cloned default must preserve target"
        );

        prop_assert_eq!(
            cloned.puzzle_kind,
            cfg.puzzle_kind,
            "cloned default must preserve puzzle kind"
        );

        prop_assert_eq!(
            cloned.max_local_puzzle_ms,
            cfg.max_local_puzzle_ms,
            "cloned default must preserve soft cap"
        );
    }

    // 19/25
    #[test]
    fn test_019_puzzle_kind_variants_are_distinct(
        _probe in any::<u8>(),
    ) {
        prop_assert_ne!(
            PorPuzzleKind::FibonacciDelayDev,
            PorPuzzleKind::FactorizationDelayDev,
            "puzzle kind variants must remain distinct consensus states"
        );
    }

    // 20/25
    #[test]
    fn test_020_puzzle_kind_copy_preserves_value(
        kind_choice in 0usize..2usize,
    ) {
        let kind = if kind_choice == 0 {
            PorPuzzleKind::FibonacciDelayDev
        } else {
            PorPuzzleKind::FactorizationDelayDev
        };

        let copied = kind;

        prop_assert_eq!(
            copied,
            kind,
            "PorPuzzleKind Copy semantics must preserve exact variant"
        );
    }

    // 21/25
    #[test]
    fn test_021_debug_strings_identify_puzzle_kind_variants(
        _probe in any::<u8>(),
    ) {
        prop_assert!(
            format!("{:?}", PorPuzzleKind::FibonacciDelayDev).contains("FibonacciDelayDev"),
            "Debug for FibonacciDelayDev must identify the variant"
        );

        prop_assert!(
            format!("{:?}", PorPuzzleKind::FactorizationDelayDev).contains("FactorizationDelayDev"),
            "Debug for FactorizationDelayDev must identify the variant"
        );
    }

    // 22/25
    #[test]
    fn test_022_config_debug_includes_struct_field_names(
        target_seed in any::<u64>(),
        max_ms in 1u64..=u64::MAX,
    ) {
        let cfg = mandatory_config(valid_target_from_seed(target_seed), max_ms);
        let debug = format!("{:?}", cfg);

        prop_assert!(
            debug.contains("target_block_time"),
            "Debug config output should expose target_block_time field name"
        );

        prop_assert!(
            debug.contains("puzzle_kind"),
            "Debug config output should expose puzzle_kind field name"
        );

        prop_assert!(
            debug.contains("max_local_puzzle_ms"),
            "Debug config output should expose max_local_puzzle_ms field name"
        );
    }

    // 23/25
    #[test]
    fn test_023_positive_soft_cap_is_observability_only_and_large_values_validate(
        target_seed in any::<u64>(),
    ) {
        let cfg = mandatory_config(valid_target_from_seed(target_seed), u64::MAX);

        prop_assert!(
            cfg.validate().is_ok(),
            "positive max_local_puzzle_ms is accepted even when huge because it is observability-only"
        );
    }

    // 24/25
    #[test]
    fn test_024_subsecond_target_duration_is_rejected_because_as_secs_is_zero(
        millis in 1u64..=999u64,
        max_ms in 1u64..=u64::MAX,
    ) {
        let cfg = PorConsensusConfig {
            target_block_time: Duration::from_millis(millis),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: max_ms,
        };

        prop_assert_eq!(
            cfg.target_block_time.as_secs(),
            0,
            "test setup must generate a subsecond duration"
        );

        prop_assert!(
            cfg.validate().is_err(),
            "subsecond target duration must be rejected because validate requires at least one full second"
        );
    }

    // 25/25
    #[test]
    fn test_025_extra_nanoseconds_do_not_change_validation_when_seconds_are_valid(
        target_seed in any::<u64>(),
        nanos in 1u32..=999_999_999u32,
        max_ms in 1u64..=u64::MAX,
    ) {
        let target_secs = valid_target_from_seed(target_seed);

        let cfg = PorConsensusConfig {
            target_block_time: Duration::new(target_secs, nanos),
            puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
            max_local_puzzle_ms: max_ms,
        };

        prop_assert_eq!(
            cfg.target_block_time.as_secs(),
            target_secs,
            "extra nanoseconds must not change whole-second validation input"
        );

        prop_assert!(
            cfg.validate().is_ok(),
            "valid whole-second target with extra nanoseconds should validate under current second-based rules"
        );
    }
}
