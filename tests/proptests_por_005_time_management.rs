use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use std::time::Duration;

use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};

const VALID_GENESIS_UNIX_BASE: u64 = 1_700_000_000;
const VALID_GENESIS_UNIX_SPAN: u64 = 10_000_000;

fn valid_genesis_unix(seed: u64) -> u64 {
    VALID_GENESIS_UNIX_BASE.saturating_add(seed % VALID_GENESIS_UNIX_SPAN)
}

fn manager_from_genesis(genesis_ts: u64) -> TimeManager {
    TimeManager::new(TimeConfig::from_genesis_ts(genesis_ts))
}

fn manager_from_seed(seed: u64) -> TimeManager {
    manager_from_genesis(valid_genesis_unix(seed))
}

fn safe_slot_bound(manager: &TimeManager) -> u64 {
    let genesis = manager.cfg().genesis_time_unix;
    let bi = manager.block_interval_secs().max(1);

    u64::MAX.saturating_sub(genesis) / bi
}

fn custom_config(
    genesis_time_unix: u64,
    block_interval_secs: u64,
    puzzle_interval_secs: u64,
    failover_window_secs: u64,
    deadline_secs: u64,
    max_rounds: u64,
    epoch_slots: u64,
) -> TimeConfig {
    TimeConfig {
        block_interval_secs,
        puzzle_interval_secs,
        activation_warmup_secs: 0,
        genesis_time_unix,
        reward_delay_blocks: 0,
        quarantine_blocks: 0,
        epoch_slots,
        failover_window_secs,
        slot_gossip_buffer_secs: 0,
        failover_proposal_deadline_secs: deadline_secs,
        failover_max_rounds: max_rounds,
        slot_gate_drift_secs: 0,
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
    fn test_001_time_config_from_genesis_ts_clamps_and_derives_safe_values(
        genesis_ts in any::<u64>(),
    ) {
        let cfg = TimeConfig::from_genesis_ts(genesis_ts);

        prop_assert!(
            cfg.genesis_time_unix >= 1,
            "genesis timestamp must be clamped to at least 1"
        );

        prop_assert!(
            cfg.block_interval_secs >= 1,
            "block interval must be at least 1 second"
        );

        prop_assert!(
            cfg.puzzle_interval_secs >= 1,
            "puzzle interval must be at least 1 second"
        );

        prop_assert!(
            cfg.puzzle_interval_secs <= cfg.block_interval_secs,
            "puzzle interval must not exceed block interval"
        );

        prop_assert!(
            cfg.failover_window_secs >= 1,
            "failover window must be at least 1 second"
        );

        prop_assert!(
            cfg.failover_proposal_deadline_secs >= 1,
            "proposal deadline must be at least 1 second"
        );

        prop_assert!(
            cfg.failover_max_rounds >= 1,
            "failover max rounds must be at least 1"
        );

        prop_assert_eq!(
            cfg.block_interval(),
            Duration::from_secs(cfg.block_interval_secs.max(1)),
            "block_interval() must match block_interval_secs"
        );

        prop_assert_eq!(
            cfg.puzzle_interval(),
            Duration::from_secs(cfg.puzzle_interval_secs.max(1)),
            "puzzle_interval() must match puzzle_interval_secs"
        );
    }

    // 02/25
    #[test]
    fn test_002_slot_start_current_slot_and_secs_into_slot_are_consistent(
        genesis_seed in any::<u64>(),
        slot in 0u64..=1_000_000u64,
        offset_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let offset = offset_seed % bi;
        let slot_start = manager.slot_start_unix(slot);
        let now = slot_start.saturating_add(offset);

        prop_assert_eq!(
            manager.current_slot(now),
            slot,
            "time inside a slot must map back to that slot"
        );

        prop_assert_eq!(
            manager.height_start_unix(slot),
            slot_start,
            "height_start_unix must alias slot_start_unix"
        );

        prop_assert_eq!(
            manager.secs_into_slot(slot, now),
            offset,
            "secs_into_slot must return offset inside the slot"
        );

        prop_assert_eq!(
            manager.secs_since_height_start(slot, now),
            offset,
            "secs_since_height_start must return offset from deterministic height start"
        );
    }

    // 03/25
    #[test]
    fn test_003_start_after_next_slot_is_within_one_block_interval_for_current_or_future_times(
        genesis_seed in any::<u64>(),
        slot in 0u64..=1_000_000u64,
        offset_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let offset = offset_seed % bi;
        let now = manager.slot_start_unix(slot).saturating_add(offset);

        let wait = manager.start_after_next_slot(now);

        prop_assert!(
            wait <= Duration::from_secs(bi),
            "start_after_next_slot must be no more than one block interval"
        );

        prop_assert_eq!(
            wait.as_secs(),
            bi.saturating_sub(offset),
            "start_after_next_slot must align to the next slot boundary"
        );
    }

    // 04/25
    #[test]
    fn test_004_round_for_height_at_time_matches_elapsed_divided_by_failover_window(
        genesis_seed in any::<u64>(),
        height in 0u64..=1_000_000u64,
        since in 0u64..=10_000u64,
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(height <= safe_slot_bound(&manager));
        prop_assume!(height <= u64::MAX.saturating_sub(manager.cfg().genesis_time_unix) / bi);

        let start = manager.height_start_unix(height);
        let now = start.saturating_add(since);
        let tau = manager.failover_window_secs().max(1);

        prop_assert_eq!(
            manager.round_for_height_at_time(height, now),
            since / tau,
            "round_for_height_at_time must be elapsed seconds divided by failover window"
        );

        let (round_from_ts, since_from_ts) = manager
            .round_for_height_from_block_timestamp(height, now)
            .expect("timestamp at or after height start should be accepted");

        prop_assert_eq!(
            since_from_ts,
            since,
            "timestamp-derived since_height_start must match elapsed seconds"
        );

        prop_assert_eq!(
            round_from_ts,
            since / tau,
            "timestamp-derived round must match elapsed / failover window"
        );
    }

    // 05/25
    #[test]
    fn test_005_round_in_slot_is_clamped_to_proposal_deadline_and_max_rounds(
        genesis_seed in any::<u64>(),
        slot in 0u64..=1_000_000u64,
        offset_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let offset = offset_seed % bi;
        let now = manager.slot_start_unix(slot).saturating_add(offset);

        let tau = manager.failover_window_secs().max(1);
        let deadline = manager.proposal_deadline_secs().max(1);
        let max_round = manager.failover_max_rounds().saturating_sub(1);

        let mut t = offset.min(bi);
        if t >= deadline {
            t = deadline.saturating_sub(1);
        }

        let expected = (t / tau).min(max_round);

        prop_assert_eq!(
            manager.round_in_slot(slot, now),
            expected,
            "round_in_slot must clamp by proposal deadline and max rounds"
        );
    }

    // 06/25
    #[test]
    fn test_006_slot_and_round_from_block_timestamp_matches_slot_schedule(
        genesis_seed in any::<u64>(),
        slot in 0u64..=1_000_000u64,
        offset_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let offset = offset_seed % bi;
        let ts = manager.slot_start_unix(slot).saturating_add(offset);
        let tau = manager.failover_window_secs().max(1);

        let (derived_slot, derived_round, secs_into_slot) = manager
            .slot_and_round_from_block_timestamp(ts)
            .expect("timestamp at a deterministic slot offset should be accepted");

        prop_assert_eq!(
            derived_slot,
            slot,
            "timestamp-derived slot must match source slot"
        );

        prop_assert_eq!(
            secs_into_slot,
            offset,
            "timestamp-derived secs_into_slot must match source offset"
        );

        prop_assert_eq!(
            derived_round,
            offset / tau,
            "timestamp-derived round must equal offset / failover window"
        );
    }

    // 07/25
    #[test]
    fn test_007_timestamp_gating_accepts_height_start_and_drift_before_height_start(
        genesis_seed in any::<u64>(),
        height in 0u64..=1_000_000u64,
        back_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(height <= safe_slot_bound(&manager));
        prop_assume!(height <= u64::MAX.saturating_sub(manager.cfg().genesis_time_unix) / bi);

        let start = manager.height_start_unix(height);
        let drift = manager.slot_gate_drift_secs();
        let back = if drift == 0 { 0 } else { back_seed % drift.saturating_add(1) };
        let ts = start.saturating_sub(back);

        let (round, since) = manager
            .round_for_height_from_block_timestamp(height, ts)
            .expect("timestamp within drift before height start should be accepted");

        prop_assert_eq!(
            round,
            0,
            "timestamp before height start but within drift must resolve to round 0"
        );

        prop_assert_eq!(
            since,
            0,
            "timestamp before height start but within drift must resolve to since=0"
        );
    }

    // 08/25
    #[test]
    fn test_008_timestamp_gating_rejects_timestamp_too_far_before_genesis(
        genesis_seed in any::<u64>(),
        extra_back in 1u64..=1_000u64,
    ) {
        let manager = manager_from_seed(genesis_seed);
        let drift = manager.slot_gate_drift_secs();
        let genesis_ts = manager.cfg().genesis_time_unix;

        prop_assume!(genesis_ts > drift.saturating_add(extra_back));

        let too_early = genesis_ts
            .saturating_sub(drift)
            .saturating_sub(extra_back);

        prop_assert!(
            manager.slot_and_round_from_block_timestamp(too_early).is_err(),
            "timestamp too far before genesis must be rejected"
        );

        prop_assert!(
            manager.round_for_height_from_block_timestamp(0, too_early).is_err(),
            "height timestamp too far before genesis must be rejected"
        );
    }

    // 09/25
    #[test]
    fn test_009_proposer_eligibility_matches_activation_delay_and_sync_gate(
        genesis_seed in any::<u64>(),
        registration_height in 0u64..=1_000_000u64,
        extra_height in 0u64..=1_000_000u64,
        is_fully_synced in any::<bool>(),
    ) {
        let manager = manager_from_seed(genesis_seed);

        let now_height = registration_height.saturating_add(extra_height);
        let required_height = registration_height.saturating_add(manager.activation_delay_blocks());

        let expected = now_height >= required_height && is_fully_synced;

        prop_assert_eq!(
            manager.is_eligible_for_proposal(
                now_height,
                registration_height,
                is_fully_synced,
            ),
            expected,
            "proposal eligibility must require activation delay and full sync"
        );

        prop_assert_eq!(
            manager.proposer_delay_blocks(),
            manager.activation_delay_blocks().max(manager.quarantine_blocks()),
            "proposer delay must be max(activation delay, quarantine blocks)"
        );
    }

    // 10/25
    #[test]
    fn test_010_epoch_helpers_are_consistent_with_height_division_and_remainder(
        genesis_seed in any::<u64>(),
        height in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let epoch_slots = manager.epoch_slots().max(1);

        let epoch = manager.epoch_of_height(height);
        let slot_in_epoch = manager.slot_in_epoch(height);

        prop_assert_eq!(
            epoch,
            height / epoch_slots,
            "epoch_of_height must be height / epoch_slots"
        );

        prop_assert_eq!(
            slot_in_epoch,
            height % epoch_slots,
            "slot_in_epoch must be height % epoch_slots"
        );

        prop_assert_eq!(
            epoch.saturating_mul(epoch_slots).saturating_add(slot_in_epoch),
            height,
            "epoch and slot_in_epoch must reconstruct height"
        );
    }

    // 11/25
    #[test]
    fn test_011_scheduling_intervals_and_consensus_timeouts_are_sane(
        genesis_seed in any::<u64>(),
        configured_heartbeat in 0u64..=10_000u64,
    ) {
        let manager = manager_from_seed(genesis_seed);

        prop_assert_eq!(
            manager.sync_poll_interval(),
            Duration::from_secs(manager.failover_window_secs().max(1)),
            "sync polling interval must follow failover window"
        );

        let heartbeat = manager
            .registry_heartbeat_interval(Some(configured_heartbeat))
            .expect("Some configured heartbeat must return Some duration");

        let expected_heartbeat = Duration::from_secs(configured_heartbeat.max(1))
            .min(Duration::from_secs(manager.failover_window_secs()));

        prop_assert_eq!(
            heartbeat,
            expected_heartbeat,
            "registry heartbeat interval must be min(configured, failover window)"
        );

        prop_assert!(
            manager.registry_heartbeat_interval(None).is_none(),
            "None configured heartbeat must return None"
        );

        let timeouts = manager.consensus_timeouts();

        prop_assert!(
            timeouts.propose > Duration::ZERO,
            "propose timeout must be positive"
        );

        prop_assert!(
            timeouts.prevote > Duration::ZERO,
            "prevote timeout must be positive"
        );

        prop_assert!(
            timeouts.precommit > Duration::ZERO,
            "precommit timeout must be positive"
        );

        prop_assert!(
            timeouts.propose > timeouts.prevote,
            "propose timeout should be larger than prevote timeout"
        );

        prop_assert_eq!(
            manager.block_interval(),
            Duration::from_secs(manager.block_interval_secs()),
            "block_interval accessor must match block_interval_secs"
        );

        prop_assert_eq!(
            manager.puzzle_interval(),
            Duration::from_secs(manager.puzzle_interval_secs()),
            "puzzle_interval accessor must match puzzle_interval_secs"
        );

        prop_assert!(
            manager.puzzle_interval_secs() <= manager.block_interval_secs(),
            "puzzle interval must not exceed block interval"
        );
    }

    // 12/25
    #[test]
    fn test_012_current_slot_and_elapsed_helpers_saturate_to_zero_before_genesis(
        genesis_seed in any::<u64>(),
        back in 0u64..=1_000_000u64,
        height in 0u64..=1_000u64,
    ) {
        let manager = manager_from_seed(genesis_seed);
        let now = manager.cfg().genesis_time_unix.saturating_sub(back);

        prop_assert_eq!(
            manager.current_slot(now),
            0,
            "current_slot before genesis must saturate to slot 0"
        );

        prop_assert_eq!(
            manager.secs_since_height_start(height, now),
            0,
            "secs_since_height_start before height start must saturate to 0"
        );

        prop_assert_eq!(
            manager.secs_into_slot(height, now),
            0,
            "secs_into_slot before slot start must saturate to 0"
        );
    }

    // 13/25
    #[test]
    fn test_013_slot_start_unix_is_exact_within_safe_range_and_saturates_when_overflowing(
        genesis_seed in any::<u64>(),
        slot in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let genesis = manager.cfg().genesis_time_unix;
        let bi = manager.block_interval_secs();
        let max_exact_slot = safe_slot_bound(&manager);

        let start = manager.slot_start_unix(slot);

        if slot <= max_exact_slot {
            prop_assert_eq!(
                start,
                genesis.saturating_add(slot.saturating_mul(bi)),
                "slot_start_unix must be exact inside safe arithmetic range"
            );
        } else {
            prop_assert_eq!(
                start,
                u64::MAX,
                "slot_start_unix must saturate instead of overflowing"
            );
        }
    }

    // 14/25
    #[test]
    fn test_014_height_start_unix_exactly_aliases_slot_start_for_all_heights(
        genesis_seed in any::<u64>(),
        height in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);

        prop_assert_eq!(
            manager.height_start_unix(height),
            manager.slot_start_unix(height),
            "height_start_unix must remain a pure alias of slot_start_unix"
        );
    }

    // 15/25
    #[test]
    fn test_015_timestamp_gating_accepts_exact_genesis_minus_drift_boundary(
        genesis_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let drift = manager.slot_gate_drift_secs();

        prop_assume!(manager.cfg().genesis_time_unix >= drift);

        let boundary = manager
            .cfg()
            .genesis_time_unix
            .saturating_sub(drift);

        let (slot, round, into) = manager
            .slot_and_round_from_block_timestamp(boundary)
            .expect("exact genesis - drift boundary must be accepted");

        prop_assert_eq!(
            slot,
            0,
            "boundary timestamp before genesis must map to slot 0"
        );

        prop_assert_eq!(
            round,
            0,
            "boundary timestamp before genesis must map to round 0"
        );

        prop_assert_eq!(
            into,
            0,
            "boundary timestamp before genesis must have zero seconds into slot"
        );
    }

    // 16/25
    #[test]
    fn test_016_round_for_height_timestamp_rejects_too_far_before_height_start_even_after_genesis(
        genesis_seed in any::<u64>(),
        height in 1u64..=1_000_000u64,
        extra_back in 1u64..=1_000u64,
    ) {
        let manager = manager_from_seed(genesis_seed);

        prop_assume!(height <= safe_slot_bound(&manager));

        let start = manager.height_start_unix(height);
        let drift = manager.slot_gate_drift_secs();

        prop_assume!(start > manager.cfg().genesis_time_unix.saturating_add(drift).saturating_add(extra_back));

        let too_early_for_height = start
            .saturating_sub(drift)
            .saturating_sub(extra_back);

        prop_assert!(
            manager
                .round_for_height_from_block_timestamp(height, too_early_for_height)
                .is_err(),
            "timestamp more than drift before height start must be rejected"
        );
    }

    // 17/25
    #[test]
    fn test_017_slot_and_round_from_timestamp_allows_far_future_without_wall_clock_rejection(
        genesis_seed in any::<u64>(),
        slot in 1_000_000u64..=2_000_000u64,
        offset_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let offset = offset_seed % bi;
        let ts = manager.slot_start_unix(slot).saturating_add(offset);

        let (derived_slot, _round, into) = manager
            .slot_and_round_from_block_timestamp(ts)
            .expect("consensus timestamp helper must not reject future timestamps by local wall clock");

        prop_assert_eq!(
            derived_slot,
            slot,
            "future deterministic timestamp must map to its scheduled slot"
        );

        prop_assert_eq!(
            into,
            offset,
            "future deterministic timestamp must preserve slot offset"
        );
    }

    // 18/25
    #[test]
    fn test_018_round_in_slot_clamps_offsets_at_or_after_deadline_to_deadline_minus_one(
        genesis_seed in any::<u64>(),
        slot in 0u64..=1_000_000u64,
        extra_after_deadline in 0u64..=1_000_000u64,
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let deadline = manager.proposal_deadline_secs().max(1);
        let offset = deadline
            .saturating_add(extra_after_deadline)
            .min(bi);

        let now = manager.slot_start_unix(slot).saturating_add(offset);
        let tau = manager.failover_window_secs().max(1);
        let max_round = manager.failover_max_rounds().saturating_sub(1);

        let expected = (deadline.saturating_sub(1) / tau).min(max_round);

        prop_assert_eq!(
            manager.round_in_slot(slot, now),
            expected,
            "round_in_slot must clamp timestamps at/after proposal deadline"
        );
    }

    // 19/25
    #[test]
    fn test_019_round_in_slot_never_exceeds_max_round_minus_one(
        genesis_seed in any::<u64>(),
        slot in 0u64..=1_000_000u64,
        offset_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);
        let bi = manager.block_interval_secs();

        prop_assume!(slot <= safe_slot_bound(&manager));

        let offset = offset_seed % bi;
        let now = manager.slot_start_unix(slot).saturating_add(offset);
        let round = manager.round_in_slot(slot, now);

        prop_assert!(
            round < manager.failover_max_rounds().max(1),
            "round_in_slot must always be less than failover_max_rounds"
        );
    }

    // 20/25
    #[test]
    fn test_020_registry_heartbeat_zero_config_clamps_to_one_second_then_min_failover(
        genesis_seed in any::<u64>(),
    ) {
        let manager = manager_from_seed(genesis_seed);

        let heartbeat = manager
            .registry_heartbeat_interval(Some(0))
            .expect("Some(0) heartbeat must still return Some duration");

        let expected = Duration::from_secs(1)
            .min(Duration::from_secs(manager.failover_window_secs()));

        prop_assert_eq!(
            heartbeat,
            expected,
            "configured heartbeat 0 must clamp to 1 second before min(failover)"
        );
    }

    // 21/25
    #[test]
    fn test_021_custom_config_accessors_clamp_zero_intervals_to_one_second(
        genesis_seed in any::<u64>(),
        epoch_slots in any::<u64>(),
    ) {
        let cfg = custom_config(
            valid_genesis_unix(genesis_seed),
            0,
            0,
            0,
            0,
            0,
            epoch_slots,
        );

        let manager = TimeManager::new(cfg);

        prop_assert_eq!(
            manager.block_interval_secs(),
            1,
            "block_interval_secs accessor must clamp zero to one"
        );

        prop_assert_eq!(
            manager.puzzle_interval_secs(),
            1,
            "puzzle_interval_secs accessor must clamp zero to one"
        );

        prop_assert_eq!(
            manager.failover_window_secs(),
            1,
            "failover_window_secs accessor must clamp zero to one"
        );

        prop_assert_eq!(
            manager.proposal_deadline_secs(),
            1,
            "proposal_deadline_secs accessor must clamp zero to one"
        );

        prop_assert_eq!(
            manager.failover_max_rounds(),
            1,
            "failover_max_rounds accessor must clamp zero to one"
        );

        prop_assert_eq!(
            manager.epoch_slots(),
            epoch_slots.max(1),
            "epoch_slots accessor must clamp zero to one"
        );
    }

    // 22/25
    #[test]
    fn test_022_custom_activation_delay_blocks_uses_ceiling_division(
        genesis_seed in any::<u64>(),
        block_interval_secs in 1u64..=10_000u64,
        warmup_secs in any::<u64>(),
    ) {
        let mut cfg = TimeConfig::from_genesis_ts(valid_genesis_unix(genesis_seed));
        cfg.block_interval_secs = block_interval_secs;
        cfg.activation_warmup_secs = warmup_secs;

        let manager = TimeManager::new(cfg);

        prop_assert_eq!(
            manager.activation_delay_blocks(),
            warmup_secs.div_ceil(block_interval_secs),
            "activation_delay_blocks must be ceil(warmup / block_interval)"
        );
    }

    // 23/25
    #[test]
    fn test_023_consensus_timeouts_are_fixed_fractions_of_block_interval(
        genesis_seed in any::<u64>(),
        block_interval_secs in 1u64..=10_000u64,
    ) {
        let mut cfg = TimeConfig::from_genesis_ts(valid_genesis_unix(genesis_seed));
        cfg.block_interval_secs = block_interval_secs;

        let manager = TimeManager::new(cfg);
        let bi = Duration::from_secs(block_interval_secs);
        let timeouts = manager.consensus_timeouts();

        prop_assert_eq!(
            timeouts.propose,
            bi.mul_f64(0.60),
            "propose timeout must be 60% of block interval"
        );

        prop_assert_eq!(
            timeouts.prevote,
            bi.mul_f64(0.20),
            "prevote timeout must be 20% of block interval"
        );

        prop_assert_eq!(
            timeouts.precommit,
            bi.mul_f64(0.20),
            "precommit timeout must be 20% of block interval"
        );
    }

    // 24/25
    #[test]
    fn test_024_assertion_helpers_never_panic_for_generated_configs(
        genesis_ts in any::<u64>(),
        block_interval_secs in any::<u64>(),
        puzzle_interval_secs in any::<u64>(),
        failover_window_secs in any::<u64>(),
        deadline_secs in any::<u64>(),
        max_rounds in any::<u64>(),
        epoch_slots in any::<u64>(),
    ) {
        let cfg = custom_config(
            genesis_ts,
            block_interval_secs,
            puzzle_interval_secs,
            failover_window_secs,
            deadline_secs,
            max_rounds,
            epoch_slots,
        );

        let manager = TimeManager::new(cfg);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            manager.assert_activation_delay_consistent();
            manager.assert_quarantine_consistent();
            manager.assert_failover_consistent();
        }));

        prop_assert!(
            result.is_ok(),
            "startup consistency assertion helpers must warn, not panic"
        );
    }

    // 25/25
    #[test]
    fn test_025_public_time_entrypoints_never_panic_for_arbitrary_inputs(
        genesis_ts in any::<u64>(),
        height in any::<u64>(),
        slot in any::<u64>(),
        now_unix in any::<u64>(),
        block_ts_unix in any::<u64>(),
        configured_heartbeat in proptest::option::of(any::<u64>()),
        is_fully_synced in any::<bool>(),
    ) {
        let manager = manager_from_genesis(genesis_ts);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = TimeManager::now_unix();
            let _ = manager.current_slot(now_unix);
            let _ = manager.slot_start_unix(slot);
            let _ = manager.height_start_unix(height);
            let _ = manager.secs_since_height_start(height, now_unix);
            let _ = manager.round_for_height_at_time(height, now_unix);
            let _ = manager.secs_into_slot(slot, now_unix);
            let _ = manager.round_in_slot(slot, now_unix);
            let _ = manager.round_for_height_from_block_timestamp(height, block_ts_unix);
            let _ = manager.slot_and_round_from_block_timestamp(block_ts_unix);
            let _ = manager.is_eligible_for_proposal(height, slot, is_fully_synced);
            let _ = manager.epoch_of_height(height);
            let _ = manager.slot_in_epoch(height);
            let _ = manager.registry_heartbeat_interval(configured_heartbeat);
            let _ = manager.sync_poll_interval();
            let _ = manager.consensus_timeouts();
            let _ = manager.block_interval();
            let _ = manager.puzzle_interval();
        }));

        prop_assert!(
            result.is_ok(),
            "public TimeManager helpers must return values/errors, not panic, for arbitrary public inputs"
        );
    }
}
