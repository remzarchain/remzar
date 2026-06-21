use remzar::consensus::por_005_time_management::{ConsensusTimeouts, TimeConfig, TimeManager};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::error::Error;
use std::io;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const TEST_GENESIS_UNIX: u64 = 1_700_000_000;

fn ts(offset_secs: u64) -> u64 {
    TEST_GENESIS_UNIX.saturating_add(offset_secs)
}

fn ts_before(offset_secs: u64) -> u64 {
    TEST_GENESIS_UNIX.saturating_sub(offset_secs)
}

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn test_config() -> TimeConfig {
    TimeConfig {
        block_interval_secs: 10,
        puzzle_interval_secs: 4,
        activation_warmup_secs: 25,
        genesis_time_unix: TEST_GENESIS_UNIX,
        reward_delay_blocks: 7,
        quarantine_blocks: 4,
        epoch_slots: 6,
        failover_window_secs: 3,
        slot_gossip_buffer_secs: 2,
        failover_proposal_deadline_secs: 8,
        failover_max_rounds: 3,
        slot_gate_drift_secs: 2,
    }
}

fn test_manager() -> TimeManager {
    TimeManager::new(test_config())
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
fn test_01_from_genesis_ts_clamps_zero_genesis_to_one() {
    let cfg = TimeConfig::from_genesis_ts(0);

    assert_eq!(cfg.genesis_time_unix, 1);
}

#[test]
fn test_02_from_genesis_ts_preserves_nonzero_genesis_timestamp() {
    let cfg = TimeConfig::from_genesis_ts(1_234_567);

    assert_eq!(cfg.genesis_time_unix, 1_234_567);
}

#[test]
fn test_03_from_genesis_ts_uses_global_block_interval() {
    let cfg = TimeConfig::from_genesis_ts(100);

    assert_eq!(
        cfg.block_interval_secs,
        GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1)
    );
}

#[test]
fn test_04_from_genesis_ts_clamps_puzzle_interval_to_block_interval() {
    let cfg = TimeConfig::from_genesis_ts(100);

    assert!(cfg.puzzle_interval_secs >= 1);
    assert!(cfg.puzzle_interval_secs <= cfg.block_interval_secs);
    assert_eq!(
        cfg.puzzle_interval_secs,
        GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS
            .max(1)
            .min(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1))
    );
}

#[test]
fn test_05_from_genesis_ts_copies_reward_quarantine_and_epoch_globals() {
    let cfg = TimeConfig::from_genesis_ts(100);

    assert_eq!(
        cfg.reward_delay_blocks,
        GlobalConfiguration::REWARD_DELAY_BLOCKS
    );
    assert_eq!(
        cfg.quarantine_blocks,
        GlobalConfiguration::QUARANTINE_BLOCKS
    );
    assert_eq!(cfg.epoch_slots, GlobalConfiguration::EPOCH_SLOTS);
}

#[test]
fn test_06_from_genesis_ts_computes_failover_globals_with_nonzero_rounds() {
    let cfg = TimeConfig::from_genesis_ts(100);

    assert!(cfg.failover_window_secs >= 1);
    assert!(cfg.failover_max_rounds >= 1);
    assert!(cfg.failover_proposal_deadline_secs >= 1);
    assert_eq!(
        cfg.slot_gate_drift_secs,
        GlobalConfiguration::SLOT_GATE_DRIFT_SECS
    );
}

#[test]
fn test_07_time_manager_accessors_return_config_values() {
    let manager = test_manager();

    assert_eq!(manager.block_interval_secs(), 10);
    assert_eq!(manager.puzzle_interval_secs(), 4);
    assert_eq!(manager.quarantine_blocks(), 4);
    assert_eq!(manager.epoch_slots(), 6);
    assert_eq!(manager.failover_window_secs(), 3);
    assert_eq!(manager.failover_max_rounds(), 3);
    assert_eq!(manager.proposal_deadline_secs(), 8);
    assert_eq!(manager.slot_gossip_buffer_secs(), 2);
    assert_eq!(manager.slot_gate_drift_secs(), 2);
}

#[test]
fn test_08_duration_accessors_match_seconds() {
    let manager = test_manager();

    assert_eq!(manager.block_interval(), Duration::from_secs(10));
    assert_eq!(manager.puzzle_interval(), Duration::from_secs(4));
    assert_eq!(manager.cfg().failover_window(), Duration::from_secs(3));
    assert_eq!(manager.sync_poll_interval(), Duration::from_secs(3));
}

#[test]
fn test_09_activation_delay_blocks_uses_ceil_division() {
    let manager = test_manager();

    assert_eq!(manager.activation_delay_blocks(), 3);
}

#[test]
fn test_10_proposer_delay_blocks_uses_max_of_activation_and_quarantine() {
    let manager = test_manager();

    assert_eq!(manager.activation_delay_blocks(), 3);
    assert_eq!(manager.quarantine_blocks(), 4);
    assert_eq!(manager.proposer_delay_blocks(), 4);
}

#[test]
fn test_11_registry_heartbeat_interval_none_stays_none() {
    let manager = test_manager();

    assert_eq!(manager.registry_heartbeat_interval(None), None);
}

#[test]
fn test_12_registry_heartbeat_interval_zero_clamps_to_one_second() {
    let manager = test_manager();

    assert_eq!(
        manager.registry_heartbeat_interval(Some(0)),
        Some(Duration::from_secs(1))
    );
}

#[test]
fn test_13_registry_heartbeat_interval_larger_than_failover_clamps_to_failover() {
    let manager = test_manager();

    assert_eq!(
        manager.registry_heartbeat_interval(Some(30)),
        Some(Duration::from_secs(3))
    );
}

#[test]
fn test_14_registry_heartbeat_interval_smaller_than_failover_is_preserved() {
    let manager = test_manager();

    assert_eq!(
        manager.registry_heartbeat_interval(Some(2)),
        Some(Duration::from_secs(2))
    );
}

#[test]
fn test_15_current_slot_before_genesis_is_zero() {
    let manager = test_manager();

    assert_eq!(manager.current_slot(ts_before(1)), 0);
}

#[test]
fn test_16_current_slot_at_genesis_is_zero() {
    let manager = test_manager();

    assert_eq!(manager.current_slot(ts(0)), 0);
}

#[test]
fn test_17_current_slot_vectors_across_boundaries() {
    let manager = test_manager();

    assert_eq!(manager.current_slot(ts(9)), 0);
    assert_eq!(manager.current_slot(ts(10)), 1);
    assert_eq!(manager.current_slot(ts(19)), 1);
    assert_eq!(manager.current_slot(ts(20)), 2);
    assert_eq!(manager.current_slot(ts(39)), 3);
}

#[test]
fn test_18_slot_start_unix_vectors() {
    let manager = test_manager();

    assert_eq!(manager.slot_start_unix(0), ts(0));
    assert_eq!(manager.slot_start_unix(1), ts(10));
    assert_eq!(manager.slot_start_unix(2), ts(20));
    assert_eq!(manager.slot_start_unix(10), ts(100));
}

#[test]
fn test_19_height_start_unix_is_alias_for_slot_start_unix() {
    let manager = test_manager();

    for height in [0_u64, 1, 2, 10, 999] {
        assert_eq!(
            manager.height_start_unix(height),
            manager.slot_start_unix(height)
        );
    }
}

#[test]
fn test_20_secs_since_height_start_saturates_before_start() {
    let manager = test_manager();

    assert_eq!(manager.secs_since_height_start(2, ts(19)), 0);
    assert_eq!(manager.secs_since_height_start(2, ts(20)), 0);
    assert_eq!(manager.secs_since_height_start(2, ts(25)), 5);
}

#[test]
fn test_21_secs_into_slot_clamps_to_block_interval() {
    let manager = test_manager();

    assert_eq!(manager.secs_into_slot(2, ts(19)), 0);
    assert_eq!(manager.secs_into_slot(2, ts(20)), 0);
    assert_eq!(manager.secs_into_slot(2, ts(25)), 5);
    assert_eq!(manager.secs_into_slot(2, ts(40)), 10);
}

#[test]
fn test_22_round_for_height_at_time_is_unbounded() {
    let manager = test_manager();

    assert_eq!(manager.round_for_height_at_time(5, ts(50)), 0);
    assert_eq!(manager.round_for_height_at_time(5, ts(52)), 0);
    assert_eq!(manager.round_for_height_at_time(5, ts(53)), 1);
    assert_eq!(manager.round_for_height_at_time(5, ts(62)), 4);
}

#[test]
fn test_23_round_in_slot_respects_deadline_and_max_rounds() {
    let manager = test_manager();

    assert_eq!(manager.round_in_slot(5, ts(50)), 0);
    assert_eq!(manager.round_in_slot(5, ts(52)), 0);
    assert_eq!(manager.round_in_slot(5, ts(53)), 1);
    assert_eq!(manager.round_in_slot(5, ts(56)), 2);
    assert_eq!(manager.round_in_slot(5, ts(58)), 2);
    assert_eq!(manager.round_in_slot(5, ts(100)), 2);
}

#[test]
fn test_24_start_after_next_slot_vectors() {
    let manager = test_manager();

    assert_eq!(
        manager.start_after_next_slot(ts(0)),
        Duration::from_secs(10)
    );
    assert_eq!(manager.start_after_next_slot(ts(9)), Duration::from_secs(1));
    assert_eq!(
        manager.start_after_next_slot(ts(10)),
        Duration::from_secs(10)
    );
}

#[test]
fn test_25_start_after_next_slot_before_genesis_targets_slot_one() {
    let manager = test_manager();

    assert_eq!(
        manager.start_after_next_slot(ts_before(10)),
        Duration::from_secs(20)
    );
}

#[test]
fn test_26_consensus_timeouts_split_block_interval() {
    let manager = test_manager();
    let ConsensusTimeouts {
        propose,
        prevote,
        precommit,
    } = manager.consensus_timeouts();

    assert_eq!(propose, Duration::from_secs(6));
    assert_eq!(prevote, Duration::from_secs(2));
    assert_eq!(precommit, Duration::from_secs(2));
}

#[test]
fn test_27_round_for_height_from_block_timestamp_rejects_before_genesis_past_drift() -> TestResult {
    let manager = test_manager();

    let message =
        validation_message(manager.round_for_height_from_block_timestamp(0, ts_before(3)))?;

    assert!(message.contains("before genesis"));
    Ok(())
}

#[test]
fn test_28_round_for_height_from_block_timestamp_accepts_genesis_minus_drift() -> TestResult {
    let manager = test_manager();

    let (round, since) = manager.round_for_height_from_block_timestamp(0, ts_before(2))?;

    assert_eq!(round, 0);
    assert_eq!(since, 0);
    Ok(())
}

#[test]
fn test_29_round_for_height_from_block_timestamp_rejects_too_far_before_height_start() -> TestResult
{
    let manager = test_manager();

    let message = validation_message(manager.round_for_height_from_block_timestamp(1, ts(7)))?;

    assert!(message.contains("too far before height start"));
    Ok(())
}

#[test]
fn test_30_round_for_height_from_block_timestamp_accepts_within_drift_before_height_start()
-> TestResult {
    let manager = test_manager();

    let (round, since) = manager.round_for_height_from_block_timestamp(1, ts(8))?;

    assert_eq!(round, 0);
    assert_eq!(since, 0);
    Ok(())
}

#[test]
fn test_31_round_for_height_from_block_timestamp_vectors_at_and_after_start() -> TestResult {
    let manager = test_manager();

    assert_eq!(
        manager.round_for_height_from_block_timestamp(1, ts(10))?,
        (0, 0)
    );
    assert_eq!(
        manager.round_for_height_from_block_timestamp(1, ts(13))?,
        (1, 3)
    );
    assert_eq!(
        manager.round_for_height_from_block_timestamp(1, ts(17))?,
        (2, 7)
    );
    Ok(())
}

#[test]
fn test_32_slot_and_round_from_block_timestamp_rejects_before_genesis_past_drift() -> TestResult {
    let manager = test_manager();

    let message = validation_message(manager.slot_and_round_from_block_timestamp(ts_before(3)))?;

    assert!(message.contains("before genesis"));
    Ok(())
}

#[test]
fn test_33_slot_and_round_from_block_timestamp_accepts_genesis_minus_drift() -> TestResult {
    let manager = test_manager();

    assert_eq!(
        manager.slot_and_round_from_block_timestamp(ts_before(2))?,
        (0, 0, 0)
    );
    Ok(())
}

#[test]
fn test_34_slot_and_round_from_block_timestamp_vectors() -> TestResult {
    let manager = test_manager();

    assert_eq!(
        manager.slot_and_round_from_block_timestamp(ts(0))?,
        (0, 0, 0)
    );
    assert_eq!(
        manager.slot_and_round_from_block_timestamp(ts(9))?,
        (0, 3, 9)
    );
    assert_eq!(
        manager.slot_and_round_from_block_timestamp(ts(10))?,
        (1, 0, 0)
    );
    assert_eq!(
        manager.slot_and_round_from_block_timestamp(ts(35))?,
        (3, 1, 5)
    );
    Ok(())
}

#[test]
fn test_35_is_eligible_for_proposal_requires_activation_delay_and_sync() {
    let manager = test_manager();

    assert!(!manager.is_eligible_for_proposal(12, 10, true));
    assert!(manager.is_eligible_for_proposal(13, 10, true));
    assert!(!manager.is_eligible_for_proposal(13, 10, false));
}

#[test]
fn test_36_is_eligible_for_proposal_uses_saturating_add_near_u64_max() {
    let manager = test_manager();

    assert!(manager.is_eligible_for_proposal(u64::MAX, u64::MAX.saturating_sub(1), true));
}

#[test]
fn test_37_epoch_helpers_return_expected_epoch_and_slot() {
    let manager = test_manager();

    assert_eq!(manager.epoch_of_height(0), 0);
    assert_eq!(manager.slot_in_epoch(0), 0);
    assert_eq!(manager.epoch_of_height(5), 0);
    assert_eq!(manager.slot_in_epoch(5), 5);
    assert_eq!(manager.epoch_of_height(6), 1);
    assert_eq!(manager.slot_in_epoch(6), 0);
    assert_eq!(manager.epoch_of_height(13), 2);
    assert_eq!(manager.slot_in_epoch(13), 1);
}

#[test]
fn test_38_zero_fields_are_clamped_by_accessors() {
    let cfg = TimeConfig {
        block_interval_secs: 0,
        puzzle_interval_secs: 0,
        activation_warmup_secs: 0,
        genesis_time_unix: 1,
        reward_delay_blocks: 0,
        quarantine_blocks: 0,
        epoch_slots: 0,
        failover_window_secs: 0,
        slot_gossip_buffer_secs: 0,
        failover_proposal_deadline_secs: 0,
        failover_max_rounds: 0,
        slot_gate_drift_secs: 0,
    };
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.block_interval_secs(), 1);
    assert_eq!(manager.puzzle_interval_secs(), 1);
    assert_eq!(manager.block_interval(), Duration::from_secs(1));
    assert_eq!(manager.puzzle_interval(), Duration::from_secs(1));
    assert_eq!(manager.failover_window_secs(), 1);
    assert_eq!(manager.failover_max_rounds(), 1);
    assert_eq!(manager.proposal_deadline_secs(), 1);
    assert_eq!(manager.epoch_slots(), 1);
}

#[test]
fn test_39_assertion_helpers_do_not_panic() {
    let manager = test_manager();

    manager.assert_activation_delay_consistent();
    manager.assert_quarantine_consistent();
    manager.assert_failover_consistent();
}

#[test]
fn test_40_new_from_missing_genesis_file_returns_error() {
    let result = TimeManager::new_from_genesis_file(
        "definitely_missing_remzar_genesis_for_time_manager_test.json",
    );

    assert!(result.is_err());
}

#[test]
fn test_41_from_genesis_ts_failover_values_match_global_formula() {
    let cfg = TimeConfig::from_genesis_ts(100);
    let block_interval = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
    let puzzle_interval = GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS
        .max(1)
        .min(block_interval);
    let min_tau = puzzle_interval
        .saturating_add(GlobalConfiguration::FAILOVER_SLACK_SECS)
        .max(1);
    let expected_tau = GlobalConfiguration::FAILOVER_WINDOW_SECS
        .max(1)
        .max(min_tau);
    let expected_buffer = if GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS >= block_interval {
        1
    } else {
        GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS
    };
    let expected_deadline = block_interval.saturating_sub(expected_buffer).max(1);
    let expected_rounds = expected_deadline.div_euclid(expected_tau).max(1);

    assert_eq!(cfg.failover_window_secs, expected_tau);
    assert_eq!(cfg.slot_gossip_buffer_secs, expected_buffer);
    assert_eq!(cfg.failover_proposal_deadline_secs, expected_deadline);
    assert_eq!(cfg.failover_max_rounds, expected_rounds);
}

#[test]
fn test_42_from_genesis_ts_current_global_failover_vectors() {
    let cfg = TimeConfig::from_genesis_ts(100);

    assert_eq!(cfg.block_interval_secs, 30);
    assert_eq!(cfg.puzzle_interval_secs, 2);
    assert_eq!(cfg.failover_window_secs, 12);
    assert_eq!(cfg.slot_gossip_buffer_secs, 6);
    assert_eq!(cfg.failover_proposal_deadline_secs, 24);
    assert_eq!(cfg.failover_max_rounds, 2);
    assert_eq!(cfg.slot_gate_drift_secs, 2);
}

#[test]
fn test_43_clone_config_preserves_all_fields() {
    let cfg = test_config();
    let cloned = cfg.clone();

    assert_eq!(cloned.block_interval_secs, cfg.block_interval_secs);
    assert_eq!(cloned.puzzle_interval_secs, cfg.puzzle_interval_secs);
    assert_eq!(cloned.activation_warmup_secs, cfg.activation_warmup_secs);
    assert_eq!(cloned.genesis_time_unix, cfg.genesis_time_unix);
    assert_eq!(cloned.reward_delay_blocks, cfg.reward_delay_blocks);
    assert_eq!(cloned.quarantine_blocks, cfg.quarantine_blocks);
    assert_eq!(cloned.epoch_slots, cfg.epoch_slots);
    assert_eq!(cloned.failover_window_secs, cfg.failover_window_secs);
    assert_eq!(cloned.slot_gossip_buffer_secs, cfg.slot_gossip_buffer_secs);
    assert_eq!(
        cloned.failover_proposal_deadline_secs,
        cfg.failover_proposal_deadline_secs
    );
    assert_eq!(cloned.failover_max_rounds, cfg.failover_max_rounds);
    assert_eq!(cloned.slot_gate_drift_secs, cfg.slot_gate_drift_secs);
}

#[test]
fn test_44_debug_config_contains_type_and_core_fields() {
    let cfg = test_config();
    let debug_text = format!("{cfg:?}");

    assert!(debug_text.contains("TimeConfig"));
    assert!(debug_text.contains("block_interval_secs"));
    assert!(debug_text.contains("puzzle_interval_secs"));
    assert!(debug_text.contains("genesis_time_unix"));
    assert!(debug_text.contains("failover_window_secs"));
}

#[test]
fn test_45_clone_manager_preserves_behavior() {
    let manager = test_manager();
    let cloned = manager.clone();

    assert_eq!(cloned.block_interval_secs(), manager.block_interval_secs());
    assert_eq!(
        cloned.puzzle_interval_secs(),
        manager.puzzle_interval_secs()
    );
    assert_eq!(cloned.current_slot(ts(35)), manager.current_slot(ts(35)));
    assert_eq!(
        cloned.round_in_slot(3, ts(35)),
        manager.round_in_slot(3, ts(35))
    );
}

#[test]
fn test_46_debug_manager_contains_type_and_cfg() {
    let manager = test_manager();
    let debug_text = format!("{manager:?}");

    assert!(debug_text.contains("TimeManager"));
    assert!(debug_text.contains("cfg"));
}

#[test]
fn test_47_consensus_timeouts_clone_copy_and_debug() {
    let timeouts = test_manager().consensus_timeouts();
    let copied = timeouts;
    let copied_again = timeouts;
    let debug_text = format!("{timeouts:?}");

    assert_eq!(copied.propose, timeouts.propose);
    assert_eq!(copied_again.prevote, timeouts.prevote);
    assert_eq!(copied.precommit, copied_again.precommit);
    assert!(debug_text.contains("ConsensusTimeouts"));
    assert!(debug_text.contains("propose"));
    assert!(debug_text.contains("prevote"));
    assert!(debug_text.contains("precommit"));
}

#[test]
fn test_48_activation_delay_zero_warmup_is_zero_blocks() {
    let mut cfg = test_config();
    cfg.activation_warmup_secs = 0;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.activation_delay_blocks(), 0);
}

#[test]
fn test_49_activation_delay_exact_multiple_vector() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 10;
    cfg.activation_warmup_secs = 30;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.activation_delay_blocks(), 3);
}

#[test]
fn test_50_activation_delay_rounds_up_one_second_over_multiple() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 10;
    cfg.activation_warmup_secs = 31;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.activation_delay_blocks(), 4);
}

#[test]
fn test_51_proposer_delay_uses_activation_when_activation_exceeds_quarantine() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 10;
    cfg.activation_warmup_secs = 100;
    cfg.quarantine_blocks = 4;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.activation_delay_blocks(), 10);
    assert_eq!(manager.proposer_delay_blocks(), 10);
}

#[test]
fn test_52_proposer_delay_uses_quarantine_when_quarantine_exceeds_activation() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 10;
    cfg.activation_warmup_secs = 10;
    cfg.quarantine_blocks = 9;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.activation_delay_blocks(), 1);
    assert_eq!(manager.proposer_delay_blocks(), 9);
}

#[test]
fn test_53_current_slot_handles_large_elapsed_without_overflow() {
    let manager = test_manager();

    assert_eq!(
        manager.current_slot(u64::MAX),
        u64::MAX.saturating_sub(ts(0)).div_euclid(10)
    );
}

#[test]
fn test_54_slot_start_unix_saturates_on_large_slot() {
    let manager = test_manager();

    assert_eq!(manager.slot_start_unix(u64::MAX), u64::MAX);
}

#[test]
fn test_55_height_start_unix_saturates_on_large_height() {
    let manager = test_manager();

    assert_eq!(manager.height_start_unix(u64::MAX), u64::MAX);
}

#[test]
fn test_56_secs_since_height_start_with_saturated_large_height_start_is_zero_before_max() {
    let manager = test_manager();

    assert_eq!(
        manager.secs_since_height_start(u64::MAX, u64::MAX.saturating_sub(1)),
        0
    );
}

#[test]
fn test_57_secs_since_height_start_with_saturated_large_height_start_at_max_is_zero() {
    let manager = test_manager();

    assert_eq!(manager.secs_since_height_start(u64::MAX, u64::MAX), 0);
}

#[test]
fn test_58_secs_into_slot_large_slot_saturates_and_clamps() {
    let manager = test_manager();

    assert_eq!(manager.secs_into_slot(u64::MAX, u64::MAX), 0);
}

#[test]
fn test_59_round_for_height_at_time_before_height_start_is_zero() {
    let manager = test_manager();

    assert_eq!(manager.round_for_height_at_time(9, ts(0)), 0);
}

#[test]
fn test_60_round_for_height_at_time_large_time_is_unbounded() {
    let manager = test_manager();

    let expected_since = ts(200).saturating_sub(manager.height_start_unix(1));
    assert_eq!(
        manager.round_for_height_at_time(1, ts(200)),
        expected_since.div_euclid(manager.failover_window_secs())
    );
}

#[test]
fn test_61_round_in_slot_before_slot_start_is_zero() {
    let manager = test_manager();

    assert_eq!(manager.round_in_slot(5, ts(0)), 0);
}

#[test]
fn test_62_round_in_slot_exact_deadline_clamps_to_last_allowed_round() {
    let manager = test_manager();

    assert_eq!(manager.round_in_slot(5, ts(58)), 2);
}

#[test]
fn test_63_round_in_slot_after_deadline_stays_last_allowed_round() {
    let manager = test_manager();

    for now in [ts(58), ts(59), ts(60), ts(70), ts(500)] {
        assert_eq!(manager.round_in_slot(5, now), 2);
    }
}

#[test]
fn test_64_round_in_slot_with_one_max_round_always_zero() {
    let mut cfg = test_config();
    cfg.failover_max_rounds = 1;
    let manager = TimeManager::new(cfg);

    for now in [ts(0), ts(3), ts(6), ts(9), ts(100)] {
        assert_eq!(manager.round_in_slot(0, now), 0);
    }
}

#[test]
fn test_65_round_in_slot_with_zero_failover_window_accessor_clamps_to_one() {
    let mut cfg = test_config();
    cfg.failover_window_secs = 0;
    cfg.failover_max_rounds = 10;
    cfg.failover_proposal_deadline_secs = 8;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.failover_window_secs(), 1);
    assert_eq!(manager.round_in_slot(0, ts(0)), 0);
    assert_eq!(manager.round_in_slot(0, ts(5)), 5);
    assert_eq!(manager.round_in_slot(0, ts(9)), 7);
}

#[test]
fn test_66_slot_and_round_from_block_timestamp_with_zero_drift_rejects_before_genesis() -> TestResult
{
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 0;
    let manager = TimeManager::new(cfg);

    let message = validation_message(manager.slot_and_round_from_block_timestamp(ts_before(1)))?;

    assert!(message.contains("before genesis"));
    Ok(())
}

#[test]
fn test_67_round_for_height_from_block_timestamp_with_zero_drift_rejects_before_height_start()
-> TestResult {
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 0;
    let manager = TimeManager::new(cfg);

    let message = validation_message(manager.round_for_height_from_block_timestamp(1, ts(9)))?;

    assert!(message.contains("too far before height start"));
    Ok(())
}

#[test]
fn test_68_round_for_height_from_block_timestamp_with_zero_drift_accepts_exact_start() -> TestResult
{
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 0;
    let manager = TimeManager::new(cfg);

    assert_eq!(
        manager.round_for_height_from_block_timestamp(1, ts(10))?,
        (0, 0)
    );
    Ok(())
}

#[test]
fn test_69_slot_and_round_from_block_timestamp_far_future_is_unbounded() -> TestResult {
    let manager = test_manager();

    let timestamp = ts(0).saturating_add(123_u64 * 10_u64).saturating_add(9_u64);
    assert_eq!(
        manager.slot_and_round_from_block_timestamp(timestamp)?,
        (123, 3, 9)
    );
    Ok(())
}

#[test]
fn test_70_round_for_height_from_block_timestamp_far_after_start_is_unbounded() -> TestResult {
    let manager = test_manager();

    assert_eq!(
        manager.round_for_height_from_block_timestamp(2, ts(100))?,
        (26, 80)
    );
    Ok(())
}

#[test]
fn test_71_start_after_next_slot_at_exact_slot_boundary_returns_full_block_interval() {
    let manager = test_manager();

    assert_eq!(
        manager.start_after_next_slot(ts(20)),
        Duration::from_secs(10)
    );
}

#[test]
fn test_72_start_after_next_slot_one_second_before_boundary_returns_one_second() {
    let manager = test_manager();

    assert_eq!(
        manager.start_after_next_slot(ts(29)),
        Duration::from_secs(1)
    );
}

#[test]
fn test_73_start_after_next_slot_far_future_still_targets_next_boundary() {
    let manager = test_manager();

    assert_eq!(
        manager.start_after_next_slot(ts(234)),
        Duration::from_secs(6)
    );
}

#[test]
fn test_74_registry_heartbeat_interval_at_failover_boundary_is_preserved() {
    let manager = test_manager();

    assert_eq!(
        manager.registry_heartbeat_interval(Some(manager.failover_window_secs())),
        Some(Duration::from_secs(manager.failover_window_secs()))
    );
}

#[test]
fn test_75_registry_heartbeat_interval_u64_max_clamps_to_failover() {
    let manager = test_manager();

    assert_eq!(
        manager.registry_heartbeat_interval(Some(u64::MAX)),
        Some(Duration::from_secs(manager.failover_window_secs()))
    );
}

#[test]
fn test_76_epoch_helpers_with_zero_epoch_slots_clamp_to_one() {
    let mut cfg = test_config();
    cfg.epoch_slots = 0;
    let manager = TimeManager::new(cfg);

    for height in [0_u64, 1, 2, 100, u64::MAX] {
        assert_eq!(manager.epoch_of_height(height), height);
        assert_eq!(manager.slot_in_epoch(height), 0);
    }
}

#[test]
fn test_77_epoch_helpers_with_large_epoch_slots_keep_height_in_epoch_zero_until_boundary() {
    let mut cfg = test_config();
    cfg.epoch_slots = 1_000;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.epoch_of_height(999), 0);
    assert_eq!(manager.slot_in_epoch(999), 999);
    assert_eq!(manager.epoch_of_height(1_000), 1);
    assert_eq!(manager.slot_in_epoch(1_000), 0);
}

#[test]
fn test_78_is_eligible_for_proposal_false_before_registration_height() {
    let manager = test_manager();

    assert!(!manager.is_eligible_for_proposal(9, 10, true));
}

#[test]
fn test_79_is_eligible_for_proposal_true_when_activation_delay_zero_and_synced() {
    let mut cfg = test_config();
    cfg.activation_warmup_secs = 0;
    cfg.quarantine_blocks = 0;
    let manager = TimeManager::new(cfg);

    assert!(manager.is_eligible_for_proposal(10, 10, true));
    assert!(!manager.is_eligible_for_proposal(10, 10, false));
}

#[test]
fn test_80_load_slot_round_and_epoch_vectors_are_stable() -> TestResult {
    let manager = test_manager();

    for height in 0_u64..128_u64 {
        let start = manager.height_start_unix(height);
        assert_eq!(manager.current_slot(start), height);
        assert_eq!(manager.slot_start_unix(height), start);
        assert_eq!(manager.secs_since_height_start(height, start), 0);
        assert_eq!(
            manager.round_for_height_from_block_timestamp(height, start)?,
            (0, 0)
        );
        assert_eq!(
            manager.slot_and_round_from_block_timestamp(start)?,
            (height, 0, 0)
        );
        assert_eq!(manager.epoch_of_height(height), height.div_euclid(6));
        assert_eq!(manager.slot_in_epoch(height), height.rem_euclid(6));
    }

    Ok(())
}

#[test]
fn test_81_edge_block_interval_zero_current_slot_uses_one_second_denominator() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 0;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.block_interval_secs(), 1);
    assert_eq!(manager.current_slot(ts(0)), 0);
    assert_eq!(manager.current_slot(ts(1)), 1);
    assert_eq!(manager.current_slot(ts(10)), 10);
}

#[test]
fn test_82_edge_block_interval_zero_slot_start_uses_one_second_steps() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 0;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.slot_start_unix(0), ts(0));
    assert_eq!(manager.slot_start_unix(1), ts(1));
    assert_eq!(manager.slot_start_unix(10), ts(10));
}

#[test]
fn test_83_edge_block_interval_zero_secs_into_slot_clamps_to_one_second() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 0;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.secs_into_slot(0, ts(0)), 0);
    assert_eq!(manager.secs_into_slot(0, ts(1)), 1);
    assert_eq!(manager.secs_into_slot(0, ts(10)), 1);
}

#[test]
fn test_84_edge_proposal_deadline_zero_round_in_slot_stays_zero() {
    let mut cfg = test_config();
    cfg.failover_proposal_deadline_secs = 0;
    cfg.failover_window_secs = 3;
    cfg.failover_max_rounds = 5;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.proposal_deadline_secs(), 1);
    assert_eq!(manager.round_in_slot(0, ts(0)), 0);
    assert_eq!(manager.round_in_slot(0, ts(5)), 0);
}

#[test]
fn test_85_edge_failover_max_rounds_zero_round_in_slot_stays_zero() {
    let mut cfg = test_config();
    cfg.failover_max_rounds = 0;
    let manager = TimeManager::new(cfg);

    assert_eq!(manager.failover_max_rounds(), 1);
    assert_eq!(manager.round_in_slot(0, ts(0)), 0);
    assert_eq!(manager.round_in_slot(0, ts(3)), 0);
    assert_eq!(manager.round_in_slot(0, ts(9)), 0);
}

#[test]
fn test_86_vector_round_in_slot_each_second_inside_slot() {
    let manager = test_manager();
    let expected = [
        (ts(0), 0_u64),
        (ts(1), 0),
        (ts(2), 0),
        (ts(3), 1),
        (ts(4), 1),
        (ts(5), 1),
        (ts(6), 2),
        (ts(7), 2),
        (ts(8), 2),
        (ts(9), 2),
        (ts(10), 2),
    ];

    for (now_unix, expected_round) in expected {
        assert_eq!(manager.round_in_slot(0, now_unix), expected_round);
    }
}

#[test]
fn test_87_vector_secs_into_slot_each_second_inside_and_after_slot() {
    let manager = test_manager();
    let expected = [
        (ts(0), 0_u64),
        (ts(1), 1),
        (ts(2), 2),
        (ts(3), 3),
        (ts(4), 4),
        (ts(5), 5),
        (ts(6), 6),
        (ts(7), 7),
        (ts(8), 8),
        (ts(9), 9),
        (ts(10), 10),
        (ts(11), 10),
    ];

    for (now_unix, expected_secs) in expected {
        assert_eq!(manager.secs_into_slot(0, now_unix), expected_secs);
    }
}

#[test]
fn test_88_vector_slot_and_round_each_second_across_slot_boundary() -> TestResult {
    let manager = test_manager();
    let expected = [
        (ts(0), (0_u64, 0_u64, 0_u64)),
        (ts(1), (0, 0, 1)),
        (ts(2), (0, 0, 2)),
        (ts(3), (0, 1, 3)),
        (ts(4), (0, 1, 4)),
        (ts(5), (0, 1, 5)),
        (ts(6), (0, 2, 6)),
        (ts(7), (0, 2, 7)),
        (ts(8), (0, 2, 8)),
        (ts(9), (0, 3, 9)),
        (ts(10), (1, 0, 0)),
    ];

    for (timestamp, expected_tuple) in expected {
        assert_eq!(
            manager.slot_and_round_from_block_timestamp(timestamp)?,
            expected_tuple
        );
    }

    Ok(())
}

#[test]
fn test_89_vector_round_for_height_from_block_timestamp_each_second() -> TestResult {
    let manager = test_manager();
    let expected = [
        (ts(0), (0_u64, 0_u64)),
        (ts(1), (0, 1)),
        (ts(2), (0, 2)),
        (ts(3), (1, 3)),
        (ts(4), (1, 4)),
        (ts(5), (1, 5)),
        (ts(6), (2, 6)),
        (ts(7), (2, 7)),
        (ts(8), (2, 8)),
        (ts(9), (3, 9)),
    ];

    for (timestamp, expected_tuple) in expected {
        assert_eq!(
            manager.round_for_height_from_block_timestamp(0, timestamp)?,
            expected_tuple
        );
    }

    Ok(())
}

#[test]
fn test_90_edge_round_for_height_from_block_timestamp_before_genesis_with_large_drift() -> TestResult
{
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 100;
    let manager = TimeManager::new(cfg);

    assert_eq!(
        manager.round_for_height_from_block_timestamp(0, ts_before(50))?,
        (0, 0)
    );
    Ok(())
}

#[test]
fn test_91_edge_slot_and_round_from_block_timestamp_before_genesis_with_large_drift() -> TestResult
{
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 100;
    let manager = TimeManager::new(cfg);

    assert_eq!(
        manager.slot_and_round_from_block_timestamp(ts_before(50))?,
        (0, 0, 0)
    );
    Ok(())
}

#[test]
fn test_92_edge_round_for_height_from_block_timestamp_before_height_start_exact_drift() -> TestResult
{
    let manager = test_manager();

    assert_eq!(
        manager.round_for_height_from_block_timestamp(2, ts(18))?,
        (0, 0)
    );
    Ok(())
}

#[test]
fn test_93_edge_round_for_height_from_block_timestamp_before_height_start_drift_plus_one_rejects()
-> TestResult {
    let manager = test_manager();

    let message = validation_message(manager.round_for_height_from_block_timestamp(2, ts(17)))?;

    assert!(message.contains("too far before height start"));
    assert!(message.contains("drift=2s"));
    Ok(())
}

#[test]
fn test_94_vector_consensus_timeouts_for_odd_block_interval() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 7;
    let manager = TimeManager::new(cfg);
    let timeouts = manager.consensus_timeouts();

    assert_eq!(timeouts.propose, Duration::from_millis(4_200));
    assert_eq!(timeouts.prevote, Duration::from_millis(1_400));
    assert_eq!(timeouts.precommit, Duration::from_millis(1_400));
}

#[test]
fn test_95_vector_consensus_timeouts_for_one_second_block_interval() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 1;
    let manager = TimeManager::new(cfg);
    let timeouts = manager.consensus_timeouts();

    assert_eq!(timeouts.propose, Duration::from_millis(600));
    assert_eq!(timeouts.prevote, Duration::from_millis(200));
    assert_eq!(timeouts.precommit, Duration::from_millis(200));
}

#[test]
fn test_96_edge_is_eligible_for_proposal_at_exact_saturating_threshold() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 10;
    cfg.activation_warmup_secs = 50;
    cfg.quarantine_blocks = 0;
    let manager = TimeManager::new(cfg);

    assert!(!manager.is_eligible_for_proposal(14, 10, true));
    assert!(manager.is_eligible_for_proposal(15, 10, true));
}

#[test]
fn test_97_edge_is_eligible_for_proposal_near_u64_max_registration_threshold() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 10;
    cfg.activation_warmup_secs = 50;
    cfg.quarantine_blocks = 0;
    let manager = TimeManager::new(cfg);

    assert!(manager.is_eligible_for_proposal(u64::MAX, u64::MAX.saturating_sub(2), true));
}

#[test]
fn test_98_vector_start_after_next_slot_for_all_offsets_inside_slot() {
    let manager = test_manager();
    let expected = [
        (ts(0), 10_u64),
        (ts(1), 9),
        (ts(2), 8),
        (ts(3), 7),
        (ts(4), 6),
        (ts(5), 5),
        (ts(6), 4),
        (ts(7), 3),
        (ts(8), 2),
        (ts(9), 1),
    ];

    for (now_unix, expected_secs) in expected {
        assert_eq!(
            manager.start_after_next_slot(now_unix),
            Duration::from_secs(expected_secs)
        );
    }
}

#[test]
fn test_99_vector_epoch_boundaries_for_epoch_size_six() {
    let manager = test_manager();
    let expected = [
        (0_u64, 0_u64, 0_u64),
        (1, 0, 1),
        (5, 0, 5),
        (6, 1, 0),
        (7, 1, 1),
        (11, 1, 5),
        (12, 2, 0),
        (13, 2, 1),
    ];

    for (height, expected_epoch, expected_slot) in expected {
        assert_eq!(manager.epoch_of_height(height), expected_epoch);
        assert_eq!(manager.slot_in_epoch(height), expected_slot);
    }
}

#[test]
fn test_100_load_vector_timestamp_gating_around_many_slot_boundaries() -> TestResult {
    let manager = test_manager();

    for slot in 0_u64..64_u64 {
        let start = manager.slot_start_unix(slot);

        assert_eq!(
            manager.slot_and_round_from_block_timestamp(start)?,
            (slot, 0, 0)
        );
        assert_eq!(
            manager.round_for_height_from_block_timestamp(slot, start)?,
            (0, 0)
        );

        let last_second = start.saturating_add(manager.block_interval_secs().saturating_sub(1));
        assert_eq!(
            manager.slot_and_round_from_block_timestamp(last_second)?,
            (
                slot,
                manager
                    .block_interval_secs()
                    .saturating_sub(1)
                    .div_euclid(manager.failover_window_secs()),
                manager.block_interval_secs().saturating_sub(1)
            )
        );
    }

    Ok(())
}
