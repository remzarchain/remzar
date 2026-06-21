use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::consensus::por_007_leader_schedule::{CommitteeSnapshot, LeaderSchedule, LeaderTrace};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::error::Error;
use std::io;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn parent_hash(seed: u64) -> [u8; 64] {
    let mut out = [0_u8; 64];
    let mut state = seed;

    for byte in &mut out {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = state.to_be_bytes()[7];
    }

    out
}

fn test_config() -> TimeConfig {
    TimeConfig {
        block_interval_secs: 10,
        puzzle_interval_secs: 1,
        activation_warmup_secs: 20,
        genesis_time_unix: 1_000,
        reward_delay_blocks: 1,
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

fn sorted_validators_from_seeds(seeds: &[u64]) -> Vec<String> {
    let mut validators = seeds.iter().copied().map(wallet).collect::<Vec<_>>();
    validators.sort();
    validators
}

fn valid_snapshot(
    height: u64,
    parent_hash_value: [u8; 64],
    validators: Vec<String>,
) -> CommitteeSnapshot {
    let activation_delay_blocks = 4;
    let committee_hash = LeaderSchedule::compute_committee_hash(
        parent_hash_value,
        height,
        activation_delay_blocks,
        &validators,
    );

    CommitteeSnapshot {
        height,
        parent_hash: parent_hash_value,
        activation_delay_blocks,
        validators,
        committee_hash,
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
fn test_01_new_schedule_canonicalizes_uppercase_local_wallet() -> TestResult {
    let canonical = wallet(1);
    let schedule = LeaderSchedule::new(canonical.to_ascii_uppercase())?;

    assert_eq!(schedule.local_wallet(), canonical);
    Ok(())
}

#[test]
fn test_02_new_schedule_rejects_invalid_local_wallet() {
    assert!(LeaderSchedule::new("bad-wallet".to_string()).is_err());
}

#[test]
fn test_03_local_wallet_accessor_returns_canonical_wallet() -> TestResult {
    let local = wallet(3);
    let schedule = LeaderSchedule::new(local.clone())?;

    assert_eq!(schedule.local_wallet(), local);
    Ok(())
}

#[test]
fn test_04_committee_snapshot_len_and_empty_helpers() {
    let snapshot = valid_snapshot(1, parent_hash(4), sorted_validators_from_seeds(&[4, 5, 6]));

    assert_eq!(snapshot.len(), 3);
    assert!(!snapshot.is_empty());
}

#[test]
fn test_05_committee_snapshot_contains_wallet_is_case_insensitive() {
    let wallet_a = wallet(5);
    let snapshot = valid_snapshot(1, parent_hash(5), vec![wallet_a.clone()]);

    assert!(snapshot.contains_wallet(&wallet_a));
    assert!(snapshot.contains_wallet(&wallet_a.to_ascii_uppercase()));
}

#[test]
fn test_06_committee_snapshot_contains_wallet_false_for_missing_or_invalid_wallet() {
    let snapshot = valid_snapshot(1, parent_hash(6), vec![wallet(6)]);

    assert!(!snapshot.contains_wallet(&wallet(7)));
    assert!(!snapshot.contains_wallet("bad-wallet"));
}

#[test]
fn test_07_compute_committee_hash_is_deterministic() {
    let validators = sorted_validators_from_seeds(&[7, 8, 9]);
    let parent = parent_hash(7);

    let first = LeaderSchedule::compute_committee_hash(parent, 7, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent, 7, 4, &validators);

    assert_eq!(first, second);
}

#[test]
fn test_08_compute_committee_hash_changes_when_parent_hash_changes() {
    let validators = sorted_validators_from_seeds(&[8, 9, 10]);

    let first = LeaderSchedule::compute_committee_hash(parent_hash(8), 8, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent_hash(9), 8, 4, &validators);

    assert_ne!(first, second);
}

#[test]
fn test_09_compute_committee_hash_changes_when_height_changes() {
    let validators = sorted_validators_from_seeds(&[9, 10, 11]);
    let parent = parent_hash(9);

    let first = LeaderSchedule::compute_committee_hash(parent, 9, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent, 10, 4, &validators);

    assert_ne!(first, second);
}

#[test]
fn test_10_compute_committee_hash_changes_when_activation_delay_changes() {
    let validators = sorted_validators_from_seeds(&[10, 11, 12]);
    let parent = parent_hash(10);

    let first = LeaderSchedule::compute_committee_hash(parent, 10, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent, 10, 5, &validators);

    assert_ne!(first, second);
}

#[test]
fn test_11_compute_committee_hash_changes_when_validator_order_changes() {
    let parent = parent_hash(11);
    let validators_sorted = sorted_validators_from_seeds(&[11, 12, 13]);
    let mut validators_reversed = validators_sorted.clone();
    validators_reversed.reverse();

    let first = LeaderSchedule::compute_committee_hash(parent, 11, 4, &validators_sorted);
    let second = LeaderSchedule::compute_committee_hash(parent, 11, 4, &validators_reversed);

    assert_ne!(first, second);
}

#[test]
fn test_12_leader_score_is_deterministic() {
    let snapshot = valid_snapshot(12, parent_hash(12), sorted_validators_from_seeds(&[12, 13]));
    let validator = wallet(12);

    let first = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &validator,
    );
    let second = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &validator,
    );

    assert_eq!(first, second);
}

#[test]
fn test_13_leader_score_changes_when_validator_changes() {
    let snapshot = valid_snapshot(13, parent_hash(13), sorted_validators_from_seeds(&[13, 14]));

    let first = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &wallet(13),
    );
    let second = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &wallet(14),
    );

    assert_ne!(first, second);
}

#[test]
fn test_14_leader_score_changes_when_round_changes() {
    let snapshot = valid_snapshot(14, parent_hash(14), sorted_validators_from_seeds(&[14, 15]));
    let validator = wallet(14);

    let first = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &validator,
    );
    let second = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        1,
        &validator,
    );

    assert_ne!(first, second);
}

#[test]
fn test_15_ordered_validators_for_round_matches_manual_score_sort() -> TestResult {
    let snapshot = valid_snapshot(
        15,
        parent_hash(15),
        sorted_validators_from_seeds(&[15, 16, 17]),
    );

    let mut manual = snapshot
        .validators
        .iter()
        .map(|validator| {
            (
                LeaderSchedule::leader_score(
                    snapshot.committee_hash,
                    snapshot.parent_hash,
                    snapshot.height,
                    0,
                    validator,
                ),
                validator.clone(),
            )
        })
        .collect::<Vec<_>>();
    manual.sort_unstable_by(|(sa, wa), (sb, wb)| sa.cmp(sb).then_with(|| wa.cmp(wb)));

    let expected = manual
        .into_iter()
        .map(|(_score, validator)| validator)
        .collect::<Vec<_>>();

    assert_eq!(
        LeaderSchedule::ordered_validators_for_round(&snapshot, 0)?,
        expected
    );
    Ok(())
}

#[test]
fn test_16_ordered_validators_for_round_is_deterministic() -> TestResult {
    let snapshot = valid_snapshot(
        16,
        parent_hash(16),
        sorted_validators_from_seeds(&[16, 17, 18, 19]),
    );

    let first = LeaderSchedule::ordered_validators_for_round(&snapshot, 2)?;
    let second = LeaderSchedule::ordered_validators_for_round(&snapshot, 2)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn test_17_ordered_validators_for_round_returns_permutation_of_snapshot_validators() -> TestResult {
    let snapshot = valid_snapshot(
        17,
        parent_hash(17),
        sorted_validators_from_seeds(&[17, 18, 19, 20]),
    );

    let mut ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 1)?;
    let mut expected = snapshot.validators.clone();

    ordered.sort();
    expected.sort();

    assert_eq!(ordered, expected);
    Ok(())
}

#[test]
fn test_18_leader_for_round_returns_first_ordered_validator() -> TestResult {
    let snapshot = valid_snapshot(
        18,
        parent_hash(18),
        sorted_validators_from_seeds(&[18, 19, 20]),
    );

    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 0)?;
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;

    assert_eq!(decision.leader, ordered[0]);
    Ok(())
}

#[test]
fn test_19_leader_decision_fields_match_snapshot_and_round() -> TestResult {
    let snapshot = valid_snapshot(
        19,
        parent_hash(19),
        sorted_validators_from_seeds(&[19, 20, 21]),
    );
    let decision = LeaderSchedule::leader_for_round(&snapshot, 3)?;

    assert_eq!(decision.height, snapshot.height);
    assert_eq!(decision.round, 3);
    assert_eq!(decision.parent_hash, snapshot.parent_hash);
    assert_eq!(decision.committee_hash, snapshot.committee_hash);
    assert_eq!(decision.committee_len, snapshot.validators.len());
    assert!(decision.leader_index_in_snapshot < snapshot.validators.len());
    assert_eq!(
        snapshot.validators[decision.leader_index_in_snapshot],
        decision.leader
    );
    Ok(())
}

#[test]
fn test_20_leader_for_round_single_validator_always_selects_only_validator() -> TestResult {
    let only = wallet(20);
    let snapshot = valid_snapshot(20, parent_hash(20), vec![only.clone()]);

    for round in [0_u64, 1, 2, 100, u64::MAX] {
        let decision = LeaderSchedule::leader_for_round(&snapshot, round)?;
        assert_eq!(decision.leader, only);
        assert_eq!(decision.leader_index_in_snapshot, 0);
        assert_eq!(decision.committee_len, 1);
    }

    Ok(())
}

#[test]
fn test_21_height_start_unix_height_zero_and_one_return_genesis() {
    let tm = test_manager();

    assert_eq!(LeaderSchedule::height_start_unix(&tm, 0), 1_000);
    assert_eq!(LeaderSchedule::height_start_unix(&tm, 1), 1_000);
}

#[test]
fn test_22_height_start_unix_vectors_after_height_one() {
    let tm = test_manager();

    assert_eq!(LeaderSchedule::height_start_unix(&tm, 2), 1_010);
    assert_eq!(LeaderSchedule::height_start_unix(&tm, 3), 1_020);
    assert_eq!(LeaderSchedule::height_start_unix(&tm, 10), 1_090);
}

#[test]
fn test_23_height_start_unix_saturates_for_large_height() {
    let tm = test_manager();

    assert_eq!(LeaderSchedule::height_start_unix(&tm, u64::MAX), u64::MAX);
}

#[test]
fn test_24_round_for_height_from_timestamp_rejects_height_zero() -> TestResult {
    let tm = test_manager();

    let message = validation_message(LeaderSchedule::round_for_height_from_timestamp(
        &tm, 0, 1_000,
    ))?;

    assert!(message.contains("height=0"));
    Ok(())
}

#[test]
fn test_25_round_for_height_from_timestamp_rejects_before_nominal_start() -> TestResult {
    let tm = test_manager();

    let message = validation_message(LeaderSchedule::round_for_height_from_timestamp(
        &tm, 2, 1_009,
    ))?;

    assert!(message.contains("earlier than nominal start"));
    Ok(())
}

#[test]
fn test_26_round_for_height_from_timestamp_exact_start_is_round_zero() -> TestResult {
    let tm = test_manager();

    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_010)?,
        (0, 0, 0, 1_010)
    );
    Ok(())
}

#[test]
fn test_27_round_for_height_from_timestamp_vectors() -> TestResult {
    let tm = test_manager();

    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_012)?,
        (0, 2, 2, 1_010)
    );
    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_013)?,
        (1, 3, 0, 1_013)
    );
    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_019)?,
        (3, 9, 0, 1_019)
    );
    Ok(())
}

#[test]
fn test_28_round_for_height_now_rejects_height_zero() -> TestResult {
    let tm = test_manager();

    let message = validation_message(LeaderSchedule::round_for_height_now(&tm, 0, 1_000))?;

    assert!(message.contains("height=0"));
    Ok(())
}

#[test]
fn test_29_round_for_height_now_rejects_too_early_past_drift() -> TestResult {
    let tm = test_manager();

    let message = validation_message(LeaderSchedule::round_for_height_now(&tm, 2, 1_007))?;

    assert!(message.contains("too early to propose height 2"));
    Ok(())
}

#[test]
fn test_30_round_for_height_now_accepts_within_drift_and_clamps_to_start() -> TestResult {
    let tm = test_manager();

    assert_eq!(
        LeaderSchedule::round_for_height_now(&tm, 2, 1_008)?,
        (0, 0, 0, 1_010)
    );
    Ok(())
}

#[test]
fn test_31_round_for_height_now_exact_start_matches_timestamp_helper() -> TestResult {
    let tm = test_manager();

    assert_eq!(
        LeaderSchedule::round_for_height_now(&tm, 2, 1_010)?,
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_010)?
    );
    Ok(())
}

#[test]
fn test_32_ensure_within_slot_proposal_window_accepts_before_deadline() -> TestResult {
    let tm = test_manager();

    LeaderSchedule::ensure_within_slot_proposal_window(&tm, 0)?;
    LeaderSchedule::ensure_within_slot_proposal_window(&tm, 7)?;
    Ok(())
}

#[test]
fn test_33_ensure_within_slot_proposal_window_rejects_at_deadline() -> TestResult {
    let tm = test_manager();

    let message = validation_message(LeaderSchedule::ensure_within_slot_proposal_window(&tm, 8))?;

    assert!(message.contains("too late in slot"));
    assert!(message.contains("elapsed=8s"));
    assert!(message.contains("deadline=8s"));
    Ok(())
}

#[test]
fn test_34_ensure_enough_time_in_round_for_local_puzzle_accepts_when_remaining_meets_need()
-> TestResult {
    let tm = test_manager();

    LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 0)?;
    LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 1)?;
    Ok(())
}

#[test]
fn test_35_ensure_enough_time_in_round_for_local_puzzle_rejects_when_remaining_too_small()
-> TestResult {
    let tm = test_manager();

    let message =
        validation_message(LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 2))?;

    assert!(message.contains("too late in round"));
    assert!(message.contains("in_round=2s"));
    assert!(message.contains("need>=2s"));
    Ok(())
}

#[test]
fn test_36_ordered_validators_rejects_snapshot_height_zero() -> TestResult {
    let mut snapshot = valid_snapshot(1, parent_hash(36), vec![wallet(36)]);
    snapshot.height = 0;
    snapshot.committee_hash = LeaderSchedule::compute_committee_hash(
        snapshot.parent_hash,
        snapshot.height,
        snapshot.activation_delay_blocks,
        &snapshot.validators,
    );

    let message = validation_message(LeaderSchedule::ordered_validators_for_round(&snapshot, 0))?;

    assert!(message.contains("height=0"));
    Ok(())
}

#[test]
fn test_37_leader_for_round_rejects_empty_snapshot() -> TestResult {
    let snapshot = valid_snapshot(37, parent_hash(37), Vec::new());

    let message = validation_message(LeaderSchedule::leader_for_round(&snapshot, 0))?;

    assert!(message.contains("committee snapshot empty"));
    Ok(())
}

#[test]
fn test_38_ordered_validators_rejects_duplicate_canonical_validators() -> TestResult {
    let lower = wallet(38);
    let upper = lower.to_ascii_uppercase();
    let snapshot = valid_snapshot(38, parent_hash(38), vec![lower, upper]);

    let message = validation_message(LeaderSchedule::ordered_validators_for_round(&snapshot, 0))?;

    assert!(message.contains("duplicate/non-canonical validators"));
    Ok(())
}

#[test]
fn test_39_leader_for_round_rejects_corrupt_committee_hash() -> TestResult {
    let mut snapshot = valid_snapshot(39, parent_hash(39), vec![wallet(39), wallet(40)]);
    snapshot.committee_hash[0] ^= 0x01;

    let message = validation_message(LeaderSchedule::leader_for_round(&snapshot, 0))?;

    assert!(message.contains("committee snapshot hash mismatch"));
    Ok(())
}

#[test]
fn test_40_trace_fingerprint_is_deterministic_and_changes_when_round_changes() -> TestResult {
    let snapshot = valid_snapshot(
        40,
        parent_hash(40),
        sorted_validators_from_seeds(&[40, 41, 42]),
    );
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;
    let trace = LeaderTrace {
        snapshot: snapshot.clone(),
        decision,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    let first = LeaderSchedule::trace_fingerprint(&trace);
    let second = LeaderSchedule::trace_fingerprint(&trace);

    assert_eq!(first, second);

    let mut changed = trace.clone();
    changed.decision = LeaderSchedule::leader_for_round(&changed.snapshot, 1)?;

    let changed_fingerprint = LeaderSchedule::trace_fingerprint(&changed);

    assert_ne!(first, changed_fingerprint);
    Ok(())
}

#[test]
fn test_41_leader_schedule_clone_and_debug_preserve_local_wallet() -> TestResult {
    let local = wallet(41);
    let schedule = LeaderSchedule::new(local.clone())?;
    let cloned = schedule.clone();
    let debug_text = format!("{schedule:?}");

    assert_eq!(cloned.local_wallet(), local);
    assert!(debug_text.contains("LeaderSchedule"));
    assert!(debug_text.contains("local_wallet"));
    Ok(())
}

#[test]
fn test_42_committee_snapshot_clone_and_debug_preserve_fields() {
    let snapshot = valid_snapshot(42, parent_hash(42), sorted_validators_from_seeds(&[42, 43]));
    let cloned = snapshot.clone();
    let debug_text = format!("{snapshot:?}");

    assert_eq!(cloned.height, snapshot.height);
    assert_eq!(cloned.parent_hash, snapshot.parent_hash);
    assert_eq!(
        cloned.activation_delay_blocks,
        snapshot.activation_delay_blocks
    );
    assert_eq!(cloned.validators, snapshot.validators);
    assert_eq!(cloned.committee_hash, snapshot.committee_hash);
    assert!(debug_text.contains("CommitteeSnapshot"));
    assert!(debug_text.contains("committee_hash"));
}

#[test]
fn test_43_leader_decision_clone_and_debug_preserve_fields() -> TestResult {
    let snapshot = valid_snapshot(
        43,
        parent_hash(43),
        sorted_validators_from_seeds(&[43, 44, 45]),
    );
    let decision = LeaderSchedule::leader_for_round(&snapshot, 1)?;
    let cloned = decision.clone();
    let debug_text = format!("{decision:?}");

    assert_eq!(cloned.height, decision.height);
    assert_eq!(cloned.round, decision.round);
    assert_eq!(cloned.parent_hash, decision.parent_hash);
    assert_eq!(cloned.committee_hash, decision.committee_hash);
    assert_eq!(cloned.leader, decision.leader);
    assert_eq!(
        cloned.leader_index_in_snapshot,
        decision.leader_index_in_snapshot
    );
    assert_eq!(cloned.committee_len, decision.committee_len);
    assert!(debug_text.contains("LeaderDecision"));
    assert!(debug_text.contains("leader_index_in_snapshot"));
    Ok(())
}

#[test]
fn test_44_leader_trace_clone_and_debug_preserve_fields() -> TestResult {
    let snapshot = valid_snapshot(44, parent_hash(44), sorted_validators_from_seeds(&[44, 45]));
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;
    let trace = LeaderTrace {
        snapshot,
        decision,
        observed_time_unix: 1_004,
        height_start_unix: 1_000,
        round_start_unix: 1_003,
        elapsed_secs: 4,
        in_round_secs: 1,
        failover_window_secs: 3,
    };
    let cloned = trace.clone();
    let debug_text = format!("{trace:?}");

    assert_eq!(cloned.observed_time_unix, trace.observed_time_unix);
    assert_eq!(cloned.height_start_unix, trace.height_start_unix);
    assert_eq!(cloned.round_start_unix, trace.round_start_unix);
    assert_eq!(cloned.elapsed_secs, trace.elapsed_secs);
    assert_eq!(cloned.in_round_secs, trace.in_round_secs);
    assert_eq!(cloned.failover_window_secs, trace.failover_window_secs);
    assert!(debug_text.contains("LeaderTrace"));
    assert!(debug_text.contains("observed_time_unix"));
    Ok(())
}

#[test]
fn test_45_existing_duration_import_is_used_by_timing_guard_vector() -> TestResult {
    let tm = test_manager();
    let deadline = Duration::from_secs(tm.proposal_deadline_secs());

    assert_eq!(deadline, Duration::from_secs(8));
    LeaderSchedule::ensure_within_slot_proposal_window(&tm, deadline.as_secs() - 1)?;
    Ok(())
}

#[test]
fn test_46_compute_committee_hash_allows_empty_validator_slice_deterministically() {
    let parent = parent_hash(46);
    let validators = Vec::<String>::new();

    let first = LeaderSchedule::compute_committee_hash(parent, 46, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent, 46, 4, &validators);

    assert_eq!(first, second);
}

#[test]
fn test_47_compute_committee_hash_empty_and_nonempty_validator_sets_differ() {
    let parent = parent_hash(47);
    let empty = Vec::<String>::new();
    let nonempty = vec![wallet(47)];

    let empty_hash = LeaderSchedule::compute_committee_hash(parent, 47, 4, &empty);
    let nonempty_hash = LeaderSchedule::compute_committee_hash(parent, 47, 4, &nonempty);

    assert_ne!(empty_hash, nonempty_hash);
}

#[test]
fn test_48_compute_committee_hash_u64_max_height_and_delay_is_deterministic() {
    let parent = parent_hash(48);
    let validators = sorted_validators_from_seeds(&[48, 49]);

    let first = LeaderSchedule::compute_committee_hash(parent, u64::MAX, u64::MAX, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent, u64::MAX, u64::MAX, &validators);

    assert_eq!(first, second);
}

#[test]
fn test_49_leader_score_u64_max_round_is_deterministic() {
    let snapshot = valid_snapshot(49, parent_hash(49), sorted_validators_from_seeds(&[49, 50]));
    let validator = wallet(49);

    let first = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        u64::MAX,
        &validator,
    );
    let second = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        u64::MAX,
        &validator,
    );

    assert_eq!(first, second);
}

#[test]
fn test_50_ordered_validators_for_round_accepts_u64_max_round() -> TestResult {
    let snapshot = valid_snapshot(
        50,
        parent_hash(50),
        sorted_validators_from_seeds(&[50, 51, 52]),
    );

    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, u64::MAX)?;

    assert_eq!(ordered.len(), snapshot.validators.len());

    let mut sorted_ordered = ordered;
    let mut expected = snapshot.validators.clone();
    sorted_ordered.sort();
    expected.sort();

    assert_eq!(sorted_ordered, expected);
    Ok(())
}

#[test]
fn test_51_leader_for_round_u64_max_round_has_valid_index_and_len() -> TestResult {
    let snapshot = valid_snapshot(
        51,
        parent_hash(51),
        sorted_validators_from_seeds(&[51, 52, 53]),
    );
    let decision = LeaderSchedule::leader_for_round(&snapshot, u64::MAX)?;

    assert_eq!(decision.round, u64::MAX);
    assert_eq!(decision.committee_len, snapshot.validators.len());
    assert!(decision.leader_index_in_snapshot < snapshot.validators.len());
    assert_eq!(
        snapshot.validators[decision.leader_index_in_snapshot],
        decision.leader
    );
    Ok(())
}

#[test]
fn test_52_snapshot_with_all_zero_wallet_is_valid_for_ordering() -> TestResult {
    let all_zero = format!("r{}", "0".repeat(128));
    let snapshot = valid_snapshot(52, parent_hash(52), vec![all_zero.clone(), wallet(52)]);

    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 0)?;

    assert_eq!(ordered.len(), 2);
    assert!(ordered.contains(&all_zero));
    assert!(ordered.contains(&wallet(52)));
    Ok(())
}

#[test]
fn test_53_snapshot_with_all_f_wallet_is_valid_for_leader_selection() -> TestResult {
    let all_f = format!("r{}", "f".repeat(128));
    let snapshot = valid_snapshot(53, parent_hash(53), vec![wallet(53), all_f.clone()]);
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;

    assert_eq!(decision.committee_len, 2);
    assert!(decision.leader == wallet(53) || decision.leader == all_f);
    Ok(())
}

#[test]
fn test_54_ordered_validators_rejects_invalid_wallet_in_snapshot() -> TestResult {
    let snapshot = valid_snapshot(
        54,
        parent_hash(54),
        vec![wallet(54), "bad-wallet".to_string()],
    );

    let message = validation_message(LeaderSchedule::ordered_validators_for_round(&snapshot, 0))?;

    assert!(!message.is_empty());
    Ok(())
}

#[test]
fn test_55_unsorted_but_canonical_snapshot_is_valid_if_hash_matches_that_order() -> TestResult {
    let mut validators = sorted_validators_from_seeds(&[55, 56, 57]);
    validators.reverse();

    let snapshot = valid_snapshot(55, parent_hash(55), validators.clone());
    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 0)?;

    assert_eq!(ordered.len(), validators.len());

    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;
    assert_eq!(
        snapshot.validators[decision.leader_index_in_snapshot],
        decision.leader
    );
    Ok(())
}

#[test]
fn test_56_snapshot_rejects_activation_delay_changed_without_rehash() -> TestResult {
    let mut snapshot = valid_snapshot(56, parent_hash(56), sorted_validators_from_seeds(&[56, 57]));

    snapshot.activation_delay_blocks = snapshot.activation_delay_blocks.saturating_add(1);

    let message = validation_message(LeaderSchedule::leader_for_round(&snapshot, 0))?;

    assert!(message.contains("committee snapshot hash mismatch"));
    Ok(())
}

#[test]
fn test_57_snapshot_rejects_height_changed_without_rehash() -> TestResult {
    let mut snapshot = valid_snapshot(57, parent_hash(57), sorted_validators_from_seeds(&[57, 58]));

    snapshot.height = snapshot.height.saturating_add(1);

    let message = validation_message(LeaderSchedule::ordered_validators_for_round(&snapshot, 0))?;

    assert!(message.contains("committee snapshot hash mismatch"));
    Ok(())
}

#[test]
fn test_58_snapshot_rejects_parent_hash_changed_without_rehash() -> TestResult {
    let mut snapshot = valid_snapshot(58, parent_hash(58), sorted_validators_from_seeds(&[58, 59]));

    snapshot.parent_hash[0] ^= 0x01;

    let message = validation_message(LeaderSchedule::leader_for_round(&snapshot, 0))?;

    assert!(message.contains("committee snapshot hash mismatch"));
    Ok(())
}

#[test]
fn test_59_round_for_height_from_timestamp_zero_failover_window_clamps_to_one() -> TestResult {
    let mut cfg = test_config();
    cfg.failover_window_secs = 0;
    let tm = TimeManager::new(cfg);

    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_015)?,
        (5, 5, 0, 1_015)
    );
    Ok(())
}

#[test]
fn test_60_round_for_height_now_zero_drift_rejects_one_second_early() -> TestResult {
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 0;
    let tm = TimeManager::new(cfg);

    let message = validation_message(LeaderSchedule::round_for_height_now(&tm, 2, 1_009))?;

    assert!(message.contains("too early to propose height 2"));
    Ok(())
}

#[test]
fn test_61_round_for_height_now_zero_drift_accepts_exact_height_start() -> TestResult {
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 0;
    let tm = TimeManager::new(cfg);

    assert_eq!(
        LeaderSchedule::round_for_height_now(&tm, 2, 1_010)?,
        (0, 0, 0, 1_010)
    );
    Ok(())
}

#[test]
fn test_62_round_for_height_now_large_drift_accepts_early_and_clamps_to_start() -> TestResult {
    let mut cfg = test_config();
    cfg.slot_gate_drift_secs = 100;
    let tm = TimeManager::new(cfg);

    assert_eq!(
        LeaderSchedule::round_for_height_now(&tm, 2, 950)?,
        (0, 0, 0, 1_010)
    );
    Ok(())
}

#[test]
fn test_63_round_for_height_from_timestamp_far_future_vector() -> TestResult {
    let tm = test_manager();

    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, 1_100)?,
        (30, 90, 0, 1_100)
    );
    Ok(())
}

#[test]
fn test_64_round_for_height_from_timestamp_in_round_remainder_vector() -> TestResult {
    let tm = test_manager();

    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 3, 1_026)?,
        (2, 6, 0, 1_026)
    );
    assert_eq!(
        LeaderSchedule::round_for_height_from_timestamp(&tm, 3, 1_027)?,
        (2, 7, 1, 1_026)
    );
    Ok(())
}

#[test]
fn test_65_ensure_within_slot_proposal_window_with_zero_deadline_clamps_to_one() -> TestResult {
    let mut cfg = test_config();
    cfg.failover_proposal_deadline_secs = 0;
    let tm = TimeManager::new(cfg);

    LeaderSchedule::ensure_within_slot_proposal_window(&tm, 0)?;

    let message = validation_message(LeaderSchedule::ensure_within_slot_proposal_window(&tm, 1))?;

    assert!(message.contains("deadline=1s"));
    Ok(())
}

#[test]
fn test_66_ensure_within_slot_proposal_window_rejects_u64_max_elapsed() -> TestResult {
    let tm = test_manager();

    let message = validation_message(LeaderSchedule::ensure_within_slot_proposal_window(
        &tm,
        u64::MAX,
    ))?;

    assert!(message.contains("too late in slot"));
    assert!(message.contains("deadline=8s"));
    Ok(())
}

#[test]
fn test_67_ensure_enough_time_in_round_zero_tau_clamps_to_one_and_rejects() -> TestResult {
    let mut cfg = test_config();
    cfg.failover_window_secs = 0;
    cfg.puzzle_interval_secs = 1;
    let tm = TimeManager::new(cfg);

    let message =
        validation_message(LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 0))?;

    assert!(message.contains("too late in round"));
    assert!(message.contains("remaining=1s"));
    assert!(message.contains("need>=2s"));
    Ok(())
}

#[test]
fn test_68_ensure_enough_time_in_round_zero_puzzle_clamps_need_to_two() -> TestResult {
    let mut cfg = test_config();
    cfg.puzzle_interval_secs = 0;
    cfg.failover_window_secs = 3;
    let tm = TimeManager::new(cfg);

    LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 1)?;

    let message =
        validation_message(LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 2))?;

    assert!(message.contains("need>=2s"));
    Ok(())
}

#[test]
fn test_69_trace_fingerprint_changes_when_committee_hash_changes() -> TestResult {
    let snapshot = valid_snapshot(69, parent_hash(69), sorted_validators_from_seeds(&[69, 70]));
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;
    let trace = LeaderTrace {
        snapshot,
        decision,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    let first = LeaderSchedule::trace_fingerprint(&trace);

    let changed_snapshot =
        valid_snapshot(69, parent_hash(70), sorted_validators_from_seeds(&[69, 70]));
    let changed_decision = LeaderSchedule::leader_for_round(&changed_snapshot, 0)?;
    let changed_trace = LeaderTrace {
        snapshot: changed_snapshot,
        decision: changed_decision,
        ..trace
    };

    let second = LeaderSchedule::trace_fingerprint(&changed_trace);

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_70_trace_fingerprint_changes_when_leader_changes() -> TestResult {
    let mut found = None;

    for seed in 70_u64..200_u64 {
        let snapshot = valid_snapshot(
            seed,
            parent_hash(seed),
            sorted_validators_from_seeds(&[70, 71, 72, 73]),
        );
        let decision_a = LeaderSchedule::leader_for_round(&snapshot, 0)?;
        let decision_b = LeaderSchedule::leader_for_round(&snapshot, 1)?;

        if decision_a.leader != decision_b.leader {
            found = Some((snapshot, decision_a, decision_b));
            break;
        }
    }

    let (snapshot, decision_a, decision_b) =
        found.ok_or_else(|| test_error("could not find leader-changing round vector"))?;

    let trace_a = LeaderTrace {
        snapshot: snapshot.clone(),
        decision: decision_a,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };
    let trace_b = LeaderTrace {
        snapshot,
        decision: decision_b,
        observed_time_unix: 1_003,
        height_start_unix: 1_000,
        round_start_unix: 1_003,
        elapsed_secs: 3,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    assert_ne!(
        LeaderSchedule::trace_fingerprint(&trace_a),
        LeaderSchedule::trace_fingerprint(&trace_b)
    );
    Ok(())
}

#[test]
fn test_71_trace_fingerprint_ignores_observed_time_when_core_leader_context_same() -> TestResult {
    let snapshot = valid_snapshot(71, parent_hash(71), sorted_validators_from_seeds(&[71, 72]));
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;
    let trace_a = LeaderTrace {
        snapshot: snapshot.clone(),
        decision: decision.clone(),
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };
    let trace_b = LeaderTrace {
        snapshot,
        decision,
        observed_time_unix: 1_002,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 2,
        in_round_secs: 2,
        failover_window_secs: 3,
    };

    assert_eq!(
        LeaderSchedule::trace_fingerprint(&trace_a),
        LeaderSchedule::trace_fingerprint(&trace_b)
    );
    Ok(())
}

#[test]
fn test_72_leader_score_accepts_noncanonical_validator_string_deterministically() {
    let snapshot = valid_snapshot(72, parent_hash(72), sorted_validators_from_seeds(&[72, 73]));
    let validator = wallet(72).to_ascii_uppercase();

    let first = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &validator,
    );
    let second = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &validator,
    );

    assert_eq!(first, second);
}

#[test]
fn test_73_leader_score_differs_for_uppercase_and_lowercase_validator_input() {
    let snapshot = valid_snapshot(73, parent_hash(73), sorted_validators_from_seeds(&[73, 74]));
    let lower = wallet(73);
    let upper = lower.to_ascii_uppercase();

    let lower_score = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &lower,
    );
    let upper_score = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &upper,
    );

    assert_ne!(lower_score, upper_score);
}

#[test]
fn test_74_compute_committee_hash_differs_for_uppercase_and_lowercase_validator_input() {
    let parent = parent_hash(74);
    let lower = vec![wallet(74)];
    let upper = vec![wallet(74).to_ascii_uppercase()];

    let lower_hash = LeaderSchedule::compute_committee_hash(parent, 74, 4, &lower);
    let upper_hash = LeaderSchedule::compute_committee_hash(parent, 74, 4, &upper);

    assert_ne!(lower_hash, upper_hash);
}

#[test]
fn test_75_ordered_validators_accepts_single_uppercase_validator_when_hash_matches() -> TestResult {
    let validator = wallet(75).to_ascii_uppercase();
    let snapshot = valid_snapshot(75, parent_hash(75), vec![validator.clone()]);

    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 0)?;
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;

    assert_eq!(ordered, vec![validator.clone()]);
    assert_eq!(decision.leader, validator);
    assert_eq!(decision.leader_index_in_snapshot, 0);
    assert_eq!(decision.committee_len, 1);
    Ok(())
}

#[test]
fn test_76_height_start_unix_with_zero_genesis_config_clamps_to_one() {
    let mut cfg = test_config();
    cfg.genesis_time_unix = 0;
    let tm = TimeManager::new(cfg);

    assert_eq!(LeaderSchedule::height_start_unix(&tm, 1), 1);
    assert_eq!(LeaderSchedule::height_start_unix(&tm, 2), 11);
}

#[test]
fn test_77_height_start_unix_with_zero_block_interval_uses_one_second_steps() {
    let mut cfg = test_config();
    cfg.block_interval_secs = 0;
    let tm = TimeManager::new(cfg);

    assert_eq!(LeaderSchedule::height_start_unix(&tm, 1), 1_000);
    assert_eq!(LeaderSchedule::height_start_unix(&tm, 2), 1_001);
    assert_eq!(LeaderSchedule::height_start_unix(&tm, 10), 1_009);
}

#[test]
fn test_78_load_ordered_validators_many_rounds_are_valid_permutations() -> TestResult {
    let snapshot = valid_snapshot(
        78,
        parent_hash(78),
        sorted_validators_from_seeds(&[78, 79, 80, 81, 82, 83, 84, 85]),
    );

    for round in 0_u64..64_u64 {
        let mut ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, round)?;
        let mut expected = snapshot.validators.clone();

        ordered.sort();
        expected.sort();

        assert_eq!(ordered, expected);
    }

    Ok(())
}

#[test]
fn test_79_load_leader_for_round_many_rounds_always_selects_committee_member() -> TestResult {
    let snapshot = valid_snapshot(
        79,
        parent_hash(79),
        sorted_validators_from_seeds(&[79, 80, 81, 82, 83, 84]),
    );

    for round in 0_u64..128_u64 {
        let decision = LeaderSchedule::leader_for_round(&snapshot, round)?;

        assert!(snapshot.contains_wallet(&decision.leader));
        assert!(decision.leader_index_in_snapshot < snapshot.validators.len());
        assert_eq!(decision.committee_len, snapshot.validators.len());
    }

    Ok(())
}

#[test]
fn test_80_adversarial_snapshot_mutation_matrix_rejects_invalid_invariants() -> TestResult {
    let base = valid_snapshot(80, parent_hash(80), sorted_validators_from_seeds(&[80, 81]));

    let mut empty = base.clone();
    empty.validators.clear();
    empty.committee_hash = LeaderSchedule::compute_committee_hash(
        empty.parent_hash,
        empty.height,
        empty.activation_delay_blocks,
        &empty.validators,
    );

    let mut duplicate = base.clone();
    duplicate.validators.push(duplicate.validators[0].clone());
    duplicate.committee_hash = LeaderSchedule::compute_committee_hash(
        duplicate.parent_hash,
        duplicate.height,
        duplicate.activation_delay_blocks,
        &duplicate.validators,
    );

    let mut bad_hash = base;
    bad_hash.committee_hash[63] ^= 0x01;

    for snapshot in [empty, duplicate, bad_hash] {
        assert!(LeaderSchedule::leader_for_round(&snapshot, 0).is_err());
    }

    Ok(())
}

#[test]
fn test_81_vector_committee_hash_is_64_bytes() {
    let validators = sorted_validators_from_seeds(&[81, 82, 83]);
    let hash = LeaderSchedule::compute_committee_hash(parent_hash(81), 81, 4, &validators);

    assert_eq!(hash.len(), 64);
}

#[test]
fn test_82_vector_leader_score_is_64_bytes() {
    let snapshot = valid_snapshot(82, parent_hash(82), sorted_validators_from_seeds(&[82, 83]));
    let score = LeaderSchedule::leader_score(
        snapshot.committee_hash,
        snapshot.parent_hash,
        snapshot.height,
        0,
        &snapshot.validators[0],
    );

    assert_eq!(score.len(), 64);
}

#[test]
fn test_83_vector_trace_fingerprint_is_64_bytes() -> TestResult {
    let snapshot = valid_snapshot(83, parent_hash(83), sorted_validators_from_seeds(&[83, 84]));
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;
    let trace = LeaderTrace {
        snapshot,
        decision,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    let fingerprint = LeaderSchedule::trace_fingerprint(&trace);

    assert_eq!(fingerprint.len(), 64);
    Ok(())
}

#[test]
fn test_84_vector_single_validator_ordered_list_is_original_validator() -> TestResult {
    let only = wallet(84);
    let snapshot = valid_snapshot(84, parent_hash(84), vec![only.clone()]);

    for round in [0_u64, 1, 2, 999, u64::MAX] {
        assert_eq!(
            LeaderSchedule::ordered_validators_for_round(&snapshot, round)?,
            vec![only.clone()]
        );
    }

    Ok(())
}

#[test]
fn test_85_edge_committee_hash_changes_when_single_validator_changes_by_one_digit() {
    let parent = parent_hash(85);
    let first = vec![wallet(85)];
    let second = vec![wallet(86)];

    let first_hash = LeaderSchedule::compute_committee_hash(parent, 85, 4, &first);
    let second_hash = LeaderSchedule::compute_committee_hash(parent, 85, 4, &second);

    assert_ne!(first_hash, second_hash);
}

#[test]
fn test_86_edge_committee_hash_changes_when_extra_validator_is_appended() {
    let parent = parent_hash(86);
    let first = sorted_validators_from_seeds(&[86, 87]);
    let second = sorted_validators_from_seeds(&[86, 87, 88]);

    let first_hash = LeaderSchedule::compute_committee_hash(parent, 86, 4, &first);
    let second_hash = LeaderSchedule::compute_committee_hash(parent, 86, 4, &second);

    assert_ne!(first_hash, second_hash);
}

#[test]
fn test_87_vector_parent_hash_all_zero_is_supported_by_hash_and_leader_primitives() -> TestResult {
    let validators = sorted_validators_from_seeds(&[87, 88, 89]);
    let snapshot = valid_snapshot(87, [0_u8; 64], validators);

    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 0)?;
    let decision = LeaderSchedule::leader_for_round(&snapshot, 0)?;

    assert_eq!(ordered[0], decision.leader);
    assert_eq!(decision.parent_hash, [0_u8; 64]);
    Ok(())
}

#[test]
fn test_88_vector_parent_hash_all_ff_is_supported_by_hash_and_leader_primitives() -> TestResult {
    let validators = sorted_validators_from_seeds(&[88, 89, 90]);
    let snapshot = valid_snapshot(88, [0xFF_u8; 64], validators);

    let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, 1)?;
    let decision = LeaderSchedule::leader_for_round(&snapshot, 1)?;

    assert_eq!(ordered[0], decision.leader);
    assert_eq!(decision.parent_hash, [0xFF_u8; 64]);
    Ok(())
}

#[test]
fn test_89_edge_round_for_height_from_timestamp_u64_max_timestamp_uses_saturating_round_start()
-> TestResult {
    let tm = test_manager();

    let (round, elapsed, in_round, round_start) =
        LeaderSchedule::round_for_height_from_timestamp(&tm, 2, u64::MAX)?;

    let height_start = LeaderSchedule::height_start_unix(&tm, 2);
    let tau = tm.failover_window_secs().max(1);
    let expected_elapsed = u64::MAX.saturating_sub(height_start);
    let expected_round = expected_elapsed.div_euclid(tau);
    let expected_round_start = height_start.saturating_add(expected_round.saturating_mul(tau));
    let expected_in_round = u64::MAX.saturating_sub(expected_round_start);

    assert_eq!(elapsed, expected_elapsed);
    assert_eq!(round, expected_round);
    assert_eq!(round_start, expected_round_start);
    assert_eq!(in_round, expected_in_round);
    Ok(())
}

#[test]
fn test_90_edge_round_for_height_now_u64_max_timestamp_is_accepted() -> TestResult {
    let tm = test_manager();

    let (round, elapsed, in_round, round_start) =
        LeaderSchedule::round_for_height_now(&tm, 2, u64::MAX)?;

    let height_start = LeaderSchedule::height_start_unix(&tm, 2);
    let tau = tm.failover_window_secs().max(1);
    let expected_elapsed = u64::MAX.saturating_sub(height_start);
    let expected_round = expected_elapsed.div_euclid(tau);
    let expected_round_start = height_start.saturating_add(expected_round.saturating_mul(tau));
    let expected_in_round = u64::MAX.saturating_sub(expected_round_start);

    assert_eq!(elapsed, expected_elapsed);
    assert_eq!(round, expected_round);
    assert_eq!(round_start, expected_round_start);
    assert_eq!(in_round, expected_in_round);
    Ok(())
}

#[test]
fn test_91_vector_round_for_height_from_timestamp_each_second_first_rounds() -> TestResult {
    let tm = test_manager();
    let expected = [
        (1_010_u64, (0_u64, 0_u64, 0_u64, 1_010_u64)),
        (1_011, (0, 1, 1, 1_010)),
        (1_012, (0, 2, 2, 1_010)),
        (1_013, (1, 3, 0, 1_013)),
        (1_014, (1, 4, 1, 1_013)),
        (1_015, (1, 5, 2, 1_013)),
        (1_016, (2, 6, 0, 1_016)),
    ];

    for (timestamp, expected_tuple) in expected {
        assert_eq!(
            LeaderSchedule::round_for_height_from_timestamp(&tm, 2, timestamp)?,
            expected_tuple
        );
    }

    Ok(())
}

#[test]
fn test_92_vector_round_for_height_now_each_second_within_and_after_drift() -> TestResult {
    let tm = test_manager();
    let expected = [
        (1_008_u64, (0_u64, 0_u64, 0_u64, 1_010_u64)),
        (1_009, (0, 0, 0, 1_010)),
        (1_010, (0, 0, 0, 1_010)),
        (1_011, (0, 1, 1, 1_010)),
        (1_012, (0, 2, 2, 1_010)),
        (1_013, (1, 3, 0, 1_013)),
    ];

    for (timestamp, expected_tuple) in expected {
        assert_eq!(
            LeaderSchedule::round_for_height_now(&tm, 2, timestamp)?,
            expected_tuple
        );
    }

    Ok(())
}

#[test]
fn test_93_edge_slot_window_accepts_deadline_minus_one_and_rejects_deadline() -> TestResult {
    let tm = test_manager();
    let deadline = tm.proposal_deadline_secs();

    LeaderSchedule::ensure_within_slot_proposal_window(&tm, deadline.saturating_sub(1))?;

    let message = validation_message(LeaderSchedule::ensure_within_slot_proposal_window(
        &tm, deadline,
    ))?;

    assert!(message.contains("too late in slot"));
    Ok(())
}

#[test]
fn test_94_edge_round_puzzle_guard_boundary_accepts_remaining_equal_need() -> TestResult {
    let tm = test_manager();

    LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 1)?;

    Ok(())
}

#[test]
fn test_95_edge_round_puzzle_guard_boundary_rejects_remaining_below_need() -> TestResult {
    let tm = test_manager();

    let message =
        validation_message(LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 2))?;

    assert!(message.contains("too late in round"));
    assert!(message.contains("remaining=1s"));
    assert!(message.contains("need>=2s"));
    Ok(())
}

#[test]
fn test_96_vector_trace_fingerprint_changes_when_height_changes() -> TestResult {
    let snapshot_a = valid_snapshot(96, parent_hash(96), sorted_validators_from_seeds(&[96, 97]));
    let decision_a = LeaderSchedule::leader_for_round(&snapshot_a, 0)?;
    let trace_a = LeaderTrace {
        snapshot: snapshot_a,
        decision: decision_a,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    let snapshot_b = valid_snapshot(97, parent_hash(96), sorted_validators_from_seeds(&[96, 97]));
    let decision_b = LeaderSchedule::leader_for_round(&snapshot_b, 0)?;
    let trace_b = LeaderTrace {
        snapshot: snapshot_b,
        decision: decision_b,
        observed_time_unix: 1_010,
        height_start_unix: 1_010,
        round_start_unix: 1_010,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    assert_ne!(
        LeaderSchedule::trace_fingerprint(&trace_a),
        LeaderSchedule::trace_fingerprint(&trace_b)
    );
    Ok(())
}

#[test]
fn test_97_vector_trace_fingerprint_changes_when_parent_hash_changes() -> TestResult {
    let snapshot_a = valid_snapshot(
        97,
        parent_hash(970),
        sorted_validators_from_seeds(&[97, 98]),
    );
    let decision_a = LeaderSchedule::leader_for_round(&snapshot_a, 0)?;
    let trace_a = LeaderTrace {
        snapshot: snapshot_a,
        decision: decision_a,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    let snapshot_b = valid_snapshot(
        97,
        parent_hash(971),
        sorted_validators_from_seeds(&[97, 98]),
    );
    let decision_b = LeaderSchedule::leader_for_round(&snapshot_b, 0)?;
    let trace_b = LeaderTrace {
        snapshot: snapshot_b,
        decision: decision_b,
        observed_time_unix: 1_000,
        height_start_unix: 1_000,
        round_start_unix: 1_000,
        elapsed_secs: 0,
        in_round_secs: 0,
        failover_window_secs: 3,
    };

    assert_ne!(
        LeaderSchedule::trace_fingerprint(&trace_a),
        LeaderSchedule::trace_fingerprint(&trace_b)
    );
    Ok(())
}

#[test]
fn test_98_load_vector_committee_hashes_distinct_across_many_heights() {
    let validators = sorted_validators_from_seeds(&[98, 99, 100]);
    let parent = parent_hash(98);
    let mut hashes = Vec::new();

    for height in 1_u64..65_u64 {
        hashes.push(LeaderSchedule::compute_committee_hash(
            parent,
            height,
            4,
            &validators,
        ));
    }

    hashes.sort();
    hashes.dedup();

    assert_eq!(hashes.len(), 64);
}

#[test]
fn test_99_load_vector_leader_scores_distinct_for_many_validators_same_round() {
    let validators = sorted_validators_from_seeds(&(99_u64..115_u64).collect::<Vec<_>>());
    let snapshot = valid_snapshot(99, parent_hash(99), validators.clone());
    let mut scores = Vec::new();

    for validator in validators {
        scores.push(LeaderSchedule::leader_score(
            snapshot.committee_hash,
            snapshot.parent_hash,
            snapshot.height,
            0,
            &validator,
        ));
    }

    scores.sort();
    scores.dedup();

    assert_eq!(scores.len(), 16);
}

#[test]
fn test_100_adversarial_vector_many_snapshot_corruptions_reject_cleanly() -> TestResult {
    let base = valid_snapshot(
        100,
        parent_hash(100),
        sorted_validators_from_seeds(&[100, 101, 102]),
    );

    let mut height_zero = base.clone();
    height_zero.height = 0;
    height_zero.committee_hash = LeaderSchedule::compute_committee_hash(
        height_zero.parent_hash,
        height_zero.height,
        height_zero.activation_delay_blocks,
        &height_zero.validators,
    );

    let mut bad_validator = base.clone();
    bad_validator.validators[0] = "bad-wallet".to_string();
    bad_validator.committee_hash = LeaderSchedule::compute_committee_hash(
        bad_validator.parent_hash,
        bad_validator.height,
        bad_validator.activation_delay_blocks,
        &bad_validator.validators,
    );

    let mut duplicate = base.clone();
    duplicate.validators.push(duplicate.validators[0].clone());
    duplicate.committee_hash = LeaderSchedule::compute_committee_hash(
        duplicate.parent_hash,
        duplicate.height,
        duplicate.activation_delay_blocks,
        &duplicate.validators,
    );

    let mut bad_hash = base;
    bad_hash.committee_hash[0] ^= 0x80;

    for snapshot in [height_zero, bad_validator, duplicate, bad_hash] {
        assert!(LeaderSchedule::ordered_validators_for_round(&snapshot, 0).is_err());
        assert!(LeaderSchedule::leader_for_round(&snapshot, 0).is_err());
    }

    Ok(())
}
