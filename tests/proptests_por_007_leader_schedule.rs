use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::validatorstate::ValidatorState;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::consensus::por_006_committee_eligibility::{
    CommitteeEligibility, CommitteeEligibilityConfig, CommitteeMemberStatus,
};
use remzar::consensus::por_007_leader_schedule::{CommitteeSnapshot, LeaderSchedule};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const UNIX_2000: u64 = 946_684_800;

static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

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

fn hash64(tag: u8, seed: u64) -> [u8; 64] {
    let fill = match tag {
        0 => 1,
        0xFF => 0xFE,
        value => value,
    };

    let mut out = [fill; 64];
    out[..8].copy_from_slice(&seed.to_be_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[63] = 0xFE;
    }

    out
}

fn distinct_hash64(tag: u8, seed: u64, other: [u8; 64]) -> [u8; 64] {
    let mut out = hash64(tag, seed);

    if out == other {
        out[63] ^= 1;

        if out == [0u8; 64] || out == [0xFFu8; 64] {
            out[63] = 0x7F;
        }
    }

    out
}

fn tm_from_seed(seed: u64) -> TimeManager {
    TimeManager::new(TimeConfig::from_genesis_ts(
        UNIX_2000.saturating_add(seed % 10_000_000),
    ))
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp())
        .unwrap_or(UNIX_2000)
        .max(UNIX_2000)
}

fn valid_timestamp(seed: u64) -> u64 {
    let now = now_secs();
    let span = now.saturating_sub(UNIX_2000).saturating_add(1);

    UNIX_2000.saturating_add(seed % span)
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

fn test_root_path() -> PathBuf {
    let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "remzar_leader_schedule_prop_{}_{}",
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

fn valid_snapshot(
    height: u64,
    parent_hash: [u8; 64],
    activation_delay_blocks: u64,
    validators: Vec<String>,
) -> CommitteeSnapshot {
    let committee_hash = LeaderSchedule::compute_committee_hash(
        parent_hash,
        height,
        activation_delay_blocks,
        &validators,
    );

    CommitteeSnapshot {
        height,
        parent_hash,
        activation_delay_blocks,
        validators,
        committee_hash,
    }
}

fn sorted_unique(mut validators: Vec<String>) -> Vec<String> {
    validators.sort_unstable();
    validators.dedup();
    validators
}

fn single_founder_state(founder: &str, timestamp: u64) -> ValidatorState {
    let mut state = fresh_state();

    state
        .seed_genesis_founder(founder, timestamp)
        .expect("valid founder should seed");

    state
}

fn state_with_two_validators(
    founder: &str,
    second: &str,
    timestamp: u64,
    tm: &TimeManager,
) -> (ValidatorState, u64) {
    let mut state = fresh_state();

    state
        .seed_genesis_founder(founder, timestamp)
        .expect("valid founder should seed");

    state
        .apply_register_tx_at_block_time(1, timestamp, &manual_register(second, timestamp))
        .expect("valid register tx should apply at explicit canonical block time");

    let active_height = 1u64.saturating_add(tm.proposer_delay_blocks());

    (state, active_height)
}

fn live_committee_for(wallet: &str) -> CommitteeEligibility {
    let mut eligibility = CommitteeEligibility::with_default_config();

    eligibility
        .mark_wallet_live(wallet, true)
        .expect("valid wallet should be markable live");

    eligibility
}

fn suppressed_committee_for(wallet: &str) -> CommitteeEligibility {
    let mut eligibility = CommitteeEligibility::new(CommitteeEligibilityConfig {
        max_tip_lag_blocks: 0,
        min_peers_connected: 0,
        min_connected_wallet_peers: 0,
        require_non_isolated: false,
        require_synced: true,
    });

    eligibility
        .upsert_status(CommitteeMemberStatus {
            wallet: wallet.to_string(),
            is_live: true,
            has_synced: false,
            local_tip: 10,
            network_tip: 10,
            peers_connected: 0,
            connected_wallet_peers: 0,
            is_isolated: true,
        })
        .expect("valid unsynced status should upsert");

    eligibility
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_leader_schedule_canonicalizes_local_wallet(
        tail in "[0-9A-F]{128}",
    ) {
        let raw = format!(" \n\tR{tail}\r\n ");
        let expected = format!("r{}", tail.to_ascii_lowercase());

        let schedule = LeaderSchedule::new(raw)
            .expect("canonicalizable local wallet must construct LeaderSchedule");

        prop_assert_eq!(
            schedule.local_wallet(),
            expected.as_str(),
            "LeaderSchedule::new must store canonical lowercase local wallet"
        );
    }

    // 02/25
    #[test]
    fn test_002_new_leader_schedule_rejects_invalid_local_wallet(
        bad_tail in "[0-9a-f]{0,127}",
    ) {
        let invalid = format!("r{bad_tail}");

        prop_assert!(
            LeaderSchedule::new(invalid).is_err(),
            "LeaderSchedule::new must reject malformed local wallet"
        );
    }

    // 03/25
    #[test]
    fn test_003_compute_committee_hash_is_deterministic_for_identical_inputs(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let validators = sorted_unique(vec![wallet_a, wallet_b]);
        let parent_hash = hash64(0x11, parent_seed);

        let first = LeaderSchedule::compute_committee_hash(
            parent_hash,
            height,
            delay,
            &validators,
        );

        let second = LeaderSchedule::compute_committee_hash(
            parent_hash,
            height,
            delay,
            &validators,
        );

        prop_assert_eq!(
            first,
            second,
            "committee hash must be deterministic for identical snapshot inputs"
        );

        prop_assert_ne!(
            first,
            [0u8; 64],
            "committee hash should not collapse to zero digest"
        );
    }

    // 04/25
    #[test]
    fn test_004_committee_hash_changes_when_parent_hash_changes(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let validators = sorted_unique(vec![wallet_a, wallet_b]);
        let parent_a = hash64(0x22, parent_seed);
        let parent_b = distinct_hash64(0x33, parent_seed.wrapping_add(1), parent_a);

        let hash_a = LeaderSchedule::compute_committee_hash(parent_a, height, delay, &validators);
        let hash_b = LeaderSchedule::compute_committee_hash(parent_b, height, delay, &validators);

        prop_assert_ne!(
            hash_a,
            hash_b,
            "committee hash must commit to parent_hash"
        );
    }

    // 05/25
    #[test]
    fn test_005_committee_hash_changes_when_height_changes(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let validators = sorted_unique(vec![wallet_a, wallet_b]);
        let parent_hash = hash64(0x44, parent_seed);

        let hash_a = LeaderSchedule::compute_committee_hash(parent_hash, height, delay, &validators);
        let hash_b = LeaderSchedule::compute_committee_hash(
            parent_hash,
            height.saturating_add(1),
            delay,
            &validators,
        );

        prop_assert_ne!(
            hash_a,
            hash_b,
            "committee hash must commit to block height"
        );
    }

    // 06/25
    #[test]
    fn test_006_committee_hash_changes_when_activation_delay_changes(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let validators = sorted_unique(vec![wallet_a, wallet_b]);
        let parent_hash = hash64(0x55, parent_seed);

        let hash_a = LeaderSchedule::compute_committee_hash(parent_hash, height, delay, &validators);
        let hash_b = LeaderSchedule::compute_committee_hash(
            parent_hash,
            height,
            delay.saturating_add(1),
            &validators,
        );

        prop_assert_ne!(
            hash_a,
            hash_b,
            "committee hash must commit to activation_delay_blocks"
        );
    }

    // 07/25
    #[test]
    fn test_007_committee_hash_changes_when_validator_membership_changes(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        let (wallet_a, wallet_b, wallet_c) = three_distinct_wallets(seed_a, seed_b, seed_c);
        let validators_ab = sorted_unique(vec![wallet_a.clone(), wallet_b]);
        let validators_ac = sorted_unique(vec![wallet_a, wallet_c]);
        let parent_hash = hash64(0x66, parent_seed);

        let hash_ab = LeaderSchedule::compute_committee_hash(parent_hash, height, delay, &validators_ab);
        let hash_ac = LeaderSchedule::compute_committee_hash(parent_hash, height, delay, &validators_ac);

        prop_assert_ne!(
            hash_ab,
            hash_ac,
            "committee hash must commit to exact validator membership"
        );
    }

    // 08/25
    #[test]
    fn test_008_committee_snapshot_len_empty_and_contains_wallet_are_consistent(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let validators = sorted_unique(vec![wallet_a.clone(), wallet_b.clone()]);
        let snapshot = valid_snapshot(height, hash64(0x77, parent_seed), delay, validators.clone());

        prop_assert_eq!(snapshot.len(), validators.len());
        prop_assert_eq!(snapshot.is_empty(), validators.is_empty());

        prop_assert!(
            snapshot.contains_wallet(&wallet_a.to_ascii_uppercase()),
            "contains_wallet must match committee member case-insensitively"
        );

        prop_assert!(
            snapshot.contains_wallet(&wallet_b),
            "contains_wallet must find canonical committee member"
        );

        prop_assert!(
            !snapshot.contains_wallet(&wallet(seed_a.wrapping_add(99_999))),
            "contains_wallet must not report unrelated wallet as present"
        );
    }

    // 09/25
    #[test]
    fn test_009_leader_score_is_deterministic_and_commits_to_round(
        parent_seed in any::<u64>(),
        committee_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        round in 0u64..10_000u64,
        validator_seed in any::<u64>(),
    ) {
        let parent_hash = hash64(0x88, parent_seed);
        let committee_hash = hash64(0x99, committee_seed);
        let validator = wallet(validator_seed);

        let first = LeaderSchedule::leader_score(
            committee_hash,
            parent_hash,
            height,
            round,
            &validator,
        );

        let second = LeaderSchedule::leader_score(
            committee_hash,
            parent_hash,
            height,
            round,
            &validator,
        );

        let next_round = LeaderSchedule::leader_score(
            committee_hash,
            parent_hash,
            height,
            round.saturating_add(1),
            &validator,
        );

        prop_assert_eq!(
            first,
            second,
            "leader_score must be deterministic for identical inputs"
        );

        prop_assert_ne!(
            first,
            next_round,
            "leader_score must commit to round number"
        );
    }

    // 10/25
    #[test]
    fn test_010_ordered_validators_for_round_returns_deterministic_permutation(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        round in 0u64..10_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        let (wallet_a, wallet_b, wallet_c) = three_distinct_wallets(seed_a, seed_b, seed_c);
        let validators = sorted_unique(vec![wallet_a, wallet_b, wallet_c]);
        let snapshot = valid_snapshot(height, hash64(0xAA, parent_seed), delay, validators.clone());

        let ordered_a = LeaderSchedule::ordered_validators_for_round(&snapshot, round)
            .expect("valid snapshot must order validators");

        let ordered_b = LeaderSchedule::ordered_validators_for_round(&snapshot, round)
            .expect("valid snapshot must order validators deterministically");

        prop_assert_eq!(
            &ordered_a,
            &ordered_b,
            "ordered_validators_for_round must be deterministic"
        );

        let set_original: BTreeSet<String> = validators.into_iter().collect();
        let set_ordered: BTreeSet<String> = ordered_a.into_iter().collect();

        prop_assert_eq!(
            set_ordered,
            set_original,
            "ordered validators must be a permutation of frozen snapshot validators"
        );
    }

    // 11/25
    #[test]
    fn test_011_leader_for_round_selects_first_ordered_validator_and_reports_consistent_metadata(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        round in 0u64..10_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        let (wallet_a, wallet_b, wallet_c) = three_distinct_wallets(seed_a, seed_b, seed_c);
        let validators = sorted_unique(vec![wallet_a, wallet_b, wallet_c]);
        let snapshot = valid_snapshot(height, hash64(0xAB, parent_seed), delay, validators.clone());

        let ordered = LeaderSchedule::ordered_validators_for_round(&snapshot, round)
            .expect("valid snapshot must order validators");

        let decision = LeaderSchedule::leader_for_round(&snapshot, round)
            .expect("valid snapshot must produce leader decision");

        prop_assert_eq!(decision.height, height);
        prop_assert_eq!(decision.round, round);
        prop_assert_eq!(decision.parent_hash, snapshot.parent_hash);
        prop_assert_eq!(decision.committee_hash, snapshot.committee_hash);
        prop_assert_eq!(decision.committee_len, validators.len());

        prop_assert_eq!(
            &decision.leader,
            &ordered[0],
            "leader_for_round must choose first validator in score ordering"
        );

        prop_assert_eq!(
            &validators[decision.leader_index_in_snapshot],
            &decision.leader,
            "leader_index_in_snapshot must point back into frozen snapshot"
        );
    }

    // 12/25
    #[test]
    fn test_012_ordering_rejects_snapshot_with_committee_hash_mismatch(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        round in 0u64..10_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let validators = sorted_unique(vec![wallet_a, wallet_b]);
        let mut snapshot = valid_snapshot(height, hash64(0xAC, parent_seed), delay, validators);

        snapshot.committee_hash[0] ^= 1;

        prop_assert!(
            LeaderSchedule::ordered_validators_for_round(&snapshot, round).is_err(),
            "ordered_validators_for_round must reject hash-mismatched snapshots"
        );

        prop_assert!(
            LeaderSchedule::leader_for_round(&snapshot, round).is_err(),
            "leader_for_round must reject hash-mismatched snapshots"
        );
    }

    // 13/25
    #[test]
    fn test_013_ordering_rejects_duplicate_or_noncanonical_snapshot_validators(
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        delay in 0u64..100u64,
        round in 0u64..10_000u64,
        seed_a in any::<u64>(),
        invalid_case in 0usize..2usize,
    ) {
        let wallet_a = wallet(seed_a);

        let validators = if invalid_case == 0 {
            vec![wallet_a.clone(), wallet_a]
        } else {
            vec![wallet_a.clone(), wallet_a.to_ascii_uppercase()]
        };

        let snapshot = valid_snapshot(height, hash64(0xAD, parent_seed), delay, validators);

        prop_assert!(
            LeaderSchedule::ordered_validators_for_round(&snapshot, round).is_err(),
            "snapshot validation must reject duplicate or noncanonical validators"
        );
    }

    // 14/25
    #[test]
    fn test_014_leader_selection_rejects_height_zero_or_empty_committee_snapshot(
        parent_seed in any::<u64>(),
        delay in 0u64..100u64,
        round in 0u64..10_000u64,
        wallet_seed in any::<u64>(),
        invalid_case in 0usize..2usize,
    ) {
        let parent_hash = hash64(0xAE, parent_seed);

        let snapshot = if invalid_case == 0 {
            valid_snapshot(0, parent_hash, delay, vec![wallet(wallet_seed)])
        } else {
            valid_snapshot(1, parent_hash, delay, Vec::new())
        };

        prop_assert!(
            LeaderSchedule::leader_for_round(&snapshot, round).is_err(),
            "leader selection must reject height zero and empty committee snapshots"
        );
    }

    // 15/25
    #[test]
    fn test_015_height_start_unix_uses_height_one_as_genesis_start_and_saturating_interval_formula(
        genesis_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let tm = tm_from_seed(genesis_seed);
        let genesis = tm.cfg().genesis_time_unix.max(1);
        let interval = tm.block_interval_secs().max(1);

        let expected = if height <= 1 {
            genesis
        } else {
            genesis.saturating_add(height.saturating_sub(1).saturating_mul(interval))
        };

        prop_assert_eq!(
            LeaderSchedule::height_start_unix(&tm, height),
            expected,
            "LeaderSchedule height start formula must be genesis + (height - 1) * block_interval"
        );

        prop_assert_eq!(
            LeaderSchedule::height_start_unix(&tm, 1),
            genesis,
            "height 1 must start at genesis_time_unix"
        );
    }

    // 16/25
    #[test]
    fn test_016_round_for_height_from_timestamp_rejects_height_zero(
        genesis_seed in any::<u64>(),
        observed_time in any::<u64>(),
    ) {
        let tm = tm_from_seed(genesis_seed);

        prop_assert!(
            LeaderSchedule::round_for_height_from_timestamp(&tm, 0, observed_time).is_err(),
            "round_for_height_from_timestamp must reject height zero"
        );
    }

    // 17/25
    #[test]
    fn test_017_round_for_height_from_timestamp_rejects_time_before_nominal_height_start(
        genesis_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        back_secs in 1u64..10_000u64,
    ) {
        let tm = tm_from_seed(genesis_seed);
        let start = LeaderSchedule::height_start_unix(&tm, height);
        let observed_time = start.saturating_sub(back_secs);

        prop_assert!(
            observed_time < start,
            "generated observed time must be before height start"
        );

        prop_assert!(
            LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed_time).is_err(),
            "timestamp before nominal height start must be rejected by deterministic round derivation"
        );
    }

    // 18/25
    #[test]
    fn test_018_round_for_height_from_timestamp_matches_tau_division_and_round_start(
        genesis_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        round in 0u64..1000u64,
        offset_seed in any::<u64>(),
    ) {
        let tm = tm_from_seed(genesis_seed);
        let tau = tm.failover_window_secs().max(1);
        let start = LeaderSchedule::height_start_unix(&tm, height);
        let offset = offset_seed % tau;
        let observed_time = start
            .saturating_add(round.saturating_mul(tau))
            .saturating_add(offset);

        let (actual_round, elapsed, in_round, round_start) =
            LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed_time)
                .expect("timestamp at or after height start must derive a round");

        prop_assert_eq!(actual_round, round);
        prop_assert_eq!(elapsed, round.saturating_mul(tau).saturating_add(offset));
        prop_assert_eq!(in_round, offset);
        prop_assert_eq!(
            round_start,
            start.saturating_add(round.saturating_mul(tau)),
            "round_start must be start + round * tau"
        );
    }

    // 19/25
    #[test]
    fn test_019_round_for_height_now_accepts_at_height_start_and_reports_round_zero(
        genesis_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let tm = tm_from_seed(genesis_seed);
        let start = LeaderSchedule::height_start_unix(&tm, height);

        let (round, elapsed, in_round, round_start) =
            LeaderSchedule::round_for_height_now(&tm, height, start)
                .expect("now exactly at height start must be accepted");

        prop_assert_eq!(round, 0);
        prop_assert_eq!(elapsed, 0);
        prop_assert_eq!(in_round, 0);
        prop_assert_eq!(round_start, start);
    }

    // 20/25
    #[test]
    fn test_020_round_for_height_now_rejects_too_early_before_drift_window(
        genesis_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        extra_back in 1u64..1000u64,
    ) {
        let tm = tm_from_seed(genesis_seed);
        let start = LeaderSchedule::height_start_unix(&tm, height);
        let drift = tm.slot_gate_drift_secs();

        prop_assume!(start > drift.saturating_add(extra_back));

        let now = start.saturating_sub(drift).saturating_sub(extra_back);

        prop_assert!(
            LeaderSchedule::round_for_height_now(&tm, height, now).is_err(),
            "round_for_height_now must reject timestamps before height_start - drift"
        );
    }

    // 21/25
    #[test]
    fn test_021_ensure_within_slot_proposal_window_accepts_before_deadline_and_rejects_at_deadline(
        genesis_seed in any::<u64>(),
    ) {
        let tm = tm_from_seed(genesis_seed);
        let deadline = tm.proposal_deadline_secs().max(1);

        prop_assert!(
            LeaderSchedule::ensure_within_slot_proposal_window(
                &tm,
                deadline.saturating_sub(1),
            )
            .is_ok(),
            "slot proposal window must allow elapsed time before deadline"
        );

        prop_assert!(
            LeaderSchedule::ensure_within_slot_proposal_window(&tm, deadline).is_err(),
            "slot proposal window must reject elapsed time at deadline"
        );
    }

    // 22/25
    #[test]
    fn test_022_ensure_enough_time_in_round_for_local_puzzle_accepts_boundary_and_rejects_too_late(
        genesis_seed in any::<u64>(),
    ) {
        let tm = tm_from_seed(genesis_seed);
        let tau = tm.failover_window_secs().max(1);
        let need = tm.puzzle_interval_secs().max(1).saturating_add(1);

        prop_assume!(tau >= need);

        let latest_ok = tau.saturating_sub(need);
        let too_late = latest_ok.saturating_add(1);

        prop_assert!(
            LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, latest_ok).is_ok(),
            "local puzzle start must be allowed when remaining time equals need"
        );

        prop_assert!(
            LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, too_late).is_err(),
            "local puzzle start must be rejected when remaining time is below need"
        );
    }

    // 23/25
    #[test]
    fn test_023_canonical_validators_for_height_comes_from_validator_state_and_ignores_runtime_liveness(
        founder_seed in any::<u64>(),
        second_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        genesis_seed in any::<u64>(),
    ) {
        let (founder, second) = distinct_wallets(founder_seed, second_seed);
        let tm = tm_from_seed(genesis_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let (state, active_height) = state_with_two_validators(&founder, &second, timestamp, &tm);

        let mut runtime = CommitteeEligibility::with_default_config();
        runtime
            .replace_live_wallets(Vec::<String>::new())
            .expect("empty runtime live set should be accepted");

        let canonical = LeaderSchedule::canonical_validators_for_height(
            &state,
            &tm,
            active_height,
        )
        .expect("canonical validators should be derived from ValidatorState");

        let active_alias = LeaderSchedule::active_validators_for_height(
            &state,
            &runtime,
            &tm,
            active_height,
        )
        .expect("active_validators_for_height alias must ignore runtime eligibility");

        prop_assert_eq!(
            &canonical,
            &active_alias,
            "active_validators_for_height must be a compatibility alias for canonical validators"
        );

        prop_assert!(
            canonical.contains(&founder),
            "canonical committee must include active founder from ValidatorState"
        );

        prop_assert!(
            canonical.contains(&second),
            "canonical committee must include proposable registered validator from ValidatorState"
        );

        prop_assert!(
            canonical.windows(2).all(|pair| pair[0] <= pair[1]),
            "canonical committee must be sorted deterministically"
        );
    }

    // 24/25
    #[test]
    fn test_024_committee_snapshot_hash_matches_computed_hash_and_runtime_eligibility_is_ignored(
        founder_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        genesis_seed in any::<u64>(),
        parent_seed in any::<u64>(),
    ) {
        let founder = wallet(founder_seed);
        let tm = tm_from_seed(genesis_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let state = single_founder_state(&founder, timestamp);
        let runtime = suppressed_committee_for(&founder);
        let parent_hash = hash64(0xBA, parent_seed);

        let snapshot = LeaderSchedule::committee_snapshot(
            &state,
            &runtime,
            &tm,
            parent_hash,
            1,
        )
        .expect("committee snapshot must be canonical and ignore runtime suppression");

        let expected_hash = LeaderSchedule::compute_committee_hash(
            parent_hash,
            1,
            tm.proposer_delay_blocks(),
            &snapshot.validators,
        );

        prop_assert_eq!(snapshot.height, 1);
        prop_assert_eq!(snapshot.parent_hash, parent_hash);
        prop_assert_eq!(snapshot.activation_delay_blocks, tm.proposer_delay_blocks());
        prop_assert_eq!(snapshot.committee_hash, expected_hash);
        prop_assert!(snapshot.contains_wallet(&founder));
    }

    // 25/25
    #[test]
    fn test_025_proposer_validation_and_local_authorization_follow_canonical_leader_plus_runtime_policy(
        founder_seed in any::<u64>(),
        timestamp_seed in any::<u64>(),
        genesis_seed in any::<u64>(),
        parent_seed in any::<u64>(),
    ) {
        let founder = wallet(founder_seed);
        let tm = tm_from_seed(genesis_seed);
        let timestamp = valid_timestamp(timestamp_seed);
        let state = single_founder_state(&founder, timestamp);
        let runtime_ready = live_committee_for(&founder);
        let parent_hash = hash64(0xCB, parent_seed);
        let now = LeaderSchedule::height_start_unix(&tm, 1);
        let schedule = LeaderSchedule::new(founder.clone())
            .expect("valid local wallet should build LeaderSchedule");

        let trace = LeaderSchedule::validate_proposer_from_block_timestamp(
            &state,
            &runtime_ready,
            &tm,
            parent_hash,
            1,
            now,
            &founder,
        )
        .expect("single canonical validator must be valid proposer for timestamp-derived round");

        prop_assert_eq!(&trace.decision.leader, &founder);
        prop_assert_eq!(trace.decision.round, 0);

        let round_decision = LeaderSchedule::validate_proposer_for_round(
            &state,
            &runtime_ready,
            &tm,
            parent_hash,
            1,
            0,
            &founder,
        )
        .expect("single canonical validator must be valid proposer for explicit round");

        prop_assert_eq!(&round_decision.leader, &founder);

        let prestage = schedule.assert_local_can_prestage_puzzle_now(
            &state,
            &runtime_ready,
            &tm,
            parent_hash,
            1,
            now,
        );

        prop_assert!(
            prestage.is_ok(),
            "local wallet in canonical committee and runtime-ready must be allowed to prestage"
        );

        let mint = schedule.assert_local_can_mint_now(
            &state,
            &runtime_ready,
            &tm,
            parent_hash,
            1,
            now,
        );

        prop_assert!(
            mint.is_ok(),
            "local wallet that is canonical leader and runtime-ready must be allowed to mint"
        );

        let runtime_suppressed = suppressed_committee_for(&founder);

        prop_assert!(
            schedule
                .assert_local_can_mint_now(
                    &state,
                    &runtime_suppressed,
                    &tm,
                    parent_hash,
                    1,
                    now,
                )
                .is_err(),
            "local mint authorization must enforce runtime policy after canonical leader check"
        );
    }
}
