// tests/proptests_blockchain_000_consensus.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::consensus::por_000_ephemeral_registration::RegistryData;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::consensus::por_006_committee_eligibility::{
    CommitteeEligibility, CommitteeEligibilityConfig,
};
use remzar::consensus::por_007_leader_schedule::LeaderSchedule;
use remzar::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};

use std::collections::BTreeSet;

const BASE_GENESIS_TS: u64 = 1_700_000_000;

fn wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

fn wallet_with_prefix(prefix: char, tail_127: &str) -> String {
    format!("r{prefix}{tail_127}")
}

fn make_tm(genesis_offset: u64) -> TimeManager {
    TimeManager::new(TimeConfig::from_genesis_ts(
        BASE_GENESIS_TS.saturating_add(genesis_offset),
    ))
}

fn canonicalize_wallet(raw: &str) -> String {
    canon_wallet_id_checked(raw).expect("test wallet should canonicalize")
}

fn collect_register_node_txs_model(
    runtime_wallets: Vec<String>,
    canonically_known: BTreeSet<String>,
) -> Vec<RegisterNodeTx> {
    let mut canonical_runtime_wallets = runtime_wallets
        .into_iter()
        .filter_map(|wallet| canon_wallet_id_checked(&wallet).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    canonical_runtime_wallets.sort();

    canonical_runtime_wallets
        .into_iter()
        .filter(|wallet| !canonically_known.contains(wallet))
        .filter_map(|wallet| RegisterNodeTx::new(wallet).ok())
        .collect()
}

fn tx_wallet(tx: &RegisterNodeTx) -> String {
    tx.wallet_str()
        .expect("RegisterNodeTx wallet_str should expose canonical wallet")
        .to_string()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    #[test]
    fn leader_schedule_height_start_is_monotonic_for_increasing_heights(
        genesis_offset in 0u64..1_000_000u64,
        height_a in 1u64..1_000_000u64,
        delta in 0u64..10_000u64,
    ) {
        let tm = make_tm(genesis_offset);
        let height_b = height_a.saturating_add(delta);

        let start_a = LeaderSchedule::height_start_unix(&tm, height_a);
        let start_b = LeaderSchedule::height_start_unix(&tm, height_b);

        prop_assert!(
            start_b >= start_a,
            "leader schedule height start must be monotonic"
        );

        if delta > 0 {
            prop_assert!(
                start_b > start_a,
                "later block heights must start after earlier heights"
            );
        }
    }

    #[test]
    fn leader_schedule_round_for_timestamp_accepts_exact_height_start_as_round_zero(
        genesis_offset in 0u64..1_000_000u64,
        height in 1u64..1_000_000u64,
    ) {
        let tm = make_tm(genesis_offset);
        let start = LeaderSchedule::height_start_unix(&tm, height);

        let (round, elapsed, in_round, round_start) =
            LeaderSchedule::round_for_height_from_timestamp(&tm, height, start)
                .expect("exact height start should be accepted");

        prop_assert_eq!(round, 0, "exact height start must be round zero");
        prop_assert_eq!(elapsed, 0, "elapsed must be zero at height start");
        prop_assert_eq!(in_round, 0, "in-round elapsed must be zero at height start");
        prop_assert_eq!(
            round_start,
            start,
            "round start must equal height start for round zero"
        );
    }

    #[test]
    fn leader_schedule_round_advances_every_failover_window(
        genesis_offset in 0u64..1_000_000u64,
        height in 1u64..1_000_000u64,
        round in 0u64..64u64,
    ) {
        let tm = make_tm(genesis_offset);
        let tau = tm.failover_window_secs();

        prop_assume!(tau > 0);

        let start = LeaderSchedule::height_start_unix(&tm, height);
        let observed = start.saturating_add(round.saturating_mul(tau));

        let (actual_round, elapsed, in_round, round_start) =
            LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed)
                .expect("timestamp on round boundary should be accepted");

        prop_assert_eq!(
            actual_round,
            round,
            "round must advance by one every failover window"
        );

        prop_assert_eq!(
            elapsed,
            round.saturating_mul(tau),
            "elapsed must equal round * failover window on boundary"
        );

        prop_assert_eq!(
            in_round,
            0,
            "in-round elapsed must be zero exactly on round boundary"
        );

        prop_assert_eq!(
            round_start,
            observed,
            "round_start must equal observed timestamp exactly on boundary"
        );
    }

    #[test]
    fn leader_schedule_round_for_timestamp_rejects_height_zero_and_too_early_timestamps(
        genesis_offset in 0u64..1_000_000u64,
        height in 1u64..1_000_000u64,
    ) {
        let tm = make_tm(genesis_offset);

        prop_assert!(
            LeaderSchedule::round_for_height_from_timestamp(&tm, 0, BASE_GENESIS_TS).is_err(),
            "height zero must be rejected"
        );

        let start = LeaderSchedule::height_start_unix(&tm, height);

        if start > 0 {
            prop_assert!(
                LeaderSchedule::round_for_height_from_timestamp(&tm, height, start - 1).is_err(),
                "timestamp before nominal height start must be rejected"
            );
        }
    }

    #[test]
    fn leader_schedule_round_for_now_allows_drift_window_but_rejects_before_it(
        genesis_offset in 0u64..1_000_000u64,
        height in 1u64..1_000_000u64,
    ) {
        let tm = make_tm(genesis_offset);
        let start = LeaderSchedule::height_start_unix(&tm, height);
        let drift = tm.slot_gate_drift_secs();

        let earliest_allowed = start.saturating_sub(drift);

        prop_assert!(
            LeaderSchedule::round_for_height_now(&tm, height, earliest_allowed).is_ok(),
            "round_for_height_now must accept the start of the allowed drift window"
        );

        if earliest_allowed > 0 {
            prop_assert!(
                LeaderSchedule::round_for_height_now(&tm, height, earliest_allowed - 1).is_err(),
                "round_for_height_now must reject before the allowed drift window"
            );
        }
    }

    #[test]
    fn proposal_window_accepts_before_deadline_and_rejects_at_or_after_deadline(
        genesis_offset in 0u64..1_000_000u64,
        elapsed_seed in any::<u64>(),
    ) {
        let tm = make_tm(genesis_offset);
        let deadline = tm.proposal_deadline_secs();

        prop_assume!(deadline > 0);

        let accepted_elapsed = elapsed_seed % deadline;

        prop_assert!(
            LeaderSchedule::ensure_within_slot_proposal_window(&tm, accepted_elapsed).is_ok(),
            "proposal window must accept elapsed seconds before deadline"
        );

        prop_assert!(
            LeaderSchedule::ensure_within_slot_proposal_window(&tm, deadline).is_err(),
            "proposal window must reject exactly at deadline"
        );

        prop_assert!(
            LeaderSchedule::ensure_within_slot_proposal_window(
                &tm,
                deadline.saturating_add(1)
            ).is_err(),
            "proposal window must reject after deadline"
        );
    }

    #[test]
    fn local_puzzle_round_time_requires_enough_time_left_in_failover_window(
        genesis_offset in 0u64..1_000_000u64,
    ) {
        let tm = make_tm(genesis_offset);
        let tau = tm.failover_window_secs();

        prop_assume!(tau > 1);

        prop_assert!(
            LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, 0).is_ok(),
            "start of failover window should have enough time for local puzzle"
        );

        prop_assert!(
            LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(
                &tm,
                tau.saturating_sub(1)
            ).is_err(),
            "last second of failover window should be too late for local puzzle"
        );
    }

    #[test]
    fn registry_live_wallet_view_canonicalizes_and_sorts_runtime_wallets(
        tail in "[0-9a-f]{127}",
        join_height in any::<u64>(),
    ) {
        let mut reg = RegistryData::new();

        let w2_raw = format!(" \tR2{}\n", tail.to_ascii_uppercase());
        let w0_raw = format!(" r0{tail} ");
        let w1_raw = format!("R1{}", tail.to_ascii_uppercase());

        let w0 = canonicalize_wallet(&w0_raw);
        let w1 = canonicalize_wallet(&w1_raw);
        let w2 = canonicalize_wallet(&w2_raw);

        reg.register_wallet_strict(&w2_raw, join_height)
            .expect("w2 should register");
        reg.register_wallet_strict(&w0_raw, join_height.saturating_add(1))
            .expect("w0 should register");
        reg.register_wallet_strict(&w1_raw, join_height.saturating_add(2))
            .expect("w1 should register");

        let sorted = reg.sorted_wallets();

        prop_assert_eq!(
            sorted,
            vec![w0.clone(), w1.clone(), w2.clone()],
            "runtime registry must expose deterministic canonical wallet order"
        );

        prop_assert!(reg.is_registered(&w0));
        prop_assert!(reg.is_registered(&w1));
        prop_assert!(reg.is_registered(&w2));
    }

    #[test]
    fn committee_eligibility_reflects_replaced_live_wallet_view(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);

        let cfg = CommitteeEligibilityConfig::from_globals();
        cfg.validate()
            .expect("global committee eligibility config should validate");

        let mut ce = CommitteeEligibility::new(cfg);

        let absent = ce.decide_wallet(&wallet);

        prop_assert!(
            !absent.eligible,
            "wallet absent from live runtime view should not be locally eligible"
        );

        ce.replace_live_wallets(vec![wallet.clone()])
            .expect("replace_live_wallets should accept canonical wallet");

        let present = ce.decide_wallet(&wallet);

        prop_assert!(
            present.eligible,
            "wallet present in live runtime view with no negative status should be locally eligible"
        );

        let uppercase = format!("R{}", tail.to_ascii_uppercase());

        let upper_decision = ce.decide_wallet(&uppercase);

        prop_assert!(
            upper_decision.eligible,
            "committee eligibility must canonicalize wallet input before decision"
        );
    }

    #[test]
    fn committee_live_wallet_replacement_rejects_malformed_wallets_without_poisoning_existing_view(
        good_tail in "[0-9a-f]{128}",
        bad_short_tail in "[0-9a-f]{0,127}",
    ) {
        let good = wallet_from_tail(&good_tail);
        let bad = wallet_from_tail(&bad_short_tail);

        let cfg = CommitteeEligibilityConfig::from_globals();
        cfg.validate()
            .expect("global committee eligibility config should validate");

        let mut ce = CommitteeEligibility::new(cfg);

        ce.replace_live_wallets(vec![good.clone()])
            .expect("initial good live-wallet replacement should succeed");

        prop_assert!(
            ce.decide_wallet(&good).eligible,
            "good wallet should be eligible after initial replacement"
        );

        prop_assert!(
            ce.replace_live_wallets(vec![bad]).is_err(),
            "malformed wallet replacement must be rejected"
        );

        prop_assert!(
            ce.decide_wallet(&good).eligible,
            "failed replacement must not poison previous live-wallet view"
        );
    }

    #[test]
    fn register_tx_collection_model_is_sorted_deduplicated_and_skips_canonically_known_wallets(
        shared_tail in "[0-9a-f]{127}",
        known_mask in 0u8..8u8,
    ) {
        let w0 = wallet_with_prefix('0', &shared_tail);
        let w1 = wallet_with_prefix('1', &shared_tail);
        let w2 = wallet_with_prefix('2', &shared_tail);

        let runtime_wallets = vec![
            format!(" \t{}\n", w2.to_ascii_uppercase()),
            w0.clone(),
            w1.clone(),
            w0.to_ascii_uppercase(),
            "not-a-wallet".to_string(),
        ];

        let mut known = BTreeSet::new();

        if known_mask & 0b001 != 0 {
            known.insert(w0.clone());
        }
        if known_mask & 0b010 != 0 {
            known.insert(w1.clone());
        }
        if known_mask & 0b100 != 0 {
            known.insert(w2.clone());
        }

        let txs = collect_register_node_txs_model(runtime_wallets, known.clone());

        let tx_wallets = txs.iter().map(tx_wallet).collect::<Vec<_>>();

        let expected = [w0, w1, w2]
            .into_iter()
            .filter(|wallet| !known.contains(wallet))
            .collect::<Vec<_>>();

        prop_assert_eq!(
            tx_wallets,
            expected,
            "registration collection model must sort, deduplicate, canonicalize, and skip canonically known wallets"
        );

        for tx in txs {
            prop_assert!(
                tx.validate().is_ok(),
                "collected RegisterNodeTx values must validate"
            );

            prop_assert_eq!(
                tx.wallet_address.len(),
                REMZAR_WALLET_LEN,
                "collected RegisterNodeTx must store fixed-length canonical wallet bytes"
            );
        }
    }

    #[test]
    fn register_tx_collection_model_never_outputs_invalid_or_duplicate_wallets(
        valid_tail in "[0-9a-f]{127}",
        invalid_tail in "[0-9a-f]{0,127}",
    ) {
        let w0 = wallet_with_prefix('0', &valid_tail);
        let w1 = wallet_with_prefix('1', &valid_tail);

        let runtime_wallets = vec![
            w1.clone(),
            w0.clone(),
            w1.to_ascii_uppercase(),
            wallet_from_tail(&invalid_tail),
            format!("p{}", "a".repeat(128)),
            format!("rz{}", "a".repeat(127)),
        ];

        let txs = collect_register_node_txs_model(runtime_wallets, BTreeSet::new());

        let tx_wallets = txs.iter().map(tx_wallet).collect::<Vec<_>>();
        let unique = tx_wallets.iter().cloned().collect::<BTreeSet<_>>();

        prop_assert_eq!(
            tx_wallets.len(),
            unique.len(),
            "registration collection model must not output duplicate wallets"
        );

        prop_assert_eq!(
            tx_wallets,
            vec![w0, w1],
            "registration collection model must ignore malformed runtime wallet strings"
        );
    }
}
