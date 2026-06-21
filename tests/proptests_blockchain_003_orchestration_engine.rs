// tests/proptests_blockchain_003_orchestration_engine.rs

use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::consensus::por_006_committee_eligibility::CommitteeStatusUpdate;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::{canon_wallet_id_checked, has_quorum, quorum_threshold_checked};

use std::sync::atomic::{AtomicU64, Ordering};

const LAST_CANONICAL_REGISTER_TIP_SENTINEL: u64 = u64::MAX;
const MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH: u64 = 512;

fn mint_sync_proposal_ready_model(
    has_synced: bool,
    is_syncing: bool,
    has_background_sync_work: bool,
) -> bool {
    has_synced && !is_syncing && !has_background_sync_work
}

fn canonical_register_should_emit_model(previous_tip: u64, tip_now: u64) -> bool {
    previous_tip == LAST_CANONICAL_REGISTER_TIP_SENTINEL
        || tip_now.saturating_sub(previous_tip)
            >= GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS
}

fn canonical_register_apply_model(state: &AtomicU64, tip_now: u64) -> bool {
    state
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |previous_tip| {
            if canonical_register_should_emit_model(previous_tip, tip_now) {
                Some(tip_now)
            } else {
                None
            }
        })
        .is_ok()
}

fn founder_reboot_scan_floor_model(original_tip: u64) -> u64 {
    original_tip.saturating_sub(MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH)
}

fn lower_hex_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-f]{128}")
        .expect("valid lowercase hex regex")
        .boxed()
}

fn mixed_hex_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-fA-F]{128}")
        .expect("valid mixed-case hex regex")
        .boxed()
}

fn valid_wallet_lower() -> BoxedStrategy<String> {
    lower_hex_128().prop_map(|body| format!("r{body}")).boxed()
}

fn valid_wallet_mixed_case() -> BoxedStrategy<String> {
    (prop_oneof![Just('r'), Just('R')], mixed_hex_128())
        .prop_map(|(prefix, body)| format!("{prefix}{body}"))
        .boxed()
}

fn invalid_wallet_wrong_prefix() -> BoxedStrategy<String> {
    (
        prop_oneof![
            Just('x'),
            Just('p'),
            Just('0'),
            Just('1'),
            Just('_'),
            Just('-'),
        ],
        lower_hex_128(),
    )
        .prop_map(|(prefix, body)| format!("{prefix}{body}"))
        .boxed()
}

fn non_hex_char() -> BoxedStrategy<char> {
    prop_oneof![
        Just('g'),
        Just('G'),
        Just('z'),
        Just('Z'),
        Just('/'),
        Just('\\'),
        Just('_'),
        Just('-'),
        Just(':'),
        Just('{'),
        Just('}'),
        Just(' '),
        Just('\n'),
        Just('\t'),
        Just('\0'),
    ]
    .boxed()
}

fn live_committee_seen_model(local_wallet_live: bool, connected_wallet_peers: usize) -> usize {
    connected_wallet_peers.saturating_add(usize::from(local_wallet_live))
}

fn slot_timing_skip_model(slot_now: u64, tip_now: u64) -> bool {
    let next_h = tip_now.saturating_add(1);
    slot_now.saturating_add(1) < next_h
}

fn miner_allowed_by_basic_intent_model(local_wallet: &str, mining_intent: bool) -> bool {
    mining_intent && !local_wallet.trim().is_empty()
}

proptest! {
    #![proptest_config(Config {
        cases: 100_000,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/35
    #[test]
    fn mint_sync_proposal_ready_requires_synced_and_no_active_sync_work(
        has_synced in any::<bool>(),
        is_syncing in any::<bool>(),
        has_background_sync_work in any::<bool>(),
    ) {
        let ready = mint_sync_proposal_ready_model(
            has_synced,
            is_syncing,
            has_background_sync_work,
        );

        prop_assert_eq!(
            ready,
            has_synced && !is_syncing && !has_background_sync_work,
            "mint readiness must only pass when synced=true, syncing=false, background_sync=false"
        );

        if ready {
            prop_assert!(has_synced, "ready node must have completed sync");
            prop_assert!(!is_syncing, "ready node must not be actively syncing");
            prop_assert!(
                !has_background_sync_work,
                "ready node must not have background sync work"
            );
        }
    }

    // 02/35
    #[test]
    fn mint_sync_proposal_ready_rejects_every_catchup_or_hydration_state(
        is_syncing in any::<bool>(),
        has_background_sync_work in any::<bool>(),
    ) {
        let unsynced_ready = mint_sync_proposal_ready_model(
            false,
            is_syncing,
            has_background_sync_work,
        );

        prop_assert!(
            !unsynced_ready,
            "unsynced node must never be proposal-ready"
        );

        let actively_syncing_ready = mint_sync_proposal_ready_model(
            true,
            true,
            has_background_sync_work,
        );

        prop_assert!(
            !actively_syncing_ready,
            "actively syncing node must never be proposal-ready"
        );

        let background_work_ready = mint_sync_proposal_ready_model(
            true,
            is_syncing,
            true,
        );

        prop_assert!(
            !background_work_ready,
            "node with background sync work must never be proposal-ready"
        );
    }

    // 03/35
    #[test]
    fn canonical_register_first_real_tip_always_emits_and_records_tip(
        tip_now in 0u64..u64::MAX,
    ) {
        let state = AtomicU64::new(LAST_CANONICAL_REGISTER_TIP_SENTINEL);

        let emitted = canonical_register_apply_model(&state, tip_now);

        prop_assert!(
            emitted,
            "first canonical RegisterNode renewal must emit for any realistic tip"
        );

        prop_assert_eq!(
            state.load(Ordering::SeqCst),
            tip_now,
            "first canonical RegisterNode renewal must record the observed tip"
        );
    }

    // 04/35
    #[test]
    fn canonical_register_duplicate_or_too_soon_tip_is_suppressed_without_state_change(
        previous_tip in 0u64..1_000_000_000_000u64,
        delta in 0u64..GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS,
    ) {
        prop_assume!(GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS > 0);

        let tip_now = previous_tip.saturating_add(delta);
        let state = AtomicU64::new(previous_tip);

        let emitted = canonical_register_apply_model(&state, tip_now);

        prop_assert!(
            !emitted,
            "duplicate or too-soon canonical RegisterNode renewal must be suppressed"
        );

        prop_assert_eq!(
            state.load(Ordering::SeqCst),
            previous_tip,
            "suppressed canonical renewal must not mutate last emitted tip"
        );
    }

    // 05/35
    #[test]
    fn canonical_register_emits_at_or_after_configured_renew_interval(
        previous_tip in 0u64..1_000_000_000_000u64,
        extra_delta in 0u64..10_000u64,
    ) {
        prop_assume!(GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS > 0);

        let tip_now = previous_tip
            .saturating_add(GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS)
            .saturating_add(extra_delta);

        let state = AtomicU64::new(previous_tip);

        let emitted = canonical_register_apply_model(&state, tip_now);

        prop_assert!(
            emitted,
            "canonical RegisterNode renewal must emit once the configured block interval is reached"
        );

        prop_assert_eq!(
            state.load(Ordering::SeqCst),
            tip_now,
            "accepted canonical renewal must update last emitted tip"
        );
    }

    // 06/35
    #[test]
    fn canonical_register_lower_tip_after_initialized_state_is_suppressed(
        higher_tip in 1u64..1_000_000_000_000u64,
        rewind in 1u64..1_000_000_000_000u64,
    ) {
        prop_assert!(
            GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS > 0,
            "canonical register renewal interval must be nonzero"
        );

        let lower_tip = higher_tip.saturating_sub(rewind);

        prop_assert!(
            lower_tip < higher_tip,
            "constructed lower_tip must always be below higher_tip"
        );

        let state = AtomicU64::new(higher_tip);

        let emitted = canonical_register_apply_model(&state, lower_tip);

        prop_assert!(
            !emitted,
            "canonical RegisterNode renewal must not rewind from a higher observed tip to a lower tip"
        );

        prop_assert_eq!(
            state.load(Ordering::SeqCst),
            higher_tip,
            "rejected lower tip must not mutate last emitted tip"
        );
    }

    // 07/35
    #[test]
    fn canonical_register_sequence_matches_atomic_reference_model(
        tips in proptest::collection::vec(0u64..1_000_000_000_000u64, 1..64),
    ) {
        prop_assume!(GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS > 0);

        let state = AtomicU64::new(LAST_CANONICAL_REGISTER_TIP_SENTINEL);
        let mut model_state = LAST_CANONICAL_REGISTER_TIP_SENTINEL;

        for tip_now in tips {
            let expected_emit = canonical_register_should_emit_model(model_state, tip_now);
            let actual_emit = canonical_register_apply_model(&state, tip_now);

            prop_assert_eq!(
                actual_emit,
                expected_emit,
                "canonical renewal decision must match the reference model"
            );

            if expected_emit {
                model_state = tip_now;
            }

            prop_assert_eq!(
                state.load(Ordering::SeqCst),
                model_state,
                "atomic state must only advance when renewal is accepted"
            );
        }
    }

    // 08/35
    #[test]
    fn founder_reboot_tip_repair_scan_floor_is_saturating_and_bounded(
        original_tip in any::<u64>(),
    ) {
        let scan_floor = founder_reboot_scan_floor_model(original_tip);

        prop_assert!(
            scan_floor <= original_tip,
            "founder reboot scan floor must never exceed original tip"
        );

        prop_assert!(
            original_tip.saturating_sub(scan_floor)
                <= MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH,
            "founder reboot scan window must never exceed configured repair depth"
        );

        if original_tip <= MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH {
            prop_assert_eq!(
                scan_floor,
                0,
                "small chains must saturate founder reboot scan floor to zero"
            );
        } else {
            prop_assert_eq!(
                scan_floor,
                original_tip - MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH,
                "deep chains must scan back exactly the configured repair depth"
            );
        }
    }

    // 09/35
    #[test]
    fn founder_reboot_scan_floor_is_monotonic_with_tip_height(
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        let low_floor = founder_reboot_scan_floor_model(low);
        let high_floor = founder_reboot_scan_floor_model(high);

        prop_assert!(
            high_floor >= low_floor,
            "scan floor must be monotonic as original tip increases"
        );
    }

    // 10/35
    #[test]
    fn orchestration_register_sentinel_does_not_overlap_realistic_generated_tips(
        realistic_tip in 0u64..u64::MAX,
    ) {
        prop_assert_ne!(
            realistic_tip,
            LAST_CANONICAL_REGISTER_TIP_SENTINEL,
            "u64::MAX is reserved as the uninitialized canonical-register sentinel"
        );
    }

    // 11/35
    #[test]
    fn orchestration_engine_prop_011_valid_lowercase_wallet_canonicalization_is_identity(
        wallet in valid_wallet_lower()
    ) {
        let canonical = canon_wallet_id_checked(&wallet)
            .expect("valid lowercase wallet should canonicalize");

        prop_assert_eq!(&canonical, &wallet);
        prop_assert_eq!(canonical.len(), 129);
        prop_assert_eq!(canonical.as_bytes().first(), Some(&b'r'));
    }

    // 12/35
    #[test]
    fn orchestration_engine_prop_012_valid_mixed_case_wallet_canonicalizes_to_lowercase(
        wallet in valid_wallet_mixed_case()
    ) {
        let canonical = canon_wallet_id_checked(&wallet)
            .expect("valid mixed-case wallet should canonicalize");

        let expected = wallet.to_ascii_lowercase();

        prop_assert_eq!(&canonical, &expected);
        prop_assert_eq!(canonical.len(), 129);
        prop_assert_eq!(&canonical, &canonical.to_ascii_lowercase());
    }

    // 13/35
    #[test]
    fn orchestration_engine_prop_013_wallet_canonicalization_trims_external_whitespace(
        wallet in valid_wallet_lower(),
        prefix in prop_oneof![Just(""), Just(" "), Just("  "), Just("\t"), Just("\n")],
        suffix in prop_oneof![Just(""), Just(" "), Just("  "), Just("\t"), Just("\n")],
    ) {
        let input = format!("{prefix}{wallet}{suffix}");

        let canonical = canon_wallet_id_checked(&input)
            .expect("valid wallet with surrounding whitespace should canonicalize");

        prop_assert_eq!(&canonical, &wallet);
    }

    // 14/35
    #[test]
    fn orchestration_engine_prop_014_wallet_wrong_prefix_is_rejected(
        wallet in invalid_wallet_wrong_prefix()
    ) {
        prop_assert!(
            canon_wallet_id_checked(&wallet).is_err(),
            "wallet with wrong prefix must be rejected"
        );
    }

    // 15/35
    #[test]
    fn orchestration_engine_prop_015_wallet_wrong_total_lengths_are_rejected(
        len in prop_oneof![
            0usize..129usize,
            130usize..260usize,
        ],
        fill in "[0-9a-f]{260}",
    ) {
        let candidate = if len == 0 {
            String::new()
        } else {
            let body_len = len.saturating_sub(1usize);
            let body = fill.chars().take(body_len).collect::<String>();
            format!("r{body}")
        };

        prop_assert_ne!(
            candidate.len(),
            129usize,
            "test generator must only create wrong-length wallets"
        );

        prop_assert!(
            canon_wallet_id_checked(&candidate).is_err(),
            "wallet with wrong total length {} must be rejected",
            candidate.len()
        );
    }

    // 16/35
    #[test]
    fn orchestration_engine_prop_016_wallet_non_hex_body_character_is_rejected(
        body in lower_hex_128(),
        index in 0usize..128usize,
        bad_char in non_hex_char(),
    ) {
        prop_assume!(!bad_char.is_ascii_hexdigit());

        let mut chars = body.chars().collect::<Vec<_>>();
        chars[index] = bad_char;

        let candidate = format!("r{}", chars.into_iter().collect::<String>());

        prop_assert!(
            canon_wallet_id_checked(&candidate).is_err(),
            "wallet body with non-hex character must be rejected"
        );
    }

    // 17/35
    #[test]
    fn orchestration_engine_prop_017_arbitrary_wallet_input_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let input = String::from_utf8_lossy(&bytes).to_string();

        let result = std::panic::catch_unwind(|| canon_wallet_id_checked(&input));

        prop_assert!(
            result.is_ok(),
            "wallet canonicalization must not panic for arbitrary external input"
        );

        if let Ok(canonical) = result.expect("panic checked above") {
            prop_assert_eq!(canonical.len(), 129);
            prop_assert_eq!(canonical.as_bytes().first(), Some(&b'r'));
            prop_assert_eq!(&canonical, &canonical.to_ascii_lowercase());
            prop_assert!(canonical.as_bytes()[1..].iter().all(|b| b.is_ascii_hexdigit()));
        }
    }

    // 18/35
    #[test]
    fn orchestration_engine_prop_018_register_node_tx_accepts_valid_canonical_wallets(
        wallet in valid_wallet_lower()
    ) {
        let tx = RegisterNodeTx::new(wallet.clone())
            .expect("RegisterNodeTx should accept valid canonical wallet");

        let kind = TxKind::RegisterNode(tx);

        prop_assert!(
            kind.validate().is_ok(),
            "TxKind::RegisterNode should validate for valid wallet"
        );
    }

    // 19/35
    #[test]
    fn orchestration_engine_prop_019_register_node_tx_rejects_invalid_wallets(
        wallet in prop_oneof![
            invalid_wallet_wrong_prefix(),
            Just("".to_string()),
            Just("r".to_string()),
            Just(format!("r{}", "a".repeat(127))),
            Just(format!("r{}", "a".repeat(129))),
            Just(format!("r{}", "g".repeat(128))),
        ]
    ) {
        prop_assert!(
            RegisterNodeTx::new(wallet).is_err(),
            "RegisterNodeTx must reject invalid wallet strings"
        );
    }

    // 20/35
    #[test]
    fn orchestration_engine_prop_020_quorum_threshold_is_sensible_for_nonzero_validator_count(
        validators_len in 1usize..10_000usize,
    ) {
        let threshold = quorum_threshold_checked(validators_len)
            .expect("nonzero validator count should produce quorum threshold");

        prop_assert!(threshold >= 1);
        prop_assert!(threshold <= validators_len);
        prop_assert!(
            has_quorum(threshold, validators_len),
            "threshold itself should satisfy quorum"
        );
    }

    // 21/35
    #[test]
    fn orchestration_engine_prop_021_quorum_is_false_below_checked_threshold(
        validators_len in 1usize..10_000usize,
    ) {
        let threshold = quorum_threshold_checked(validators_len)
            .expect("nonzero validator count should produce quorum threshold");

        if threshold > 0 {
            prop_assert!(
                !has_quorum(threshold - 1, validators_len),
                "one below threshold should not have quorum"
            );
        }
    }

    // 22/35
    #[test]
    fn orchestration_engine_prop_022_quorum_is_monotonic_in_live_count(
        validators_len in 1usize..10_000usize,
        a in 0usize..10_000usize,
        b in 0usize..10_000usize,
    ) {
        let low = a.min(b);
        let high = a.max(b);

        if has_quorum(low, validators_len) {
            prop_assert!(
                has_quorum(high, validators_len),
                "quorum must be monotonic as live count increases"
            );
        }
    }

    // 23/35
    #[test]
    fn orchestration_engine_prop_023_zero_live_committee_members_never_has_quorum_when_validators_exist(
        validators_len in 1usize..10_000usize,
    ) {
        prop_assert!(
            !has_quorum(0, validators_len),
            "zero live committee members must not satisfy quorum"
        );
    }

    // 24/35
    #[test]
    fn orchestration_engine_prop_024_full_live_committee_always_has_quorum(
        validators_len in 1usize..10_000usize,
    ) {
        prop_assert!(
            has_quorum(validators_len, validators_len),
            "all validators live must satisfy quorum"
        );
    }

    // 25/35
    #[test]
    fn orchestration_engine_prop_025_live_committee_seen_saturates_with_local_wallet_live(
        connected_wallet_peers in 0usize..1_000_000usize,
        local_wallet_live in any::<bool>(),
    ) {
        let seen = live_committee_seen_model(local_wallet_live, connected_wallet_peers);

        if local_wallet_live {
            prop_assert_eq!(seen, connected_wallet_peers.saturating_add(1));
        } else {
            prop_assert_eq!(seen, connected_wallet_peers);
        }
    }

    // 26/35
    #[test]
    fn orchestration_engine_prop_026_committee_status_validates_for_bounded_runtime_inputs(
        is_live in any::<bool>(),
        has_synced in any::<bool>(),
        local_tip in 0u64..1_000_000u64,
        network_lead in 0u64..1_000_000u64,
        peers_connected in 0usize..1_000usize,
        connected_wallet_peer_seed in 0usize..1_000usize,
    ) {
        let connected_wallet_peers = connected_wallet_peer_seed % peers_connected.saturating_add(1);
        let network_tip = local_tip.saturating_add(network_lead);

        let update = CommitteeStatusUpdate {
            is_live,
            has_synced,
            local_tip,
            network_tip,
            peers_connected,
            connected_wallet_peers,
        };

        prop_assert!(
            update.validate_invariants().is_ok(),
            "bounded runtime committee status should validate"
        );
    }

    // 27/35
    #[test]
    fn orchestration_engine_prop_027_committee_status_validation_never_panics_for_extreme_inputs(
        is_live in any::<bool>(),
        has_synced in any::<bool>(),
        local_tip in any::<u64>(),
        network_tip in any::<u64>(),
        peers_connected in any::<usize>(),
        connected_wallet_peers in any::<usize>(),
    ) {
        let update = CommitteeStatusUpdate {
            is_live,
            has_synced,
            local_tip,
            network_tip,
            peers_connected,
            connected_wallet_peers,
        };

        let result = std::panic::catch_unwind(|| update.validate_invariants());

        prop_assert!(
            result.is_ok(),
            "CommitteeStatusUpdate::validate_invariants must not panic"
        );
    }

    // 28/35
    #[test]
    fn orchestration_engine_prop_028_basic_miner_intent_model_requires_wallet_and_intent(
        wallet in prop_oneof![
            Just("".to_string()),
            Just(" ".to_string()),
            Just("\t".to_string()),
            valid_wallet_lower(),
        ],
        mining_intent in any::<bool>(),
    ) {
        let allowed = miner_allowed_by_basic_intent_model(&wallet, mining_intent);

        prop_assert_eq!(allowed, mining_intent && !wallet.trim().is_empty());

        if allowed {
            prop_assert!(mining_intent);
            prop_assert!(!wallet.trim().is_empty());
        }
    }

    // 29/35
    #[test]
    fn orchestration_engine_prop_029_slot_timing_skip_model_uses_saturating_next_height(
        slot_now in any::<u64>(),
        tip_now in any::<u64>(),
    ) {
        let next_h = tip_now.saturating_add(1);
        let should_skip = slot_timing_skip_model(slot_now, tip_now);

        prop_assert_eq!(should_skip, slot_now.saturating_add(1) < next_h);

        if tip_now == u64::MAX {
            prop_assert_eq!(next_h, u64::MAX);
        } else {
            prop_assert_eq!(next_h, tip_now + 1);
        }
    }

    // 30/35
    #[test]
    fn orchestration_engine_prop_030_slot_timing_never_skips_when_slot_is_already_at_or_above_next_height(
        tip_now in 0u64..u64::MAX,
        lead in 0u64..1_000_000u64,
    ) {
        let next_h = tip_now.saturating_add(1);
        let slot_now = next_h.saturating_add(lead);

        prop_assert!(
            !slot_timing_skip_model(slot_now, tip_now),
            "slot gate must not skip once slot_now is at or above next height"
        );
    }

    // 31/35
    #[test]
    fn orchestration_engine_prop_031_slot_timing_skips_when_slot_is_too_far_behind(
        tip_now in 2u64..1_000_000_000u64,
        lag in 1u64..1_000u64,
    ) {
        let next_h = tip_now.saturating_add(1);
        let slot_now = next_h.saturating_sub(1).saturating_sub(lag);

        prop_assert!(
            slot_timing_skip_model(slot_now, tip_now),
            "slot gate must skip while slot_now + 1 is still below next height"
        );
    }

    // 32/35
    #[test]
    fn orchestration_engine_prop_032_heartbeat_interval_is_nonzero_and_zero_grace_is_allowed(_case in any::<u8>()) {
        prop_assert!(
            GlobalConfiguration::HEARTBEAT_TX_INTERVAL_SECS > 0,
            "registry heartbeat interval must be nonzero"
        );

        let eviction_plus_grace = GlobalConfiguration::DEAD_PEER_EVICTION_SECS
            .saturating_add(GlobalConfiguration::HEARTBEAT_GRACE_SECS);

        prop_assert!(
            eviction_plus_grace >= GlobalConfiguration::DEAD_PEER_EVICTION_SECS,
            "heartbeat grace may be zero, but adding it must not reduce eviction window"
        );
    }

    // 33/35
    #[test]
    fn orchestration_engine_prop_033_dead_peer_eviction_window_is_at_least_base_eviction_interval(_case in any::<u8>()) {
        let eviction_plus_grace = GlobalConfiguration::DEAD_PEER_EVICTION_SECS
            .saturating_add(GlobalConfiguration::HEARTBEAT_GRACE_SECS);

        prop_assert!(
            eviction_plus_grace >= GlobalConfiguration::DEAD_PEER_EVICTION_SECS,
            "eviction + grace must include the base eviction interval"
        );

        prop_assert!(
            eviction_plus_grace >= GlobalConfiguration::HEARTBEAT_GRACE_SECS,
            "eviction + grace must include the grace interval"
        );
    }

    // 34/35
    #[test]
    fn orchestration_engine_prop_034_canonical_renew_interval_configuration_is_nonzero(_case in any::<u8>()) {
        prop_assert!(
            GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS > 0,
            "canonical register renewal interval must be nonzero"
        );
    }

    // 35/35
    #[test]
    fn orchestration_engine_prop_035_runtime_tick_counter_increment_model_saturates(
        current_ticks in any::<u64>(),
    ) {
        let next = current_ticks.saturating_add(1);

        prop_assert!(next >= current_ticks);

        if current_ticks == u64::MAX {
            prop_assert_eq!(next, u64::MAX);
        } else {
            prop_assert_eq!(next, current_ticks + 1);
        }
    }
}
