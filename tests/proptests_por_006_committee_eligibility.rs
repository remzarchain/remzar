use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_006_committee_eligibility::{
    CommitteeEligibility, CommitteeEligibilityConfig, CommitteeEligibilityDecision,
    CommitteeMemberStatus, CommitteeStatusUpdate, IneligibilityReason,
};

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

fn live_synced_status(
    wallet: String,
    local_tip: u64,
    network_tip: u64,
    peers_connected: usize,
    connected_wallet_peers: usize,
) -> CommitteeMemberStatus {
    CommitteeMemberStatus {
        wallet,
        is_live: true,
        has_synced: true,
        local_tip,
        network_tip,
        peers_connected,
        connected_wallet_peers,
        is_isolated: connected_wallet_peers == 0,
    }
}

fn not_live_status(wallet: String) -> CommitteeMemberStatus {
    CommitteeMemberStatus {
        wallet,
        is_live: false,
        has_synced: true,
        local_tip: 0,
        network_tip: 0,
        peers_connected: 0,
        connected_wallet_peers: 0,
        is_isolated: true,
    }
}

fn assert_reason(decision: &CommitteeEligibilityDecision, expected: IneligibilityReason) -> bool {
    decision.reasons.iter().any(|reason| reason == &expected)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_default_config_is_valid_and_new_committee_starts_empty(
        _case in any::<u8>(),
    ) {
        let config = CommitteeEligibilityConfig::default();

        prop_assert!(
            config.validate().is_ok(),
            "default CommitteeEligibilityConfig must be valid"
        );

        let committee = CommitteeEligibility::new(config.clone());

        prop_assert!(
            committee.validate_config().is_ok(),
            "CommitteeEligibility created with default config must validate"
        );

        prop_assert!(
            committee.is_empty(),
            "new CommitteeEligibility must start empty"
        );

        prop_assert_eq!(
            committee.len(),
            0,
            "new CommitteeEligibility must have zero statuses"
        );

        prop_assert!(
            committee.live_wallets().is_empty(),
            "new CommitteeEligibility must have no live wallets"
        );

        prop_assert_eq!(
            committee.config(),
            &config,
            "new CommitteeEligibility must preserve supplied config"
        );
    }

    // 02/25
    #[test]
    fn test_002_config_rejects_wallet_peer_minimum_above_total_peer_minimum(
        min_peers in 0usize..32usize,
        extra in 1usize..32usize,
    ) {
        let config = CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: min_peers,
            min_connected_wallet_peers: min_peers.saturating_add(extra),
            require_non_isolated: false,
            require_synced: false,
        };

        prop_assert!(
            config.validate().is_err(),
            "config must reject min_connected_wallet_peers > min_peers_connected"
        );

        let committee = CommitteeEligibility::new(config);

        prop_assert!(
            committee.validate_config().is_err(),
            "CommitteeEligibility must expose invalid stored config through validate_config"
        );
    }

    // 03/25
    #[test]
    fn test_003_status_update_isolation_is_derived_from_connected_wallet_peers_and_invariants_hold(
        is_live in any::<bool>(),
        has_synced in any::<bool>(),
        local_tip in any::<u64>(),
        lag in 0u64..1000u64,
        peers_connected in 0usize..64usize,
        wallet_peer_seed in any::<usize>(),
    ) {
        let connected_wallet_peers = if peers_connected == 0 {
            0
        } else {
            wallet_peer_seed % peers_connected.saturating_add(1)
        };

        let update = CommitteeStatusUpdate {
            is_live,
            has_synced,
            local_tip,
            network_tip: local_tip.saturating_add(lag),
            peers_connected,
            connected_wallet_peers,
        };

        prop_assert_eq!(
            update.is_isolated(),
            connected_wallet_peers == 0,
            "CommitteeStatusUpdate::is_isolated must be derived only from connected_wallet_peers == 0"
        );

        prop_assert!(
            update.validate_invariants().is_ok(),
            "valid CommitteeStatusUpdate peer counts must pass invariants"
        );
    }

    // 04/25
    #[test]
    fn test_004_status_update_rejects_connected_wallet_peers_above_total_peers(
        peers_connected in 0usize..64usize,
        extra in 1usize..64usize,
    ) {
        let update = CommitteeStatusUpdate {
            is_live: true,
            has_synced: true,
            local_tip: 0,
            network_tip: 0,
            peers_connected,
            connected_wallet_peers: peers_connected.saturating_add(extra),
        };

        prop_assert!(
            update.validate_invariants().is_err(),
            "CommitteeStatusUpdate must reject connected_wallet_peers > peers_connected"
        );
    }

    // 05/25
    #[test]
    fn test_005_member_status_tip_lag_saturates_and_valid_status_passes_invariants(
        wallet_seed in any::<u64>(),
        local_tip in any::<u64>(),
        network_tip in any::<u64>(),
        peers_connected in 0usize..64usize,
        wallet_peer_seed in any::<usize>(),
    ) {
        let connected_wallet_peers = if peers_connected == 0 {
            0
        } else {
            wallet_peer_seed % peers_connected.saturating_add(1)
        };

        let status = CommitteeMemberStatus {
            wallet: wallet(wallet_seed),
            is_live: true,
            has_synced: true,
            local_tip,
            network_tip,
            peers_connected,
            connected_wallet_peers,
            is_isolated: connected_wallet_peers == 0,
        };

        prop_assert_eq!(
            status.tip_lag(),
            network_tip.saturating_sub(local_tip),
            "tip_lag must saturate instead of underflowing when local_tip > network_tip"
        );

        prop_assert_eq!(
            status.canonical_wallet(),
            status.wallet.as_str(),
            "canonical_wallet must return the stored wallet string"
        );

        prop_assert!(
            status.validate_invariants().is_ok(),
            "valid CommitteeMemberStatus must pass invariants"
        );
    }

    // 06/25
    #[test]
    fn test_006_member_status_rejects_invalid_wallet_peer_counts_or_isolation_contradiction(
        wallet_seed in any::<u64>(),
        invalid_case in 0usize..3usize,
    ) {
        let mut status = live_synced_status(
            wallet(wallet_seed),
            10,
            10,
            1,
            1,
        );

        match invalid_case {
            0 => status.wallet = "not-a-wallet".to_string(),
            1 => {
                status.peers_connected = 1;
                status.connected_wallet_peers = 2;
                status.is_isolated = false;
            }
            _ => {
                status.peers_connected = 1;
                status.connected_wallet_peers = 1;
                status.is_isolated = true;
            }
        }

        prop_assert!(
            status.validate_invariants().is_err(),
            "CommitteeMemberStatus must reject invalid wallet, wallet peers above total peers, or isolated=true with wallet peers"
        );
    }

    // 07/25
    #[test]
    fn test_007_replace_live_wallets_canonicalizes_deduplicates_and_sorts_wallets(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);
        let raw_a_upper = wallet_a.to_ascii_uppercase();
        let raw_a_spaced = format!(" \n\t{wallet_a}\r\n ");

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .replace_live_wallets(vec![raw_a_upper, raw_a_spaced, wallet_b.clone()])
            .expect("canonicalizable live wallet set should be accepted");

        let live = committee.live_wallets();
        let mut sorted = live.clone();
        sorted.sort_unstable();

        prop_assert_eq!(
            &live,
            &sorted,
            "live_wallets must be returned in deterministic sorted order"
        );

        prop_assert_eq!(
            live.len(),
            2,
            "replace_live_wallets must deduplicate canonical wallet aliases"
        );

        prop_assert!(live.contains(&wallet_a));
        prop_assert!(live.contains(&wallet_b));
    }

    // 08/25
    #[test]
    fn test_008_replace_live_wallets_rejects_invalid_wallet_and_preserves_existing_live_set(
        seed_existing in any::<u64>(),
        bad_tail in "[0-9a-f]{0,127}",
    ) {
        let existing = wallet(seed_existing);
        let invalid = format!("r{bad_tail}");

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .replace_live_wallets(vec![existing.clone()])
            .expect("initial valid live wallet should be accepted");

        prop_assert!(
            committee.replace_live_wallets(vec![invalid]).is_err(),
            "replace_live_wallets must reject malformed wallet input"
        );

        prop_assert_eq!(
            committee.live_wallets(),
            vec![existing],
            "failed replace_live_wallets must preserve previous live-wallet view"
        );
    }

    // 09/25
    #[test]
    fn test_009_mark_wallet_live_adds_and_removes_canonical_wallet_without_touching_statuses(
        wallet_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);
        let raw_upper = wallet.to_ascii_uppercase();

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .mark_wallet_live(&raw_upper, true)
            .expect("canonicalizable wallet should be markable live");

        prop_assert!(
            committee.is_wallet_live(&wallet),
            "mark_wallet_live(true) must add canonical wallet to live set"
        );

        prop_assert_eq!(
            committee.len(),
            0,
            "mark_wallet_live must not create a runtime status entry"
        );

        committee
            .mark_wallet_live(&wallet, false)
            .expect("canonical wallet should be removable from live set");

        prop_assert!(
            !committee.is_wallet_live(&wallet),
            "mark_wallet_live(false) must remove wallet from live set"
        );

        prop_assert!(
            committee.is_empty(),
            "committee must be empty after live-only wallet removal"
        );
    }

    // 10/25
    #[test]
    fn test_010_mark_wallet_live_rejects_invalid_wallet_and_leaves_live_set_unchanged(
        existing_seed in any::<u64>(),
        bad_tail in "[0-9a-f]{0,127}",
    ) {
        let existing = wallet(existing_seed);
        let invalid = format!("r{bad_tail}");

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .mark_wallet_live(&existing, true)
            .expect("valid wallet should be marked live");

        prop_assert!(
            committee.mark_wallet_live(&invalid, true).is_err(),
            "mark_wallet_live must reject malformed wallet"
        );

        prop_assert_eq!(
            committee.live_wallets(),
            vec![existing],
            "failed mark_wallet_live must not mutate live set"
        );
    }

    // 11/25
    #[test]
    fn test_011_upsert_live_status_normalizes_wallet_stores_status_and_marks_live(
        wallet_seed in any::<u64>(),
        local_tip in 0u64..1_000_000u64,
        lag in 0u64..=2u64,
    ) {
        let wallet = wallet(wallet_seed);
        let raw_upper = wallet.to_ascii_uppercase();

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .upsert_status(live_synced_status(
                raw_upper,
                local_tip,
                local_tip.saturating_add(lag),
                0,
                0,
            ))
            .expect("valid live status should upsert");

        prop_assert_eq!(
            committee.len(),
            1,
            "upsert_status must store exactly one status"
        );

        prop_assert!(
            committee.is_wallet_live(&wallet),
            "upsert_status with is_live=true must mark wallet live"
        );

        let stored = committee
            .get_status(&wallet)
            .expect("upserted wallet status must be retrievable");

        prop_assert_eq!(
            &stored.wallet,
            &wallet,
            "upsert_status must store canonical lowercase wallet"
        );

        prop_assert!(
            committee.is_wallet_runtime_ready(&wallet),
            "live synced status within default lag must be runtime ready"
        );
    }

    // 12/25
    #[test]
    fn test_012_upsert_not_live_status_stores_status_but_removes_live_readiness(
        wallet_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .mark_wallet_live(&wallet, true)
            .expect("wallet should be initially live");

        committee
            .upsert_status(not_live_status(wallet.clone()))
            .expect("valid not-live status should upsert");

        prop_assert_eq!(
            committee.len(),
            1,
            "not-live status should still be stored for observability"
        );

        prop_assert!(
            !committee.is_wallet_live(&wallet),
            "upsert_status with is_live=false must remove wallet from live set"
        );

        let decision = committee.decide_wallet(&wallet);

        prop_assert!(!decision.eligible);
        prop_assert_eq!(
            decision.reasons,
            vec![IneligibilityReason::NotLive],
            "not-live wallet must be rejected only for NotLive before other status policy"
        );
    }

    // 13/25
    #[test]
    fn test_013_update_local_status_computes_isolation_and_overwrites_previous_status(
        wallet_seed in any::<u64>(),
        local_tip in 0u64..1_000_000u64,
    ) {
        let wallet = wallet(wallet_seed);

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .update_local_status(
                &wallet,
                CommitteeStatusUpdate {
                    is_live: true,
                    has_synced: false,
                    local_tip,
                    network_tip: local_tip,
                    peers_connected: 8,
                    connected_wallet_peers: 4,
                },
            )
            .expect("first local status update should succeed");

        committee
            .update_local_status(
                &wallet,
                CommitteeStatusUpdate {
                    is_live: true,
                    has_synced: true,
                    local_tip,
                    network_tip: local_tip,
                    peers_connected: 0,
                    connected_wallet_peers: 0,
                },
            )
            .expect("second local status update should overwrite");

        let stored = committee
            .get_status(&wallet)
            .expect("local status must be stored");

        prop_assert!(stored.has_synced);
        prop_assert_eq!(stored.peers_connected, 0);
        prop_assert_eq!(stored.connected_wallet_peers, 0);
        prop_assert!(
            stored.is_isolated,
            "update_local_status must derive is_isolated from connected_wallet_peers == 0"
        );
    }

    // 14/25
    #[test]
    fn test_014_update_remote_status_uses_same_normalization_and_invariant_checks_as_local_status(
        wallet_seed in any::<u64>(),
        peers_connected in 0usize..32usize,
        extra in 1usize..32usize,
    ) {
        let wallet = wallet(wallet_seed);
        let raw_upper = wallet.to_ascii_uppercase();

        let mut committee = CommitteeEligibility::with_default_config();

        prop_assert!(
            committee
                .update_remote_status(
                    &raw_upper,
                    CommitteeStatusUpdate {
                        is_live: true,
                        has_synced: true,
                        local_tip: 10,
                        network_tip: 10,
                        peers_connected,
                        connected_wallet_peers: peers_connected.saturating_add(extra),
                    },
                )
                .is_err(),
            "update_remote_status must reject invalid wallet-peer counts"
        );

        prop_assert!(
            committee.get_status(&wallet).is_none(),
            "failed remote status update must not insert status"
        );

        committee
            .update_remote_status(
                &raw_upper,
                CommitteeStatusUpdate {
                    is_live: true,
                    has_synced: true,
                    local_tip: 10,
                    network_tip: 10,
                    peers_connected: 1,
                    connected_wallet_peers: 1,
                },
            )
            .expect("valid remote status update should succeed");

        prop_assert!(
            committee.is_wallet_live(&wallet),
            "valid remote live status must mark canonical wallet live"
        );

        let stored = committee
            .get_status(&wallet)
            .expect("remote status must exist");

        prop_assert_eq!(
            &stored.wallet,
            &wallet,
            "remote status must be stored under canonical wallet"
        );
    }

    // 15/25
    #[test]
    fn test_015_live_wallet_without_explicit_status_is_runtime_ready_by_default(
        wallet_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .mark_wallet_live(&wallet, true)
            .expect("valid wallet should be marked live");

        let decision = committee.decide_wallet(&wallet);

        prop_assert!(
            decision.eligible,
            "live wallet with no explicit runtime status must be ready by default"
        );

        prop_assert!(
            decision.reasons.is_empty(),
            "eligible decision must have no ineligibility reasons"
        );

        prop_assert!(committee.is_wallet_eligible(&wallet));
        prop_assert!(committee.is_wallet_runtime_ready(&wallet));
    }

    // 16/25
    #[test]
    fn test_016_not_live_wallet_is_ineligible_even_if_status_exists(
        wallet_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .upsert_status(not_live_status(wallet.clone()))
            .expect("not-live status should upsert");

        let decision = committee.decide_wallet(&wallet);

        prop_assert!(
            !decision.eligible,
            "wallet not in live set must be ineligible"
        );

        prop_assert_eq!(
            decision.reasons,
            vec![IneligibilityReason::NotLive],
            "not-live wallet must report NotLive"
        );

        prop_assert!(!committee.is_wallet_eligible(&wallet));
        prop_assert!(!committee.is_wallet_runtime_ready(&wallet));
    }

    // 17/25
    #[test]
    fn test_017_require_synced_rejects_live_unsynced_status_and_config_mut_can_restore_readiness(
        wallet_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);

        let config = CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: 0,
            min_connected_wallet_peers: 0,
            require_non_isolated: false,
            require_synced: true,
        };

        let mut committee = CommitteeEligibility::new(config);

        committee
            .upsert_status(CommitteeMemberStatus {
                wallet: wallet.clone(),
                is_live: true,
                has_synced: false,
                local_tip: 100,
                network_tip: 100,
                peers_connected: 0,
                connected_wallet_peers: 0,
                is_isolated: true,
            })
            .expect("live unsynced status should upsert");

        let rejected = committee.decide_wallet(&wallet);

        prop_assert!(!rejected.eligible);
        prop_assert!(
            assert_reason(&rejected, IneligibilityReason::NotSynced),
            "require_synced=true must reject unsynced status"
        );

        committee.config_mut().require_synced = false;

        prop_assert!(
            committee.decide_wallet(&wallet).eligible,
            "config_mut disabling require_synced must make otherwise healthy live status ready"
        );
    }

    // 18/25
    #[test]
    fn test_018_tip_lag_is_accepted_at_boundary_and_rejected_above_boundary(
        wallet_seed in any::<u64>(),
        local_tip in 0u64..1_000_000u64,
        max_lag in 0u64..100u64,
    ) {
        let wallet = wallet(wallet_seed);

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: max_lag,
            min_peers_connected: 0,
            min_connected_wallet_peers: 0,
            require_non_isolated: false,
            require_synced: true,
        });

        committee
            .upsert_status(live_synced_status(
                wallet.clone(),
                local_tip,
                local_tip.saturating_add(max_lag),
                0,
                0,
            ))
            .expect("boundary lag status should upsert");

        prop_assert!(
            committee.decide_wallet(&wallet).eligible,
            "tip lag exactly at max_tip_lag_blocks must be accepted"
        );

        committee
            .upsert_status(live_synced_status(
                wallet.clone(),
                local_tip,
                local_tip.saturating_add(max_lag).saturating_add(1),
                0,
                0,
            ))
            .expect("above-boundary lag status should upsert");

        let rejected = committee.decide_wallet(&wallet);

        prop_assert!(!rejected.eligible);
        prop_assert!(
            assert_reason(
                &rejected,
                IneligibilityReason::TooFarBehind {
                    lag: max_lag.saturating_add(1),
                    max_allowed: max_lag,
                }
            ),
            "tip lag above max_tip_lag_blocks must produce TooFarBehind"
        );
    }

    // 19/25
    #[test]
    fn test_019_multi_node_mode_enforces_minimum_total_peer_count(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        min_peers in 1usize..16usize,
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: min_peers,
            min_connected_wallet_peers: 0,
            require_non_isolated: false,
            require_synced: true,
        });

        committee
            .replace_live_wallets(vec![wallet_a.clone(), wallet_b])
            .expect("two live wallets should set multi-node mode");

        committee
            .upsert_status(live_synced_status(
                wallet_a.clone(),
                100,
                100,
                min_peers.saturating_sub(1),
                0,
            ))
            .expect("status below total peer minimum should upsert");

        let decision = committee.decide_wallet(&wallet_a);

        prop_assert!(!decision.eligible);
        prop_assert!(
            assert_reason(
                &decision,
                IneligibilityReason::NotEnoughPeers {
                    connected: min_peers.saturating_sub(1),
                    min_required: min_peers,
                }
            ),
            "multi-node readiness must enforce min_peers_connected"
        );
    }

    // 20/25
    #[test]
    fn test_020_multi_node_mode_enforces_minimum_connected_wallet_peer_count(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        min_wallet_peers in 1usize..16usize,
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: min_wallet_peers,
            min_connected_wallet_peers: min_wallet_peers,
            require_non_isolated: false,
            require_synced: true,
        });

        committee
            .replace_live_wallets(vec![wallet_a.clone(), wallet_b])
            .expect("two live wallets should set multi-node mode");

        committee
            .upsert_status(live_synced_status(
                wallet_a.clone(),
                100,
                100,
                min_wallet_peers,
                min_wallet_peers.saturating_sub(1),
            ))
            .expect("status below wallet-peer minimum should upsert");

        let decision = committee.decide_wallet(&wallet_a);

        prop_assert!(!decision.eligible);
        prop_assert!(
            assert_reason(
                &decision,
                IneligibilityReason::NotEnoughWalletPeers {
                    connected: min_wallet_peers.saturating_sub(1),
                    min_required: min_wallet_peers,
                }
            ),
            "multi-node readiness must enforce min_connected_wallet_peers"
        );
    }

    // 21/25
    #[test]
    fn test_021_multi_node_mode_enforces_non_isolated_requirement(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: 0,
            min_connected_wallet_peers: 0,
            require_non_isolated: true,
            require_synced: true,
        });

        committee
            .replace_live_wallets(vec![wallet_a.clone(), wallet_b])
            .expect("two live wallets should set multi-node mode");

        committee
            .upsert_status(live_synced_status(wallet_a.clone(), 100, 100, 0, 0))
            .expect("isolated status should upsert");

        let decision = committee.decide_wallet(&wallet_a);

        prop_assert!(!decision.eligible);
        prop_assert!(
            assert_reason(&decision, IneligibilityReason::Isolated),
            "multi-node readiness must enforce require_non_isolated"
        );
    }

    // 22/25
    #[test]
    fn test_022_solo_live_validator_bypasses_connectivity_and_isolation_checks(
        wallet_seed in any::<u64>(),
    ) {
        let wallet = wallet(wallet_seed);

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: 10,
            min_connected_wallet_peers: 10,
            require_non_isolated: true,
            require_synced: true,
        });

        committee
            .replace_live_wallets(vec![wallet.clone()])
            .expect("single live wallet should be accepted");

        committee
            .upsert_status(live_synced_status(wallet.clone(), 100, 100, 0, 0))
            .expect("solo isolated status should upsert");

        let decision = committee.decide_wallet(&wallet);

        prop_assert!(
            decision.eligible,
            "solo live validator must remain runtime-ready despite zero peers and isolation"
        );

        prop_assert!(
            decision.reasons.is_empty(),
            "solo rule must suppress connectivity/isolation reasons when synced and not lagging"
        );
    }

    // 23/25
    #[test]
    fn test_023_unhealthy_multi_node_status_accumulates_all_independent_reasons(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: 1,
            min_peers_connected: 3,
            min_connected_wallet_peers: 2,
            require_non_isolated: true,
            require_synced: true,
        });

        committee
            .replace_live_wallets(vec![wallet_a.clone(), wallet_b])
            .expect("two live wallets should set multi-node mode");

        committee
            .upsert_status(CommitteeMemberStatus {
                wallet: wallet_a.clone(),
                is_live: true,
                has_synced: false,
                local_tip: 10,
                network_tip: 15,
                peers_connected: 1,
                connected_wallet_peers: 0,
                is_isolated: true,
            })
            .expect("structurally valid unhealthy status should upsert");

        let decision = committee.decide_wallet(&wallet_a);

        prop_assert!(!decision.eligible);

        prop_assert!(
            assert_reason(&decision, IneligibilityReason::NotSynced),
            "decision must include NotSynced"
        );

        prop_assert!(
            assert_reason(
                &decision,
                IneligibilityReason::TooFarBehind {
                    lag: 5,
                    max_allowed: 1,
                }
            ),
            "decision must include TooFarBehind"
        );

        prop_assert!(
            assert_reason(
                &decision,
                IneligibilityReason::NotEnoughPeers {
                    connected: 1,
                    min_required: 3,
                }
            ),
            "decision must include NotEnoughPeers"
        );

        prop_assert!(
            assert_reason(
                &decision,
                IneligibilityReason::NotEnoughWalletPeers {
                    connected: 0,
                    min_required: 2,
                }
            ),
            "decision must include NotEnoughWalletPeers"
        );

        prop_assert!(
            assert_reason(&decision, IneligibilityReason::Isolated),
            "decision must include Isolated"
        );
    }

    // 24/25
    #[test]
    fn test_024_remove_wallet_and_clear_remove_live_status_and_observability_state(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let (wallet_a, wallet_b) = distinct_wallets(seed_a, seed_b);

        let mut committee = CommitteeEligibility::with_default_config();

        committee
            .upsert_status(live_synced_status(wallet_a.clone(), 100, 100, 0, 0))
            .expect("wallet_a status should upsert");

        committee
            .mark_wallet_live(&wallet_b, true)
            .expect("wallet_b should be marked live");

        prop_assert_eq!(committee.len(), 1);
        prop_assert!(committee.is_wallet_live(&wallet_a));
        prop_assert!(committee.is_wallet_live(&wallet_b));

        prop_assert!(
            committee.remove_wallet(&wallet_a),
            "remove_wallet must return true when status/live state existed"
        );

        prop_assert!(!committee.is_wallet_live(&wallet_a));
        prop_assert!(committee.get_status(&wallet_a).is_none());

        prop_assert!(
            !committee.remove_wallet("invalid-wallet"),
            "remove_wallet must return false for malformed wallet input"
        );

        committee.clear();

        prop_assert!(
            committee.is_empty(),
            "clear must remove both statuses and live wallets"
        );

        prop_assert_eq!(committee.len(), 0);
        prop_assert!(committee.live_wallets().is_empty());
    }

    // 25/25
    #[test]
    fn test_025_filter_helpers_and_all_runtime_decisions_report_runtime_readiness_only(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        let (wallet_a, wallet_b, wallet_c) = three_distinct_wallets(seed_a, seed_b, seed_c);
        let raw_a_upper = wallet_a.to_ascii_uppercase();

        let mut committee = CommitteeEligibility::new(CommitteeEligibilityConfig {
            max_tip_lag_blocks: 2,
            min_peers_connected: 0,
            min_connected_wallet_peers: 0,
            require_non_isolated: false,
            require_synced: true,
        });

        committee
            .mark_wallet_live(&wallet_a, true)
            .expect("wallet_a should be live without explicit status");

        committee
            .upsert_status(CommitteeMemberStatus {
                wallet: wallet_b.clone(),
                is_live: true,
                has_synced: false,
                local_tip: 100,
                network_tip: 100,
                peers_connected: 0,
                connected_wallet_peers: 0,
                is_isolated: true,
            })
            .expect("wallet_b unsynced status should upsert");

        let candidates = vec![raw_a_upper.clone(), wallet_b.clone(), wallet_c.clone()];

        let kept = committee.filter_candidates(candidates.clone());

        prop_assert_eq!(
            kept,
            vec![raw_a_upper.clone()],
            "filter_candidates must keep only runtime-ready candidates and preserve original candidate spelling"
        );

        let (kept_with_decisions, decisions) =
            committee.filter_candidates_with_decisions(candidates.clone());

        prop_assert_eq!(
            kept_with_decisions,
            vec![raw_a_upper],
            "filter_candidates_with_decisions must keep the same ready candidates as filter_candidates"
        );

        prop_assert_eq!(
            decisions.len(),
            3,
            "filter_candidates_with_decisions must produce one decision per input candidate"
        );

        prop_assert!(
            decisions.iter().any(|decision| {
                decision.wallet.eq_ignore_ascii_case(wallet_a.as_str()) && decision.eligible
            }),
            "decisions must include eligible wallet_a"
        );

        prop_assert!(
            decisions.iter().any(|decision| {
                decision.wallet.as_str() == wallet_b.as_str()
                    && !decision.eligible
                    && assert_reason(decision, IneligibilityReason::NotSynced)
            }),
            "decisions must include wallet_b rejected for NotSynced"
        );

        prop_assert!(
            decisions.iter().any(|decision| {
                decision.wallet.as_str() == wallet_c.as_str()
                    && !decision.eligible
                    && decision.reasons == vec![IneligibilityReason::NotLive]
            }),
            "decisions must include wallet_c rejected for NotLive"
        );

        let all = committee.all_runtime_decisions();

        prop_assert_eq!(
            all.len(),
            2,
            "all_runtime_decisions must cover the union of live wallets and known status wallets, not arbitrary candidates"
        );

        prop_assert!(
            all.iter().any(|decision| {
                decision.wallet.as_str() == wallet_a.as_str() && decision.eligible
            }),
            "all_runtime_decisions must include live wallet_a"
        );

        prop_assert!(
            all.iter().any(|decision| {
                decision.wallet.as_str() == wallet_b.as_str() && !decision.eligible
            }),
            "all_runtime_decisions must include known but unsynced wallet_b"
        );
    }
}
