use libp2p::PeerId;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_019_inflight_limiter::{
    InflightDecision, InflightDrop, InflightLimiter, InflightPermit,
};

fn peer() -> PeerId {
    PeerId::random()
}

fn distinct_peer(other: &PeerId) -> PeerId {
    loop {
        let candidate = peer();
        if &candidate != other {
            return candidate;
        }
    }
}

fn distinct_peers(count: usize) -> Vec<PeerId> {
    let mut peers = Vec::with_capacity(count);

    while peers.len() < count {
        let candidate = peer();
        if !peers.iter().any(|p| p == &candidate) {
            peers.push(candidate);
        }
    }

    peers
}

fn expect_allow(decision: InflightDecision) -> InflightPermit {
    match decision {
        InflightDecision::Allow(permit) => permit,
        InflightDecision::Drop(_) => panic!("expected InflightDecision::Allow"),
    }
}

fn expect_drop(decision: InflightDecision) -> InflightDrop {
    match decision {
        InflightDecision::Allow(_) => panic!("expected InflightDecision::Drop"),
        InflightDecision::Drop(reason) => reason,
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
    fn test_001_positive_caps_allow_first_request(
        max_per_peer in 1u32..100u32,
        max_global in 1u32..100u32,
    ) {
        let limiter = InflightLimiter::new(max_per_peer, max_global);
        let peer = peer();

        let _permit = expect_allow(limiter.try_acquire(&peer));
    }

    // 02/25
    #[test]
    fn test_002_zero_peer_cap_rejects_immediately_with_peer_cap(
        max_global in 1u32..100u32,
    ) {
        let limiter = InflightLimiter::new(0, max_global);
        let peer = peer();

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "max_per_peer=0 must fail closed with PeerCap"
        );
    }

    // 03/25
    #[test]
    fn test_003_zero_global_cap_rejects_immediately_with_global_cap_when_peer_cap_allows(
        max_per_peer in 1u32..100u32,
    ) {
        let limiter = InflightLimiter::new(max_per_peer, 0);
        let peer = peer();

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::GlobalCap,
            "max_global=0 must fail closed with GlobalCap when peer cap has room"
        );
    }

    // 04/25
    #[test]
    fn test_004_zero_peer_and_zero_global_reports_peer_cap_first(
        _case in any::<u8>(),
    ) {
        let limiter = InflightLimiter::new(0, 0);
        let peer = peer();

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "peer cap check intentionally happens before normal global cap check"
        );
    }

    // 05/25
    #[test]
    fn test_005_per_peer_cap_allows_exactly_cap_active_permits_then_peer_cap_drop(
        cap in 1u32..32u32,
        extra_global_room in 0u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap.saturating_add(extra_global_room).max(cap));
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "same peer must be rejected after exactly max_per_peer active permits"
        );

        drop(permits);
    }

    // 06/25
    #[test]
    fn test_006_dropping_one_permit_below_peer_cap_allows_same_peer_again(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap
        );

        permits.pop();

        let _replacement = expect_allow(limiter.try_acquire(&peer));
    }

    // 07/25
    #[test]
    fn test_007_dropping_all_permits_fully_releases_peer_and_global_state(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap
        );

        drop(permits);

        let mut second_wave = Vec::new();

        for _ in 0..cap {
            second_wave.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "after full release, peer must again be allowed exactly cap permits"
        );

        drop(second_wave);
    }

    // 08/25
    #[test]
    fn test_008_global_cap_allows_exactly_cap_active_permits_across_distinct_peers(
        global_cap in 1usize..32usize,
    ) {
        let limiter = InflightLimiter::new(10_000, global_cap as u32);
        let peers = distinct_peers(global_cap.saturating_add(1));

        let mut permits = Vec::new();

        for peer in peers.iter().take(global_cap) {
            permits.push(expect_allow(limiter.try_acquire(peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peers[global_cap])),
            InflightDrop::GlobalCap,
            "global cap must reject a new peer after exactly max_global active permits"
        );

        drop(permits);
    }

    // 09/25
    #[test]
    fn test_009_dropping_any_global_permit_frees_one_global_slot_for_another_peer(
        global_cap in 1usize..32usize,
    ) {
        let limiter = InflightLimiter::new(10_000, global_cap as u32);
        let peers = distinct_peers(global_cap.saturating_add(2));

        let mut permits = Vec::new();

        for peer in peers.iter().take(global_cap) {
            permits.push(expect_allow(limiter.try_acquire(peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peers[global_cap])),
            InflightDrop::GlobalCap
        );

        permits.pop();

        let _replacement = expect_allow(limiter.try_acquire(&peers[global_cap + 1]));

        drop(permits);
    }

    // 10/25
    #[test]
    fn test_010_peer_cap_takes_priority_when_same_peer_also_fills_global_cap(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "when same peer hits both peer and global caps, PeerCap is reported first"
        );

        drop(permits);
    }

    // 11/25
    #[test]
    fn test_011_global_cap_rejects_new_peer_when_global_full_but_new_peer_has_no_peer_usage(
        global_cap in 1usize..32usize,
    ) {
        let limiter = InflightLimiter::new(10_000, global_cap as u32);
        let peers = distinct_peers(global_cap.saturating_add(1));

        let mut permits = Vec::new();

        for peer in peers.iter().take(global_cap) {
            permits.push(expect_allow(limiter.try_acquire(peer)));
        }

        let fresh_peer = peers[global_cap];

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&fresh_peer)),
            InflightDrop::GlobalCap,
            "fresh peer with zero peer usage must still be rejected when global cap is full"
        );

        drop(permits);
    }

    // 12/25
    #[test]
    fn test_012_one_peer_at_peer_cap_does_not_block_other_peer_when_global_has_room(
        peer_cap in 1u32..32u32,
        global_extra in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(peer_cap, peer_cap.saturating_add(global_extra));
        let peer_a = peer();
        let peer_b = distinct_peer(&peer_a);

        let mut permits = Vec::new();

        for _ in 0..peer_cap {
            permits.push(expect_allow(limiter.try_acquire(&peer_a)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer_a)),
            InflightDrop::PeerCap
        );

        let _peer_b_permit = expect_allow(limiter.try_acquire(&peer_b));

        drop(permits);
    }

    // 13/25
    #[test]
    fn test_013_cloned_limiter_shares_peer_and_global_state(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let cloned = limiter.clone();
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(cloned.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "permits acquired through clone must count against original limiter"
        );

        drop(permits);
    }

    // 14/25
    #[test]
    fn test_014_dropping_permit_acquired_from_clone_releases_capacity_visible_to_original(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let cloned = limiter.clone();
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(cloned.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap
        );

        permits.pop();

        let _replacement = expect_allow(limiter.try_acquire(&peer));

        drop(permits);
    }

    // 15/25
    #[test]
    fn test_015_dropping_permits_out_of_order_releases_exact_number_of_slots(
        cap in 2u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap
        );

        let middle = usize::try_from(cap / 2).expect("small cap fits usize");

        drop(permits.remove(middle));
        drop(permits.pop());

        let _slot_one = expect_allow(limiter.try_acquire(&peer));
        let _slot_two = expect_allow(limiter.try_acquire(&peer));

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "dropping two permits must free exactly two replacement slots"
        );

        drop(permits);
    }

    // 16/25
    #[test]
    fn test_016_clearing_permit_vector_releases_all_global_capacity(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peers = distinct_peers(usize::try_from(cap).expect("small cap fits usize"));

        let mut permits = Vec::new();

        for peer in &peers {
            permits.push(expect_allow(limiter.try_acquire(peer)));
        }

        let extra_peer = peer();

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&extra_peer)),
            InflightDrop::GlobalCap
        );

        permits.clear();

        let _after_clear = expect_allow(limiter.try_acquire(&extra_peer));
    }

    // 17/25
    #[test]
    fn test_017_dropping_one_peers_permit_does_not_release_another_peers_peer_cap(
        peer_cap in 1u32..16u32,
    ) {
        let limiter = InflightLimiter::new(peer_cap, peer_cap.saturating_mul(2).saturating_add(1));
        let peer_a = peer();
        let peer_b = distinct_peer(&peer_a);

        let mut peer_a_permits = Vec::new();
        let mut peer_b_permits = Vec::new();

        for _ in 0..peer_cap {
            peer_a_permits.push(expect_allow(limiter.try_acquire(&peer_a)));
            peer_b_permits.push(expect_allow(limiter.try_acquire(&peer_b)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer_b)),
            InflightDrop::PeerCap
        );

        peer_a_permits.pop();

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer_b)),
            InflightDrop::PeerCap,
            "dropping peer A's permit must not reduce peer B's per-peer count"
        );

        let _peer_a_replacement = expect_allow(limiter.try_acquire(&peer_a));

        drop(peer_a_permits);
        drop(peer_b_permits);
    }

    // 18/25
    #[test]
    fn test_018_global_cap_is_enforced_when_per_peer_cap_is_much_larger(
        global_cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(global_cap.saturating_add(100), global_cap);
        let peer = peer();
        let other = distinct_peer(&peer);

        let mut permits = Vec::new();

        for _ in 0..global_cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&other)),
            InflightDrop::GlobalCap,
            "global cap must enforce total active permits even when peer cap has room"
        );

        drop(permits);
    }

    // 19/25
    #[test]
    fn test_019_peer_cap_is_enforced_when_global_cap_is_much_larger(
        peer_cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(peer_cap, peer_cap.saturating_add(100));
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..peer_cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "per-peer cap must enforce one peer's active permits even when global cap has room"
        );

        drop(permits);
    }

    // 20/25
    #[test]
    fn test_020_large_balanced_acquisition_across_two_peers_releases_cleanly(
        cap in 1u32..24u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap.saturating_mul(2));
        let peer_a = peer();
        let peer_b = distinct_peer(&peer_a);

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer_a)));
            permits.push(expect_allow(limiter.try_acquire(&peer_b)));
        }

        let peer_c = distinct_peer(&peer_a);

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer_c)),
            InflightDrop::GlobalCap
        );

        drop(permits);

        let _fresh = expect_allow(limiter.try_acquire(&peer_c));
    }

    // 21/25
    #[test]
    fn test_021_peer_cap_drop_does_not_increment_counters(
        cap in 1u32..32u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_allow(limiter.try_acquire(&peer)));
        }

        for _ in 0..10 {
            prop_assert_eq!(
                expect_drop(limiter.try_acquire(&peer)),
                InflightDrop::PeerCap,
                "repeated rejected peer-cap attempts must not change counters"
            );
        }

        permits.pop();

        let _replacement = expect_allow(limiter.try_acquire(&peer));

        drop(permits);
    }

    // 22/25
    #[test]
    fn test_022_global_cap_drop_does_not_increment_counters(
        global_cap in 1usize..32usize,
    ) {
        let limiter = InflightLimiter::new(10_000, global_cap as u32);
        let peers = distinct_peers(global_cap.saturating_add(3));

        let mut permits = Vec::new();

        for peer in peers.iter().take(global_cap) {
            permits.push(expect_allow(limiter.try_acquire(peer)));
        }

        for peer in peers.iter().skip(global_cap).take(2) {
            prop_assert_eq!(
                expect_drop(limiter.try_acquire(peer)),
                InflightDrop::GlobalCap,
                "repeated rejected global-cap attempts must not change counters"
            );
        }

        permits.pop();

        let _replacement = expect_allow(limiter.try_acquire(&peers[global_cap]));

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peers[global_cap + 1])),
            InflightDrop::GlobalCap,
            "only one slot should be freed by dropping one permit"
        );

        drop(permits);
    }

    // 23/25
    #[test]
    fn test_023_concurrent_same_peer_acquisition_respects_peer_cap_across_clones(
        cap in 2u32..16u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();

        let mut handles = Vec::new();

        for _ in 0..cap {
            let cloned = limiter.clone();
            handles.push(std::thread::spawn(move || {
                expect_allow(cloned.try_acquire(&peer))
            }));
        }

        let mut permits = Vec::new();

        for handle in handles {
            permits.push(handle.join().expect("worker thread should not panic"));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&peer)),
            InflightDrop::PeerCap,
            "concurrent same-peer acquisitions must still respect max_per_peer"
        );

        drop(permits);

        let _after_threads = expect_allow(limiter.try_acquire(&peer));
    }

    // 24/25
    #[test]
    fn test_024_concurrent_global_acquisition_respects_global_cap_across_clones(
        cap in 2u32..16u32,
    ) {
        let limiter = InflightLimiter::new(cap, cap);
        let peer = peer();
        let fresh_peer = distinct_peer(&peer);

        let mut handles = Vec::new();

        for _ in 0..cap {
            let cloned = limiter.clone();
            handles.push(std::thread::spawn(move || {
                expect_allow(cloned.try_acquire(&peer))
            }));
        }

        let mut permits = Vec::new();

        for handle in handles {
            permits.push(handle.join().expect("worker thread should not panic"));
        }

        prop_assert_eq!(
            expect_drop(limiter.try_acquire(&fresh_peer)),
            InflightDrop::GlobalCap,
            "concurrent acquisitions through clones must still respect max_global"
        );

        drop(permits);

        let _after_threads = expect_allow(limiter.try_acquire(&fresh_peer));
    }

    // 25/25
    #[test]
    fn test_025_random_acquire_drop_sequence_matches_simple_counter_model(
        max_per_peer in 1u32..6u32,
        max_global in 1u32..12u32,
        ops in proptest::collection::vec((0usize..4usize, any::<bool>()), 1..96),
    ) {
        let limiter = InflightLimiter::new(max_per_peer, max_global);
        let peers = distinct_peers(4);

        let mut model_per_peer = [0u32; 4];
        let mut model_global = 0u32;
        let mut permits: Vec<Vec<InflightPermit>> = vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()];

        for (peer_index, should_acquire) in ops {
            let peer = peers[peer_index];

            if should_acquire {
                let expected_drop = if model_per_peer[peer_index] >= max_per_peer {
                    Some(InflightDrop::PeerCap)
                } else if model_global >= max_global {
                    Some(InflightDrop::GlobalCap)
                } else {
                    None
                };

                match expected_drop {
                    Some(reason) => {
                        prop_assert_eq!(
                            expect_drop(limiter.try_acquire(&peer)),
                            reason,
                            "limiter drop reason must match model"
                        );
                    }
                    None => {
                        let permit = expect_allow(limiter.try_acquire(&peer));
                        permits[peer_index].push(permit);
                        model_per_peer[peer_index] = model_per_peer[peer_index].saturating_add(1);
                        model_global = model_global.saturating_add(1);
                    }
                }
            } else if permits[peer_index].pop().is_some() {
                model_per_peer[peer_index] = model_per_peer[peer_index].saturating_sub(1);
                model_global = model_global.saturating_sub(1);
            }
        }

        drop(permits);

        let final_peer = peer();

        prop_assert!(
            matches!(limiter.try_acquire(&final_peer), InflightDecision::Allow(_)),
            "after dropping all modeled permits, limiter must have capacity again"
        );
    }
}
