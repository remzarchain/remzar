use libp2p::PeerId;
use remzar::network::p2p_019_inflight_limiter::{
    InflightDecision, InflightDrop, InflightLimiter, InflightPermit,
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

fn peer_id() -> PeerId {
    PeerId::random()
}

fn permit_option(decision: InflightDecision) -> Option<InflightPermit> {
    match decision {
        InflightDecision::Allow(permit) => Some(permit),
        InflightDecision::Drop(_) => None,
    }
}

fn drop_reason(decision: InflightDecision) -> Option<InflightDrop> {
    match decision {
        InflightDecision::Allow(_permit) => None,
        InflightDecision::Drop(reason) => Some(reason),
    }
}

#[test]
fn test_01_first_acquire_allows_permit() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));

    assert!(permit.is_some());
}

#[test]
fn test_02_live_permit_blocks_same_peer_when_peer_cap_is_one() {
    let limiter = InflightLimiter::new(1, 10);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
}

#[test]
fn test_03_dropping_permit_releases_same_peer_capacity() {
    let limiter = InflightLimiter::new(1, 10);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    drop(first);

    let second = permit_option(limiter.try_acquire(&peer));
    assert!(second.is_some());
}

#[test]
fn test_04_live_permit_blocks_global_capacity_when_global_cap_is_one() {
    let limiter = InflightLimiter::new(10, 1);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
}

#[test]
fn test_05_dropping_permit_releases_global_capacity() {
    let limiter = InflightLimiter::new(10, 1);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    assert!(first.is_some());

    drop(first);

    let second = permit_option(limiter.try_acquire(&second_peer));
    assert!(second.is_some());
}

#[test]
fn test_06_zero_peer_cap_drops_peer_cap() {
    let limiter = InflightLimiter::new(0, 10);
    let peer = peer_id();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );
}

#[test]
fn test_07_zero_global_cap_drops_global_cap_when_peer_cap_allows() {
    let limiter = InflightLimiter::new(1, 0);
    let peer = peer_id();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::GlobalCap)
    );
}

#[test]
fn test_08_zero_peer_and_zero_global_reports_peer_cap_first() {
    let limiter = InflightLimiter::new(0, 0);
    let peer = peer_id();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );
}

#[test]
fn test_09_exact_peer_cap_allows_that_many_permits() {
    let limiter = InflightLimiter::new(3, 10);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    let second = permit_option(limiter.try_acquire(&peer));
    let third = permit_option(limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    drop(first);
    drop(second);
    drop(third);
}

#[test]
fn test_10_exceeding_peer_cap_drops_peer_cap() {
    let limiter = InflightLimiter::new(3, 10);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    let second = permit_option(limiter.try_acquire(&peer));
    let third = permit_option(limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
    drop(second);
    drop(third);
}

#[test]
fn test_11_exact_global_cap_allows_that_many_permits_across_peers() {
    let limiter = InflightLimiter::new(10, 3);

    let first = permit_option(limiter.try_acquire(&peer_id()));
    let second = permit_option(limiter.try_acquire(&peer_id()));
    let third = permit_option(limiter.try_acquire(&peer_id()));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    drop(first);
    drop(second);
    drop(third);
}

#[test]
fn test_12_exceeding_global_cap_drops_global_cap() {
    let limiter = InflightLimiter::new(10, 3);

    let first = permit_option(limiter.try_acquire(&peer_id()));
    let second = permit_option(limiter.try_acquire(&peer_id()));
    let third = permit_option(limiter.try_acquire(&peer_id()));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
    drop(second);
    drop(third);
}

#[test]
fn test_13_per_peer_caps_are_independent_between_peers() {
    let limiter = InflightLimiter::new(1, 10);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    let second = permit_option(limiter.try_acquire(&second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&first_peer)),
        Some(InflightDrop::PeerCap)
    );
    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
    drop(second);
}

#[test]
fn test_14_cloned_limiter_shares_global_state() {
    let limiter = InflightLimiter::new(10, 1);
    let cloned = limiter.clone();

    let first = permit_option(limiter.try_acquire(&peer_id()));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(cloned.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
}

#[test]
fn test_15_cloned_limiter_shares_peer_state() {
    let limiter = InflightLimiter::new(1, 10);
    let cloned = limiter.clone();
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(cloned.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
}

#[test]
fn test_16_dropping_permit_from_original_releases_capacity_for_clone() {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    drop(first);

    let second = permit_option(cloned.try_acquire(&peer));
    assert!(second.is_some());
}

#[test]
fn test_17_separate_limiters_do_not_share_state() {
    let first_limiter = InflightLimiter::new(1, 1);
    let second_limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let first = permit_option(first_limiter.try_acquire(&peer));
    let second = permit_option(second_limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);
    drop(second);
}

#[test]
fn test_18_dropping_permits_in_reverse_order_releases_all_capacity() {
    let limiter = InflightLimiter::new(3, 3);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    let second = permit_option(limiter.try_acquire(&peer));
    let third = permit_option(limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    drop(third);
    drop(second);
    drop(first);

    let reacquired = permit_option(limiter.try_acquire(&peer));
    assert!(reacquired.is_some());
}

#[test]
fn test_19_multiple_same_peer_permits_require_all_to_drop_before_full_capacity_returns() {
    let limiter = InflightLimiter::new(2, 10);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    let second = permit_option(limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);

    let replacement = permit_option(limiter.try_acquire(&peer));
    assert!(replacement.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(second);
    drop(replacement);
}

#[test]
fn test_20_different_peers_share_global_cap_even_with_peer_capacity_available() {
    let limiter = InflightLimiter::new(2, 2);
    let first_peer = peer_id();
    let second_peer = peer_id();
    let third_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    let second = permit_option(limiter.try_acquire(&second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&third_peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
    drop(second);
}

#[test]
fn test_21_peer_cap_precedence_when_peer_and_global_are_both_full() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
}

#[test]
fn test_22_global_cap_returned_when_peer_has_capacity_but_global_is_full() {
    let limiter = InflightLimiter::new(2, 1);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
}

#[test]
fn test_23_inflight_drop_copy_clone_equality_and_debug_are_usable() {
    let first = InflightDrop::PeerCap;
    let copied = first;
    let cloned = first;

    assert_eq!(first, copied);
    assert_eq!(first, cloned);
    assert_ne!(InflightDrop::PeerCap, InflightDrop::GlobalCap);
    assert_eq!(format!("{:?}", InflightDrop::PeerCap), "PeerCap");
    assert_eq!(format!("{:?}", InflightDrop::GlobalCap), "GlobalCap");
}

#[test]
fn test_24_limiter_debug_contains_cap_field_names() {
    let limiter = InflightLimiter::new(7, 11);
    let rendered = format!("{:?}", limiter);

    assert!(rendered.contains("max_per_peer"));
    assert!(rendered.contains("max_global"));
}

#[test]
fn test_25_peer_can_reacquire_after_all_its_permits_drop() {
    let limiter = InflightLimiter::new(2, 2);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    let second = permit_option(limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);
    drop(second);

    let third = permit_option(limiter.try_acquire(&peer));
    let fourth = permit_option(limiter.try_acquire(&peer));

    assert!(third.is_some());
    assert!(fourth.is_some());
}

#[test]
fn test_26_permits_stored_in_vector_hold_capacity() {
    let limiter = InflightLimiter::new(10, 3);
    let mut permits = Vec::new();

    for _ in 0..3 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => {}
        }
    }

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);

    let after_clear = permit_option(limiter.try_acquire(&peer_id()));
    assert!(after_clear.is_some());
}

#[test]
fn test_27_dropping_vector_of_permits_releases_global_capacity() {
    let limiter = InflightLimiter::new(10, 4);
    let mut permits = Vec::new();

    for _ in 0..4 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => {}
        }
    }

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    permits.clear();

    let permit = permit_option(limiter.try_acquire(&peer_id()));
    assert!(permit.is_some());
}

#[test]
fn test_28_dropping_one_permit_from_vector_releases_one_global_slot() {
    let limiter = InflightLimiter::new(10, 2);
    let mut permits = Vec::new();

    for _ in 0..2 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => {}
        }
    }

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    let removed = permits.pop();
    drop(removed);

    let replacement = permit_option(limiter.try_acquire(&peer_id()));
    assert!(replacement.is_some());

    drop(permits);
    drop(replacement);
}

#[test]
fn test_29_large_peer_cap_small_global_cap_is_governed_by_global() {
    let limiter = InflightLimiter::new(u32::MAX, 1);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
}

#[test]
fn test_30_large_global_cap_small_peer_cap_is_governed_by_peer() {
    let limiter = InflightLimiter::new(1, u32::MAX);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
}

#[test]
fn test_31_many_peers_can_each_hold_one_when_global_allows() {
    let limiter = InflightLimiter::new(1, 32);
    let mut permits = Vec::new();

    for _ in 0..32 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => {}
        }
    }

    assert_eq!(permits.len(), 32);

    drop(permits);
}

#[test]
fn test_32_one_peer_can_hold_many_when_peer_and_global_allow() {
    let limiter = InflightLimiter::new(32, 32);
    let peer = peer_id();
    let mut permits = Vec::new();

    for _ in 0..32 {
        match limiter.try_acquire(&peer) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => {}
        }
    }

    assert_eq!(permits.len(), 32);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(permits);
}

#[test]
fn test_33_dropping_permit_for_one_peer_does_not_release_other_peer_count() {
    let limiter = InflightLimiter::new(1, 2);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    let second = permit_option(limiter.try_acquire(&second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);

    let first_again = permit_option(limiter.try_acquire(&first_peer));
    assert!(first_again.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(second);
    drop(first_again);
}

#[test]
fn test_34_dropping_permit_for_one_peer_releases_global_slot_for_other_peer() {
    let limiter = InflightLimiter::new(1, 1);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    assert!(first.is_some());

    drop(first);

    let second = permit_option(limiter.try_acquire(&second_peer));
    assert!(second.is_some());
}

#[test]
fn test_35_clone_chain_all_shares_same_state() {
    let first = InflightLimiter::new(1, 1);
    let second = first.clone();
    let third = second.clone();
    let peer = peer_id();

    let permit = permit_option(first.try_acquire(&peer));
    assert!(permit.is_some());

    assert_eq!(
        drop_reason(second.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );
    assert_eq!(
        drop_reason(third.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(permit);

    let after_drop = permit_option(third.try_acquire(&peer));
    assert!(after_drop.is_some());
}

#[test]
fn test_36_load_churn_repeated_acquire_and_drop_same_peer() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    for _ in 0..128 {
        let permit = permit_option(limiter.try_acquire(&peer));
        assert!(permit.is_some());
        drop(permit);
    }

    let final_permit = permit_option(limiter.try_acquire(&peer));
    assert!(final_permit.is_some());
}

#[test]
fn test_37_load_churn_repeated_acquire_and_drop_many_peers() {
    let limiter = InflightLimiter::new(1, 8);

    for _ in 0..128 {
        let peer = peer_id();
        let permit = permit_option(limiter.try_acquire(&peer));
        assert!(permit.is_some());
        drop(permit);
    }

    let final_permit = permit_option(limiter.try_acquire(&peer_id()));
    assert!(final_permit.is_some());
}

#[test]
fn test_38_threaded_zero_peer_cap_all_threads_drop_peer_cap() {
    let limiter = Arc::new(InflightLimiter::new(0, 100));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            let peer = peer_id();
            barrier_for_thread.wait();
            drop_reason(limiter_for_thread.try_acquire(&peer)) == Some(InflightDrop::PeerCap)
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
        let passed: bool = joined.unwrap_or_default();
        assert!(passed);
    }
}

#[test]
fn test_39_threaded_zero_global_cap_all_threads_drop_global_cap() {
    let limiter = Arc::new(InflightLimiter::new(1, 0));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            let peer = peer_id();
            barrier_for_thread.wait();
            drop_reason(limiter_for_thread.try_acquire(&peer)) == Some(InflightDrop::GlobalCap)
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
        let passed: bool = joined.unwrap_or_default();
        assert!(passed);
    }
}

#[test]
fn test_40_threaded_permits_release_after_threads_finish() {
    let limiter = Arc::new(InflightLimiter::new(1, 4));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            let peer = peer_id();
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(5));
                    true
                }
                InflightDecision::Drop(_reason) => false,
            }
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
        let passed: bool = joined.unwrap_or_default();
        assert!(passed);
    }

    let after_threads = permit_option(limiter.try_acquire(&peer_id()));
    assert!(after_threads.is_some());
}

#[test]
fn test_41_inflight_decision_allow_holds_capacity_until_dropped() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let decision = limiter.try_acquire(&peer);
    let permit = permit_option(decision);

    assert!(permit.is_some());
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(permit);

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_42_inflight_decision_drop_contains_peer_cap_reason() {
    let limiter = InflightLimiter::new(1, 10);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    match limiter.try_acquire(&peer) {
        InflightDecision::Allow(_permit) => panic!("unexpected inflight decision"),
        InflightDecision::Drop(reason) => assert_eq!(reason, InflightDrop::PeerCap),
    }

    drop(permit);
}

#[test]
fn test_43_inflight_decision_drop_contains_global_cap_reason() {
    let limiter = InflightLimiter::new(10, 1);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&first_peer));
    assert!(permit.is_some());

    match limiter.try_acquire(&second_peer) {
        InflightDecision::Allow(_permit) => panic!("unexpected inflight decision"),
        InflightDecision::Drop(reason) => assert_eq!(reason, InflightDrop::GlobalCap),
    }

    drop(permit);
}

#[test]
fn test_44_debug_for_permit_is_not_required_but_decision_drop_is_testable() {
    let limiter = InflightLimiter::new(0, 100);
    let peer = peer_id();

    let reason = drop_reason(limiter.try_acquire(&peer));

    assert_eq!(reason, Some(InflightDrop::PeerCap));
}

#[test]
fn test_45_many_same_peer_permits_exactly_fill_peer_cap() {
    let limiter = InflightLimiter::new(5, 10);
    let peer = peer_id();
    let mut permits = Vec::new();

    for _ in 0..5 {
        match limiter.try_acquire(&peer) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 5);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(permits);
}

#[test]
fn test_46_many_unique_peer_permits_exactly_fill_global_cap() {
    let limiter = InflightLimiter::new(10, 5);
    let mut permits = Vec::new();

    for _ in 0..5 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 5);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
}

#[test]
fn test_47_peer_cap_is_checked_before_global_cap_for_same_peer() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(permit);
}

#[test]
fn test_48_global_cap_is_checked_after_peer_has_capacity() {
    let limiter = InflightLimiter::new(2, 1);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(permit);
}

#[test]
fn test_49_scope_drop_releases_capacity() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    {
        let permit = permit_option(limiter.try_acquire(&peer));
        assert!(permit.is_some());
        assert_eq!(
            drop_reason(limiter.try_acquire(&peer)),
            Some(InflightDrop::PeerCap)
        );
    }

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_50_nested_scope_drop_releases_only_inner_permit() {
    let limiter = InflightLimiter::new(2, 2);
    let peer = peer_id();

    let outer = permit_option(limiter.try_acquire(&peer));
    assert!(outer.is_some());

    {
        let inner = permit_option(limiter.try_acquire(&peer));
        assert!(inner.is_some());
        assert_eq!(
            drop_reason(limiter.try_acquire(&peer)),
            Some(InflightDrop::PeerCap)
        );
    }

    let replacement = permit_option(limiter.try_acquire(&peer));
    assert!(replacement.is_some());

    drop(outer);
    drop(replacement);
}

#[test]
fn test_51_option_take_drops_no_permit_until_taken_value_is_dropped() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let mut permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    let taken = permit.take();
    assert!(taken.is_some());
    assert!(permit.is_none());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(taken);

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_52_vec_truncate_releases_removed_permits() {
    let limiter = InflightLimiter::new(10, 4);
    let mut permits = Vec::new();

    for _ in 0..4 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    permits.truncate(2);

    let first_replacement = permit_option(limiter.try_acquire(&peer_id()));
    let second_replacement = permit_option(limiter.try_acquire(&peer_id()));

    assert!(first_replacement.is_some());
    assert!(second_replacement.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
    drop(first_replacement);
    drop(second_replacement);
}

#[test]
fn test_53_vec_remove_releases_one_permit() {
    let limiter = InflightLimiter::new(10, 2);
    let mut permits = Vec::new();

    for _ in 0..2 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    let removed = permits.remove(0);
    drop(removed);

    let replacement = permit_option(limiter.try_acquire(&peer_id()));
    assert!(replacement.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
    drop(replacement);
}

#[test]
fn test_54_vec_drain_releases_all_permits() {
    let limiter = InflightLimiter::new(10, 3);
    let mut permits = Vec::new();

    for _ in 0..3 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    for permit in permits.drain(..) {
        drop(permit);
    }

    let first = permit_option(limiter.try_acquire(&peer_id()));
    let second = permit_option(limiter.try_acquire(&peer_id()));
    let third = permit_option(limiter.try_acquire(&peer_id()));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());
}

#[test]
fn test_55_drop_order_mixed_peers_releases_expected_slots() {
    let limiter = InflightLimiter::new(2, 3);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first_a = permit_option(limiter.try_acquire(&first_peer));
    let first_b = permit_option(limiter.try_acquire(&first_peer));
    let second_a = permit_option(limiter.try_acquire(&second_peer));

    assert!(first_a.is_some());
    assert!(first_b.is_some());
    assert!(second_a.is_some());

    drop(first_b);

    let first_replacement = permit_option(limiter.try_acquire(&first_peer));
    assert!(first_replacement.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(first_a);
    drop(second_a);
    drop(first_replacement);
}

#[test]
fn test_56_drop_one_peer_permit_does_not_reduce_other_peer_cap_count() {
    let limiter = InflightLimiter::new(1, 2);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    let second = permit_option(limiter.try_acquire(&second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);

    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::PeerCap)
    );

    let first_again = permit_option(limiter.try_acquire(&first_peer));
    assert!(first_again.is_some());

    drop(second);
    drop(first_again);
}

#[test]
fn test_57_clone_created_after_acquire_observes_existing_state() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    let cloned = limiter.clone();

    assert_eq!(
        drop_reason(cloned.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );
    assert_eq!(
        drop_reason(cloned.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permit);
}

#[test]
fn test_58_clone_created_before_acquire_observes_later_state() {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    let permit = permit_option(cloned.try_acquire(&peer));
    assert!(permit.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(permit);
}

#[test]
fn test_59_many_clones_all_release_to_same_shared_state() {
    let first = InflightLimiter::new(2, 2);
    let second = first.clone();
    let third = second.clone();
    let peer = peer_id();

    let first_permit = permit_option(first.try_acquire(&peer));
    let second_permit = permit_option(second.try_acquire(&peer));

    assert!(first_permit.is_some());
    assert!(second_permit.is_some());

    assert_eq!(
        drop_reason(third.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first_permit);

    let third_permit = permit_option(third.try_acquire(&peer));
    assert!(third_permit.is_some());

    drop(second_permit);
    drop(third_permit);
}

#[test]
fn test_60_permit_can_be_moved_to_thread_and_dropped_there() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    let handle = thread::spawn(move || {
        drop(permit);
        true
    });

    let joined = handle.join();
    assert!(joined.is_ok());

    let passed: bool = joined.unwrap_or_default();
    assert!(passed);

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_61_limiter_clone_can_be_moved_to_thread_and_used() {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    let handle = thread::spawn(move || permit_option(cloned.try_acquire(&peer)).is_some());

    let joined = handle.join();
    assert!(joined.is_ok());

    let acquired: bool = joined.unwrap_or_default();
    assert!(acquired);

    assert!(permit_option(limiter.try_acquire(&peer_id())).is_some());
}

#[test]
fn test_62_thread_held_global_permit_blocks_main_until_thread_finishes() {
    let limiter = Arc::new(InflightLimiter::new(10, 1));
    let barrier = Arc::new(Barrier::new(2));

    let limiter_for_thread = Arc::clone(&limiter);
    let barrier_for_thread = Arc::clone(&barrier);

    let handle = thread::spawn(move || {
        let peer = peer_id();
        let permit = permit_option(limiter_for_thread.try_acquire(&peer));
        let acquired = permit.is_some();

        barrier_for_thread.wait();
        thread::sleep(Duration::from_millis(10));

        drop(permit);
        acquired
    });

    barrier.wait();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    let joined = handle.join();
    assert!(joined.is_ok());

    let acquired: bool = joined.unwrap_or_default();
    assert!(acquired);

    assert!(permit_option(limiter.try_acquire(&peer_id())).is_some());
}

#[test]
fn test_63_thread_held_peer_permit_blocks_same_peer_until_thread_finishes() {
    let limiter = Arc::new(InflightLimiter::new(1, 10));
    let barrier = Arc::new(Barrier::new(2));
    let peer = peer_id();

    let limiter_for_thread = Arc::clone(&limiter);
    let barrier_for_thread = Arc::clone(&barrier);

    let handle = thread::spawn(move || {
        let permit = permit_option(limiter_for_thread.try_acquire(&peer));
        let acquired = permit.is_some();

        barrier_for_thread.wait();
        thread::sleep(Duration::from_millis(10));

        drop(permit);
        acquired
    });

    barrier.wait();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    let joined = handle.join();
    assert!(joined.is_ok());

    let acquired: bool = joined.unwrap_or_default();
    assert!(acquired);

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_64_threaded_unique_peers_respect_global_cap() {
    let limiter = Arc::new(InflightLimiter::new(1, 4));
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::new();

    for _ in 0..16 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            let peer = peer_id();
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(10));
                    true
                }
                InflightDecision::Drop(InflightDrop::GlobalCap) => false,
                InflightDecision::Drop(InflightDrop::PeerCap) => false,
            }
        }));
    }

    let mut allowed = 0usize;
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let was_allowed: bool = joined.unwrap_or_default();

        if was_allowed {
            allowed += 1;
        }
    }

    assert_eq!(allowed, 4);
    assert!(permit_option(limiter.try_acquire(&peer_id())).is_some());
}

#[test]
fn test_65_threaded_same_peer_respects_peer_cap() {
    let limiter = Arc::new(InflightLimiter::new(3, 16));
    let barrier = Arc::new(Barrier::new(16));
    let peer = peer_id();
    let mut handles = Vec::new();

    for _ in 0..16 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);
        let peer_for_thread = peer;

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer_for_thread) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(10));
                    true
                }
                InflightDecision::Drop(InflightDrop::PeerCap) => false,
                InflightDecision::Drop(InflightDrop::GlobalCap) => false,
            }
        }));
    }

    let mut allowed = 0usize;
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let was_allowed: bool = joined.unwrap_or_default();

        if was_allowed {
            allowed += 1;
        }
    }

    assert_eq!(allowed, 3);
    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_66_threaded_drops_release_all_global_capacity_after_join() {
    let limiter = Arc::new(InflightLimiter::new(1, 8));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer_id()) {
                InflightDecision::Allow(_permit) => true,
                InflightDecision::Drop(_reason) => false,
            }
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let acquired: bool = joined.unwrap_or_default();
        assert!(acquired);
    }

    let mut permits = Vec::new();
    for _ in 0..8 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 8);
    drop(permits);
}

#[test]
fn test_67_threaded_global_cap_zero_is_stable_under_contention() {
    let limiter = Arc::new(InflightLimiter::new(100, 0));
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::new();

    for _ in 0..16 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();
            drop_reason(limiter_for_thread.try_acquire(&peer_id())) == Some(InflightDrop::GlobalCap)
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let passed: bool = joined.unwrap_or_default();
        assert!(passed);
    }
}

#[test]
fn test_68_threaded_peer_cap_zero_is_stable_under_contention() {
    let limiter = Arc::new(InflightLimiter::new(0, 100));
    let barrier = Arc::new(Barrier::new(16));
    let peer = peer_id();
    let mut handles = Vec::new();

    for _ in 0..16 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);
        let peer_for_thread = peer;

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();
            drop_reason(limiter_for_thread.try_acquire(&peer_for_thread))
                == Some(InflightDrop::PeerCap)
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let passed: bool = joined.unwrap_or_default();
        assert!(passed);
    }
}

#[test]
fn test_69_threaded_mixed_same_and_unique_peers_never_exceed_global_cap() {
    let limiter = Arc::new(InflightLimiter::new(2, 4));
    let barrier = Arc::new(Barrier::new(12));
    let shared_peer = peer_id();
    let mut handles = Vec::new();

    for index in 0..12 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);
        let peer_for_thread = if index < 6 { shared_peer } else { peer_id() };

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer_for_thread) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(10));
                    true
                }
                InflightDecision::Drop(_reason) => false,
            }
        }));
    }

    let mut allowed = 0usize;
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let was_allowed: bool = joined.unwrap_or_default();

        if was_allowed {
            allowed += 1;
        }
    }

    assert!(allowed <= 4);
    assert!(permit_option(limiter.try_acquire(&peer_id())).is_some());
}

#[test]
fn test_70_load_repeated_vector_clear_and_reacquire() {
    let limiter = InflightLimiter::new(16, 16);

    for _ in 0..32 {
        let mut permits = Vec::new();

        for _ in 0..16 {
            match limiter.try_acquire(&peer_id()) {
                InflightDecision::Allow(permit) => permits.push(permit),
                InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
            }
        }

        assert_eq!(permits.len(), 16);
        permits.clear();

        let probe = permit_option(limiter.try_acquire(&peer_id()));
        assert!(probe.is_some());
        drop(probe);
    }
}

#[test]
fn test_71_load_repeated_same_peer_fill_and_clear() {
    let limiter = InflightLimiter::new(8, 8);
    let peer = peer_id();

    for _ in 0..32 {
        let mut permits = Vec::new();

        for _ in 0..8 {
            match limiter.try_acquire(&peer) {
                InflightDecision::Allow(permit) => permits.push(permit),
                InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
            }
        }

        assert_eq!(
            drop_reason(limiter.try_acquire(&peer)),
            Some(InflightDrop::PeerCap)
        );

        permits.clear();

        assert!(permit_option(limiter.try_acquire(&peer)).is_some());
    }
}

#[test]
fn test_72_load_alternating_two_peers_respects_each_peer_cap() {
    let limiter = InflightLimiter::new(4, 8);
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut permits = Vec::new();

    for _ in 0..4 {
        match limiter.try_acquire(&first_peer) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
        match limiter.try_acquire(&second_peer) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(
        drop_reason(limiter.try_acquire(&first_peer)),
        Some(InflightDrop::PeerCap)
    );
    assert_eq!(
        drop_reason(limiter.try_acquire(&second_peer)),
        Some(InflightDrop::PeerCap)
    );
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
}

#[test]
fn test_73_load_many_unique_peers_then_drop_half_and_refill_half() {
    let limiter = InflightLimiter::new(1, 10);
    let mut permits = Vec::new();

    for _ in 0..10 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    permits.truncate(5);

    let mut replacements = Vec::new();
    for _ in 0..5 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => replacements.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(replacements.len(), 5);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
    drop(replacements);
}

#[test]
fn test_74_vector_distinct_peers_with_same_limiter_clone_share_global_cap() {
    let limiter = InflightLimiter::new(1, 3);
    let clone_a = limiter.clone();
    let clone_b = limiter.clone();
    let clone_c = limiter.clone();
    let clone_d = limiter.clone();

    let first = permit_option(clone_a.try_acquire(&peer_id()));
    let second = permit_option(clone_b.try_acquire(&peer_id()));
    let third = permit_option(clone_c.try_acquire(&peer_id()));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    assert_eq!(
        drop_reason(clone_d.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(first);
    drop(second);
    drop(third);
}

#[test]
fn test_75_vector_same_peer_with_limiter_clones_share_peer_cap() {
    let limiter = InflightLimiter::new(3, 10);
    let clone_a = limiter.clone();
    let clone_b = limiter.clone();
    let clone_c = limiter.clone();
    let clone_d = limiter.clone();
    let peer = peer_id();

    let first = permit_option(clone_a.try_acquire(&peer));
    let second = permit_option(clone_b.try_acquire(&peer));
    let third = permit_option(clone_c.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());

    assert_eq!(
        drop_reason(clone_d.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
    drop(second);
    drop(third);
}

#[test]
fn test_76_peer_state_removed_after_last_permit_drop_allows_clean_reentry() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    assert!(first.is_some());
    drop(first);

    let second = permit_option(limiter.try_acquire(&peer));
    assert!(second.is_some());
    drop(second);

    let third = permit_option(limiter.try_acquire(&peer));
    assert!(third.is_some());
}

#[test]
fn test_77_global_state_returns_to_zero_after_last_permit_drop() {
    let limiter = InflightLimiter::new(10, 2);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    let second = permit_option(limiter.try_acquire(&second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);
    drop(second);

    let third = permit_option(limiter.try_acquire(&peer_id()));
    let fourth = permit_option(limiter.try_acquire(&peer_id()));

    assert!(third.is_some());
    assert!(fourth.is_some());
}

#[test]
fn test_78_mixed_drop_sequence_preserves_global_count_correctness() {
    let limiter = InflightLimiter::new(3, 3);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first_a = permit_option(limiter.try_acquire(&first_peer));
    let first_b = permit_option(limiter.try_acquire(&first_peer));
    let second_a = permit_option(limiter.try_acquire(&second_peer));

    assert!(first_a.is_some());
    assert!(first_b.is_some());
    assert!(second_a.is_some());

    drop(first_a);

    let second_b = permit_option(limiter.try_acquire(&second_peer));
    assert!(second_b.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(first_b);
    drop(second_a);
    drop(second_b);
}

#[test]
fn test_79_mixed_drop_sequence_preserves_peer_count_correctness() {
    let limiter = InflightLimiter::new(2, 4);
    let peer = peer_id();

    let first = permit_option(limiter.try_acquire(&peer));
    let second = permit_option(limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());

    drop(first);

    let third = permit_option(limiter.try_acquire(&peer));
    assert!(third.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(second);
    drop(third);
}

#[test]
fn test_80_global_cap_one_allows_serial_acquire_from_many_peers() {
    let limiter = InflightLimiter::new(1, 1);

    for _ in 0..64 {
        let peer = peer_id();
        let permit = permit_option(limiter.try_acquire(&peer));
        assert!(permit.is_some());
        drop(permit);
    }

    assert!(permit_option(limiter.try_acquire(&peer_id())).is_some());
}

#[test]
fn test_81_peer_cap_one_allows_serial_acquire_from_same_peer() {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    for _ in 0..64 {
        let permit = permit_option(limiter.try_acquire(&peer));
        assert!(permit.is_some());
        drop(permit);
    }

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_82_adversarial_same_peer_flood_only_cap_permits_succeed() {
    let limiter = InflightLimiter::new(4, 100);
    let peer = peer_id();
    let mut permits = Vec::new();
    let mut peer_cap_drops = 0usize;

    for _ in 0..32 {
        match limiter.try_acquire(&peer) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(InflightDrop::PeerCap) => peer_cap_drops += 1,
            InflightDecision::Drop(InflightDrop::GlobalCap) => {
                panic!("unexpected inflight decision")
            }
        }
    }

    assert_eq!(permits.len(), 4);
    assert_eq!(peer_cap_drops, 28);

    drop(permits);
}

#[test]
fn test_83_adversarial_unique_peer_flood_only_global_cap_permits_succeed() {
    let limiter = InflightLimiter::new(1, 4);
    let mut permits = Vec::new();
    let mut global_cap_drops = 0usize;

    for _ in 0..32 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(InflightDrop::GlobalCap) => global_cap_drops += 1,
            InflightDecision::Drop(InflightDrop::PeerCap) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 4);
    assert_eq!(global_cap_drops, 28);

    drop(permits);
}

#[test]
fn test_84_adversarial_alternating_peer_flood_hits_peer_caps_before_global_when_configured() {
    let limiter = InflightLimiter::new(1, 100);
    let first_peer = peer_id();
    let second_peer = peer_id();

    let first = permit_option(limiter.try_acquire(&first_peer));
    let second = permit_option(limiter.try_acquire(&second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    for _ in 0..8 {
        assert_eq!(
            drop_reason(limiter.try_acquire(&first_peer)),
            Some(InflightDrop::PeerCap)
        );
        assert_eq!(
            drop_reason(limiter.try_acquire(&second_peer)),
            Some(InflightDrop::PeerCap)
        );
    }

    drop(first);
    drop(second);
}

#[test]
fn test_85_adversarial_alternating_unique_peer_flood_hits_global_cap_when_configured() {
    let limiter = InflightLimiter::new(100, 2);

    let first = permit_option(limiter.try_acquire(&peer_id()));
    let second = permit_option(limiter.try_acquire(&peer_id()));

    assert!(first.is_some());
    assert!(second.is_some());

    for _ in 0..8 {
        assert_eq!(
            drop_reason(limiter.try_acquire(&peer_id())),
            Some(InflightDrop::GlobalCap)
        );
    }

    drop(first);
    drop(second);
}

#[test]
fn test_86_u32_max_caps_allow_first_permit() {
    let limiter = InflightLimiter::new(u32::MAX, u32::MAX);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));

    assert!(permit.is_some());
}

#[test]
fn test_87_u32_max_peer_cap_with_zero_global_drops_global() {
    let limiter = InflightLimiter::new(u32::MAX, 0);
    let peer = peer_id();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::GlobalCap)
    );
}

#[test]
fn test_88_zero_peer_cap_with_u32_max_global_drops_peer() {
    let limiter = InflightLimiter::new(0, u32::MAX);
    let peer = peer_id();

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );
}

#[test]
fn test_89_small_peer_cap_with_large_global_allows_many_peers_one_each() {
    let limiter = InflightLimiter::new(1, 16);
    let mut permits = Vec::new();

    for _ in 0..16 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 16);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
}

#[test]
fn test_90_large_peer_cap_with_small_global_allows_one_peer_up_to_global() {
    let limiter = InflightLimiter::new(16, 4);
    let peer = peer_id();
    let mut permits = Vec::new();

    for _ in 0..4 {
        match limiter.try_acquire(&peer) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 4);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer)),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
}

#[test]
fn test_91_vector_many_limiters_are_independent() {
    let mut permits = Vec::new();

    for _ in 0..16 {
        let limiter = InflightLimiter::new(1, 1);
        let peer = peer_id();
        let permit = permit_option(limiter.try_acquire(&peer));

        assert!(permit.is_some());
        assert_eq!(
            drop_reason(limiter.try_acquire(&peer)),
            Some(InflightDrop::PeerCap)
        );

        permits.push(permit);
    }

    assert_eq!(permits.len(), 16);
}

#[test]
fn test_92_vector_same_peer_across_independent_limiters_is_allowed() {
    let peer = peer_id();
    let first_limiter = InflightLimiter::new(1, 1);
    let second_limiter = InflightLimiter::new(1, 1);
    let third_limiter = InflightLimiter::new(1, 1);

    let first = permit_option(first_limiter.try_acquire(&peer));
    let second = permit_option(second_limiter.try_acquire(&peer));
    let third = permit_option(third_limiter.try_acquire(&peer));

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());
}

#[test]
fn test_93_vector_same_peer_across_cloned_limiters_is_capped() {
    let peer = peer_id();
    let limiter = InflightLimiter::new(1, 10);
    let first_clone = limiter.clone();
    let second_clone = limiter.clone();

    let first = permit_option(first_clone.try_acquire(&peer));
    assert!(first.is_some());

    assert_eq!(
        drop_reason(second_clone.try_acquire(&peer)),
        Some(InflightDrop::PeerCap)
    );

    drop(first);
}

#[test]
fn test_94_threaded_clone_drop_releases_capacity_for_original() {
    let limiter = Arc::new(InflightLimiter::new(1, 1));
    let cloned = Arc::clone(&limiter);
    let peer = peer_id();

    let handle = thread::spawn(move || {
        let permit = permit_option(cloned.try_acquire(&peer));
        let acquired = permit.is_some();
        drop(permit);
        acquired
    });

    let joined = handle.join();
    assert!(joined.is_ok());

    let acquired: bool = joined.unwrap_or_default();
    assert!(acquired);

    assert!(permit_option(limiter.try_acquire(&peer)).is_some());
}

#[test]
fn test_95_threaded_original_drop_releases_capacity_for_clone() {
    let limiter = Arc::new(InflightLimiter::new(1, 1));
    let cloned = Arc::clone(&limiter);
    let peer = peer_id();

    let permit = permit_option(limiter.try_acquire(&peer));
    assert!(permit.is_some());

    let handle = thread::spawn(move || {
        drop(permit);
        true
    });

    let joined = handle.join();
    assert!(joined.is_ok());

    let passed: bool = joined.unwrap_or_default();
    assert!(passed);

    assert!(permit_option(cloned.try_acquire(&peer)).is_some());
}

#[test]
fn test_96_threaded_contention_same_peer_allows_exact_peer_cap() {
    let limiter = Arc::new(InflightLimiter::new(2, 10));
    let barrier = Arc::new(Barrier::new(10));
    let peer = peer_id();
    let mut handles = Vec::new();

    for _ in 0..10 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);
        let peer_for_thread = peer;

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer_for_thread) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(10));
                    true
                }
                InflightDecision::Drop(_reason) => false,
            }
        }));
    }

    let mut allowed = 0usize;
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let was_allowed: bool = joined.unwrap_or_default();

        if was_allowed {
            allowed += 1;
        }
    }

    assert_eq!(allowed, 2);
}

#[test]
fn test_97_threaded_contention_unique_peers_allows_exact_global_cap() {
    let limiter = Arc::new(InflightLimiter::new(1, 3));
    let barrier = Arc::new(Barrier::new(12));
    let mut handles = Vec::new();

    for _ in 0..12 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer_id()) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(10));
                    true
                }
                InflightDecision::Drop(_reason) => false,
            }
        }));
    }

    let mut allowed = 0usize;
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());

        let was_allowed: bool = joined.unwrap_or_default();

        if was_allowed {
            allowed += 1;
        }
    }

    assert_eq!(allowed, 3);
}

#[test]
fn test_98_threaded_after_contention_limiter_is_reusable() {
    let limiter = Arc::new(InflightLimiter::new(1, 2));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let limiter_for_thread = Arc::clone(&limiter);
        let barrier_for_thread = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier_for_thread.wait();

            match limiter_for_thread.try_acquire(&peer_id()) {
                InflightDecision::Allow(_permit) => {
                    thread::sleep(Duration::from_millis(5));
                    true
                }
                InflightDecision::Drop(_reason) => false,
            }
        }));
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
    }

    let first = permit_option(limiter.try_acquire(&peer_id()));
    let second = permit_option(limiter.try_acquire(&peer_id()));

    assert!(first.is_some());
    assert!(second.is_some());
}

#[test]
fn test_99_property_no_more_than_global_cap_live_permits_can_be_held() {
    let limiter = InflightLimiter::new(100, 7);
    let mut permits = Vec::new();

    for _ in 0..32 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => permits.push(permit),
            InflightDecision::Drop(InflightDrop::GlobalCap) => {}
            InflightDecision::Drop(InflightDrop::PeerCap) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(permits.len(), 7);
    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(permits);
}

#[test]
fn test_100_end_to_end_inflight_limiter_mixed_raii_clone_thread_and_load_sim() {
    let limiter = Arc::new(InflightLimiter::new(2, 4));
    let peer_a = peer_id();
    let peer_b = peer_id();
    let peer_c = peer_id();

    let first_a = permit_option(limiter.try_acquire(&peer_a));
    let second_a = permit_option(limiter.try_acquire(&peer_a));
    let first_b = permit_option(limiter.try_acquire(&peer_b));

    assert!(first_a.is_some());
    assert!(second_a.is_some());
    assert!(first_b.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_a)),
        Some(InflightDrop::PeerCap)
    );

    let limiter_for_thread = Arc::clone(&limiter);
    let handle = thread::spawn(move || permit_option(limiter_for_thread.try_acquire(&peer_c)));

    let joined = handle.join();
    assert!(joined.is_ok());

    let thread_permit: Option<InflightPermit> = joined.unwrap_or_default();
    assert!(thread_permit.is_some());

    assert_eq!(
        drop_reason(limiter.try_acquire(&peer_id())),
        Some(InflightDrop::GlobalCap)
    );

    drop(first_a);

    let replacement_a = permit_option(limiter.try_acquire(&peer_a));
    assert!(replacement_a.is_some());

    drop(second_a);
    drop(first_b);
    drop(thread_permit);
    drop(replacement_a);

    let mut final_permits = Vec::new();
    for _ in 0..4 {
        match limiter.try_acquire(&peer_id()) {
            InflightDecision::Allow(permit) => final_permits.push(permit),
            InflightDecision::Drop(_reason) => panic!("unexpected inflight decision"),
        }
    }

    assert_eq!(final_permits.len(), 4);
}
