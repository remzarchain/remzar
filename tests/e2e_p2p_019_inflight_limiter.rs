#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, identity};
use remzar::network::p2p_019_inflight_limiter::{
    InflightDecision, InflightDrop, InflightLimiter, InflightPermit,
};
use std::{
    sync::{Arc, Barrier, mpsc},
    thread,
};

type TestResult<T = ()> = Result<T, String>;

fn peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn acquire(limiter: &InflightLimiter, peer: &PeerId) -> TestResult<InflightPermit> {
    match limiter.try_acquire(peer) {
        InflightDecision::Allow(permit) => Ok(permit),
        InflightDecision::Drop(drop) => Err(format!("expected allow, got drop {drop:?}")),
    }
}

fn assert_allow(decision: InflightDecision) -> InflightPermit {
    match decision {
        InflightDecision::Allow(permit) => permit,
        InflightDecision::Drop(drop) => panic!("expected allow, got drop {drop:?}"),
    }
}

fn assert_drop(decision: InflightDecision, expected: InflightDrop) {
    match decision {
        InflightDecision::Allow(_permit) => {
            panic!("expected drop {expected:?}, got allow");
        }
        InflightDecision::Drop(actual) => assert_eq!(actual, expected),
    }
}

#[test]
fn e2e_01_new_limiter_allows_first_request_when_caps_are_available() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let _permit = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_02_same_peer_second_request_hits_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(1, 10);
    let peer = peer_id();

    let _permit = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_03_different_peer_second_request_hits_global_cap() -> TestResult {
    let limiter = InflightLimiter::new(10, 1);
    let first = peer_id();
    let second = peer_id();

    let _permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_04_dropping_permit_releases_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(1, 10);
    let peer = peer_id();

    let permit = acquire(&limiter, &peer)?;
    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    drop(permit);

    let _permit_after_drop = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_05_dropping_permit_releases_global_cap() -> TestResult {
    let limiter = InflightLimiter::new(10, 1);
    let first = peer_id();
    let second = peer_id();

    let permit = acquire(&limiter, &first)?;
    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);

    drop(permit);

    let _permit_after_drop = acquire(&limiter, &second)?;

    Ok(())
}

#[test]
fn e2e_06_same_peer_can_hold_up_to_per_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(2, 10);
    let peer = peer_id();

    let _first = acquire(&limiter, &peer)?;
    let _second = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_07_same_peer_third_request_hits_peer_cap_when_cap_is_two() -> TestResult {
    let limiter = InflightLimiter::new(2, 10);
    let peer = peer_id();

    let _first = acquire(&limiter, &peer)?;
    let _second = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_08_two_different_peers_can_acquire_when_global_cap_allows() -> TestResult {
    let limiter = InflightLimiter::new(1, 2);
    let first = peer_id();
    let second = peer_id();

    let _first_permit = acquire(&limiter, &first)?;
    let _second_permit = acquire(&limiter, &second)?;

    Ok(())
}

#[test]
fn e2e_09_third_peer_hits_global_cap_when_two_permits_are_held() -> TestResult {
    let limiter = InflightLimiter::new(1, 2);
    let first = peer_id();
    let second = peer_id();
    let third = peer_id();

    let _first_permit = acquire(&limiter, &first)?;
    let _second_permit = acquire(&limiter, &second)?;

    assert_drop(limiter.try_acquire(&third), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_10_peer_cap_is_independent_per_peer() -> TestResult {
    let limiter = InflightLimiter::new(1, 10);
    let first = peer_id();
    let second = peer_id();

    let _first_permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&first), InflightDrop::PeerCap);

    let _second_permit = acquire(&limiter, &second)?;

    Ok(())
}

#[test]
fn e2e_11_global_cap_blocks_even_when_second_peer_is_below_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(10, 1);
    let first = peer_id();
    let second = peer_id();

    let _first_permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_12_zero_per_peer_cap_drops_with_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(0, 10);
    let peer = peer_id();

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_13_zero_global_cap_drops_with_global_cap_when_peer_cap_allows() -> TestResult {
    let limiter = InflightLimiter::new(1, 0);
    let peer = peer_id();

    assert_drop(limiter.try_acquire(&peer), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_14_zero_peer_and_zero_global_prefers_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(0, 0);
    let peer = peer_id();

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_15_peer_cap_check_happens_before_global_cap_when_both_are_full_for_same_peer() -> TestResult
{
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let _permit = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_16_global_cap_check_happens_for_different_peer_when_global_is_full() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let first = peer_id();
    let second = peer_id();

    let _permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_17_multiple_permits_drop_allows_full_reacquire() -> TestResult {
    let limiter = InflightLimiter::new(3, 3);
    let peer = peer_id();

    let first = acquire(&limiter, &peer)?;
    let second = acquire(&limiter, &peer)?;
    let third = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    drop(first);
    drop(second);
    drop(third);

    let _a = acquire(&limiter, &peer)?;
    let _b = acquire(&limiter, &peer)?;
    let _c = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_18_partial_drop_releases_only_one_peer_slot() -> TestResult {
    let limiter = InflightLimiter::new(2, 10);
    let peer = peer_id();

    let first = acquire(&limiter, &peer)?;
    let _second = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    drop(first);

    let _third = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_19_vector_clear_drops_all_permits_and_releases_caps() -> TestResult {
    let limiter = InflightLimiter::new(5, 5);
    let peer = peer_id();

    let mut permits = Vec::new();

    for _ in 0usize..5usize {
        permits.push(acquire(&limiter, &peer)?);
    }

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    permits.clear();

    let _permit = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_20_forgetting_permit_keeps_slot_occupied() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = acquire(&limiter, &peer)?;
    std::mem::forget(permit);

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_21_cloned_limiter_shares_peer_counter() -> TestResult {
    let limiter = InflightLimiter::new(1, 10);
    let cloned = limiter.clone();
    let peer = peer_id();

    let _permit = acquire(&limiter, &peer)?;

    assert_drop(cloned.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_22_cloned_limiter_shares_global_counter() -> TestResult {
    let limiter = InflightLimiter::new(10, 1);
    let cloned = limiter.clone();

    let first = peer_id();
    let second = peer_id();

    let _permit = acquire(&limiter, &first)?;

    assert_drop(cloned.try_acquire(&second), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_23_permit_from_clone_releases_slot_for_original() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    let permit = acquire(&cloned, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    drop(permit);

    let _permit_after_drop = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_24_permit_from_original_releases_slot_for_clone() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    let permit = acquire(&limiter, &peer)?;

    assert_drop(cloned.try_acquire(&peer), InflightDrop::PeerCap);

    drop(permit);

    let _permit_after_drop = acquire(&cloned, &peer)?;

    Ok(())
}

#[test]
fn e2e_25_cloned_limiter_still_works_after_original_is_dropped() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    drop(limiter);

    let _permit = acquire(&cloned, &peer)?;

    Ok(())
}

#[test]
fn e2e_26_original_limiter_still_works_after_clone_is_dropped() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    drop(cloned);

    let _permit = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_27_drop_enum_peer_cap_is_stable() -> TestResult {
    assert_eq!(InflightDrop::PeerCap, InflightDrop::PeerCap);
    assert_ne!(InflightDrop::PeerCap, InflightDrop::GlobalCap);
    assert!(format!("{:?}", InflightDrop::PeerCap).contains("PeerCap"));

    Ok(())
}

#[test]
fn e2e_28_drop_enum_global_cap_is_stable() -> TestResult {
    assert_eq!(InflightDrop::GlobalCap, InflightDrop::GlobalCap);
    assert_ne!(InflightDrop::GlobalCap, InflightDrop::PeerCap);
    assert!(format!("{:?}", InflightDrop::GlobalCap).contains("GlobalCap"));

    Ok(())
}

#[test]
fn e2e_29_many_sequential_acquire_drop_cycles_same_peer_do_not_stick() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    for _ in 0usize..100usize {
        let permit = acquire(&limiter, &peer)?;
        drop(permit);
    }

    let _final_permit = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_30_many_unique_peers_fill_global_cap_then_release() -> TestResult {
    let limiter = InflightLimiter::new(1, 10);

    let peers: Vec<PeerId> = (0usize..10usize).map(|_| peer_id()).collect();
    let mut permits = Vec::new();

    for peer in &peers {
        permits.push(acquire(&limiter, peer)?);
    }

    assert_drop(limiter.try_acquire(&peer_id()), InflightDrop::GlobalCap);

    drop(permits);

    let _permit_after_release = acquire(&limiter, &peer_id())?;

    Ok(())
}

#[test]
fn e2e_31_global_slot_released_when_one_of_many_permits_drops() -> TestResult {
    let limiter = InflightLimiter::new(1, 2);

    let first = peer_id();
    let second = peer_id();
    let third = peer_id();

    let first_permit = acquire(&limiter, &first)?;
    let _second_permit = acquire(&limiter, &second)?;

    assert_drop(limiter.try_acquire(&third), InflightDrop::GlobalCap);

    drop(first_permit);

    let _third_permit = acquire(&limiter, &third)?;

    Ok(())
}

#[test]
fn e2e_32_large_caps_allow_small_number_of_permits() -> TestResult {
    let limiter = InflightLimiter::new(u32::MAX, u32::MAX);
    let peer = peer_id();

    let _first = acquire(&limiter, &peer)?;
    let _second = acquire(&limiter, &peer)?;
    let _third = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_33_large_peer_cap_with_global_one_still_enforces_global_cap() -> TestResult {
    let limiter = InflightLimiter::new(u32::MAX, 1);
    let first = peer_id();
    let second = peer_id();

    let _permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_34_peer_cap_two_global_two_same_peer_third_returns_peer_cap() -> TestResult {
    let limiter = InflightLimiter::new(2, 2);
    let peer = peer_id();

    let _first = acquire(&limiter, &peer)?;
    let _second = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_35_peer_cap_two_global_two_different_peer_third_returns_global_cap() -> TestResult {
    let limiter = InflightLimiter::new(2, 2);
    let first = peer_id();
    let second = peer_id();
    let third = peer_id();

    let _first_permit = acquire(&limiter, &first)?;
    let _second_permit = acquire(&limiter, &second)?;

    assert_drop(limiter.try_acquire(&third), InflightDrop::GlobalCap);

    Ok(())
}

#[test]
fn e2e_36_permit_can_be_moved_to_thread_and_dropped_there() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    let handle = thread::spawn(move || {
        drop(permit);
    });

    handle.join().map_err(|_| "thread panicked".to_string())?;

    let _permit_after_thread_drop = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_37_limiter_clone_can_be_moved_to_thread_and_acquire() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let cloned = limiter.clone();
    let peer = peer_id();

    let handle = thread::spawn(move || -> TestResult {
        let _permit = acquire(&cloned, &peer)?;
        Ok(())
    });

    handle.join().map_err(|_| "thread panicked".to_string())??;

    let _permit_after_thread = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_38_two_threads_hold_global_cap_and_main_gets_global_drop() -> TestResult {
    let limiter = InflightLimiter::new(1, 2);
    let barrier = Arc::new(Barrier::new(3));
    let (tx, rx) = mpsc::channel();

    let first_peer = peer_id();
    let second_peer = peer_id();
    let third_peer = peer_id();

    let mut handles = Vec::new();

    for peer in [first_peer, second_peer] {
        let limiter_clone = limiter.clone();
        let barrier_clone = Arc::clone(&barrier);
        let tx_clone = tx.clone();

        let handle = thread::spawn(move || {
            let _permit = assert_allow(limiter_clone.try_acquire(&peer));
            tx_clone.send(()).expect("send acquisition signal");

            // Hold permit until main confirms global cap is full.
            barrier_clone.wait();

            // Permit drops here at thread exit.
        });

        handles.push(handle);
    }

    rx.recv().map_err(|err| err.to_string())?;
    rx.recv().map_err(|err| err.to_string())?;

    assert_drop(limiter.try_acquire(&third_peer), InflightDrop::GlobalCap);

    barrier.wait();

    for handle in handles {
        handle.join().map_err(|_| "thread panicked".to_string())?;
    }

    let _permit_after_release = acquire(&limiter, &third_peer)?;

    Ok(())
}

#[test]
fn e2e_39_thread_holding_peer_cap_blocks_main_same_peer_until_release() -> TestResult {
    let limiter = InflightLimiter::new(1, 10);
    let barrier = Arc::new(Barrier::new(2));
    let (tx, rx) = mpsc::channel();
    let peer = peer_id();

    let limiter_clone = limiter.clone();
    let barrier_clone = Arc::clone(&barrier);
    let thread_peer = peer;

    let handle = thread::spawn(move || {
        let _permit = assert_allow(limiter_clone.try_acquire(&thread_peer));
        tx.send(()).expect("send acquisition signal");

        // Hold permit until main confirms peer cap is full.
        barrier_clone.wait();

        // Permit drops here at thread exit.
    });

    rx.recv().map_err(|err| err.to_string())?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    barrier.wait();
    handle.join().map_err(|_| "thread panicked".to_string())?;

    let _permit_after_release = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_40_repeated_clone_churn_does_not_break_shared_state() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    for _ in 0usize..50usize {
        let cloned = limiter.clone();
        let permit = acquire(&cloned, &peer)?;
        assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);
        drop(permit);
    }

    let _final_permit = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_41_permit_drop_is_idempotent_from_user_perspective_under_many_scope_exits() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    for _ in 0usize..25usize {
        {
            let _permit = acquire(&limiter, &peer)?;
        }

        let _next = acquire(&limiter, &peer)?;
    }

    Ok(())
}

#[test]
fn e2e_42_global_cap_is_recovered_after_dropping_permits_in_reverse_order() -> TestResult {
    let limiter = InflightLimiter::new(1, 3);

    let first = peer_id();
    let second = peer_id();
    let third = peer_id();
    let fourth = peer_id();

    let first_permit = acquire(&limiter, &first)?;
    let second_permit = acquire(&limiter, &second)?;
    let third_permit = acquire(&limiter, &third)?;

    assert_drop(limiter.try_acquire(&fourth), InflightDrop::GlobalCap);

    drop(third_permit);
    drop(second_permit);
    drop(first_permit);

    let _fourth_permit = acquire(&limiter, &fourth)?;

    Ok(())
}

#[test]
fn e2e_43_peer_cap_is_recovered_after_dropping_permits_in_reverse_order() -> TestResult {
    let limiter = InflightLimiter::new(3, 10);
    let peer = peer_id();

    let first = acquire(&limiter, &peer)?;
    let second = acquire(&limiter, &peer)?;
    let third = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    drop(third);
    drop(second);
    drop(first);

    let _permit = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_44_multiple_peers_one_released_peer_can_reacquire_without_affecting_others() -> TestResult {
    let limiter = InflightLimiter::new(1, 3);

    let first = peer_id();
    let second = peer_id();
    let third = peer_id();

    let first_permit = acquire(&limiter, &first)?;
    let _second_permit = acquire(&limiter, &second)?;
    let _third_permit = acquire(&limiter, &third)?;

    assert_drop(limiter.try_acquire(&first), InflightDrop::PeerCap);

    drop(first_permit);

    let _first_again = acquire(&limiter, &first)?;

    Ok(())
}

#[test]
fn e2e_45_same_peer_drop_one_of_two_allows_one_new_but_not_two_new() -> TestResult {
    let limiter = InflightLimiter::new(2, 10);
    let peer = peer_id();

    let first = acquire(&limiter, &peer)?;
    let _second = acquire(&limiter, &peer)?;

    drop(first);

    let _third = acquire(&limiter, &peer)?;

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    Ok(())
}

#[test]
fn e2e_46_global_drop_does_not_consume_any_slot() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);

    let first = peer_id();
    let second = peer_id();

    let first_permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);
    assert_drop(limiter.try_acquire(&second), InflightDrop::GlobalCap);

    drop(first_permit);

    let _second_permit = acquire(&limiter, &second)?;

    Ok(())
}

#[test]
fn e2e_47_peer_drop_does_not_consume_global_slot() -> TestResult {
    let limiter = InflightLimiter::new(1, 2);

    let first = peer_id();
    let second = peer_id();

    let _first_permit = acquire(&limiter, &first)?;

    assert_drop(limiter.try_acquire(&first), InflightDrop::PeerCap);

    let _second_permit = acquire(&limiter, &second)?;

    Ok(())
}

#[test]
fn e2e_48_decision_allow_contains_live_permit_that_holds_capacity() -> TestResult {
    let limiter = InflightLimiter::new(1, 1);
    let peer = peer_id();

    let permit = assert_allow(limiter.try_acquire(&peer));

    assert_drop(limiter.try_acquire(&peer), InflightDrop::PeerCap);

    drop(permit);

    let _after_drop = acquire(&limiter, &peer)?;

    Ok(())
}

#[test]
fn e2e_49_limiter_debug_mentions_caps_and_inner_state() -> TestResult {
    let limiter = InflightLimiter::new(7, 11);
    let text = format!("{limiter:?}");

    assert!(text.contains("InflightLimiter"));
    assert!(text.contains("max_per_peer"));
    assert!(text.contains("max_global"));
    assert!(text.contains("inner"));

    Ok(())
}

#[test]
fn e2e_50_full_inflight_limiter_lifecycle_peer_cap_global_cap_clone_thread_and_release()
-> TestResult {
    let limiter = InflightLimiter::new(2, 3);

    let first_peer = peer_id();
    let second_peer = peer_id();
    let third_peer = peer_id();

    // 1. Same peer can hold up to max_per_peer.
    let first_a = acquire(&limiter, &first_peer)?;
    let first_b = acquire(&limiter, &first_peer)?;

    assert_drop(limiter.try_acquire(&first_peer), InflightDrop::PeerCap);

    // 2. A different peer can consume remaining global capacity.
    let second_a = acquire(&limiter, &second_peer)?;

    assert_drop(limiter.try_acquire(&third_peer), InflightDrop::GlobalCap);

    // 3. Dropping one permit releases one global and one peer slot.
    drop(first_a);

    let third_a = acquire(&limiter, &third_peer)?;

    // At this point global is full again: first_b + second_a + third_a.
    // For second_peer, peer cap is not full, so the correct drop is GlobalCap.
    assert_drop(limiter.try_acquire(&second_peer), InflightDrop::GlobalCap);

    // 4. Clone shares state.
    let cloned = limiter.clone();

    assert_drop(cloned.try_acquire(&peer_id()), InflightDrop::GlobalCap);

    // 5. Releasing permits restores capacity.
    drop(first_b);
    drop(second_a);
    drop(third_a);

    let first_after_release = acquire(&cloned, &first_peer)?;
    let second_after_release = acquire(&limiter, &second_peer)?;

    // 6. Permit can move across a thread and release there.
    let thread_peer = peer_id();
    let thread_permit = acquire(&limiter, &thread_peer)?;

    // Global is full here: first_after_release + second_after_release + thread_permit.
    // Same peer is not at peer cap, so GlobalCap is the correct result.
    assert_drop(limiter.try_acquire(&thread_peer), InflightDrop::GlobalCap);

    drop(first_after_release);
    drop(second_after_release);

    // Now only thread_permit is held. Same peer can acquire one more because max_per_peer is 2.
    let thread_peer_second = acquire(&limiter, &thread_peer)?;

    assert_drop(limiter.try_acquire(&thread_peer), InflightDrop::PeerCap);

    drop(thread_peer_second);

    let handle = thread::spawn(move || {
        drop(thread_permit);
    });

    handle.join().map_err(|_| "thread panicked".to_string())?;

    let _thread_peer_after_drop = acquire(&limiter, &thread_peer)?;

    Ok(())
}
