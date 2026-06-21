use libp2p::PeerId;
use remzar::network::p2p_018_last_resort_guards::{
    ActionClass, LastResortActionRequest, LastResortConfig, LastResortDecision, LastResortDrop,
    LastResortGuards, LastResortInflightDecision,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

macro_rules! permit_option {
    ($decision:expr) => {
        match $decision {
            LastResortInflightDecision::Allow(permit) => Some(permit),
            LastResortInflightDecision::Drop(_) => None,
        }
    };
}

fn peer_id() -> PeerId {
    PeerId::random()
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn ip6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    ))
}

fn test_config() -> LastResortConfig {
    LastResortConfig {
        require_admission_for: vec![
            ActionClass::BlockTxGetBlock,
            ActionClass::BlockTxGetBatch,
            ActionClass::BlockTxGetTx,
        ],
        peer_bucket_capacity: 10,
        peer_refill_per_sec: 10,
        enable_ip_bucket: true,
        ip_bucket_capacity: 10,
        ip_refill_per_sec: 10,
        max_inflight_per_peer: 2,
        max_inflight_global: 5,
        dup_window: Duration::from_millis(100),
        dup_max_entries_per_peer: 4,
        peer_bytes_capacity: 100,
        peer_bytes_refill_per_sec: 100,
        global_bytes_capacity: 500,
        global_bytes_refill_per_sec: 500,
        badness_threshold: 10,
        cooldown: Duration::from_millis(100),
        badness_decay_per_sec: 10,
    }
}

fn action_request(
    now: Instant,
    peer_id: PeerId,
    admitted: bool,
    peer_ip: Option<IpAddr>,
    action: ActionClass,
    cost_tokens: u32,
    dup_key: Option<u64>,
) -> LastResortActionRequest {
    LastResortActionRequest {
        now,
        peer_id,
        admitted,
        peer_ip,
        action,
        cost_tokens,
        dup_key,
    }
}

fn check_action(
    guards: &mut LastResortGuards,
    now: Instant,
    peer_id: PeerId,
    admitted: bool,
    peer_ip: Option<IpAddr>,
    action: ActionClass,
    cost_tokens: u32,
    dup_key: Option<u64>,
) -> LastResortDecision {
    guards.check_action(action_request(
        now,
        peer_id,
        admitted,
        peer_ip,
        action,
        cost_tokens,
        dup_key,
    ))
}

#[test]
fn test_01_default_config_contains_expected_production_guard_knobs() {
    let cfg = LastResortConfig::default();

    assert!(
        cfg.require_admission_for
            .contains(&ActionClass::BlockTxGetBlock)
    );
    assert!(
        cfg.require_admission_for
            .contains(&ActionClass::BlockTxGetBatch)
    );
    assert!(
        cfg.require_admission_for
            .contains(&ActionClass::BlockTxGetTx)
    );
    assert!(!cfg.require_admission_for.contains(&ActionClass::Version));
    assert!(!cfg.require_admission_for.contains(&ActionClass::Identify));
    assert!(cfg.peer_bucket_capacity > 0);
    assert!(cfg.peer_refill_per_sec > 0);
    assert!(cfg.enable_ip_bucket);
    assert!(cfg.ip_bucket_capacity > 0);
    assert!(cfg.ip_refill_per_sec > 0);
    assert!(cfg.max_inflight_per_peer > 0);
    assert!(cfg.max_inflight_global >= cfg.max_inflight_per_peer);
    assert!(cfg.dup_window > Duration::ZERO);
    assert!(cfg.dup_max_entries_per_peer > 0);
    assert!(cfg.peer_bytes_capacity > 0);
    assert!(cfg.peer_bytes_refill_per_sec > 0);
    assert!(cfg.global_bytes_capacity >= cfg.peer_bytes_capacity);
    assert!(cfg.global_bytes_refill_per_sec >= cfg.peer_bytes_refill_per_sec);
    assert!(cfg.badness_threshold > 0);
    assert!(cfg.cooldown > Duration::ZERO);
    assert!(cfg.badness_decay_per_sec > 0);
}

#[test]
fn test_02_new_guard_exposes_config_reference_without_mutating_it() {
    let now = Instant::now();
    let cfg = test_config();
    let guards = LastResortGuards::new(cfg, now);

    assert_eq!(guards.cfg().peer_bucket_capacity, 10);
    assert_eq!(guards.cfg().peer_refill_per_sec, 10);
    assert_eq!(guards.cfg().ip_bucket_capacity, 10);
    assert_eq!(guards.cfg().ip_refill_per_sec, 10);
    assert_eq!(guards.cfg().max_inflight_per_peer, 2);
    assert_eq!(guards.cfg().max_inflight_global, 5);
    assert_eq!(guards.cfg().dup_window, Duration::from_millis(100));
    assert_eq!(guards.cfg().dup_max_entries_per_peer, 4);
    assert_eq!(guards.cfg().peer_bytes_capacity, 100);
    assert_eq!(guards.cfg().global_bytes_capacity, 500);
}

#[test]
fn test_03_not_admitted_sync_get_block_is_dropped_before_rate_budget_is_spent() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 10;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 3, 1)),
            ActionClass::BlockTxGetBlock,
            10,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 3, 1)),
            ActionClass::BlockTxGetBlock,
            10,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_04_version_action_is_allowed_before_admission() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 4, 1)),
            ActionClass::Version,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_05_identify_action_is_allowed_before_admission() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 5, 1)),
            ActionClass::Identify,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_06_custom_admission_gate_can_require_gossip_admission() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.require_admission_for = vec![ActionClass::Gossip];

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 6, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            false,
            Some(ip4(10, 18, 6, 1)),
            ActionClass::Version,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_07_peer_rate_limit_allows_exact_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 3;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    for offset in 0u64..3u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer,
                true,
                Some(ip4(10, 18, 7, 1)),
                ActionClass::Gossip,
                1,
                None,
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_08_peer_rate_limit_drops_after_capacity_is_spent() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 2;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 8, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 8, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 8, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_09_zero_cost_token_request_still_costs_one_token() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 9, 1)),
            ActionClass::Kad,
            0,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 9, 1)),
            ActionClass::Kad,
            0,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_10_cost_larger_than_peer_capacity_is_peer_rate_limited() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 5;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 10, 1)),
            ActionClass::Kad,
            6,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_11_peer_bucket_refills_using_integer_time() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 2;
    cfg.peer_refill_per_sec = 2;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 11, 1)),
            ActionClass::Gossip,
            2,
            None,
        ),
        LastResortDecision::Allow
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 11, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(501),
            peer,
            true,
            Some(ip4(10, 18, 11, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_12_zero_peer_refill_keeps_peer_limited_across_time() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 12, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(60),
            peer,
            true,
            Some(ip4(10, 18, 12, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_13_peer_buckets_are_independent_between_peers() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(ip4(10, 18, 13, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            second_peer,
            true,
            Some(ip4(10, 18, 13, 2)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_14_ip_bucket_limits_peer_id_churn_from_same_ip() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = 2;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);
    let ip = ip4(10, 18, 14, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );
}

#[test]
fn test_15_disabled_ip_bucket_bypasses_same_ip_peer_churn_limit() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.enable_ip_bucket = false;
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);
    let ip = ip4(10, 18, 15, 1);

    for offset in 0u64..5u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer_id(),
                true,
                Some(ip),
                ActionClass::Gossip,
                1,
                None,
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_16_missing_peer_ip_bypasses_optional_ip_bucket() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    for offset in 0u64..3u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer_id(),
                true,
                None,
                ActionClass::Gossip,
                1,
                None,
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_17_ip_bucket_refills_after_time_window() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 10;

    let mut guards = LastResortGuards::new(cfg, now);
    let ip = ip4(10, 18, 17, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(101),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_18_non_sync_duplicate_request_is_dropped() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("gossip:duplicate:18");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 18, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 18, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
}

#[test]
fn test_19_sync_retrieval_duplicate_is_allowed_and_rate_limited_normally() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("GetBlockByIndex:19");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 19, 1)),
            ActionClass::BlockTxGetBlock,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 19, 1)),
            ActionClass::BlockTxGetBlock,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_20_duplicate_at_exact_window_boundary_is_still_duplicate() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("gossip:boundary:20");
    let mut cfg = test_config();
    cfg.dup_window = Duration::from_millis(100);

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 20, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(100),
            peer,
            true,
            Some(ip4(10, 18, 20, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
}

#[test]
fn test_21_duplicate_after_window_is_allowed_again() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("gossip:after-window:21");
    let mut cfg = test_config();
    cfg.dup_window = Duration::from_millis(100);

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 21, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(101),
            peer,
            true,
            Some(ip4(10, 18, 21, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_22_duplicate_key_ring_evicts_oldest_entry_when_max_entries_is_reached() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.dup_max_entries_per_peer = 2;
    cfg.dup_window = Duration::from_secs(10);

    let mut guards = LastResortGuards::new(cfg, now);

    let first_key = 1;
    let second_key = 2;
    let third_key = 3;

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 22, 1)),
            ActionClass::Gossip,
            1,
            Some(first_key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 22, 1)),
            ActionClass::Gossip,
            1,
            Some(second_key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 22, 1)),
            ActionClass::Gossip,
            1,
            Some(third_key),
        ),
        LastResortDecision::Allow
    );

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(3),
            peer,
            true,
            Some(ip4(10, 18, 22, 1)),
            ActionClass::Gossip,
            1,
            Some(first_key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_23_duplicate_badness_can_trigger_peer_cooldown() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("cooldown:duplicate:23");
    let mut cfg = test_config();
    cfg.badness_threshold = 2;
    cfg.badness_decay_per_sec = 0;
    cfg.cooldown = Duration::from_millis(100);

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 23, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 23, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 23, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_24_peer_byte_budget_allows_exact_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        guards.check_bytes(now, peer, 100),
        LastResortDecision::Allow
    );
}

#[test]
fn test_25_peer_byte_budget_drops_when_capacity_is_exceeded() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        guards.check_bytes(now, peer, 101),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
}

#[test]
fn test_26_peer_byte_budget_refills_with_integer_time() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        guards.check_bytes(now, peer, 100),
        LastResortDecision::Allow
    );

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(11), peer, 1),
        LastResortDecision::Allow
    );
}

#[test]
fn test_27_global_byte_budget_is_shared_across_peers() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 1_000;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 100;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, first_peer, 60),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), second_peer, 50),
        LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded)
    );
}

#[test]
fn test_28_zero_byte_check_is_allowed_repeatedly() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    for offset in 0u64..5u64 {
        assert_eq!(
            guards.check_bytes(now + Duration::from_millis(offset), peer, 0),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_29_peer_byte_budget_violation_can_trigger_cooldown() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 5;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, peer, 101),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_30_report_misbehavior_at_threshold_starts_cooldown() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 5;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 5);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 30, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_31_report_misbehavior_below_threshold_does_not_cool_down_peer() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 5;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 4);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 31, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_32_cooldown_expires_and_peer_is_allowed_again() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 5;
    cfg.badness_decay_per_sec = 0;
    cfg.cooldown = Duration::from_millis(10);

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 5);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(5),
            peer,
            true,
            Some(ip4(10, 18, 32, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(11),
            peer,
            true,
            Some(ip4(10, 18, 32, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_33_badness_decay_prevents_later_small_report_from_reaching_threshold() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 10;
    cfg.badness_decay_per_sec = 10;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 9);
    guards.report_misbehavior(now + Duration::from_secs(1), peer, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(1),
            peer,
            true,
            Some(ip4(10, 18, 33, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_34_zero_and_negative_misbehavior_points_are_treated_as_one_point() {
    let now = Instant::now();
    let zero_peer = peer_id();
    let negative_peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, zero_peer, 0);
    guards.report_misbehavior(now, negative_peer, -100);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            zero_peer,
            true,
            Some(ip4(10, 18, 34, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            negative_peer,
            true,
            Some(ip4(10, 18, 34, 2)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_35_peer_inflight_cap_blocks_third_same_peer_request() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 2;
    cfg.max_inflight_global = 10;

    let mut guards = LastResortGuards::new(cfg, now);

    let first = permit_option!(guards.try_begin_inflight(now, &peer));
    let second = permit_option!(guards.try_begin_inflight(now + Duration::from_millis(1), &peer));

    assert!(first.is_some());
    assert!(second.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(2), &peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));

    drop(first);
    drop(second);
}

#[test]
fn test_36_global_inflight_cap_blocks_extra_peer_when_global_full() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let third_peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 10;
    cfg.max_inflight_global = 2;

    let mut guards = LastResortGuards::new(cfg, now);

    let first = permit_option!(guards.try_begin_inflight(now, &first_peer));
    let second =
        permit_option!(guards.try_begin_inflight(now + Duration::from_millis(1), &second_peer));

    assert!(first.is_some());
    assert!(second.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(2), &third_peer),
        LastResortInflightDecision::Drop(LastResortDrop::GlobalInflightCap)
    ));

    drop(first);
    drop(second);
}

#[test]
fn test_37_dropping_raii_permit_releases_peer_inflight_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 10;

    let mut guards = LastResortGuards::new(cfg, now);

    let first = permit_option!(guards.try_begin_inflight(now, &peer));

    assert!(first.is_some());
    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(1), &peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));

    drop(first);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(2), &peer),
        LastResortInflightDecision::Allow(_)
    ));
}

#[test]
fn test_38_disconnect_does_not_force_release_live_inflight_permit_but_drop_does() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 10;

    let mut guards = LastResortGuards::new(cfg, now);

    let permit = permit_option!(guards.try_begin_inflight(now, &peer));
    assert!(permit.is_some());

    guards.on_peer_disconnected(peer);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(1), &peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));

    drop(permit);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(2), &peer),
        LastResortInflightDecision::Allow(_)
    ));
}

#[test]
fn test_39_disconnect_clears_peer_rate_state_when_ip_bucket_is_disabled() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.enable_ip_bucket = false;
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 39, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 39, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    guards.on_peer_disconnected(peer);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 39, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_40_end_to_end_adversarial_load_vector_mixes_ipv4_ipv6_rate_bytes_and_inflight() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 4;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = 8;
    cfg.ip_refill_per_sec = 0;
    cfg.max_inflight_per_peer = 2;
    cfg.max_inflight_global = 4;
    cfg.peer_bytes_capacity = 64;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 256;
    cfg.global_bytes_refill_per_sec = 0;
    cfg.badness_threshold = 20;

    let mut guards = LastResortGuards::new(cfg, now);

    let shared_ip = ip4(10, 18, 40, 1);
    let ipv6 = ip6([0x2001, 0x0db8, 0x0018, 0x0040, 0, 0, 0, 1]);

    let peer_a = peer_id();
    let peer_b = peer_id();
    let peer_c = peer_id();

    for offset in 0u64..4u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer_a,
                true,
                Some(shared_ip),
                ActionClass::Gossip,
                1,
                Some(offset),
            ),
            LastResortDecision::Allow
        );
    }

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(5),
            peer_a,
            true,
            Some(shared_ip),
            ActionClass::Gossip,
            1,
            Some(999),
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    for offset in 10u64..14u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer_b,
                true,
                Some(shared_ip),
                ActionClass::Kad,
                1,
                Some(offset + 1_000),
            ),
            LastResortDecision::Allow
        );
    }

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(20),
            peer_c,
            true,
            Some(ipv6),
            ActionClass::Identify,
            1,
            None,
        ),
        LastResortDecision::Allow
    );

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(21), peer_a, 64),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(22), peer_a, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    let permit_a1 =
        permit_option!(guards.try_begin_inflight(now + Duration::from_millis(23), &peer_a));
    let permit_a2 =
        permit_option!(guards.try_begin_inflight(now + Duration::from_millis(24), &peer_a));

    assert!(permit_a1.is_some());
    assert!(permit_a2.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(25), &peer_a),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));

    drop(permit_a1);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(26), &peer_a),
        LastResortInflightDecision::Allow(_)
    ));

    drop(permit_a2);
}

#[test]
fn test_41_custom_config_clone_preserves_all_fields() {
    let cfg = LastResortConfig {
        require_admission_for: vec![ActionClass::Gossip, ActionClass::Kad],
        peer_bucket_capacity: 41,
        peer_refill_per_sec: 42,
        enable_ip_bucket: false,
        ip_bucket_capacity: 43,
        ip_refill_per_sec: 44,
        max_inflight_per_peer: 45,
        max_inflight_global: 46,
        dup_window: Duration::from_millis(47),
        dup_max_entries_per_peer: 48,
        peer_bytes_capacity: 49,
        peer_bytes_refill_per_sec: 50,
        global_bytes_capacity: 51,
        global_bytes_refill_per_sec: 52,
        badness_threshold: 53,
        cooldown: Duration::from_millis(54),
        badness_decay_per_sec: 55,
    };

    let cloned = cfg.clone();

    assert_eq!(cloned.require_admission_for, cfg.require_admission_for);
    assert_eq!(cloned.peer_bucket_capacity, 41);
    assert_eq!(cloned.peer_refill_per_sec, 42);
    assert!(!cloned.enable_ip_bucket);
    assert_eq!(cloned.ip_bucket_capacity, 43);
    assert_eq!(cloned.ip_refill_per_sec, 44);
    assert_eq!(cloned.max_inflight_per_peer, 45);
    assert_eq!(cloned.max_inflight_global, 46);
    assert_eq!(cloned.dup_window, Duration::from_millis(47));
    assert_eq!(cloned.dup_max_entries_per_peer, 48);
    assert_eq!(cloned.peer_bytes_capacity, 49);
    assert_eq!(cloned.peer_bytes_refill_per_sec, 50);
    assert_eq!(cloned.global_bytes_capacity, 51);
    assert_eq!(cloned.global_bytes_refill_per_sec, 52);
    assert_eq!(cloned.badness_threshold, 53);
    assert_eq!(cloned.cooldown, Duration::from_millis(54));
    assert_eq!(cloned.badness_decay_per_sec, 55);
}

#[test]
fn test_42_action_class_debug_copy_and_equality_are_usable() {
    let action = ActionClass::BlockTxGetBatch;
    let copied = action;

    assert_eq!(action, copied);
    assert_eq!(format!("{:?}", ActionClass::Version), "Version");
    assert_eq!(
        format!("{:?}", ActionClass::BlockTxGetBlock),
        "BlockTxGetBlock"
    );
    assert_eq!(
        format!("{:?}", ActionClass::BlockTxGetBatch),
        "BlockTxGetBatch"
    );
    assert_eq!(format!("{:?}", ActionClass::BlockTxGetTx), "BlockTxGetTx");
    assert_eq!(format!("{:?}", ActionClass::Gossip), "Gossip");
    assert_eq!(format!("{:?}", ActionClass::Kad), "Kad");
    assert_eq!(format!("{:?}", ActionClass::Identify), "Identify");
}

#[test]
fn test_43_decision_and_drop_debug_output_is_stable_for_logs() {
    assert_eq!(format!("{:?}", LastResortDecision::Allow), "Allow");
    assert_eq!(
        format!(
            "{:?}",
            LastResortDecision::Drop(LastResortDrop::NotAdmitted)
        ),
        "Drop(NotAdmitted)"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::PeerRateLimited),
        "PeerRateLimited"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::IpRateLimited),
        "IpRateLimited"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::PeerInflightCap),
        "PeerInflightCap"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::GlobalInflightCap),
        "GlobalInflightCap"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::DuplicateRequest),
        "DuplicateRequest"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::PeerByteBudgetExceeded),
        "PeerByteBudgetExceeded"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::GlobalByteBudgetExceeded),
        "GlobalByteBudgetExceeded"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::PeerCoolingDown),
        "PeerCoolingDown"
    );
    assert_eq!(
        format!("{:?}", LastResortDrop::CounterOverflow),
        "CounterOverflow"
    );
}

#[test]
fn test_44_dup_key_from_str_is_deterministic_for_same_input() {
    let first = LastResortGuards::dup_key_from_str("GetBlockByIndex:44");
    let second = LastResortGuards::dup_key_from_str("GetBlockByIndex:44");

    assert_eq!(first, second);
}

#[test]
fn test_45_dup_key_from_str_distinguishes_common_request_strings() {
    let first = LastResortGuards::dup_key_from_str("GetBlockByIndex:45");
    let second = LastResortGuards::dup_key_from_str("GetBlockByIndex:46");
    let third = LastResortGuards::dup_key_from_str("GetBatchByHash:45");

    assert_ne!(first, second);
    assert_ne!(first, third);
    assert_ne!(second, third);
}

#[test]
fn test_46_empty_string_duplicate_key_is_stable_and_nonzero() {
    let first = LastResortGuards::dup_key_from_str("");
    let second = LastResortGuards::dup_key_from_str("");

    assert_eq!(first, second);
    assert_ne!(first, 0);
}

#[test]
fn test_47_not_admitted_get_batch_is_dropped() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 47, 1)),
            ActionClass::BlockTxGetBatch,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );
}

#[test]
fn test_48_not_admitted_get_tx_is_dropped() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 48, 1)),
            ActionClass::BlockTxGetTx,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );
}

#[test]
fn test_49_admitted_sync_actions_are_allowed_by_admission_gate() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);
    let actions = [
        ActionClass::BlockTxGetBlock,
        ActionClass::BlockTxGetBatch,
        ActionClass::BlockTxGetTx,
    ];

    for action in actions {
        assert_eq!(
            check_action(
                &mut guards,
                now,
                peer,
                true,
                Some(ip4(10, 18, 49, 1)),
                action,
                1,
                None,
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_50_empty_admission_gate_allows_sync_action_before_admission() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.require_admission_for.clear();

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 50, 1)),
            ActionClass::BlockTxGetBlock,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_51_peer_rate_limit_allows_multiple_costs_that_exactly_sum_to_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 10;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 51, 1)),
            ActionClass::Kad,
            5,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 51, 1)),
            ActionClass::Kad,
            5,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 51, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_52_peer_rate_refill_is_capped_at_bucket_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 4;
    cfg.peer_refill_per_sec = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 52, 1)),
            ActionClass::Kad,
            4,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(10),
            peer,
            true,
            Some(ip4(10, 18, 52, 1)),
            ActionClass::Kad,
            4,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(10) + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 52, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_53_peer_rate_limited_peer_does_not_affect_other_peer_when_ip_bucket_disabled() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.enable_ip_bucket = false;
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(ip4(10, 18, 53, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            first_peer,
            true,
            Some(ip4(10, 18, 53, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            second_peer,
            true,
            Some(ip4(10, 18, 53, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_54_ip_bucket_allows_costs_that_exactly_sum_to_capacity_across_peers() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = 10;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);
    let ip = ip4(10, 18, 54, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer_id(),
            true,
            Some(ip),
            ActionClass::Kad,
            4,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Kad,
            6,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );
}

#[test]
fn test_55_ip_bucket_drops_cost_larger_than_capacity_even_when_peer_has_capacity() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 5;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer_id(),
            true,
            Some(ip4(10, 18, 55, 1)),
            ActionClass::Kad,
            6,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );
}

#[test]
fn test_56_ipv4_and_ipv6_ip_buckets_are_independent() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer_id(),
            true,
            Some(ip4(10, 18, 56, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer_id(),
            true,
            Some(ip6([0x2001, 0x0db8, 0x0018, 0x0056, 0, 0, 0, 1])),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_57_ip_rate_refill_is_capped_at_bucket_capacity() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 3;
    cfg.ip_refill_per_sec = 100;

    let mut guards = LastResortGuards::new(cfg, now);
    let ip = ip4(10, 18, 57, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer_id(),
            true,
            Some(ip),
            ActionClass::Kad,
            3,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(10),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Kad,
            3,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(10) + Duration::from_millis(1),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );
}

#[test]
fn test_58_repeated_actions_without_duplicate_key_are_not_duplicate_suppressed() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    for offset in 0u64..5u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer,
                true,
                Some(ip4(10, 18, 58, 1)),
                ActionClass::Gossip,
                1,
                None,
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_59_duplicate_suppression_is_per_peer() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("duplicate-per-peer:59");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(ip4(10, 18, 59, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            second_peer,
            true,
            Some(ip4(10, 18, 59, 2)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_60_duplicate_key_is_shared_across_non_sync_action_classes_for_same_peer() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("shared-key:60");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 60, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 60, 1)),
            ActionClass::Kad,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
}

#[test]
fn test_61_sync_get_batch_duplicate_is_allowed() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("GetBatchByHash:61");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 61, 1)),
            ActionClass::BlockTxGetBatch,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 61, 1)),
            ActionClass::BlockTxGetBatch,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_62_sync_get_tx_duplicate_is_allowed() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("GetTxByHash:62");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 62, 1)),
            ActionClass::BlockTxGetTx,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 62, 1)),
            ActionClass::BlockTxGetTx,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_63_duplicate_drop_happens_before_peer_rate_budget_check() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("duplicate-before-rate:63");
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;
    cfg.badness_threshold = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 63, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 63, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
}

#[test]
fn test_64_disconnect_clears_duplicate_history_for_peer() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("disconnect-clears-dup:64");
    let mut cfg = test_config();
    cfg.enable_ip_bucket = false;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 64, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 64, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );

    guards.on_peer_disconnected(peer);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 64, 1)),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_65_disconnect_clears_peer_cooldown_state() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.enable_ip_bucket = false;
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 65, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    guards.on_peer_disconnected(peer);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 65, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_66_disconnect_does_not_clear_ip_bucket_state() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let ip = ip4(10, 18, 66, 1);
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(ip),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );

    guards.on_peer_disconnected(first_peer);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            second_peer,
            true,
            Some(ip),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );
}

#[test]
fn test_67_duplicate_key_zero_is_a_valid_duplicate_key() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 67, 1)),
            ActionClass::Gossip,
            1,
            Some(0),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 67, 1)),
            ActionClass::Gossip,
            1,
            Some(0),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
}

#[test]
fn test_68_peer_byte_budgets_are_independent_between_peers() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 10;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 100;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, first_peer, 10),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), second_peer, 10),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(2), first_peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
}

#[test]
fn test_69_peer_byte_refill_is_capped_at_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 10;
    cfg.peer_bytes_refill_per_sec = 1_000;
    cfg.global_bytes_capacity = 1_000;
    cfg.global_bytes_refill_per_sec = 1_000;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(guards.check_bytes(now, peer, 10), LastResortDecision::Allow);
    assert_eq!(
        guards.check_bytes(now + Duration::from_secs(10), peer, 10),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(
            now + Duration::from_secs(10) + Duration::from_millis(1),
            peer,
            1
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_70_global_byte_budget_refills_after_failed_global_attempt_timestamp() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 1_000;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 100;
    cfg.global_bytes_refill_per_sec = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, first_peer, 100),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), second_peer, 1),
        LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded)
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(11), second_peer, 1),
        LastResortDecision::Allow
    );
}

#[test]
fn test_71_peer_byte_failure_does_not_consume_global_byte_budget() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();

    cfg.peer_bytes_capacity = 15;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 15;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, first_peer, 16),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), second_peer, 15),
        LastResortDecision::Allow
    );
}

#[test]
fn test_72_global_byte_failure_still_spends_peer_byte_budget_first() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 1_000;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 10;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, first_peer, 10),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), second_peer, 20),
        LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded)
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(2), second_peer, 981),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
}

#[test]
fn test_73_check_bytes_returns_cooling_down_before_budget_checks() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 1);

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_74_try_begin_inflight_returns_cooling_down_for_bad_peer() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 1);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(1), &peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerCoolingDown)
    ));
}

#[test]
fn test_75_peer_inflight_cap_failure_can_trigger_cooldown() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 10;
    cfg.badness_threshold = 4;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    let permit = permit_option!(guards.try_begin_inflight(now, &peer));
    assert!(permit.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(1), &peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer,
            true,
            Some(ip4(10, 18, 75, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    drop(permit);
}

#[test]
fn test_76_global_inflight_cap_failure_can_trigger_cooldown_for_blocked_peer() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 10;
    cfg.max_inflight_global = 1;
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    let permit = permit_option!(guards.try_begin_inflight(now, &first_peer));
    assert!(permit.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(1), &second_peer),
        LastResortInflightDecision::Drop(LastResortDrop::GlobalInflightCap)
    ));
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            second_peer,
            true,
            Some(ip4(10, 18, 76, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    drop(permit);
}

#[test]
fn test_77_dropping_raii_permit_releases_global_inflight_capacity() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 10;
    cfg.max_inflight_global = 1;
    cfg.badness_threshold = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    let permit = permit_option!(guards.try_begin_inflight(now, &first_peer));
    assert!(permit.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(1), &second_peer),
        LastResortInflightDecision::Drop(LastResortDrop::GlobalInflightCap)
    ));

    drop(permit);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(2), &second_peer),
        LastResortInflightDecision::Allow(_)
    ));
}

#[test]
fn test_78_dropping_one_of_two_peer_permits_releases_one_peer_slot() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 2;
    cfg.max_inflight_global = 10;

    let mut guards = LastResortGuards::new(cfg, now);

    let first = permit_option!(guards.try_begin_inflight(now, &peer));
    let second = permit_option!(guards.try_begin_inflight(now + Duration::from_millis(1), &peer));

    assert!(first.is_some());
    assert!(second.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(2), &peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));

    drop(first);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(3), &peer),
        LastResortInflightDecision::Allow(_)
    ));

    drop(second);
}

#[test]
fn test_79_load_inflight_global_cap_with_multiple_peers() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.max_inflight_per_peer = 10;
    cfg.max_inflight_global = 4;

    let mut guards = LastResortGuards::new(cfg, now);
    let mut permits = Vec::new();

    for offset in 0u64..4u64 {
        match guards.try_begin_inflight(now + Duration::from_millis(offset), &peer_id()) {
            LastResortInflightDecision::Allow(permit) => permits.push(permit),
            LastResortInflightDecision::Drop(drop) => {
                panic!(
                    "unexpected inflight drop while filling global cap: {:?}",
                    drop
                );
            }
        }
    }

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(5), &peer_id()),
        LastResortInflightDecision::Drop(LastResortDrop::GlobalInflightCap)
    ));

    drop(permits);
}

#[test]
fn test_80_disconnect_clears_peer_byte_budget_state() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 10;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 100;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(guards.check_bytes(now, peer, 10), LastResortDecision::Allow);
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    guards.on_peer_disconnected(peer);

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(2), peer, 10),
        LastResortDecision::Allow
    );
}

#[test]
fn test_81_disconnect_does_not_clear_global_byte_budget_state() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 100;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 10;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, first_peer, 10),
        LastResortDecision::Allow
    );

    guards.on_peer_disconnected(first_peer);

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), second_peer, 1),
        LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded)
    );
}

#[test]
fn test_82_large_misbehavior_report_enters_cooldown() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 10;
    cfg.badness_decay_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, i32::MAX);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 82, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_83_cooldown_exact_boundary_allows_peer_again() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;
    cfg.cooldown = Duration::from_millis(10);

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(10),
            peer,
            true,
            Some(ip4(10, 18, 83, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_84_cooldown_before_boundary_still_blocks_peer() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 1;
    cfg.badness_decay_per_sec = 0;
    cfg.cooldown = Duration::from_millis(10);

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(9),
            peer,
            true,
            Some(ip4(10, 18, 84, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_85_negative_badness_decay_disables_decay() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.badness_threshold = 10;
    cfg.badness_decay_per_sec = -1;
    cfg.cooldown = Duration::from_millis(100);

    let mut guards = LastResortGuards::new(cfg, now);

    guards.report_misbehavior(now, peer, 9);
    guards.report_misbehavior(now + Duration::from_secs(1), peer, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_secs(1) + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 85, 1)),
            ActionClass::Kad,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
}

#[test]
fn test_86_u32_max_cost_is_allowed_when_peer_and_ip_buckets_have_u32_max_capacity() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = u32::MAX;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = u32::MAX;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 86, 1)),
            ActionClass::Kad,
            u32::MAX,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_87_u32_max_cost_is_peer_rate_limited_when_capacity_is_smaller() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = u32::MAX - 1;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = u32::MAX;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 87, 1)),
            ActionClass::Kad,
            u32::MAX,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
}

#[test]
fn test_88_u64_max_bytes_are_peer_budget_limited() {
    let now = Instant::now();
    let peer = peer_id();
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        guards.check_bytes(now, peer, u64::MAX),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
}

#[test]
fn test_89_global_byte_budget_allows_exact_capacity_single_request() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 1_000;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 200;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, peer, 200),
        LastResortDecision::Allow
    );
}

#[test]
fn test_90_global_byte_budget_allows_exact_capacity_across_peers_then_drops_extra() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bytes_capacity = 1_000;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 200;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        guards.check_bytes(now, peer_id(), 100),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(1), peer_id(), 100),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(2), peer_id(), 1),
        LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded)
    );
}

#[test]
fn test_91_vector_all_action_classes_allowed_when_admitted_and_budget_available() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 100;

    let mut guards = LastResortGuards::new(cfg, now);
    let actions = [
        ActionClass::Version,
        ActionClass::BlockTxGetBlock,
        ActionClass::BlockTxGetBatch,
        ActionClass::BlockTxGetTx,
        ActionClass::Gossip,
        ActionClass::Kad,
        ActionClass::Identify,
    ];

    for action in actions {
        assert_eq!(
            check_action(
                &mut guards,
                now,
                peer,
                true,
                Some(ip4(10, 18, 91, 1)),
                action,
                1,
                None,
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_92_vector_default_gate_only_blocks_sync_retrieval_actions_when_unadmitted() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 100;

    let mut guards = LastResortGuards::new(cfg, now);
    let cases = [
        (ActionClass::Version, LastResortDecision::Allow),
        (
            ActionClass::BlockTxGetBlock,
            LastResortDecision::Drop(LastResortDrop::NotAdmitted),
        ),
        (
            ActionClass::BlockTxGetBatch,
            LastResortDecision::Drop(LastResortDrop::NotAdmitted),
        ),
        (
            ActionClass::BlockTxGetTx,
            LastResortDecision::Drop(LastResortDrop::NotAdmitted),
        ),
        (ActionClass::Gossip, LastResortDecision::Allow),
        (ActionClass::Kad, LastResortDecision::Allow),
        (ActionClass::Identify, LastResortDecision::Allow),
    ];

    for (index, (action, expected)) in cases.into_iter().enumerate() {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(u64::try_from(index).unwrap_or(0)),
                peer_id(),
                false,
                None,
                action,
                1,
                None,
            ),
            expected
        );
    }
}

#[test]
fn test_93_ipv4_and_ipv6_same_peer_ip_buckets_are_independent() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 0;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(ip4(10, 18, 93, 1)),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            second_peer,
            true,
            Some(ip6([0x2001, 0x0db8, 0x0018, 0x0093, 0, 0, 0, 1])),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_94_load_many_unique_duplicate_keys_are_accepted() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 100;
    cfg.dup_max_entries_per_peer = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    for key in 0u64..64u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(key),
                peer,
                true,
                Some(ip4(10, 18, 94, 1)),
                ActionClass::Gossip,
                1,
                Some(key),
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_95_zero_duplicate_entry_limit_means_keys_are_not_retained() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.dup_max_entries_per_peer = 0;
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    for offset in 0u64..3u64 {
        assert_eq!(
            check_action(
                &mut guards,
                now + Duration::from_millis(offset),
                peer,
                true,
                Some(ip4(10, 18, 95, 1)),
                ActionClass::Gossip,
                1,
                Some(95),
            ),
            LastResortDecision::Allow
        );
    }
}

#[test]
fn test_96_zero_duplicate_window_only_suppresses_same_instant_duplicate() {
    let now = Instant::now();
    let peer = peer_id();
    let mut cfg = test_config();
    cfg.dup_window = Duration::ZERO;
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 96, 1)),
            ActionClass::Gossip,
            1,
            Some(96),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip4(10, 18, 96, 1)),
            ActionClass::Gossip,
            1,
            Some(96),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_nanos(1),
            peer,
            true,
            Some(ip4(10, 18, 96, 1)),
            ActionClass::Gossip,
            1,
            Some(96),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_97_admission_gate_runs_before_duplicate_tracking() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("admission-before-dup:97");
    let mut guards = LastResortGuards::new(test_config(), now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            false,
            Some(ip4(10, 18, 97, 1)),
            ActionClass::BlockTxGetBlock,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip4(10, 18, 97, 1)),
            ActionClass::BlockTxGetBlock,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_98_duplicate_drop_does_not_consume_ip_rate_budget() {
    let now = Instant::now();
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("dup-before-ip-budget:98");
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 2;
    cfg.ip_refill_per_sec = 0;
    cfg.badness_threshold = 100;

    let mut guards = LastResortGuards::new(cfg, now);
    let ip = ip4(10, 18, 98, 1);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            peer,
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            peer,
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            Some(key),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            peer_id(),
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            Some(9_898),
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_99_peer_rate_limit_drop_does_not_consume_ip_rate_budget() {
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();
    let ip = ip4(10, 18, 99, 1);
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = 2;
    cfg.ip_refill_per_sec = 0;
    cfg.badness_threshold = 100;

    let mut guards = LastResortGuards::new(cfg, now);

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            first_peer,
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            second_peer,
            true,
            Some(ip),
            ActionClass::Gossip,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}

#[test]
fn test_100_end_to_end_last_resort_guard_extended_mixed_pressure_sim() {
    let now = Instant::now();
    let mut cfg = test_config();
    cfg.peer_bucket_capacity = 3;
    cfg.peer_refill_per_sec = 0;
    cfg.ip_bucket_capacity = 5;
    cfg.ip_refill_per_sec = 0;
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 2;
    cfg.peer_bytes_capacity = 50;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 100;
    cfg.global_bytes_refill_per_sec = 0;
    cfg.badness_threshold = 50;

    let mut guards = LastResortGuards::new(cfg, now);

    let shared_ip = ip4(10, 18, 100, 1);
    let first_peer = peer_id();
    let second_peer = peer_id();
    let third_peer = peer_id();

    assert_eq!(
        check_action(
            &mut guards,
            now,
            first_peer,
            true,
            Some(shared_ip),
            ActionClass::Gossip,
            1,
            Some(100_001),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(1),
            first_peer,
            true,
            Some(shared_ip),
            ActionClass::Gossip,
            1,
            Some(100_001),
        ),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(2),
            second_peer,
            true,
            Some(shared_ip),
            ActionClass::Kad,
            3,
            Some(100_002),
        ),
        LastResortDecision::Allow
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(3),
            second_peer,
            true,
            Some(shared_ip),
            ActionClass::Kad,
            1,
            Some(100_003),
        ),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(4),
            third_peer,
            false,
            Some(shared_ip),
            ActionClass::BlockTxGetBlock,
            1,
            Some(100_004),
        ),
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(5), first_peer, 50),
        LastResortDecision::Allow
    );
    assert_eq!(
        guards.check_bytes(now + Duration::from_millis(6), first_peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    let first_permit =
        permit_option!(guards.try_begin_inflight(now + Duration::from_millis(7), &first_peer));
    assert!(first_permit.is_some());

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(8), &first_peer),
        LastResortInflightDecision::Drop(LastResortDrop::PeerInflightCap)
    ));

    drop(first_permit);

    assert!(matches!(
        guards.try_begin_inflight(now + Duration::from_millis(9), &first_peer),
        LastResortInflightDecision::Allow(_)
    ));

    guards.on_peer_disconnected(first_peer);

    assert_eq!(
        check_action(
            &mut guards,
            now + Duration::from_millis(10),
            first_peer,
            true,
            Some(ip4(10, 18, 100, 2)),
            ActionClass::Identify,
            1,
            None,
        ),
        LastResortDecision::Allow
    );
}
