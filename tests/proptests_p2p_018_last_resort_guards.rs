use libp2p::PeerId;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_018_last_resort_guards::{
    ActionClass, LastResortActionRequest, LastResortConfig, LastResortDecision, LastResortDrop,
    LastResortGuards, LastResortInflightDecision,
};
use remzar::network::p2p_019_inflight_limiter::InflightPermit;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

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

        if !peers.iter().any(|existing| existing == &candidate) {
            peers.push(candidate);
        }
    }

    peers
}

fn ip(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

fn base_cfg() -> LastResortConfig {
    LastResortConfig {
        require_admission_for: vec![
            ActionClass::BlockTxGetBlock,
            ActionClass::BlockTxGetBatch,
            ActionClass::BlockTxGetTx,
        ],

        peer_bucket_capacity: 100,
        peer_refill_per_sec: 0,

        enable_ip_bucket: false,
        ip_bucket_capacity: 100,
        ip_refill_per_sec: 0,

        max_inflight_per_peer: 100,
        max_inflight_global: 100,

        dup_window: Duration::from_millis(100),
        dup_max_entries_per_peer: 128,

        peer_bytes_capacity: 1024 * 1024,
        peer_bytes_refill_per_sec: 0,
        global_bytes_capacity: 16 * 1024 * 1024,
        global_bytes_refill_per_sec: 0,

        badness_threshold: 10_000,
        cooldown: Duration::from_secs(30),
        badness_decay_per_sec: 0,
    }
}

fn request(
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

fn expect_allow(decision: LastResortDecision) {
    match decision {
        LastResortDecision::Allow => {}
        LastResortDecision::Drop(reason) => {
            panic!("expected LastResortDecision::Allow, got Drop({reason:?})");
        }
    }
}

fn expect_drop(decision: LastResortDecision) -> LastResortDrop {
    match decision {
        LastResortDecision::Allow => panic!("expected LastResortDecision::Drop"),
        LastResortDecision::Drop(reason) => reason,
    }
}

fn expect_inflight_allow(decision: LastResortInflightDecision) -> InflightPermit {
    match decision {
        LastResortInflightDecision::Allow(permit) => permit,
        LastResortInflightDecision::Drop(reason) => {
            panic!("expected inflight Allow, got Drop({reason:?})");
        }
    }
}

fn expect_inflight_drop(decision: LastResortInflightDecision) -> LastResortDrop {
    match decision {
        LastResortInflightDecision::Allow(_) => panic!("expected inflight Drop"),
        LastResortInflightDecision::Drop(reason) => reason,
    }
}

fn later(now: Instant, duration: Duration) -> Instant {
    now.checked_add(duration)
        .expect("test Instant addition should not overflow")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_default_config_has_production_guardrails_and_sync_admission_requirements(
        _case in any::<u8>(),
    ) {
        let cfg = LastResortConfig::default();

        prop_assert!(cfg.require_admission_for.contains(&ActionClass::BlockTxGetBlock));
        prop_assert!(cfg.require_admission_for.contains(&ActionClass::BlockTxGetBatch));
        prop_assert!(cfg.require_admission_for.contains(&ActionClass::BlockTxGetTx));

        prop_assert!(cfg.peer_bucket_capacity > 0);
        prop_assert!(cfg.peer_refill_per_sec > 0);
        prop_assert!(cfg.enable_ip_bucket);
        prop_assert!(cfg.ip_bucket_capacity >= cfg.peer_bucket_capacity);
        prop_assert!(cfg.max_inflight_per_peer > 0);
        prop_assert!(cfg.max_inflight_global >= cfg.max_inflight_per_peer);

        prop_assert!(cfg.dup_window > Duration::ZERO);
        prop_assert!(cfg.dup_max_entries_per_peer > 0);

        prop_assert!(cfg.peer_bytes_capacity > 0);
        prop_assert!(cfg.peer_bytes_refill_per_sec > 0);
        prop_assert!(cfg.global_bytes_capacity >= cfg.peer_bytes_capacity);
        prop_assert!(cfg.global_bytes_refill_per_sec >= cfg.peer_bytes_refill_per_sec);

        prop_assert!(cfg.badness_threshold > 0);
        prop_assert!(cfg.cooldown > Duration::ZERO);
        prop_assert!(cfg.badness_decay_per_sec > 0);
    }

    // 02/25
    #[test]
    fn test_002_dup_key_from_str_is_deterministic_and_matches_fnv_offset_for_empty_input(
        suffix in "[a-zA-Z0-9:_-]{0,64}",
    ) {
        let empty = LastResortGuards::dup_key_from_str("");

        prop_assert_eq!(
            empty,
            14695981039346656037u64,
            "empty FNV-1a key must equal the FNV offset basis"
        );

        let key_input = format!("GetBlockByIndex:{}", suffix);

        prop_assert_eq!(
            LastResortGuards::dup_key_from_str(&key_input),
            LastResortGuards::dup_key_from_str(&key_input),
            "duplicate-key hashing must be deterministic"
        );

        prop_assert_ne!(
            LastResortGuards::dup_key_from_str("GetBlockByIndex:1"),
            LastResortGuards::dup_key_from_str("GetBlockByIndex:2"),
            "known adjacent duplicate-key strings should not collapse"
        );
    }

    // 03/25
    #[test]
    fn test_003_unadmitted_required_sync_actions_are_dropped_before_rate_or_dup_checks(
        action_index in 0usize..3usize,
        cost in any::<u32>(),
        dup_key in any::<u64>(),
    ) {
        let cfg = base_cfg();
        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        let action = match action_index {
            0 => ActionClass::BlockTxGetBlock,
            1 => ActionClass::BlockTxGetBatch,
            _ => ActionClass::BlockTxGetTx,
        };

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                false,
                None,
                action,
                cost,
                Some(dup_key),
            ))),
            LastResortDrop::NotAdmitted,
            "unadmitted DB/sync retrieval action must be rejected cheaply"
        );
    }

    // 04/25
    #[test]
    fn test_004_unadmitted_non_required_actions_are_allowed_when_rate_limits_have_room(
        action_index in 0usize..4usize,
        cost in 1u32..10u32,
    ) {
        let cfg = base_cfg();
        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        let action = match action_index {
            0 => ActionClass::Version,
            1 => ActionClass::Identify,
            2 => ActionClass::Gossip,
            _ => ActionClass::Kad,
        };

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            false,
            None,
            action,
            cost,
            None,
        )));
    }

    // 05/25
    #[test]
    fn test_005_zero_cost_action_is_charged_as_one_token(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = 1;
        cfg.peer_refill_per_sec = 0;

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::Version,
            0,
            None,
        )));

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerRateLimited,
            "zero cost must still consume one peer bucket token"
        );
    }

    // 06/25
    #[test]
    fn test_006_peer_token_bucket_allows_exact_capacity_then_peer_rate_limit(
        capacity in 1u32..64u32,
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = capacity;
        cfg.peer_refill_per_sec = 0;

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        for _ in 0..capacity {
            expect_allow(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            )));
        }

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerRateLimited,
            "peer token bucket must reject exactly after capacity is exhausted"
        );
    }

    // 07/25
    #[test]
    fn test_007_peer_token_bucket_refills_with_elapsed_time_and_caps_at_capacity(
        capacity in 1u32..64u32,
        refill_per_sec in 1u32..64u32,
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = capacity;
        cfg.peer_refill_per_sec = refill_per_sec;

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        for _ in 0..capacity {
            expect_allow(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            )));
        }

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerRateLimited
        );

        expect_allow(guards.check_action(request(
            later(now, Duration::from_secs(1)),
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            None,
        )));
    }

    // 08/25
    #[test]
    fn test_008_peer_rate_limit_adds_badness_and_can_put_peer_into_cooldown(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = 0;
        cfg.peer_refill_per_sec = 0;
        cfg.badness_threshold = 3;
        cfg.cooldown = Duration::from_secs(60);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerRateLimited
        );

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerCoolingDown,
            "rate-limit badness at threshold must activate cooldown"
        );
    }

    // 09/25
    #[test]
    fn test_009_cooldown_expires_after_configured_window(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.badness_threshold = 1;
        cfg.cooldown = Duration::from_millis(50);
        cfg.badness_decay_per_sec = 0;

        let now = Instant::now();
        let peer_id = peer();
        let cooldown = cfg.cooldown;
        let mut guards = LastResortGuards::new(cfg, now);

        guards.report_misbehavior(now, peer_id, 1);

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerCoolingDown
        );

        expect_allow(guards.check_action(request(
            later(now, cooldown + Duration::from_millis(1)),
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            None,
        )));
    }

    // 10/25
    #[test]
    fn test_010_report_misbehavior_treats_zero_or_negative_points_as_one_point(
        points in -1000i32..=0i32,
    ) {
        let mut cfg = base_cfg();
        cfg.badness_threshold = 1;
        cfg.cooldown = Duration::from_secs(60);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        guards.report_misbehavior(now, peer_id, points);

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::PeerCoolingDown,
            "zero or negative misbehavior points must still count as one"
        );
    }

    // 11/25
    #[test]
    fn test_011_badness_decay_prevents_stale_subthreshold_reports_from_accumulating_forever(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.badness_threshold = 10;
        cfg.badness_decay_per_sec = 10;
        cfg.cooldown = Duration::from_secs(60);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        guards.report_misbehavior(now, peer_id, 5);
        guards.report_misbehavior(later(now, Duration::from_secs(1)), peer_id, 5);

        expect_allow(guards.check_action(request(
            later(now, Duration::from_secs(1)),
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            None,
        )));
    }

    // 12/25
    #[test]
    fn test_012_non_sync_duplicate_inside_window_is_dropped_and_adds_badness(
        key in any::<u64>(),
    ) {
        let cfg = base_cfg();
        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            Some(key),
        )));

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peer_id,
                true,
                None,
                ActionClass::Version,
                1,
                Some(key),
            ))),
            LastResortDrop::DuplicateRequest,
            "non-sync duplicate key inside duplicate window must be dropped"
        );
    }

    // 13/25
    #[test]
    fn test_013_sync_retrieval_duplicate_is_not_hard_dropped_by_duplicate_filter(
        key in any::<u64>(),
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = 10;
        cfg.peer_refill_per_sec = 0;

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::BlockTxGetBlock,
            1,
            Some(key),
        )));

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::BlockTxGetBlock,
            1,
            Some(key),
        )));
    }

    // 14/25
    #[test]
    fn test_014_duplicate_key_window_expiry_allows_same_non_sync_key_again(
        key in any::<u64>(),
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = 10;
        cfg.peer_refill_per_sec = 0;
        cfg.dup_window = Duration::from_millis(20);

        let now = Instant::now();
        let peer_id = peer();
        let window = cfg.dup_window;
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            Some(key),
        )));

        expect_allow(guards.check_action(request(
            later(now, window + Duration::from_millis(1)),
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            Some(key),
        )));
    }

    // 15/25
    #[test]
    fn test_015_duplicate_key_capacity_evicts_oldest_key_per_peer(
        key_a in any::<u64>(),
        key_b in any::<u64>(),
    ) {
        prop_assume!(key_a != key_b);

        let mut cfg = base_cfg();
        cfg.peer_bucket_capacity = 10;
        cfg.peer_refill_per_sec = 0;
        cfg.dup_max_entries_per_peer = 1;
        cfg.dup_window = Duration::from_secs(60);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            Some(key_a),
        )));

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            Some(key_b),
        )));

        expect_allow(guards.check_action(request(
            now,
            peer_id,
            true,
            None,
            ActionClass::Version,
            1,
            Some(key_a),
        )));
    }

    // 16/25
    #[test]
    fn test_016_ip_bucket_limits_peerid_churn_on_same_ip_when_enabled(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.enable_ip_bucket = true;
        cfg.ip_bucket_capacity = 2;
        cfg.ip_refill_per_sec = 0;
        cfg.peer_bucket_capacity = 10;

        let now = Instant::now();
        let shared_ip = ip(1);
        let peers = distinct_peers(4);
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_action(request(
            now,
            peers[0],
            true,
            Some(shared_ip),
            ActionClass::Version,
            1,
            None,
        )));

        expect_allow(guards.check_action(request(
            now,
            peers[1],
            true,
            Some(shared_ip),
            ActionClass::Version,
            1,
            None,
        )));

        prop_assert_eq!(
            expect_drop(guards.check_action(request(
                now,
                peers[2],
                true,
                Some(shared_ip),
                ActionClass::Version,
                1,
                None,
            ))),
            LastResortDrop::IpRateLimited,
            "third peer ID behind same IP must be IP-rate-limited"
        );

        expect_allow(guards.check_action(request(
            now,
            peers[3],
            true,
            Some(ip(2)),
            ActionClass::Version,
            1,
            None,
        )));
    }

    // 17/25
    #[test]
    fn test_017_disabled_ip_bucket_ignores_shared_ip_pressure(
        requests in 2usize..16usize,
    ) {
        let mut cfg = base_cfg();
        cfg.enable_ip_bucket = false;
        cfg.ip_bucket_capacity = 1;
        cfg.ip_refill_per_sec = 0;
        cfg.peer_bucket_capacity = 10;

        let now = Instant::now();
        let shared_ip = ip(3);
        let peers = distinct_peers(requests);
        let mut guards = LastResortGuards::new(cfg, now);

        for peer_id in peers {
            expect_allow(guards.check_action(request(
                now,
                peer_id,
                true,
                Some(shared_ip),
                ActionClass::Version,
                1,
                None,
            )));
        }
    }

    // 18/25
    #[test]
    fn test_018_peer_byte_budget_allows_exact_capacity_then_rejects_next_byte(
        capacity in 1u64..8192u64,
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bytes_capacity = capacity;
        cfg.peer_bytes_refill_per_sec = 0;
        cfg.global_bytes_capacity = capacity.saturating_mul(10).saturating_add(10);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_bytes(now, peer_id, capacity));

        prop_assert_eq!(
            expect_drop(guards.check_bytes(now, peer_id, 1)),
            LastResortDrop::PeerByteBudgetExceeded,
            "peer byte budget must reject after exact capacity is consumed"
        );
    }

    // 19/25
    #[test]
    fn test_019_global_byte_budget_limits_total_bytes_across_peers(
        capacity in 1u64..8192u64,
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bytes_capacity = capacity.saturating_mul(10).saturating_add(10);
        cfg.global_bytes_capacity = capacity;
        cfg.global_bytes_refill_per_sec = 0;

        let now = Instant::now();
        let peer_a = peer();
        let peer_b = distinct_peer(&peer_a);
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_bytes(now, peer_a, capacity));

        prop_assert_eq!(
            expect_drop(guards.check_bytes(now, peer_b, 1)),
            LastResortDrop::GlobalByteBudgetExceeded,
            "global byte budget must reject even when peer byte budget has room"
        );
    }

    // 20/25
    #[test]
    fn test_020_byte_budgets_refill_with_elapsed_time(
        capacity in 1u64..8192u64,
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bytes_capacity = capacity;
        cfg.peer_bytes_refill_per_sec = capacity;
        cfg.global_bytes_capacity = capacity;
        cfg.global_bytes_refill_per_sec = capacity;

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        expect_allow(guards.check_bytes(now, peer_id, capacity));

        prop_assert_eq!(
            expect_drop(guards.check_bytes(now, peer_id, 1)),
            LastResortDrop::PeerByteBudgetExceeded
        );

        expect_allow(guards.check_bytes(
            later(now, Duration::from_secs(1)),
            peer_id,
            1,
        ));
    }

    // 21/25
    #[test]
    fn test_021_byte_budget_exhaustion_can_trigger_cooldown(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.peer_bytes_capacity = 0;
        cfg.peer_bytes_refill_per_sec = 0;
        cfg.badness_threshold = 5;
        cfg.cooldown = Duration::from_secs(60);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        prop_assert_eq!(
            expect_drop(guards.check_bytes(now, peer_id, 1)),
            LastResortDrop::PeerByteBudgetExceeded
        );

        prop_assert_eq!(
            expect_drop(guards.check_bytes(now, peer_id, 1)),
            LastResortDrop::PeerCoolingDown,
            "peer byte-budget badness at threshold must activate cooldown"
        );
    }

    // 22/25
    #[test]
    fn test_022_inflight_per_peer_cap_is_raii_released_by_dropping_permit(
        cap in 1u32..32u32,
    ) {
        let mut cfg = base_cfg();
        cfg.max_inflight_per_peer = cap;
        cfg.max_inflight_global = cap.saturating_add(100);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        let mut permits = Vec::new();

        for _ in 0..cap {
            permits.push(expect_inflight_allow(
                guards.try_begin_inflight(now, &peer_id)
            ));
        }

        prop_assert_eq!(
            expect_inflight_drop(guards.try_begin_inflight(now, &peer_id)),
            LastResortDrop::PeerInflightCap
        );

        permits.pop();

        let _replacement = expect_inflight_allow(
            guards.try_begin_inflight(now, &peer_id)
        );

        drop(permits);
    }

    // 23/25
    #[test]
    fn test_023_inflight_global_cap_is_raii_released_across_distinct_peers(
        cap in 1usize..32usize,
    ) {
        let mut cfg = base_cfg();
        cfg.max_inflight_per_peer = 10_000;
        cfg.max_inflight_global = cap as u32;

        let now = Instant::now();
        let peers = distinct_peers(cap.saturating_add(2));
        let mut guards = LastResortGuards::new(cfg, now);

        let mut permits = Vec::new();

        for peer_id in peers.iter().take(cap) {
            permits.push(expect_inflight_allow(
                guards.try_begin_inflight(now, peer_id)
            ));
        }

        prop_assert_eq!(
            expect_inflight_drop(guards.try_begin_inflight(now, &peers[cap])),
            LastResortDrop::GlobalInflightCap
        );

        permits.pop();

        let _replacement = expect_inflight_allow(
            guards.try_begin_inflight(now, &peers[cap + 1])
        );

        drop(permits);
    }

    // 24/25
    #[test]
    fn test_024_inflight_cap_failures_add_badness_and_can_trigger_cooldown(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.max_inflight_per_peer = 0;
        cfg.max_inflight_global = 100;
        cfg.badness_threshold = 4;
        cfg.cooldown = Duration::from_secs(60);

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        prop_assert_eq!(
            expect_inflight_drop(guards.try_begin_inflight(now, &peer_id)),
            LastResortDrop::PeerInflightCap
        );

        prop_assert_eq!(
            expect_inflight_drop(guards.try_begin_inflight(now, &peer_id)),
            LastResortDrop::PeerCoolingDown,
            "inflight-cap badness at threshold must activate cooldown"
        );
    }

    // 25/25
    #[test]
    fn test_025_disconnect_removes_guard_state_but_does_not_force_clear_live_inflight_permits(
        _case in any::<u8>(),
    ) {
        let mut cfg = base_cfg();
        cfg.max_inflight_per_peer = 1;
        cfg.max_inflight_global = 1;

        let now = Instant::now();
        let peer_id = peer();
        let mut guards = LastResortGuards::new(cfg, now);

        let permit = expect_inflight_allow(
            guards.try_begin_inflight(now, &peer_id)
        );

        guards.on_peer_disconnected(peer_id);

        prop_assert_eq!(
            expect_inflight_drop(guards.try_begin_inflight(now, &peer_id)),
            LastResortDrop::PeerInflightCap,
            "disconnect must not force-clear a still-live RAII inflight permit"
        );

        drop(permit);

        let _after_drop = expect_inflight_allow(
            guards.try_begin_inflight(now, &peer_id)
        );
    }
}
