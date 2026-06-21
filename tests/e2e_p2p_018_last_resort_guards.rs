#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, identity};
use remzar::network::p2p_018_last_resort_guards::{
    ActionClass, LastResortActionRequest, LastResortConfig, LastResortDecision, LastResortDrop,
    LastResortGuards, LastResortInflightDecision,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, String>;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

fn peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn compact_cfg() -> LastResortConfig {
    LastResortConfig {
        require_admission_for: vec![
            ActionClass::BlockTxGetBlock,
            ActionClass::BlockTxGetBatch,
            ActionClass::BlockTxGetTx,
        ],
        peer_bucket_capacity: 3,
        peer_refill_per_sec: 1,
        enable_ip_bucket: true,
        ip_bucket_capacity: 5,
        ip_refill_per_sec: 1,
        max_inflight_per_peer: 2,
        max_inflight_global: 4,
        dup_window: Duration::from_millis(100),
        dup_max_entries_per_peer: 4,
        peer_bytes_capacity: 100,
        peer_bytes_refill_per_sec: 10,
        global_bytes_capacity: 500,
        global_bytes_refill_per_sec: 50,
        badness_threshold: 10,
        cooldown: Duration::from_secs(5),
        badness_decay_per_sec: 1,
    }
}

fn no_ip_cfg() -> LastResortConfig {
    let mut cfg = compact_cfg();
    cfg.enable_ip_bucket = false;
    cfg
}

fn req(
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

fn admitted_req(
    now: Instant,
    peer_id: PeerId,
    action: ActionClass,
    cost_tokens: u32,
    dup_key: Option<u64>,
) -> LastResortActionRequest {
    req(
        now,
        peer_id,
        true,
        Some(ip4(127, 0, 0, 1)),
        action,
        cost_tokens,
        dup_key,
    )
}

fn assert_inflight_allow(decision: LastResortInflightDecision) {
    match decision {
        LastResortInflightDecision::Allow(_permit) => {}
        LastResortInflightDecision::Drop(drop) => {
            panic!("expected inflight allow, got drop {drop:?}");
        }
    }
}

fn assert_inflight_drop(decision: LastResortInflightDecision, expected: LastResortDrop) {
    match decision {
        LastResortInflightDecision::Allow(_permit) => {
            panic!("expected inflight drop {expected:?}, got allow");
        }
        LastResortInflightDecision::Drop(drop) => assert_eq!(drop, expected),
    }
}

#[test]
fn e2e_01_default_config_is_production_sane() -> TestResult {
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
    assert_eq!(cfg.peer_bucket_capacity, 600);
    assert_eq!(cfg.peer_refill_per_sec, 200);
    assert!(cfg.enable_ip_bucket);
    assert_eq!(cfg.ip_bucket_capacity, 6000);
    assert_eq!(cfg.ip_refill_per_sec, 600);
    assert_eq!(cfg.max_inflight_per_peer, 64);
    assert_eq!(cfg.max_inflight_global, 2048);
    assert_eq!(cfg.dup_window, Duration::from_millis(100));
    assert_eq!(cfg.dup_max_entries_per_peer, 1024);
    assert!(cfg.peer_bytes_capacity >= 16 * MIB);
    assert!(cfg.peer_bytes_refill_per_sec >= 2 * MIB);
    assert!(cfg.global_bytes_capacity >= 128 * MIB);
    assert!(cfg.global_bytes_refill_per_sec >= 16 * MIB);
    assert_eq!(cfg.badness_threshold, 100);
    assert_eq!(cfg.cooldown, Duration::from_secs(120));
    assert_eq!(cfg.badness_decay_per_sec, 5);

    Ok(())
}

#[test]
fn e2e_02_config_clone_preserves_all_fields() -> TestResult {
    let cfg = compact_cfg();
    let cloned = cfg.clone();

    assert_eq!(cloned.require_admission_for, cfg.require_admission_for);
    assert_eq!(cloned.peer_bucket_capacity, cfg.peer_bucket_capacity);
    assert_eq!(cloned.peer_refill_per_sec, cfg.peer_refill_per_sec);
    assert_eq!(cloned.enable_ip_bucket, cfg.enable_ip_bucket);
    assert_eq!(cloned.ip_bucket_capacity, cfg.ip_bucket_capacity);
    assert_eq!(cloned.ip_refill_per_sec, cfg.ip_refill_per_sec);
    assert_eq!(cloned.max_inflight_per_peer, cfg.max_inflight_per_peer);
    assert_eq!(cloned.max_inflight_global, cfg.max_inflight_global);
    assert_eq!(cloned.dup_window, cfg.dup_window);
    assert_eq!(
        cloned.dup_max_entries_per_peer,
        cfg.dup_max_entries_per_peer
    );
    assert_eq!(cloned.peer_bytes_capacity, cfg.peer_bytes_capacity);
    assert_eq!(
        cloned.peer_bytes_refill_per_sec,
        cfg.peer_bytes_refill_per_sec
    );
    assert_eq!(cloned.global_bytes_capacity, cfg.global_bytes_capacity);
    assert_eq!(
        cloned.global_bytes_refill_per_sec,
        cfg.global_bytes_refill_per_sec
    );
    assert_eq!(cloned.badness_threshold, cfg.badness_threshold);
    assert_eq!(cloned.cooldown, cfg.cooldown);
    assert_eq!(cloned.badness_decay_per_sec, cfg.badness_decay_per_sec);

    Ok(())
}

#[test]
fn e2e_03_new_guard_exposes_config_reference() -> TestResult {
    let now = Instant::now();
    let cfg = compact_cfg();
    let guard = LastResortGuards::new(cfg.clone(), now);

    assert_eq!(guard.cfg().peer_bucket_capacity, cfg.peer_bucket_capacity);
    assert_eq!(guard.cfg().max_inflight_per_peer, cfg.max_inflight_per_peer);
    assert_eq!(guard.cfg().cooldown, cfg.cooldown);

    Ok(())
}

#[test]
fn e2e_04_dup_key_from_str_is_deterministic() -> TestResult {
    let a = LastResortGuards::dup_key_from_str("GetBlockByIndex:123");
    let b = LastResortGuards::dup_key_from_str("GetBlockByIndex:123");

    assert_eq!(a, b);
    assert_ne!(a, 0);

    Ok(())
}

#[test]
fn e2e_05_dup_key_from_str_distinguishes_different_strings() -> TestResult {
    let a = LastResortGuards::dup_key_from_str("GetBlockByIndex:123");
    let b = LastResortGuards::dup_key_from_str("GetBlockByIndex:124");

    assert_ne!(a, b);

    Ok(())
}

#[test]
fn e2e_06_version_action_is_allowed_before_admission_by_default() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    let decision = guard.check_action(req(
        now,
        peer,
        false,
        Some(ip4(127, 0, 0, 1)),
        ActionClass::Version,
        1,
        None,
    ));

    assert_eq!(decision, LastResortDecision::Allow);

    Ok(())
}

#[test]
fn e2e_07_identify_action_is_allowed_before_admission_by_default() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    let decision = guard.check_action(req(
        now,
        peer,
        false,
        Some(ip4(127, 0, 0, 1)),
        ActionClass::Identify,
        1,
        None,
    ));

    assert_eq!(decision, LastResortDecision::Allow);

    Ok(())
}

#[test]
fn e2e_08_get_block_requires_admission() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    let decision = guard.check_action(req(
        now,
        peer,
        false,
        Some(ip4(127, 0, 0, 1)),
        ActionClass::BlockTxGetBlock,
        1,
        None,
    ));

    assert_eq!(
        decision,
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    Ok(())
}

#[test]
fn e2e_09_get_batch_requires_admission() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    let decision = guard.check_action(req(
        now,
        peer,
        false,
        Some(ip4(127, 0, 0, 1)),
        ActionClass::BlockTxGetBatch,
        1,
        None,
    ));

    assert_eq!(
        decision,
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    Ok(())
}

#[test]
fn e2e_10_get_tx_requires_admission() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    let decision = guard.check_action(req(
        now,
        peer,
        false,
        Some(ip4(127, 0, 0, 1)),
        ActionClass::BlockTxGetTx,
        1,
        None,
    ));

    assert_eq!(
        decision,
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    Ok(())
}

#[test]
fn e2e_11_admitted_sync_retrieval_action_is_allowed() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    let decision = guard.check_action(admitted_req(
        now,
        peer,
        ActionClass::BlockTxGetBlock,
        1,
        None,
    ));

    assert_eq!(decision, LastResortDecision::Allow);

    Ok(())
}

#[test]
fn e2e_12_zero_cost_still_costs_one_token() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 0, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 0, None)),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    Ok(())
}

#[test]
fn e2e_13_peer_bucket_drops_after_capacity_is_consumed() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 2;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    Ok(())
}

#[test]
fn e2e_14_peer_bucket_refills_after_elapsed_time() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );
    assert_eq!(
        guard.check_action(admitted_req(
            now + Duration::from_secs(1),
            peer,
            ActionClass::Version,
            1,
            None,
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_15_peer_bucket_does_not_refill_at_same_instant() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 100;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    Ok(())
}

#[test]
fn e2e_16_peer_buckets_are_independent_per_peer() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let first = peer_id();
    let second = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, first, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, second, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_17_ip_bucket_drops_peerid_churn_from_same_ip() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 2;
    cfg.ip_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let ip = Some(ip4(10, 1, 1, 1));

    assert_eq!(
        guard.check_action(req(now, peer_id(), true, ip, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(req(now, peer_id(), true, ip, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(req(now, peer_id(), true, ip, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );

    Ok(())
}

#[test]
fn e2e_18_disabling_ip_bucket_allows_peerid_churn_at_ip_layer() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.enable_ip_bucket = false;
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let ip = Some(ip4(10, 1, 1, 2));

    for _ in 0usize..5usize {
        assert_eq!(
            guard.check_action(req(now, peer_id(), true, ip, ActionClass::Version, 1, None)),
            LastResortDecision::Allow
        );
    }

    Ok(())
}

#[test]
fn e2e_19_ip_buckets_are_independent_per_ip() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);

    assert_eq!(
        guard.check_action(req(
            now,
            peer_id(),
            true,
            Some(ip4(10, 1, 1, 3)),
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(req(
            now,
            peer_id(),
            true,
            Some(ip4(10, 1, 1, 4)),
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_20_ip_bucket_refills_after_elapsed_time() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bucket_capacity = 100;
    cfg.ip_bucket_capacity = 1;
    cfg.ip_refill_per_sec = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let ip = Some(ip4(10, 1, 1, 5));

    assert_eq!(
        guard.check_action(req(now, peer_id(), true, ip, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(req(now, peer_id(), true, ip, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::IpRateLimited)
    );
    assert_eq!(
        guard.check_action(req(
            now + Duration::from_secs(1),
            peer_id(),
            true,
            ip,
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_21_duplicate_non_sync_gossip_request_is_dropped() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(no_ip_cfg(), now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("gossip:hello");

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Gossip, 1, Some(key))),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Gossip, 1, Some(key))),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );

    Ok(())
}

#[test]
fn e2e_22_duplicate_sync_get_block_is_not_hard_dropped_by_dup_guard() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("GetBlockByIndex:22");

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            peer,
            ActionClass::BlockTxGetBlock,
            1,
            Some(key)
        )),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(
            now,
            peer,
            ActionClass::BlockTxGetBlock,
            1,
            Some(key)
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_23_duplicate_key_expires_after_window() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.dup_window = Duration::from_millis(100);
    cfg.peer_bucket_capacity = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("kad:23");

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Kad, 1, Some(key))),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(
            now + Duration::from_millis(101),
            peer,
            ActionClass::Kad,
            1,
            Some(key)
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_24_duplicate_entry_cap_evicts_oldest_key() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.dup_window = Duration::from_secs(60);
    cfg.dup_max_entries_per_peer = 1;
    cfg.peer_bucket_capacity = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    let k1 = LastResortGuards::dup_key_from_str("kad:k1");
    let k2 = LastResortGuards::dup_key_from_str("kad:k2");

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Kad, 1, Some(k1))),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Kad, 1, Some(k2))),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Kad, 1, Some(k1))),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_25_duplicate_keys_are_scoped_per_peer() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(no_ip_cfg(), now);
    let first = peer_id();
    let second = peer_id();
    let key = LastResortGuards::dup_key_from_str("identify:shared");

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            first,
            ActionClass::Identify,
            1,
            Some(key)
        )),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(
            now,
            second,
            ActionClass::Identify,
            1,
            Some(key)
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_26_report_misbehavior_triggers_cooldown_at_threshold() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 5;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    guard.report_misbehavior(now, peer, 5);

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    Ok(())
}

#[test]
fn e2e_27_zero_or_negative_misbehavior_points_are_clamped_to_one() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    guard.report_misbehavior(now, peer, 0);

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    Ok(())
}

#[test]
fn e2e_28_cooldown_expires_after_window() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 1;
    cfg.cooldown = Duration::from_secs(2);

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    guard.report_misbehavior(now, peer, 1);

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );
    assert_eq!(
        guard.check_action(admitted_req(
            now + Duration::from_secs(3),
            peer,
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_29_badness_decays_before_crossing_threshold() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 10;
    cfg.badness_decay_per_sec = 5;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    guard.report_misbehavior(now, peer, 9);
    guard.report_misbehavior(now + Duration::from_secs(2), peer, 1);

    assert_eq!(
        guard.check_action(admitted_req(
            now + Duration::from_secs(2),
            peer,
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_30_cooldown_blocks_byte_budget_checks() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    guard.report_misbehavior(now, peer, 1);

    assert_eq!(
        guard.check_bytes(now, peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    Ok(())
}

#[test]
fn e2e_31_cooldown_blocks_inflight_acquisition() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    guard.report_misbehavior(now, peer, 1);

    assert_inflight_drop(
        guard.try_begin_inflight(now, &peer),
        LastResortDrop::PeerCoolingDown,
    );

    Ok(())
}

#[test]
fn e2e_32_check_bytes_under_budget_is_allowed() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    assert_eq!(guard.check_bytes(now, peer, 50), LastResortDecision::Allow);

    Ok(())
}

#[test]
fn e2e_33_peer_byte_budget_exceeded_is_dropped() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bytes_capacity = 100;
    cfg.global_bytes_capacity = 1_000;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_bytes(now, peer, 101),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    Ok(())
}

#[test]
fn e2e_34_peer_byte_budget_refills_after_elapsed_time() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bytes_capacity = 100;
    cfg.peer_bytes_refill_per_sec = 50;
    cfg.global_bytes_capacity = 1_000;
    cfg.global_bytes_refill_per_sec = 1_000;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(guard.check_bytes(now, peer, 100), LastResortDecision::Allow);
    assert_eq!(
        guard.check_bytes(now, peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
    assert_eq!(
        guard.check_bytes(now + Duration::from_secs(1), peer, 50),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_35_global_byte_budget_exceeded_across_peers() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bytes_capacity = 1_000;
    cfg.peer_bytes_refill_per_sec = 0;
    cfg.global_bytes_capacity = 150;
    cfg.global_bytes_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);

    assert_eq!(
        guard.check_bytes(now, peer_id(), 100),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_bytes(now, peer_id(), 100),
        LastResortDecision::Drop(LastResortDrop::GlobalByteBudgetExceeded)
    );

    Ok(())
}

#[test]
fn e2e_36_peer_byte_budget_drop_can_trigger_cooldown() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bytes_capacity = 10;
    cfg.global_bytes_capacity = 1_000;
    cfg.badness_threshold = 5;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_bytes(now, peer, 11),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    Ok(())
}

#[test]
fn e2e_37_zero_byte_check_is_allowed() -> TestResult {
    let now = Instant::now();
    let mut guard = LastResortGuards::new(compact_cfg(), now);
    let peer = peer_id();

    assert_eq!(guard.check_bytes(now, peer, 0), LastResortDecision::Allow);

    Ok(())
}

#[test]
fn e2e_38_inflight_per_peer_cap_drops_second_request_when_permit_is_held() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    let _permit = match guard.try_begin_inflight(now, &peer) {
        LastResortInflightDecision::Allow(permit) => permit,
        LastResortInflightDecision::Drop(drop) => {
            return Err(format!("unexpected drop: {drop:?}"));
        }
    };

    assert_inflight_drop(
        guard.try_begin_inflight(now, &peer),
        LastResortDrop::PeerInflightCap,
    );

    Ok(())
}

#[test]
fn e2e_39_dropping_inflight_permit_releases_peer_cap() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    let permit = match guard.try_begin_inflight(now, &peer) {
        LastResortInflightDecision::Allow(permit) => permit,
        LastResortInflightDecision::Drop(drop) => {
            return Err(format!("unexpected drop: {drop:?}"));
        }
    };

    drop(permit);

    assert_inflight_allow(guard.try_begin_inflight(now, &peer));

    Ok(())
}

#[test]
fn e2e_40_global_inflight_cap_drops_request_across_peers() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.max_inflight_per_peer = 10;
    cfg.max_inflight_global = 2;

    let mut guard = LastResortGuards::new(cfg, now);

    let mut permits = Vec::new();

    for _ in 0usize..2usize {
        match guard.try_begin_inflight(now, &peer_id()) {
            LastResortInflightDecision::Allow(permit) => permits.push(permit),
            LastResortInflightDecision::Drop(drop) => {
                return Err(format!("unexpected drop: {drop:?}"));
            }
        }
    }

    assert_inflight_drop(
        guard.try_begin_inflight(now, &peer_id()),
        LastResortDrop::GlobalInflightCap,
    );

    drop(permits);

    Ok(())
}

#[test]
fn e2e_41_dropping_inflight_permit_releases_global_cap() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.max_inflight_per_peer = 10;
    cfg.max_inflight_global = 1;

    let mut guard = LastResortGuards::new(cfg, now);

    let first_peer = peer_id();
    let second_peer = peer_id();

    let permit = match guard.try_begin_inflight(now, &first_peer) {
        LastResortInflightDecision::Allow(permit) => permit,
        LastResortInflightDecision::Drop(drop) => {
            return Err(format!("unexpected drop: {drop:?}"));
        }
    };

    assert_inflight_drop(
        guard.try_begin_inflight(now, &second_peer),
        LastResortDrop::GlobalInflightCap,
    );

    drop(permit);

    assert_inflight_allow(guard.try_begin_inflight(now, &second_peer));

    Ok(())
}

#[test]
fn e2e_42_disconnect_clears_peer_rate_state() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    guard.on_peer_disconnected(peer);

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_43_disconnect_does_not_force_release_live_inflight_permit() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    let permit = match guard.try_begin_inflight(now, &peer) {
        LastResortInflightDecision::Allow(permit) => permit,
        LastResortInflightDecision::Drop(drop) => {
            return Err(format!("unexpected drop: {drop:?}"));
        }
    };

    guard.on_peer_disconnected(peer);

    assert_inflight_drop(
        guard.try_begin_inflight(now, &peer),
        LastResortDrop::PeerInflightCap,
    );

    drop(permit);

    assert_inflight_allow(guard.try_begin_inflight(now, &peer));

    Ok(())
}

#[test]
fn e2e_44_not_admitted_drop_happens_before_rate_or_duplicate_checks() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("not-admitted-sync");

    let decision = guard.check_action(req(
        now,
        peer,
        false,
        None,
        ActionClass::BlockTxGetBlock,
        u32::MAX,
        Some(key),
    ));

    assert_eq!(
        decision,
        LastResortDecision::Drop(LastResortDrop::NotAdmitted)
    );

    Ok(())
}

#[test]
fn e2e_45_peer_cooling_down_takes_precedence_over_duplicate_drop() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 1;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("cooldown-before-dup");

    guard.report_misbehavior(now, peer, 1);

    let decision = guard.check_action(admitted_req(now, peer, ActionClass::Gossip, 1, Some(key)));

    assert_eq!(
        decision,
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    Ok(())
}

#[test]
fn e2e_46_sync_duplicate_is_still_subject_to_peer_rate_limit() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 1;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("GetBlockByIndex:46");

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            peer,
            ActionClass::BlockTxGetBlock,
            1,
            Some(key)
        )),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(
            now,
            peer,
            ActionClass::BlockTxGetBlock,
            1,
            Some(key)
        )),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    Ok(())
}

#[test]
fn e2e_47_non_sync_duplicate_can_escalate_to_cooldown() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.badness_threshold = 2;
    cfg.peer_bucket_capacity = 10;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();
    let key = LastResortGuards::dup_key_from_str("gossip:duplicate-cooldown");

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Gossip, 1, Some(key))),
        LastResortDecision::Allow
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Gossip, 1, Some(key))),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );
    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 1, None)),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    Ok(())
}

#[test]
fn e2e_48_action_cost_larger_than_bucket_capacity_is_rate_limited() -> TestResult {
    let now = Instant::now();
    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 3;
    cfg.peer_refill_per_sec = 0;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_action(admitted_req(now, peer, ActionClass::Version, 4, None)),
        LastResortDecision::Drop(LastResortDrop::PeerRateLimited)
    );

    Ok(())
}

#[test]
fn e2e_49_large_byte_cost_larger_than_peer_capacity_is_dropped() -> TestResult {
    let now = Instant::now();
    let mut cfg = compact_cfg();
    cfg.peer_bytes_capacity = 100;
    cfg.global_bytes_capacity = 10_000;

    let mut guard = LastResortGuards::new(cfg, now);
    let peer = peer_id();

    assert_eq!(
        guard.check_bytes(now, peer, 1_000),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    Ok(())
}

#[test]
fn e2e_50_full_last_resort_lifecycle_rate_dup_inflight_bytes_cooldown_and_disconnect() -> TestResult
{
    let now = Instant::now();

    let mut cfg = no_ip_cfg();
    cfg.peer_bucket_capacity = 20;
    cfg.peer_refill_per_sec = 0;
    cfg.max_inflight_per_peer = 1;
    cfg.max_inflight_global = 2;
    cfg.peer_bytes_capacity = 100;
    cfg.global_bytes_capacity = 500;
    cfg.badness_threshold = 10_000;
    cfg.cooldown = Duration::from_secs(2);

    let mut guard = LastResortGuards::new(cfg, now);

    let sync_peer = peer_id();
    let inflight_peer = peer_id();
    let byte_peer = peer_id();
    let cooldown_peer = peer_id();

    // 1. Sync duplicate requests are intentionally not hard-dropped by the duplicate guard.
    let sync_key = LastResortGuards::dup_key_from_str("GetBlockByIndex:50");

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            sync_peer,
            ActionClass::BlockTxGetBlock,
            1,
            Some(sync_key)
        )),
        LastResortDecision::Allow
    );

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            sync_peer,
            ActionClass::BlockTxGetBlock,
            1,
            Some(sync_key)
        )),
        LastResortDecision::Allow
    );

    // 2. Non-sync duplicate gossip is dropped.
    let gossip_key = LastResortGuards::dup_key_from_str("gossip:50");

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            sync_peer,
            ActionClass::Gossip,
            1,
            Some(gossip_key)
        )),
        LastResortDecision::Allow
    );

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            sync_peer,
            ActionClass::Gossip,
            1,
            Some(gossip_key)
        )),
        LastResortDecision::Drop(LastResortDrop::DuplicateRequest)
    );

    // 3. In-flight guard allows one request and blocks the second while the permit is held.
    let permit = match guard.try_begin_inflight(now, &inflight_peer) {
        LastResortInflightDecision::Allow(permit) => permit,
        LastResortInflightDecision::Drop(drop) => {
            return Err(format!("unexpected inflight drop: {drop:?}"));
        }
    };

    assert_inflight_drop(
        guard.try_begin_inflight(now, &inflight_peer),
        LastResortDrop::PeerInflightCap,
    );

    drop(permit);

    // 4. Dropping the permit releases the in-flight slot.
    assert_inflight_allow(guard.try_begin_inflight(now, &inflight_peer));

    // 5. Byte budget allows exactly the peer capacity, then rejects excess.
    assert_eq!(
        guard.check_bytes(now, byte_peer, 100),
        LastResortDecision::Allow
    );

    assert_eq!(
        guard.check_bytes(now, byte_peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerByteBudgetExceeded)
    );

    // 6. Explicit misbehavior triggers cooldown.
    guard.report_misbehavior(now, cooldown_peer, 10_000);

    assert_eq!(
        guard.check_action(admitted_req(
            now,
            cooldown_peer,
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    assert_eq!(
        guard.check_bytes(now, cooldown_peer, 1),
        LastResortDecision::Drop(LastResortDrop::PeerCoolingDown)
    );

    assert_inflight_drop(
        guard.try_begin_inflight(now, &cooldown_peer),
        LastResortDrop::PeerCoolingDown,
    );

    // 7. After cooldown expires, the peer can act again.
    assert_eq!(
        guard.check_action(admitted_req(
            now + Duration::from_secs(3),
            cooldown_peer,
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );

    // 8. Disconnect cleanup clears per-peer limiter state.
    guard.on_peer_disconnected(sync_peer);
    guard.on_peer_disconnected(inflight_peer);
    guard.on_peer_disconnected(byte_peer);
    guard.on_peer_disconnected(cooldown_peer);

    assert_eq!(
        guard.check_action(admitted_req(
            now + Duration::from_secs(3),
            sync_peer,
            ActionClass::Version,
            1,
            None
        )),
        LastResortDecision::Allow
    );

    Ok(())
}
