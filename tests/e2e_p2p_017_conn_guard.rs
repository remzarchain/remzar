#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use remzar::network::p2p_017_conn_guard::{ConnGuard, ConnGuardConfig, DropReason, GuardDecision};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, String>;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn ip4_addr(ip: &str, port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/{ip}/tcp/{port}").parse().map_err(fmt_err)
}

fn ip6_addr(ip: &str, port: u16) -> TestResult<Multiaddr> {
    format!("/ip6/{ip}/tcp/{port}").parse().map_err(fmt_err)
}

fn dns_addr(port: u16) -> TestResult<Multiaddr> {
    format!("/dns4/example.com/tcp/{port}")
        .parse()
        .map_err(fmt_err)
}

fn memory_addr(id: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(id));
    addr
}

fn p2p_addr(mut base: Multiaddr, peer: PeerId) -> Multiaddr {
    base.push(Protocol::P2p(peer));
    base
}

fn default_guard() -> ConnGuard {
    ConnGuard::new(ConnGuardConfig::default())
}

fn compact_cfg() -> ConnGuardConfig {
    ConnGuardConfig {
        max_per_ip: 2,
        max_per_v4_24: 3,
        max_per_v6_64: 2,
        max_handshaking: 4,
        handshake_deadline: Duration::from_secs(5),
        rate_window: Duration::from_secs(10),
        max_new_conns_per_ip_per_window: 10,
    }
}

fn rate_cfg(max_attempts: usize) -> ConnGuardConfig {
    ConnGuardConfig {
        max_per_ip: 100,
        max_per_v4_24: 100,
        max_per_v6_64: 100,
        max_handshaking: 100,
        handshake_deadline: Duration::from_secs(5),
        rate_window: Duration::from_secs(10),
        max_new_conns_per_ip_per_window: max_attempts,
    }
}

fn pool_cfg(max_handshaking: usize) -> ConnGuardConfig {
    ConnGuardConfig {
        max_per_ip: 100,
        max_per_v4_24: 100,
        max_per_v6_64: 100,
        max_handshaking,
        handshake_deadline: Duration::from_secs(5),
        rate_window: Duration::from_secs(10),
        max_new_conns_per_ip_per_window: 100,
    }
}

#[test]
fn e2e_01_default_config_values_are_sane() -> TestResult {
    let cfg = ConnGuardConfig::default();

    assert_eq!(cfg.max_per_ip, 8);
    assert_eq!(cfg.max_per_v4_24, 32);
    assert_eq!(cfg.max_per_v6_64, 16);
    assert_eq!(cfg.max_handshaking, 32);
    assert_eq!(cfg.handshake_deadline, Duration::from_secs(5));
    assert_eq!(cfg.rate_window, Duration::from_secs(10));
    assert_eq!(cfg.max_new_conns_per_ip_per_window, 10);

    Ok(())
}

#[test]
fn e2e_02_config_clone_preserves_all_fields() -> TestResult {
    let cfg = compact_cfg();
    let cloned = cfg.clone();

    assert_eq!(cloned.max_per_ip, cfg.max_per_ip);
    assert_eq!(cloned.max_per_v4_24, cfg.max_per_v4_24);
    assert_eq!(cloned.max_per_v6_64, cfg.max_per_v6_64);
    assert_eq!(cloned.max_handshaking, cfg.max_handshaking);
    assert_eq!(cloned.handshake_deadline, cfg.handshake_deadline);
    assert_eq!(cloned.rate_window, cfg.rate_window);
    assert_eq!(
        cloned.max_new_conns_per_ip_per_window,
        cfg.max_new_conns_per_ip_per_window
    );

    Ok(())
}

#[test]
fn e2e_03_guard_exposes_config_reference() -> TestResult {
    let cfg = compact_cfg();
    let guard = ConnGuard::new(cfg.clone());

    assert_eq!(guard._cfg().max_per_ip, cfg.max_per_ip);
    assert_eq!(guard._cfg().max_handshaking, cfg.max_handshaking);
    assert_eq!(guard._cfg().handshake_deadline, cfg.handshake_deadline);

    Ok(())
}

#[test]
fn e2e_04_new_guard_starts_empty() -> TestResult {
    let guard = default_guard();

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_05_ip_from_multiaddr_extracts_ipv4() -> TestResult {
    let addr = ip4_addr("127.0.0.1", 30105)?;
    let ip = ConnGuard::ip_from_multiaddr(&addr);

    assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

    Ok(())
}

#[test]
fn e2e_06_ip_from_multiaddr_extracts_ipv6() -> TestResult {
    let addr = ip6_addr("::1", 30106)?;
    let ip = ConnGuard::ip_from_multiaddr(&addr);

    assert_eq!(ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    Ok(())
}

#[test]
fn e2e_07_ip_from_multiaddr_ignores_dns_without_ip_component() -> TestResult {
    let addr = dns_addr(30107)?;

    assert_eq!(ConnGuard::ip_from_multiaddr(&addr), None);

    Ok(())
}

#[test]
fn e2e_08_ip_from_multiaddr_ignores_memory_addr() -> TestResult {
    let addr = memory_addr(8);

    assert_eq!(ConnGuard::ip_from_multiaddr(&addr), None);

    Ok(())
}

#[test]
fn e2e_09_ip_from_multiaddr_extracts_ip_before_p2p_suffix() -> TestResult {
    let addr = p2p_addr(ip4_addr("10.1.2.3", 30109)?, peer_id());

    assert_eq!(
        ConnGuard::ip_from_multiaddr(&addr),
        Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
    );

    Ok(())
}

#[test]
fn e2e_10_connection_with_missing_ip_is_dropped() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    let decision = guard.on_connection_established(peer, &memory_addr(10), now);

    assert_eq!(decision, GuardDecision::Drop(DropReason::MissingIp));
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_11_connection_with_dns_only_addr_is_dropped_missing_ip() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    let decision = guard.on_connection_established(peer, &dns_addr(30111)?, now);

    assert_eq!(decision, GuardDecision::Drop(DropReason::MissingIp));
    assert_eq!(guard.pending_len(), 0);

    Ok(())
}

#[test]
fn e2e_12_valid_ipv4_connection_enters_pending_but_not_admitted() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    let decision = guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30112)?, now);

    assert_eq!(decision, GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));

    Ok(())
}

#[test]
fn e2e_13_valid_ipv6_connection_enters_pending_but_not_admitted() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    let decision = guard.on_connection_established(peer, &ip6_addr("::1", 30113)?, now);

    assert_eq!(decision, GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));

    Ok(())
}

#[test]
fn e2e_14_same_peer_multiple_connections_keep_single_pending_entry() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();
    let addr = ip4_addr("127.0.0.1", 30114)?;

    assert_eq!(
        guard.on_connection_established(peer, &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.on_connection_established(peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_15_try_admit_unknown_peer_drops_missing_ip() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();

    let decision = guard.try_admit(peer);

    assert_eq!(decision, GuardDecision::Drop(DropReason::MissingIp));
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_16_try_admit_pending_peer_succeeds_and_removes_pending() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30116)?, now),
        GuardDecision::Allow
    );

    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);
    assert!(guard.is_admitted(&peer));
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 1);

    Ok(())
}

#[test]
fn e2e_17_try_admit_already_admitted_peer_is_idempotent() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30117)?, now);
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);

    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));

    Ok(())
}

#[test]
fn e2e_18_connection_closed_for_pending_peer_removes_pending_state() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30118)?, now);
    assert_eq!(guard.pending_len(), 1);

    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));

    Ok(())
}

#[test]
fn e2e_19_connection_closed_for_admitted_peer_removes_admission() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30119)?, now);
    guard.try_admit(peer);

    assert!(guard.is_admitted(&peer));
    assert_eq!(guard.admitted_len(), 1);

    guard.on_connection_closed(peer);

    assert!(!guard.is_admitted(&peer));
    assert_eq!(guard.admitted_len(), 0);
    assert_eq!(guard.pending_len(), 0);

    Ok(())
}

#[test]
fn e2e_20_unknown_connection_closed_is_safe_noop() -> TestResult {
    let mut guard = default_guard();

    guard.on_connection_closed(peer_id());

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_21_two_connections_same_peer_require_two_closes_before_removal() -> TestResult {
    let mut guard = default_guard();
    let peer = peer_id();
    let now = Instant::now();
    let addr = ip4_addr("127.0.0.1", 30121)?;

    guard.on_connection_established(peer, &addr, now);
    guard.on_connection_established(peer, &addr, now + Duration::from_millis(1));
    guard.try_admit(peer);

    assert!(guard.is_admitted(&peer));
    assert_eq!(guard.admitted_len(), 1);

    guard.on_connection_closed(peer);

    assert!(guard.is_admitted(&peer));
    assert_eq!(guard.admitted_len(), 1);

    guard.on_connection_closed(peer);

    assert!(!guard.is_admitted(&peer));
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_22_rate_limit_drops_connection_after_window_capacity() -> TestResult {
    let mut guard = ConnGuard::new(rate_cfg(2));
    let now = Instant::now();
    let addr = ip4_addr("127.0.0.1", 30122)?;

    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    let third = guard.on_connection_established(peer_id(), &addr, now + Duration::from_millis(2));

    assert_eq!(third, GuardDecision::Drop(DropReason::RateLimited));

    Ok(())
}

#[test]
fn e2e_23_rate_limit_is_per_ip_not_global() -> TestResult {
    let mut guard = ConnGuard::new(rate_cfg(1));
    let now = Instant::now();

    assert_eq!(
        guard.on_connection_established(peer_id(), &ip4_addr("10.0.0.1", 30123)?, now),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.on_connection_established(peer_id(), &ip4_addr("10.0.0.2", 30123)?, now),
        GuardDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_24_rate_limit_window_prunes_old_attempts_after_window() -> TestResult {
    let mut cfg = rate_cfg(1);
    cfg.rate_window = Duration::from_secs(2);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();
    let addr = ip4_addr("127.0.0.1", 30124)?;

    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let later = now + Duration::from_secs(3);
    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, later),
        GuardDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_25_rate_limit_does_not_prune_at_exact_window_boundary() -> TestResult {
    let mut cfg = rate_cfg(1);
    cfg.rate_window = Duration::from_secs(2);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();
    let addr = ip4_addr("127.0.0.1", 30125)?;

    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let exact_boundary = now + Duration::from_secs(2);
    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, exact_boundary),
        GuardDecision::Drop(DropReason::RateLimited)
    );

    Ok(())
}

#[test]
fn e2e_26_rate_limited_drop_does_not_add_pending_peer() -> TestResult {
    let mut guard = ConnGuard::new(rate_cfg(1));
    let now = Instant::now();
    let addr = ip4_addr("127.0.0.1", 30126)?;

    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let before_pending = guard.pending_len();

    assert_eq!(
        guard.on_connection_established(peer_id(), &addr, now + Duration::from_millis(1)),
        GuardDecision::Drop(DropReason::RateLimited)
    );

    assert_eq!(guard.pending_len(), before_pending);

    Ok(())
}

#[test]
fn e2e_27_handshake_pool_full_drops_new_peer() -> TestResult {
    let mut guard = ConnGuard::new(pool_cfg(2));
    let now = Instant::now();

    assert_eq!(
        guard.on_connection_established(peer_id(), &ip4_addr("10.0.1.1", 30127)?, now),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.on_connection_established(peer_id(), &ip4_addr("10.0.1.2", 30127)?, now),
        GuardDecision::Allow
    );

    let decision = guard.on_connection_established(peer_id(), &ip4_addr("10.0.1.3", 30127)?, now);

    assert_eq!(decision, GuardDecision::Drop(DropReason::HandshakePoolFull));
    assert_eq!(guard.pending_len(), 2);

    Ok(())
}

#[test]
fn e2e_28_handshake_pool_full_still_allows_existing_pending_peer_extra_connection() -> TestResult {
    let mut guard = ConnGuard::new(pool_cfg(1));
    let now = Instant::now();
    let peer = peer_id();
    let addr = ip4_addr("10.0.2.1", 30128)?;

    assert_eq!(
        guard.on_connection_established(peer, &addr, now),
        GuardDecision::Allow
    );

    assert_eq!(
        guard.on_connection_established(peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);

    Ok(())
}

#[test]
fn e2e_29_admitting_peer_frees_pending_pool_slot() -> TestResult {
    let mut guard = ConnGuard::new(pool_cfg(1));
    let now = Instant::now();

    let first = peer_id();
    let second = peer_id();

    assert_eq!(
        guard.on_connection_established(first, &ip4_addr("10.0.3.1", 30129)?, now),
        GuardDecision::Allow
    );

    assert_eq!(guard.try_admit(first), GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 0);

    assert_eq!(
        guard.on_connection_established(second, &ip4_addr("10.0.3.2", 30129)?, now),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);

    Ok(())
}

#[test]
fn e2e_30_per_ip_cap_drops_third_admission_same_ip() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 2;
    cfg.max_per_v4_24 = 100;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();
    let addr = ip4_addr("10.0.4.1", 30130)?;

    let p1 = peer_id();
    let p2 = peer_id();
    let p3 = peer_id();

    guard.on_connection_established(p1, &addr, now);
    guard.on_connection_established(p2, &addr, now + Duration::from_millis(1));
    guard.on_connection_established(p3, &addr, now + Duration::from_millis(2));

    assert_eq!(guard.try_admit(p1), GuardDecision::Allow);
    assert_eq!(guard.try_admit(p2), GuardDecision::Allow);

    assert_eq!(
        guard.try_admit(p3),
        GuardDecision::Drop(DropReason::PerIpCap)
    );
    assert!(!guard.is_admitted(&p3));
    assert_eq!(guard.admitted_len(), 2);

    Ok(())
}

#[test]
fn e2e_31_per_ip_cap_is_released_after_disconnect() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 1;
    cfg.max_per_v4_24 = 100;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();
    let addr = ip4_addr("10.0.5.1", 30131)?;

    let first = peer_id();
    let second = peer_id();

    guard.on_connection_established(first, &addr, now);
    guard.on_connection_established(second, &addr, now + Duration::from_millis(1));

    assert_eq!(guard.try_admit(first), GuardDecision::Allow);
    assert_eq!(
        guard.try_admit(second),
        GuardDecision::Drop(DropReason::PerIpCap)
    );

    guard.on_connection_closed(first);

    assert_eq!(guard.try_admit(second), GuardDecision::Allow);
    assert!(guard.is_admitted(&second));
    assert_eq!(guard.admitted_len(), 1);

    Ok(())
}

#[test]
fn e2e_32_v4_subnet_cap_drops_peer_when_24_subnet_is_full() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 100;
    cfg.max_per_v4_24 = 2;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let p1 = peer_id();
    let p2 = peer_id();
    let p3 = peer_id();

    guard.on_connection_established(p1, &ip4_addr("10.9.8.1", 30132)?, now);
    guard.on_connection_established(p2, &ip4_addr("10.9.8.2", 30132)?, now);
    guard.on_connection_established(p3, &ip4_addr("10.9.8.3", 30132)?, now);

    assert_eq!(guard.try_admit(p1), GuardDecision::Allow);
    assert_eq!(guard.try_admit(p2), GuardDecision::Allow);
    assert_eq!(
        guard.try_admit(p3),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );

    assert_eq!(guard.admitted_len(), 2);

    Ok(())
}

#[test]
fn e2e_33_v4_subnet_cap_allows_different_24_subnets() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 100;
    cfg.max_per_v4_24 = 1;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let p1 = peer_id();
    let p2 = peer_id();

    guard.on_connection_established(p1, &ip4_addr("10.9.8.1", 30133)?, now);
    guard.on_connection_established(p2, &ip4_addr("10.9.9.1", 30133)?, now);

    assert_eq!(guard.try_admit(p1), GuardDecision::Allow);
    assert_eq!(guard.try_admit(p2), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 2);

    Ok(())
}

#[test]
fn e2e_34_v6_subnet_cap_drops_peer_when_64_subnet_is_full() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 100;
    cfg.max_per_v6_64 = 2;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let p1 = peer_id();
    let p2 = peer_id();
    let p3 = peer_id();

    guard.on_connection_established(p1, &ip6_addr("2001:db8:abcd:12::1", 30134)?, now);
    guard.on_connection_established(p2, &ip6_addr("2001:db8:abcd:12::2", 30134)?, now);
    guard.on_connection_established(p3, &ip6_addr("2001:db8:abcd:12::3", 30134)?, now);

    assert_eq!(guard.try_admit(p1), GuardDecision::Allow);
    assert_eq!(guard.try_admit(p2), GuardDecision::Allow);
    assert_eq!(
        guard.try_admit(p3),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );

    Ok(())
}

#[test]
fn e2e_35_v6_subnet_cap_allows_different_64_subnets() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 100;
    cfg.max_per_v6_64 = 1;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let p1 = peer_id();
    let p2 = peer_id();

    guard.on_connection_established(p1, &ip6_addr("2001:db8:abcd:12::1", 30135)?, now);
    guard.on_connection_established(p2, &ip6_addr("2001:db8:abcd:13::1", 30135)?, now);

    assert_eq!(guard.try_admit(p1), GuardDecision::Allow);
    assert_eq!(guard.try_admit(p2), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 2);

    Ok(())
}

#[test]
fn e2e_36_sweep_timeouts_drops_peer_after_deadline() -> TestResult {
    let mut guard = ConnGuard::new(compact_cfg());
    let now = Instant::now();
    let peer = peer_id();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30136)?, now);
    assert_eq!(guard.pending_len(), 1);

    let dropped = guard.sweep_timeouts(now + Duration::from_secs(6));

    assert_eq!(dropped, vec![peer]);
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);

    Ok(())
}

#[test]
fn e2e_37_sweep_timeouts_does_not_drop_at_exact_deadline() -> TestResult {
    let mut guard = ConnGuard::new(compact_cfg());
    let now = Instant::now();
    let peer = peer_id();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30137)?, now);

    let dropped = guard.sweep_timeouts(now + Duration::from_secs(5));

    assert!(dropped.is_empty());
    assert_eq!(guard.pending_len(), 1);

    Ok(())
}

#[test]
fn e2e_38_sweep_timeouts_drops_only_expired_pending_peers() -> TestResult {
    let mut guard = ConnGuard::new(compact_cfg());
    let now = Instant::now();

    let old_peer = peer_id();
    let fresh_peer = peer_id();

    guard.on_connection_established(old_peer, &ip4_addr("127.0.0.1", 30138)?, now);
    guard.on_connection_established(
        fresh_peer,
        &ip4_addr("127.0.0.2", 30138)?,
        now + Duration::from_secs(4),
    );

    let dropped = guard.sweep_timeouts(now + Duration::from_secs(6));

    assert_eq!(dropped, vec![old_peer]);
    assert_eq!(guard.pending_len(), 1);
    assert!(!guard.is_admitted(&old_peer));
    assert!(!guard.is_admitted(&fresh_peer));

    Ok(())
}

#[test]
fn e2e_39_admitted_peer_is_not_returned_by_timeout_sweep() -> TestResult {
    let mut guard = ConnGuard::new(compact_cfg());
    let now = Instant::now();
    let peer = peer_id();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30139)?, now);
    guard.try_admit(peer);

    let dropped = guard.sweep_timeouts(now + Duration::from_secs(999));

    assert!(dropped.is_empty());
    assert!(guard.is_admitted(&peer));
    assert_eq!(guard.pending_len(), 0);

    Ok(())
}

#[test]
fn e2e_40_disconnect_after_timeout_cleans_remaining_peer_state() -> TestResult {
    let mut guard = ConnGuard::new(compact_cfg());
    let now = Instant::now();
    let peer = peer_id();

    guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30140)?, now);

    let dropped = guard.sweep_timeouts(now + Duration::from_secs(6));
    assert_eq!(dropped, vec![peer]);

    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));

    Ok(())
}

#[test]
fn e2e_41_missing_ip_attempt_does_not_poison_later_valid_attempt() -> TestResult {
    let mut guard = ConnGuard::new(rate_cfg(1));
    let now = Instant::now();
    let peer = peer_id();

    assert_eq!(
        guard.on_connection_established(peer, &memory_addr(41), now),
        GuardDecision::Drop(DropReason::MissingIp)
    );

    assert_eq!(
        guard.on_connection_established(peer, &ip4_addr("127.0.0.1", 30141)?, now),
        GuardDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_42_reconnect_same_peer_after_disconnect_is_allowed() -> TestResult {
    let mut guard = ConnGuard::new(rate_cfg(10));
    let now = Instant::now();
    let peer = peer_id();
    let addr = ip4_addr("127.0.0.1", 30142)?;

    assert_eq!(
        guard.on_connection_established(peer, &addr, now),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);

    assert_eq!(
        guard.on_connection_established(peer, &addr, now + Duration::from_secs(1)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);

    Ok(())
}

#[test]
fn e2e_43_peer_ip_can_change_before_admission_and_latest_ip_is_used_for_caps() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 1;
    cfg.max_per_v4_24 = 100;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let moving_peer = peer_id();
    let other_peer = peer_id();

    guard.on_connection_established(moving_peer, &ip4_addr("10.1.1.1", 30143)?, now);
    guard.on_connection_established(
        moving_peer,
        &ip4_addr("10.1.1.2", 30143)?,
        now + Duration::from_millis(1),
    );
    guard.on_connection_established(
        other_peer,
        &ip4_addr("10.1.1.1", 30143)?,
        now + Duration::from_millis(2),
    );

    assert_eq!(guard.try_admit(moving_peer), GuardDecision::Allow);
    assert_eq!(guard.try_admit(other_peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 2);

    Ok(())
}

#[test]
fn e2e_44_per_subnet_counter_is_released_after_admitted_peer_disconnects() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 100;
    cfg.max_per_v4_24 = 1;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let first = peer_id();
    let second = peer_id();

    guard.on_connection_established(first, &ip4_addr("10.2.3.1", 30144)?, now);
    guard.on_connection_established(second, &ip4_addr("10.2.3.2", 30144)?, now);

    assert_eq!(guard.try_admit(first), GuardDecision::Allow);
    assert_eq!(
        guard.try_admit(second),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );

    guard.on_connection_closed(first);

    assert_eq!(guard.try_admit(second), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 1);

    Ok(())
}

#[test]
fn e2e_45_pending_pool_is_released_after_pending_disconnect() -> TestResult {
    let mut guard = ConnGuard::new(pool_cfg(1));
    let now = Instant::now();

    let first = peer_id();
    let second = peer_id();

    guard.on_connection_established(first, &ip4_addr("10.4.5.1", 30145)?, now);

    assert_eq!(
        guard.on_connection_established(second, &ip4_addr("10.4.5.2", 30145)?, now),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );

    guard.on_connection_closed(first);

    assert_eq!(
        guard.on_connection_established(second, &ip4_addr("10.4.5.2", 30145)?, now),
        GuardDecision::Allow
    );

    Ok(())
}

#[test]
fn e2e_46_many_allowed_pending_connections_respect_configured_pool_size() -> TestResult {
    let mut guard = ConnGuard::new(pool_cfg(8));
    let now = Instant::now();

    for idx in 0u8..8u8 {
        let ip = format!("10.7.0.{}", idx + 1);
        assert_eq!(
            guard.on_connection_established(peer_id(), &ip4_addr(&ip, 30146)?, now),
            GuardDecision::Allow
        );
    }

    assert_eq!(guard.pending_len(), 8);

    let extra = guard.on_connection_established(peer_id(), &ip4_addr("10.7.0.99", 30146)?, now);

    assert_eq!(extra, GuardDecision::Drop(DropReason::HandshakePoolFull));
    assert_eq!(guard.pending_len(), 8);

    Ok(())
}

#[test]
fn e2e_47_debug_format_for_decision_and_reason_is_stable_enough_for_logs() -> TestResult {
    let decision = GuardDecision::Drop(DropReason::RateLimited);
    let text = format!("{decision:?}");

    assert!(text.contains("Drop"));
    assert!(text.contains("RateLimited"));

    Ok(())
}

#[test]
fn e2e_48_all_drop_reasons_are_distinct() -> TestResult {
    let reasons = [
        DropReason::MissingIp,
        DropReason::RateLimited,
        DropReason::HandshakePoolFull,
        DropReason::PerIpCap,
        DropReason::PerSubnetCap,
        DropReason::HandshakeDeadlineOverflow,
        DropReason::CounterOverflow,
    ];

    for (i, left) in reasons.iter().enumerate() {
        for (j, right) in reasons.iter().enumerate() {
            if i == j {
                assert_eq!(left, right);
            } else {
                assert_ne!(left, right);
            }
        }
    }

    Ok(())
}

#[test]
fn e2e_49_ipv4_and_ipv6_counters_do_not_interfere() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 1;
    cfg.max_per_v4_24 = 1;
    cfg.max_per_v6_64 = 1;

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let v4_peer = peer_id();
    let v6_peer = peer_id();

    guard.on_connection_established(v4_peer, &ip4_addr("192.168.55.1", 30149)?, now);
    guard.on_connection_established(v6_peer, &ip6_addr("2001:db8:feed:1::1", 30149)?, now);

    assert_eq!(guard.try_admit(v4_peer), GuardDecision::Allow);
    assert_eq!(guard.try_admit(v6_peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 2);

    Ok(())
}

#[test]
fn e2e_50_full_conn_guard_lifecycle_rate_pending_admit_caps_timeout_and_disconnect() -> TestResult {
    let mut cfg = compact_cfg();
    cfg.max_per_ip = 1;
    cfg.max_per_v4_24 = 2;
    cfg.max_handshaking = 2;
    cfg.max_new_conns_per_ip_per_window = 2;
    cfg.handshake_deadline = Duration::from_secs(5);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    let first = peer_id();
    let second = peer_id();
    let third = peer_id();

    let first_addr = ip4_addr("10.50.0.1", 30150)?;
    let second_addr = ip4_addr("10.50.0.1", 30151)?;
    let third_addr = ip4_addr("10.50.0.2", 30152)?;

    assert_eq!(
        guard.on_connection_established(first, &first_addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.on_connection_established(second, &second_addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 2);

    assert_eq!(
        guard.on_connection_established(third, &third_addr, now + Duration::from_millis(2)),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );

    assert_eq!(guard.try_admit(first), GuardDecision::Allow);
    assert!(guard.is_admitted(&first));
    assert_eq!(guard.pending_len(), 1);

    assert_eq!(
        guard.try_admit(second),
        GuardDecision::Drop(DropReason::PerIpCap)
    );
    assert!(!guard.is_admitted(&second));

    let timed_out = guard.sweep_timeouts(now + Duration::from_secs(6));
    assert_eq!(timed_out, vec![second]);
    assert_eq!(guard.pending_len(), 0);

    guard.on_connection_closed(first);
    assert!(!guard.is_admitted(&first));
    assert_eq!(guard.admitted_len(), 0);

    assert_eq!(
        guard.on_connection_established(third, &third_addr, now + Duration::from_secs(20)),
        GuardDecision::Allow
    );
    assert_eq!(guard.try_admit(third), GuardDecision::Allow);
    assert!(guard.is_admitted(&third));
    assert_eq!(guard.admitted_len(), 1);

    Ok(())
}
