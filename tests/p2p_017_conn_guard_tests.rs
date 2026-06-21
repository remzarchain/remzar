use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use remzar::network::p2p_017_conn_guard::{ConnGuard, ConnGuardConfig, DropReason, GuardDecision};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

fn peer_id() -> PeerId {
    PeerId::random()
}

fn permissive_config() -> ConnGuardConfig {
    ConnGuardConfig {
        max_per_ip: 10_000,
        max_per_v4_24: 10_000,
        max_per_v6_64: 10_000,
        max_handshaking: 10_000,
        handshake_deadline: Duration::from_millis(50),
        rate_window: Duration::from_millis(100),
        max_new_conns_per_ip_per_window: 10_000,
    }
}

fn custom_config(
    max_per_ip: usize,
    max_per_v4_24: usize,
    max_per_v6_64: usize,
    max_handshaking: usize,
    rate_limit: usize,
) -> ConnGuardConfig {
    ConnGuardConfig {
        max_per_ip,
        max_per_v4_24,
        max_per_v6_64,
        max_handshaking,
        handshake_deadline: Duration::from_millis(50),
        rate_window: Duration::from_millis(100),
        max_new_conns_per_ip_per_window: rate_limit,
    }
}

fn addr_v4(a: u8, b: u8, c: u8, d: u8) -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::new(a, b, c, d)))
        .with(Protocol::Tcp(36_213))
}

fn addr_v6(segments: [u16; 8]) -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip6(Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )))
        .with(Protocol::Tcp(36_213))
}

fn connect(guard: &mut ConnGuard, peer: PeerId, addr: &Multiaddr, now: Instant) -> GuardDecision {
    guard.on_connection_established(peer, addr, now)
}

fn connect_and_admit(
    guard: &mut ConnGuard,
    peer: PeerId,
    addr: &Multiaddr,
    now: Instant,
) -> GuardDecision {
    let decision = guard.on_connection_established(peer, addr, now);
    if decision != GuardDecision::Allow {
        return decision;
    }
    guard.try_admit(peer)
}

#[test]
fn test_01_default_config_matches_expected_policy_knobs() {
    let cfg = ConnGuardConfig::default();

    assert_eq!(cfg.max_per_ip, 8);
    assert_eq!(cfg.max_per_v4_24, 32);
    assert_eq!(cfg.max_per_v6_64, 16);
    assert_eq!(cfg.max_handshaking, 32);
    assert_eq!(cfg.handshake_deadline, Duration::from_secs(5));
    assert_eq!(cfg.rate_window, Duration::from_secs(10));
    assert_eq!(cfg.max_new_conns_per_ip_per_window, 10);
}

#[test]
fn test_02_ip_from_multiaddr_extracts_ipv4() {
    let addr = addr_v4(127, 0, 0, 1);

    let ip = ConnGuard::ip_from_multiaddr(&addr);

    assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
}

#[test]
fn test_03_ip_from_multiaddr_extracts_ipv6() {
    let addr = addr_v6([0x2607, 0xf8b0, 0x4005, 0x0805, 0, 0, 0, 0x200e]);

    let ip = ConnGuard::ip_from_multiaddr(&addr);

    assert_eq!(
        ip,
        Some(IpAddr::V6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4005, 0x0805, 0, 0, 0, 0x200e
        )))
    );
}

#[test]
fn test_04_ip_from_multiaddr_returns_none_without_ip() {
    let addr = Multiaddr::empty().with(Protocol::Tcp(36_213));

    let ip = ConnGuard::ip_from_multiaddr(&addr);

    assert_eq!(ip, None);
}

#[test]
fn test_05_connection_missing_ip_drops_and_does_not_create_pending_state() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = Multiaddr::empty().with(Protocol::Tcp(36_213));

    let decision = connect(&mut guard, peer, &addr, Instant::now());

    assert_eq!(decision, GuardDecision::Drop(DropReason::MissingIp));
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_06_new_ipv4_connection_becomes_pending_not_admitted() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 0, 0, 1);

    let decision = connect(&mut guard, peer, &addr, Instant::now());

    assert_eq!(decision, GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_07_new_ipv6_connection_becomes_pending_not_admitted() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v6([0x2001, 0x0db8, 0xabcd, 0x0001, 0, 0, 0, 1]);

    let decision = connect(&mut guard, peer, &addr, Instant::now());

    assert_eq!(decision, GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_08_try_admit_unknown_peer_drops_missing_ip() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();

    let decision = guard.try_admit(peer);

    assert_eq!(decision, GuardDecision::Drop(DropReason::MissingIp));
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_09_admit_after_pending_handshake_succeeds() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 1, 1, 1);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));
}

#[test]
fn test_10_duplicate_admit_is_idempotent() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 1, 1, 2);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));
}

#[test]
fn test_11_closing_pending_peer_removes_pending_state() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 1, 1, 3);

    assert_eq!(
        connect(&mut guard, peer, &addr, Instant::now()),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_12_closing_admitted_peer_removes_admission_state() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 1, 1, 4);

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr, Instant::now()),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_13_closing_unknown_peer_is_noop() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();

    guard.on_connection_closed(peer);
    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_14_multiple_connections_same_peer_require_all_connections_closed() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 1, 1, 5);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);

    guard.on_connection_closed(peer);

    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));

    guard.on_connection_closed(peer);

    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_15_rate_limit_allows_exact_threshold() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 2));
    let addr = addr_v4(172, 16, 0, 1);
    let now = Instant::now();

    let first = connect(&mut guard, peer_id(), &addr, now);
    let second = connect(&mut guard, peer_id(), &addr, now + Duration::from_millis(1));

    assert_eq!(first, GuardDecision::Allow);
    assert_eq!(second, GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 2);
}

#[test]
fn test_16_rate_limit_drops_above_threshold() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 2));
    let addr = addr_v4(172, 16, 0, 2);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    let third = connect(&mut guard, peer_id(), &addr, now + Duration::from_millis(2));

    assert_eq!(third, GuardDecision::Drop(DropReason::RateLimited));
    assert_eq!(guard.pending_len(), 2);
}

#[test]
fn test_17_rate_limit_window_exact_boundary_still_counts() {
    let mut cfg = custom_config(100, 100, 100, 100, 1);
    cfg.rate_window = Duration::from_millis(100);

    let mut guard = ConnGuard::new(cfg);
    let addr = addr_v4(172, 16, 0, 3);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let at_exact_boundary = connect(
        &mut guard,
        peer_id(),
        &addr,
        now + Duration::from_millis(100),
    );

    assert_eq!(
        at_exact_boundary,
        GuardDecision::Drop(DropReason::RateLimited)
    );
}

#[test]
fn test_18_rate_limit_after_window_boundary_allows_again() {
    let mut cfg = custom_config(100, 100, 100, 100, 1);
    cfg.rate_window = Duration::from_millis(100);

    let mut guard = ConnGuard::new(cfg);
    let addr = addr_v4(172, 16, 0, 4);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let after_boundary = connect(
        &mut guard,
        peer_id(),
        &addr,
        now + Duration::from_millis(101),
    );

    assert_eq!(after_boundary, GuardDecision::Allow);
}

#[test]
fn test_19_handshaking_pool_cap_drops_new_peer() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 1, 100));
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr_v4(10, 2, 0, 1), now),
        GuardDecision::Allow
    );

    let second = connect(
        &mut guard,
        peer_id(),
        &addr_v4(10, 2, 0, 2),
        now + Duration::from_millis(1),
    );

    assert_eq!(second, GuardDecision::Drop(DropReason::HandshakePoolFull));
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_20_handshaking_pool_cap_allows_existing_pending_peer_extra_connection() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 1, 100));
    let peer = peer_id();
    let addr = addr_v4(10, 2, 0, 3);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);

    let second_same_peer = connect(&mut guard, peer, &addr, now + Duration::from_millis(1));

    assert_eq!(second_same_peer, GuardDecision::Allow);
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_21_per_ip_cap_is_enforced_on_admit() {
    let mut guard = ConnGuard::new(custom_config(1, 100, 100, 100, 100));
    let addr = addr_v4(192, 168, 1, 10);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let second_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            second_peer,
            &addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        guard.try_admit(second_peer),
        GuardDecision::Drop(DropReason::PerIpCap)
    );
    assert_eq!(guard.admitted_len(), 1);
    assert!(!guard.is_admitted(&second_peer));
}

#[test]
fn test_22_per_ip_cap_is_released_after_admitted_peer_closes() {
    let mut guard = ConnGuard::new(custom_config(1, 100, 100, 100, 100));
    let addr = addr_v4(192, 168, 1, 11);
    let first_peer = peer_id();
    let second_peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, first_peer, &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            second_peer,
            &addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(second_peer),
        GuardDecision::Drop(DropReason::PerIpCap)
    );

    guard.on_connection_closed(first_peer);

    assert_eq!(guard.try_admit(second_peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&second_peer));
}

#[test]
fn test_23_ipv4_subnet_cap_is_enforced_on_admit() {
    let mut guard = ConnGuard::new(custom_config(10, 2, 100, 100, 100));
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer_id(), &addr_v4(203, 0, 113, 1), now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v4(203, 0, 113, 2),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    let third_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            third_peer,
            &addr_v4(203, 0, 113, 3),
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        guard.try_admit(third_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    assert_eq!(guard.admitted_len(), 2);
}

#[test]
fn test_24_ipv4_different_subnets_can_admit_when_each_subnet_is_under_cap() {
    let mut guard = ConnGuard::new(custom_config(10, 1, 100, 100, 100));
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer_id(), &addr_v4(203, 0, 113, 10), now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v4(203, 0, 114, 10),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(guard.admitted_len(), 2);
}

#[test]
fn test_25_ipv6_subnet_cap_is_enforced_on_admit() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 2, 100, 100));
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v6([0x2001, 0x0db8, 0x1111, 0x2222, 0, 0, 0, 1]),
            now
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v6([0x2001, 0x0db8, 0x1111, 0x2222, 0, 0, 0, 2]),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    let third_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            third_peer,
            &addr_v6([0x2001, 0x0db8, 0x1111, 0x2222, 0, 0, 0, 3]),
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        guard.try_admit(third_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    assert_eq!(guard.admitted_len(), 2);
}

#[test]
fn test_26_ipv6_different_64s_can_admit_when_each_subnet_is_under_cap() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 1, 100, 100));
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v6([0x2001, 0x0db8, 0xaaaa, 0x0001, 0, 0, 0, 1]),
            now
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v6([0x2001, 0x0db8, 0xaaaa, 0x0002, 0, 0, 0, 1]),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(guard.admitted_len(), 2);
}

#[test]
fn test_27_sweep_at_exact_deadline_keeps_pending_peer() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(20);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 3, 0, 1), now),
        GuardDecision::Allow
    );

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(20));

    assert!(timed_out.is_empty());
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_28_sweep_after_deadline_returns_peer_and_removes_pending_peer() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(20);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 3, 0, 2), now),
        GuardDecision::Allow
    );

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(21));

    assert_eq!(timed_out.len(), 1);
    assert!(timed_out.contains(&peer));
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_29_admitted_peer_is_not_swept_after_deadline() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(20);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr_v4(10, 3, 0, 3), now),
        GuardDecision::Allow
    );

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(21));

    assert!(timed_out.is_empty());
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));
}

#[test]
fn test_30_close_pending_before_deadline_prevents_timeout_drop() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(20);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 3, 0, 4), now),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(21));

    assert!(timed_out.is_empty());
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_31_handshake_deadline_overflow_drops_connection() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::MAX;

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();

    let decision = connect(&mut guard, peer, &addr_v4(10, 4, 0, 1), Instant::now());

    assert_eq!(
        decision,
        GuardDecision::Drop(DropReason::HandshakeDeadlineOverflow)
    );
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_32_drop_decisions_do_not_mark_peer_admitted() {
    let mut guard = ConnGuard::new(custom_config(1, 100, 100, 100, 100));
    let addr = addr_v4(198, 51, 100, 1);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let blocked_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            blocked_peer,
            &addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    let decision = guard.try_admit(blocked_peer);

    assert_eq!(decision, GuardDecision::Drop(DropReason::PerIpCap));
    assert!(!guard.is_admitted(&blocked_peer));
    assert_eq!(guard.admitted_len(), 1);
}

#[test]
fn test_33_vector_transport_only_multiaddrs_without_ip_are_rejected() {
    let mut guard = ConnGuard::new(permissive_config());
    let now = Instant::now();

    let addrs = vec![
        Multiaddr::empty(),
        Multiaddr::empty().with(Protocol::Tcp(36_213)),
        Multiaddr::empty().with(Protocol::Udp(36_213)),
        Multiaddr::empty().with(Protocol::Memory(7)),
    ];

    for addr in &addrs {
        assert_eq!(ConnGuard::ip_from_multiaddr(addr), None);
        assert_eq!(
            connect(&mut guard, peer_id(), addr, now),
            GuardDecision::Drop(DropReason::MissingIp)
        );
    }

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_34_fuzz_style_ipv4_extraction_vectors_are_stable() {
    let cases = [
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(10, 255, 254, 253),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(172, 16, 255, 1),
        Ipv4Addr::new(192, 168, 255, 254),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ];

    for ip in cases {
        let addr = Multiaddr::empty()
            .with(Protocol::Ip4(ip))
            .with(Protocol::Tcp(36_213));

        assert_eq!(ConnGuard::ip_from_multiaddr(&addr), Some(IpAddr::V4(ip)));
    }
}

#[test]
fn test_35_fuzz_style_ipv6_extraction_vectors_are_stable() {
    let cases = [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 1),
        Ipv6Addr::new(0x2607, 0xf8b0, 0x4005, 0x0805, 0, 0, 0, 0x200e),
    ];

    for ip in cases {
        let addr = Multiaddr::empty()
            .with(Protocol::Ip6(ip))
            .with(Protocol::Tcp(36_213));

        assert_eq!(ConnGuard::ip_from_multiaddr(&addr), Some(IpAddr::V6(ip)));
    }
}

#[test]
fn test_36_property_pending_len_never_exceeds_handshake_pool_cap() {
    let max_handshaking = 3;
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, max_handshaking, 100));
    let now = Instant::now();

    for host in 1u8..=30u8 {
        let decision = connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 10, 1, host),
            now + Duration::from_millis(u64::from(host)),
        );

        if host <= 3 {
            assert_eq!(decision, GuardDecision::Allow);
        } else {
            assert_eq!(decision, GuardDecision::Drop(DropReason::HandshakePoolFull));
        }

        assert!(guard.pending_len() <= max_handshaking);
        assert_eq!(guard.admitted_len(), 0);
    }
}

#[test]
fn test_37_property_admitted_len_never_exceeds_per_ip_cap() {
    let max_per_ip = 3;
    let mut guard = ConnGuard::new(custom_config(max_per_ip, 100, 100, 100, 100));
    let addr = addr_v4(10, 10, 2, 1);
    let now = Instant::now();

    for offset in 0u64..10u64 {
        let peer = peer_id();
        assert_eq!(
            connect(&mut guard, peer, &addr, now + Duration::from_millis(offset)),
            GuardDecision::Allow
        );

        let decision = guard.try_admit(peer);

        if offset < 3 {
            assert_eq!(decision, GuardDecision::Allow);
        } else {
            assert_eq!(decision, GuardDecision::Drop(DropReason::PerIpCap));
        }

        assert!(guard.admitted_len() <= max_per_ip);
    }
}

#[test]
fn test_38_adversarial_single_ip_flood_is_rate_limited_but_honest_ip_is_allowed() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 3));
    let attacker_addr = addr_v4(45, 45, 45, 45);
    let honest_addr = addr_v4(46, 46, 46, 46);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &attacker_addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &attacker_addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &attacker_addr,
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &attacker_addr,
            now + Duration::from_millis(3)
        ),
        GuardDecision::Drop(DropReason::RateLimited)
    );

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &honest_addr,
            now + Duration::from_millis(4)
        ),
        GuardDecision::Allow
    );
}

#[test]
fn test_39_adversarial_ipv4_sybil_subnet_pressure_blocks_extra_but_other_subnet_works() {
    let mut guard = ConnGuard::new(custom_config(100, 4, 100, 100, 100));
    let now = Instant::now();

    for host in 1u8..=4u8 {
        assert_eq!(
            connect_and_admit(
                &mut guard,
                peer_id(),
                &addr_v4(100, 64, 7, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
    }

    let blocked_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            blocked_peer,
            &addr_v4(100, 64, 7, 99),
            now + Duration::from_millis(99)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(blocked_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );

    assert_eq!(
        connect_and_admit(
            &mut guard,
            peer_id(),
            &addr_v4(100, 64, 8, 1),
            now + Duration::from_millis(100)
        ),
        GuardDecision::Allow
    );

    assert_eq!(guard.admitted_len(), 5);
}

#[test]
fn test_40_load_many_unique_peers_can_admit_and_close_cleanly() {
    let mut guard = ConnGuard::new(custom_config(1_000, 1_000, 1_000, 1_000, 1_000));
    let now = Instant::now();
    let mut peers = Vec::new();

    for host in 1u8..=96u8 {
        let peer = peer_id();
        let addr = addr_v4(10, 200, host, 1);

        assert_eq!(
            connect_and_admit(
                &mut guard,
                peer,
                &addr,
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );

        peers.push(peer);
    }

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), peers.len());

    for peer in peers {
        assert!(guard.is_admitted(&peer));
        guard.on_connection_closed(peer);
    }

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_41_new_guard_starts_empty_and_exposes_config_reference() {
    let cfg = ConnGuardConfig {
        max_per_ip: 3,
        max_per_v4_24: 4,
        max_per_v6_64: 5,
        max_handshaking: 6,
        handshake_deadline: Duration::from_millis(7),
        rate_window: Duration::from_millis(8),
        max_new_conns_per_ip_per_window: 9,
    };
    let guard = ConnGuard::new(cfg);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert_eq!(guard._cfg().max_per_ip, 3);
    assert_eq!(guard._cfg().max_per_v4_24, 4);
    assert_eq!(guard._cfg().max_per_v6_64, 5);
    assert_eq!(guard._cfg().max_handshaking, 6);
    assert_eq!(guard._cfg().handshake_deadline, Duration::from_millis(7));
    assert_eq!(guard._cfg().rate_window, Duration::from_millis(8));
    assert_eq!(guard._cfg().max_new_conns_per_ip_per_window, 9);
}

#[test]
fn test_42_custom_config_clone_preserves_all_policy_fields() {
    let cfg = ConnGuardConfig {
        max_per_ip: 11,
        max_per_v4_24: 12,
        max_per_v6_64: 13,
        max_handshaking: 14,
        handshake_deadline: Duration::from_millis(15),
        rate_window: Duration::from_millis(16),
        max_new_conns_per_ip_per_window: 17,
    };

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
}

#[test]
fn test_43_independent_guards_do_not_share_peer_state() {
    let mut first = ConnGuard::new(permissive_config());
    let mut second = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 41, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut first, peer, &addr, now),
        GuardDecision::Allow
    );

    assert!(first.is_admitted(&peer));
    assert!(!second.is_admitted(&peer));
    assert_eq!(first.admitted_len(), 1);
    assert_eq!(second.admitted_len(), 0);
    assert_eq!(
        second.try_admit(peer),
        GuardDecision::Drop(DropReason::MissingIp)
    );
}

#[test]
fn test_44_default_handshake_pool_allows_exact_default_capacity() {
    let mut guard = ConnGuard::new(ConnGuardConfig::default());
    let now = Instant::now();

    for host in 1u8..=32u8 {
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr_v4(10, 44, 0, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
    }

    assert_eq!(guard.pending_len(), 32);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_45_default_handshake_pool_drops_thirty_third_pending_peer() {
    let mut guard = ConnGuard::new(ConnGuardConfig::default());
    let now = Instant::now();

    for host in 1u8..=32u8 {
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr_v4(10, 45, 0, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
    }

    let decision = connect(
        &mut guard,
        peer_id(),
        &addr_v4(10, 45, 0, 33),
        now + Duration::from_millis(33),
    );

    assert_eq!(decision, GuardDecision::Drop(DropReason::HandshakePoolFull));
    assert_eq!(guard.pending_len(), 32);
}

#[test]
fn test_46_default_rate_limit_allows_ten_and_drops_eleventh_attempt() {
    let mut guard = ConnGuard::new(ConnGuardConfig::default());
    let addr = addr_v4(10, 46, 0, 1);
    let now = Instant::now();

    for offset in 0u64..10u64 {
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr,
                now + Duration::from_millis(offset)
            ),
            GuardDecision::Allow
        );
    }

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr,
            now + Duration::from_millis(10)
        ),
        GuardDecision::Drop(DropReason::RateLimited)
    );
    assert_eq!(guard.pending_len(), 10);
}

#[test]
fn test_47_rate_limit_is_tracked_independently_per_ip() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 1));
    let first_addr = addr_v4(10, 47, 0, 1);
    let second_addr = addr_v4(10, 47, 0, 2);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &first_addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &first_addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Drop(DropReason::RateLimited)
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &second_addr,
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 2);
}

#[test]
fn test_48_handshake_pool_full_attempt_still_consumes_rate_budget_for_that_ip() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 0, 1));
    let addr = addr_v4(10, 48, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );
    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now + Duration::from_millis(1)),
        GuardDecision::Drop(DropReason::RateLimited)
    );
    assert_eq!(guard.pending_len(), 0);
}

#[test]
fn test_49_missing_ip_does_not_consume_rate_budget() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 1));
    let missing_ip_addr = Multiaddr::empty().with(Protocol::Tcp(36_213));
    let valid_addr = addr_v4(10, 49, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &missing_ip_addr, now),
        GuardDecision::Drop(DropReason::MissingIp)
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &valid_addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_50_rate_window_prunes_old_attempts_and_allows_new_attempts() {
    let mut cfg = custom_config(100, 100, 100, 100, 2);
    cfg.rate_window = Duration::from_millis(100);

    let mut guard = ConnGuard::new(cfg);
    let addr = addr_v4(10, 50, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr,
            now + Duration::from_millis(102)
        ),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 3);
}

#[test]
fn test_51_peer_dropped_by_handshake_pool_full_cannot_be_admitted() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 0, 100));
    let peer = peer_id();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 51, 0, 1), Instant::now()),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );
    assert_eq!(
        guard.try_admit(peer),
        GuardDecision::Drop(DropReason::MissingIp)
    );
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_52_peer_dropped_by_rate_limit_cannot_be_admitted() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 1));
    let addr = addr_v4(10, 52, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let blocked_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            blocked_peer,
            &addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Drop(DropReason::RateLimited)
    );
    assert_eq!(
        guard.try_admit(blocked_peer),
        GuardDecision::Drop(DropReason::MissingIp)
    );
    assert!(!guard.is_admitted(&blocked_peer));
}

#[test]
fn test_53_deadline_overflow_drop_leaves_no_pending_or_admitted_metric() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::MAX;

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 53, 0, 1), Instant::now()),
        GuardDecision::Drop(DropReason::HandshakeDeadlineOverflow)
    );

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_54_closing_after_deadline_overflow_cleans_peer_state() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::MAX;

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 54, 0, 1), Instant::now()),
        GuardDecision::Drop(DropReason::HandshakeDeadlineOverflow)
    );

    guard.on_connection_closed(peer);

    assert_eq!(
        guard.try_admit(peer),
        GuardDecision::Drop(DropReason::MissingIp)
    );
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_55_sweep_many_expired_pending_peers_returns_all_of_them() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();
    let peers = [peer_id(), peer_id(), peer_id(), peer_id(), peer_id()];

    for peer in peers {
        assert_eq!(
            connect(&mut guard, peer, &addr_v4(10, 55, 0, 1), now),
            GuardDecision::Allow
        );
    }

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(11));

    assert_eq!(timed_out.len(), 5);
    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_56_sweep_mixed_deadlines_only_removes_expired_peers() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();
    let early_peer = peer_id();
    let later_peer = peer_id();

    assert_eq!(
        connect(&mut guard, early_peer, &addr_v4(10, 56, 0, 1), now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            later_peer,
            &addr_v4(10, 56, 0, 2),
            now + Duration::from_millis(10)
        ),
        GuardDecision::Allow
    );

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(11));

    assert_eq!(timed_out.len(), 1);
    assert!(timed_out.contains(&early_peer));
    assert!(!timed_out.contains(&later_peer));
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_57_sweep_timeout_frees_handshake_pool_capacity() {
    let mut cfg = custom_config(100, 100, 100, 1, 100);
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer_id(), &addr_v4(10, 57, 0, 1), now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 57, 0, 2),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(11));

    assert_eq!(timed_out.len(), 1);
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 57, 0, 3),
            now + Duration::from_millis(12)
        ),
        GuardDecision::Allow
    );
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_58_close_pending_peer_frees_handshake_pool_capacity() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 1, 100));
    let now = Instant::now();
    let first_peer = peer_id();

    assert_eq!(
        connect(&mut guard, first_peer, &addr_v4(10, 58, 0, 1), now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 58, 0, 2),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );

    guard.on_connection_closed(first_peer);

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 58, 0, 3),
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_59_closing_admitted_ipv4_peer_releases_subnet_capacity() {
    let mut guard = ConnGuard::new(custom_config(100, 1, 100, 100, 100));
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();

    assert_eq!(
        connect_and_admit(&mut guard, first_peer, &addr_v4(10, 59, 0, 1), now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            second_peer,
            &addr_v4(10, 59, 0, 2),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(second_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );

    guard.on_connection_closed(first_peer);

    assert_eq!(guard.try_admit(second_peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 1);
}

#[test]
fn test_60_closing_admitted_ipv6_peer_releases_subnet_capacity() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 1, 100, 100));
    let now = Instant::now();
    let first_peer = peer_id();
    let second_peer = peer_id();

    assert_eq!(
        connect_and_admit(
            &mut guard,
            first_peer,
            &addr_v6([0x2001, 0x0db8, 0x0060, 0x0001, 0, 0, 0, 1]),
            now
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(
            &mut guard,
            second_peer,
            &addr_v6([0x2001, 0x0db8, 0x0060, 0x0001, 0, 0, 0, 2]),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(second_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );

    guard.on_connection_closed(first_peer);

    assert_eq!(guard.try_admit(second_peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 1);
}

#[test]
fn test_61_per_ip_cap_takes_precedence_when_same_ip_also_exhausts_subnet() {
    let mut guard = ConnGuard::new(custom_config(1, 1, 100, 100, 100));
    let addr = addr_v4(10, 61, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer_id(), &addr, now),
        GuardDecision::Allow
    );

    let second_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            second_peer,
            &addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        guard.try_admit(second_peer),
        GuardDecision::Drop(DropReason::PerIpCap)
    );
}

#[test]
fn test_62_subnet_cap_is_returned_when_per_ip_has_capacity() {
    let mut guard = ConnGuard::new(custom_config(2, 1, 100, 100, 100));
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer_id(), &addr_v4(10, 62, 0, 1), now),
        GuardDecision::Allow
    );

    let second_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            second_peer,
            &addr_v4(10, 62, 0, 2),
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        guard.try_admit(second_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
}

#[test]
fn test_63_zero_max_per_ip_denies_first_admission() {
    let mut guard = ConnGuard::new(custom_config(0, 100, 100, 100, 100));
    let peer = peer_id();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 63, 0, 1), Instant::now()),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(peer),
        GuardDecision::Drop(DropReason::PerIpCap)
    );
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_64_zero_ipv4_subnet_cap_denies_first_ipv4_admission() {
    let mut guard = ConnGuard::new(custom_config(100, 0, 100, 100, 100));
    let peer = peer_id();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 64, 0, 1), Instant::now()),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_65_zero_ipv6_subnet_cap_denies_first_ipv6_admission() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 0, 100, 100));
    let peer = peer_id();

    assert_eq!(
        connect(
            &mut guard,
            peer,
            &addr_v6([0x2001, 0x0db8, 0x0065, 0x0001, 0, 0, 0, 1]),
            Instant::now()
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_66_zero_handshaking_capacity_drops_first_valid_connection() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 0, 100));

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 66, 0, 1),
            Instant::now()
        ),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );
    assert_eq!(guard.pending_len(), 0);
}

#[test]
fn test_67_zero_rate_limit_drops_first_valid_connection() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 0));

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 67, 0, 1),
            Instant::now()
        ),
        GuardDecision::Drop(DropReason::RateLimited)
    );
    assert_eq!(guard.pending_len(), 0);
}

#[test]
fn test_68_zero_rate_limit_still_reports_missing_ip_first() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 0));
    let addr = Multiaddr::empty().with(Protocol::Tcp(36_213));

    assert_eq!(
        connect(&mut guard, peer_id(), &addr, Instant::now()),
        GuardDecision::Drop(DropReason::MissingIp)
    );
    assert_eq!(guard.pending_len(), 0);
}

#[test]
fn test_69_same_peer_multiple_connections_only_counts_one_admitted_peer() {
    let mut guard = ConnGuard::new(custom_config(1, 100, 100, 100, 100));
    let peer = peer_id();
    let addr = addr_v4(10, 69, 0, 1);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 1);

    let blocked_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            blocked_peer,
            &addr,
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(blocked_peer),
        GuardDecision::Drop(DropReason::PerIpCap)
    );

    guard.on_connection_closed(peer);
    assert_eq!(
        guard.try_admit(blocked_peer),
        GuardDecision::Drop(DropReason::PerIpCap)
    );

    guard.on_connection_closed(peer);
    assert_eq!(guard.try_admit(blocked_peer), GuardDecision::Allow);
}

#[test]
fn test_70_admitted_peer_new_connection_reenters_pending_until_readmitted() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 70, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));
}

#[test]
fn test_71_readmitting_already_admitted_peer_clears_duplicate_pending_state() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 71, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );
    assert_eq!(guard.pending_len(), 1);

    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 1);
    assert!(guard.is_admitted(&peer));
}

#[test]
fn test_72_closing_admitted_peer_more_than_once_is_safe() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr_v4(10, 72, 0, 1), Instant::now()),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);
    guard.on_connection_closed(peer);
    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_73_closing_one_of_two_pending_connections_keeps_peer_pending() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 73, 0, 1);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_74_closing_all_duplicate_pending_connections_removes_pending_state() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 74, 0, 1);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Allow
    );

    guard.on_connection_closed(peer);
    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_75_same_peer_can_reconnect_after_full_close() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 75, 0, 1);
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr, now),
        GuardDecision::Allow
    );
    guard.on_connection_closed(peer);

    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(101)),
        GuardDecision::Allow
    );
    assert_eq!(guard.try_admit(peer), GuardDecision::Allow);
    assert_eq!(guard.admitted_len(), 1);
}

#[test]
fn test_76_same_peer_reconnect_after_full_close_starts_pending_again() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let addr = addr_v4(10, 76, 0, 1);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    guard.on_connection_closed(peer);

    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(101)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_77_same_peer_attempt_is_rate_limited_then_allowed_after_window() {
    let mut cfg = custom_config(100, 100, 100, 100, 1);
    cfg.rate_window = Duration::from_millis(100);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let addr = addr_v4(10, 77, 0, 1);
    let now = Instant::now();

    assert_eq!(connect(&mut guard, peer, &addr, now), GuardDecision::Allow);
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(1)),
        GuardDecision::Drop(DropReason::RateLimited)
    );
    assert_eq!(
        connect(&mut guard, peer, &addr, now + Duration::from_millis(101)),
        GuardDecision::Allow
    );

    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_78_multiaddr_with_ipv4_then_ipv6_returns_first_ip_protocol() {
    let v4 = Ipv4Addr::new(10, 78, 0, 1);
    let v6 = Ipv6Addr::LOCALHOST;
    let addr = Multiaddr::empty()
        .with(Protocol::Ip4(v4))
        .with(Protocol::Ip6(v6))
        .with(Protocol::Tcp(36_213));

    assert_eq!(ConnGuard::ip_from_multiaddr(&addr), Some(IpAddr::V4(v4)));
}

#[test]
fn test_79_multiaddr_with_ipv6_then_ipv4_returns_first_ip_protocol() {
    let v6 = Ipv6Addr::LOCALHOST;
    let v4 = Ipv4Addr::new(10, 79, 0, 1);
    let addr = Multiaddr::empty()
        .with(Protocol::Ip6(v6))
        .with(Protocol::Ip4(v4))
        .with(Protocol::Tcp(36_213));

    assert_eq!(ConnGuard::ip_from_multiaddr(&addr), Some(IpAddr::V6(v6)));
}

#[test]
fn test_80_vector_private_ipv4_ranges_are_extractable_and_connectable() {
    let mut guard = ConnGuard::new(permissive_config());
    let now = Instant::now();
    let addrs = [
        addr_v4(10, 0, 0, 1),
        addr_v4(172, 16, 0, 1),
        addr_v4(192, 168, 0, 1),
        addr_v4(127, 0, 0, 1),
    ];

    for addr in &addrs {
        assert!(ConnGuard::ip_from_multiaddr(addr).is_some());
        assert_eq!(
            connect(&mut guard, peer_id(), addr, now),
            GuardDecision::Allow
        );
    }

    assert_eq!(guard.pending_len(), addrs.len());
}

#[test]
fn test_81_vector_ipv4_edge_addresses_are_extractable() {
    let cases = [
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(0, 0, 0, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(198, 51, 100, 255),
        Ipv4Addr::new(203, 0, 113, 255),
        Ipv4Addr::new(255, 255, 255, 255),
    ];

    for ip in cases {
        let addr = Multiaddr::empty()
            .with(Protocol::Ip4(ip))
            .with(Protocol::Tcp(36_213));

        assert_eq!(ConnGuard::ip_from_multiaddr(&addr), Some(IpAddr::V4(ip)));
    }
}

#[test]
fn test_82_vector_ipv6_special_addresses_are_extractable() {
    let cases = [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0082, 0x0001, 0, 0, 0, 1),
    ];

    for ip in cases {
        let addr = Multiaddr::empty()
            .with(Protocol::Ip6(ip))
            .with(Protocol::Tcp(36_213));

        assert_eq!(ConnGuard::ip_from_multiaddr(&addr), Some(IpAddr::V6(ip)));
    }
}

#[test]
fn test_83_vector_tcp_port_edges_do_not_affect_ip_extraction() {
    let ip = Ipv4Addr::new(10, 83, 0, 1);
    let low_port = Multiaddr::empty()
        .with(Protocol::Ip4(ip))
        .with(Protocol::Tcp(0));
    let high_port = Multiaddr::empty()
        .with(Protocol::Ip4(ip))
        .with(Protocol::Tcp(65_535));

    assert_eq!(
        ConnGuard::ip_from_multiaddr(&low_port),
        Some(IpAddr::V4(ip))
    );
    assert_eq!(
        ConnGuard::ip_from_multiaddr(&high_port),
        Some(IpAddr::V4(ip))
    );
}

#[test]
fn test_84_load_pending_one_hundred_twenty_eight_then_close_cleanly() {
    let mut guard = ConnGuard::new(custom_config(1_000, 1_000, 1_000, 128, 1_000));
    let now = Instant::now();
    let mut peers = Vec::new();

    for host in 1u8..=128u8 {
        let peer = peer_id();
        assert_eq!(
            connect(
                &mut guard,
                peer,
                &addr_v4(10, 84, host, 1),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
        peers.push(peer);
    }

    assert_eq!(guard.pending_len(), 128);

    for peer in peers {
        guard.on_connection_closed(peer);
    }

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}

#[test]
fn test_85_load_admit_one_hundred_twenty_eight_unique_ipv4_peers() {
    let mut guard = ConnGuard::new(custom_config(1, 1_000, 1_000, 1_000, 1_000));
    let now = Instant::now();

    for host in 1u8..=128u8 {
        assert_eq!(
            connect_and_admit(
                &mut guard,
                peer_id(),
                &addr_v4(10, 85, host, 1),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
    }

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 128);
}

#[test]
fn test_86_load_rate_buckets_across_many_ips_remain_independent() {
    let mut guard = ConnGuard::new(custom_config(1_000, 1_000, 1_000, 1_000, 2));
    let now = Instant::now();

    for host in 1u8..=40u8 {
        let addr = addr_v4(10, 86, host, 1);

        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr,
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr,
                now + Duration::from_millis(u64::from(host) + 1)
            ),
            GuardDecision::Allow
        );
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr,
                now + Duration::from_millis(u64::from(host) + 2)
            ),
            GuardDecision::Drop(DropReason::RateLimited)
        );
    }

    assert_eq!(guard.pending_len(), 80);
}

#[test]
fn test_87_adversarial_pending_pool_attack_recovers_after_timeouts() {
    let mut cfg = custom_config(100, 100, 100, 3, 100);
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let now = Instant::now();

    for host in 1u8..=3u8 {
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr_v4(10, 87, 0, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
    }

    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 87, 0, 4),
            now + Duration::from_millis(4)
        ),
        GuardDecision::Drop(DropReason::HandshakePoolFull)
    );

    let timed_out = guard.sweep_timeouts(now + Duration::from_millis(20));

    assert_eq!(timed_out.len(), 3);
    assert_eq!(
        connect(
            &mut guard,
            peer_id(),
            &addr_v4(10, 87, 0, 5),
            now + Duration::from_millis(21)
        ),
        GuardDecision::Allow
    );
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_88_adversarial_single_ip_sybil_limits_admitted_count() {
    let mut guard = ConnGuard::new(custom_config(4, 100, 100, 100, 100));
    let addr = addr_v4(10, 88, 0, 1);
    let now = Instant::now();

    for offset in 0u64..4u64 {
        assert_eq!(
            connect_and_admit(
                &mut guard,
                peer_id(),
                &addr,
                now + Duration::from_millis(offset)
            ),
            GuardDecision::Allow
        );
    }

    for offset in 4u64..12u64 {
        let peer = peer_id();
        assert_eq!(
            connect(&mut guard, peer, &addr, now + Duration::from_millis(offset)),
            GuardDecision::Allow
        );
        assert_eq!(
            guard.try_admit(peer),
            GuardDecision::Drop(DropReason::PerIpCap)
        );
    }

    assert_eq!(guard.admitted_len(), 4);
}

#[test]
fn test_89_adversarial_ipv6_64_sybil_limits_admitted_count() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 3, 100, 100));
    let now = Instant::now();

    for low in 1u16..=3u16 {
        assert_eq!(
            connect_and_admit(
                &mut guard,
                peer_id(),
                &addr_v6([0x2001, 0x0db8, 0x0089, 0x0001, 0, 0, 0, low]),
                now + Duration::from_millis(u64::from(low))
            ),
            GuardDecision::Allow
        );
    }

    let blocked_peer = peer_id();
    assert_eq!(
        connect(
            &mut guard,
            blocked_peer,
            &addr_v6([0x2001, 0x0db8, 0x0089, 0x0001, 0, 0, 0, 4]),
            now + Duration::from_millis(4)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(blocked_peer),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    assert_eq!(guard.admitted_len(), 3);
}

#[test]
fn test_90_property_per_ip_admitted_count_stays_bounded_during_churn() {
    let cap = 3;
    let mut guard = ConnGuard::new(custom_config(cap, 100, 100, 100, 100));
    let addr = addr_v4(10, 90, 0, 1);
    let now = Instant::now();
    let mut current = std::collections::VecDeque::<PeerId>::new();

    for offset in 0u64..3u64 {
        let peer = peer_id();
        assert_eq!(
            connect_and_admit(&mut guard, peer, &addr, now + Duration::from_millis(offset)),
            GuardDecision::Allow
        );
        current.push_back(peer);
    }

    for offset in 3u64..20u64 {
        if let Some(old_peer) = current.pop_front() {
            guard.on_connection_closed(old_peer);
        }

        let new_peer = peer_id();
        assert_eq!(
            connect_and_admit(
                &mut guard,
                new_peer,
                &addr,
                now + Duration::from_millis(offset)
            ),
            GuardDecision::Allow
        );
        current.push_back(new_peer);

        assert!(guard.admitted_len() <= cap);
    }
}

#[test]
fn test_91_property_ipv4_subnet_admitted_count_stays_bounded_during_churn() {
    let cap = 3;
    let mut guard = ConnGuard::new(custom_config(100, cap, 100, 100, 100));
    let now = Instant::now();
    let mut current = std::collections::VecDeque::<PeerId>::new();

    for host in 1u8..=3u8 {
        let peer = peer_id();
        assert_eq!(
            connect_and_admit(
                &mut guard,
                peer,
                &addr_v4(10, 91, 0, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
        current.push_back(peer);
    }

    for host in 4u8..=20u8 {
        if let Some(old_peer) = current.pop_front() {
            guard.on_connection_closed(old_peer);
        }

        let new_peer = peer_id();
        assert_eq!(
            connect_and_admit(
                &mut guard,
                new_peer,
                &addr_v4(10, 91, 0, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
        current.push_back(new_peer);

        assert!(guard.admitted_len() <= cap);
    }
}

#[test]
fn test_92_property_sweep_timeouts_is_idempotent() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 92, 0, 1), now),
        GuardDecision::Allow
    );

    let first = guard.sweep_timeouts(now + Duration::from_millis(11));
    let second = guard.sweep_timeouts(now + Duration::from_millis(12));

    assert_eq!(first.len(), 1);
    assert!(first.contains(&peer));
    assert!(second.is_empty());
    assert_eq!(guard.pending_len(), 0);
}

#[test]
fn test_93_property_close_after_timeout_sweep_is_safe_and_idempotent() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 93, 0, 1), now),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.sweep_timeouts(now + Duration::from_millis(11)).len(),
        1
    );

    guard.on_connection_closed(peer);
    guard.on_connection_closed(peer);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
    assert!(!guard.is_admitted(&peer));
}

#[test]
fn test_94_property_admitted_peer_survives_repeated_future_sweeps() {
    let mut cfg = permissive_config();
    cfg.handshake_deadline = Duration::from_millis(10);

    let mut guard = ConnGuard::new(cfg);
    let peer = peer_id();
    let now = Instant::now();

    assert_eq!(
        connect_and_admit(&mut guard, peer, &addr_v4(10, 94, 0, 1), now),
        GuardDecision::Allow
    );

    for offset in 11u64..=30u64 {
        assert!(
            guard
                .sweep_timeouts(now + Duration::from_millis(offset))
                .is_empty()
        );
        assert!(guard.is_admitted(&peer));
        assert_eq!(guard.admitted_len(), 1);
    }
}

#[test]
fn test_95_debug_output_for_decisions_and_reasons_is_stable_enough_for_logs() {
    assert_eq!(format!("{:?}", GuardDecision::Allow), "Allow");
    assert_eq!(
        format!("{:?}", GuardDecision::Drop(DropReason::RateLimited)),
        "Drop(RateLimited)"
    );
    assert_eq!(format!("{:?}", DropReason::MissingIp), "MissingIp");
    assert_eq!(format!("{:?}", DropReason::PerSubnetCap), "PerSubnetCap");
}

#[test]
fn test_96_drop_reason_variants_are_distinct_for_branching() {
    assert_ne!(DropReason::MissingIp, DropReason::RateLimited);
    assert_ne!(DropReason::RateLimited, DropReason::HandshakePoolFull);
    assert_ne!(DropReason::HandshakePoolFull, DropReason::PerIpCap);
    assert_ne!(DropReason::PerIpCap, DropReason::PerSubnetCap);
    assert_ne!(
        DropReason::PerSubnetCap,
        DropReason::HandshakeDeadlineOverflow
    );
    assert_ne!(
        DropReason::HandshakeDeadlineOverflow,
        DropReason::CounterOverflow
    );
}

#[test]
fn test_97_guard_decision_copy_clone_and_equality_are_usable() {
    let first = GuardDecision::Drop(DropReason::RateLimited);
    let copied = first;
    let cloned = first.clone();

    assert_eq!(first, copied);
    assert_eq!(first, cloned);
    assert_ne!(first, GuardDecision::Allow);
}

#[test]
fn test_98_future_instant_with_normal_duration_allows_connection() {
    let mut guard = ConnGuard::new(permissive_config());
    let peer = peer_id();
    let future_now = Instant::now() + Duration::from_secs(60 * 60 * 24);

    assert_eq!(
        connect(&mut guard, peer, &addr_v4(10, 98, 0, 1), future_now),
        GuardDecision::Allow
    );
    assert_eq!(guard.pending_len(), 1);
}

#[test]
fn test_99_many_distinct_ips_in_same_subnet_use_independent_rate_buckets() {
    let mut guard = ConnGuard::new(custom_config(100, 100, 100, 100, 1));
    let now = Instant::now();

    for host in 1u8..=20u8 {
        assert_eq!(
            connect(
                &mut guard,
                peer_id(),
                &addr_v4(10, 99, 0, host),
                now + Duration::from_millis(u64::from(host))
            ),
            GuardDecision::Allow
        );
    }

    assert_eq!(guard.pending_len(), 20);
}

#[test]
fn test_100_end_to_end_mixed_network_sim_admits_blocks_and_cleans_up() {
    let mut guard = ConnGuard::new(custom_config(2, 3, 2, 20, 3));
    let now = Instant::now();

    let same_ip_peer_one = peer_id();
    let same_ip_peer_two = peer_id();
    let same_ip_blocked = peer_id();
    let subnet_peer = peer_id();
    let subnet_blocked = peer_id();
    let v6_peer_one = peer_id();
    let v6_peer_two = peer_id();
    let v6_blocked = peer_id();

    let same_ip_addr = addr_v4(10, 100, 0, 1);

    assert_eq!(
        connect_and_admit(&mut guard, same_ip_peer_one, &same_ip_addr, now),
        GuardDecision::Allow
    );
    assert_eq!(
        connect_and_admit(
            &mut guard,
            same_ip_peer_two,
            &same_ip_addr,
            now + Duration::from_millis(1)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        connect(
            &mut guard,
            same_ip_blocked,
            &same_ip_addr,
            now + Duration::from_millis(2)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(same_ip_blocked),
        GuardDecision::Drop(DropReason::PerIpCap)
    );
    guard.on_connection_closed(same_ip_blocked);

    assert_eq!(
        connect_and_admit(
            &mut guard,
            subnet_peer,
            &addr_v4(10, 100, 0, 2),
            now + Duration::from_millis(3)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        connect(
            &mut guard,
            subnet_blocked,
            &addr_v4(10, 100, 0, 3),
            now + Duration::from_millis(4)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(subnet_blocked),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    guard.on_connection_closed(subnet_blocked);

    assert_eq!(
        connect_and_admit(
            &mut guard,
            v6_peer_one,
            &addr_v6([0x2001, 0x0db8, 0x0100, 0x0001, 0, 0, 0, 1]),
            now + Duration::from_millis(5)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        connect_and_admit(
            &mut guard,
            v6_peer_two,
            &addr_v6([0x2001, 0x0db8, 0x0100, 0x0001, 0, 0, 0, 2]),
            now + Duration::from_millis(6)
        ),
        GuardDecision::Allow
    );

    assert_eq!(
        connect(
            &mut guard,
            v6_blocked,
            &addr_v6([0x2001, 0x0db8, 0x0100, 0x0001, 0, 0, 0, 3]),
            now + Duration::from_millis(7)
        ),
        GuardDecision::Allow
    );
    assert_eq!(
        guard.try_admit(v6_blocked),
        GuardDecision::Drop(DropReason::PerSubnetCap)
    );
    guard.on_connection_closed(v6_blocked);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 5);

    guard.on_connection_closed(same_ip_peer_one);
    guard.on_connection_closed(same_ip_peer_two);
    guard.on_connection_closed(subnet_peer);
    guard.on_connection_closed(v6_peer_one);
    guard.on_connection_closed(v6_peer_two);

    assert_eq!(guard.pending_len(), 0);
    assert_eq!(guard.admitted_len(), 0);
}
