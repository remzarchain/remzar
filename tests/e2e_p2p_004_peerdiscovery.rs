#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use remzar::{
    network::{
        p2p_003_behaviour::RemzarBehaviour,
        p2p_004_peerdiscovery::{add_peerdiscovery_peers, kick_off_peerdiscovery},
    },
    utility::alpha_003_detection_system::DetectionSystem,
};

type TestResult<T = ()> = Result<T, String>;

const MAX_PEERDISCOVERY_ADDRS_PER_CALL_FOR_TEST: usize = 256;
const MAX_MULTIADDR_BYTES_FOR_TEST: usize = 256;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn keypair() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

fn peer_id() -> PeerId {
    PeerId::from(keypair().public())
}

fn behaviour() -> TestResult<RemzarBehaviour> {
    RemzarBehaviour::new(keypair()).map_err(fmt_err)
}

fn detection() -> DetectionSystem {
    DetectionSystem::new()
}

fn ip4_addr(ip: &str, port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/{ip}/tcp/{port}").parse().map_err(fmt_err)
}

fn ip6_addr(ip: &str, port: u16) -> TestResult<Multiaddr> {
    format!("/ip6/{ip}/tcp/{port}").parse().map_err(fmt_err)
}

fn dns_addr(host: &str, port: u16) -> TestResult<Multiaddr> {
    format!("/dns4/{host}/tcp/{port}").parse().map_err(fmt_err)
}

fn memory_addr(id: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(id));
    addr
}

fn with_p2p(mut base: Multiaddr, peer: PeerId) -> Multiaddr {
    base.push(Protocol::P2p(peer));
    base
}

fn p2p_only(peer: PeerId) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::P2p(peer));
    addr
}

fn oversized_multiaddr() -> Multiaddr {
    let mut addr = Multiaddr::empty();

    for i in 0u64..100u64 {
        addr.push(Protocol::Memory(i));
    }

    assert!(
        addr.to_vec().len() > MAX_MULTIADDR_BYTES_FOR_TEST,
        "test oversized multiaddr must exceed defensive cap"
    );

    addr
}

fn assert_bootstrap_has_no_known_peers(behaviour: &mut RemzarBehaviour) {
    let err = behaviour
        .kad_bootstrap_checked()
        .expect_err("expected no known peers");

    assert!(
        err.to_string().contains("no known peers"),
        "unexpected bootstrap error: {err}"
    );
}

fn assert_bootstrap_can_start(behaviour: &mut RemzarBehaviour) -> TestResult {
    let _query = behaviour.kad_bootstrap_checked().map_err(fmt_err)?;
    Ok(())
}

fn add_addrs(behaviour: &mut RemzarBehaviour, addrs: &[Multiaddr]) -> TestResult {
    add_peerdiscovery_peers(behaviour, addrs, &detection()).map_err(fmt_err)
}

fn err_text<E: std::fmt::Debug>(result: Result<(), E>) -> String {
    format!("{:?}", result.expect_err("expected error"))
}

#[test]
fn e2e_01_empty_addr_list_is_ok_and_adds_no_known_peers() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(&mut b, &[])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_02_plain_ip4_addr_without_p2p_suffix_is_ignored() -> TestResult {
    let mut b = behaviour()?;
    let addr = ip4_addr("127.0.0.1", 31002)?;

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_03_plain_ip6_addr_without_p2p_suffix_is_ignored() -> TestResult {
    let mut b = behaviour()?;
    let addr = ip6_addr("::1", 31003)?;

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_04_plain_dns_addr_without_p2p_suffix_is_ignored() -> TestResult {
    let mut b = behaviour()?;
    let addr = dns_addr("localhost", 31004)?;

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_05_memory_addr_without_p2p_suffix_is_ignored() -> TestResult {
    let mut b = behaviour()?;
    let addr = memory_addr(5);

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_06_p2p_only_addr_with_empty_base_is_ignored() -> TestResult {
    let mut b = behaviour()?;
    let addr = p2p_only(peer_id());

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_07_valid_ip4_p2p_addr_adds_known_peer() -> TestResult {
    let mut b = behaviour()?;
    let addr = with_p2p(ip4_addr("127.0.0.1", 31007)?, peer_id());

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_08_valid_ip6_p2p_addr_adds_known_peer() -> TestResult {
    let mut b = behaviour()?;
    let addr = with_p2p(ip6_addr("::1", 31008)?, peer_id());

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_09_valid_dns_p2p_addr_adds_known_peer() -> TestResult {
    let mut b = behaviour()?;
    let addr = with_p2p(dns_addr("localhost", 31009)?, peer_id());

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_10_valid_memory_p2p_addr_adds_known_peer() -> TestResult {
    let mut b = behaviour()?;
    let addr = with_p2p(memory_addr(10), peer_id());

    add_addrs(&mut b, &[addr])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_11_mixed_plain_and_p2p_addrs_adds_only_valid_p2p_peers() -> TestResult {
    let mut b = behaviour()?;

    let addrs = vec![
        ip4_addr("127.0.0.1", 31011)?,
        memory_addr(11),
        with_p2p(ip4_addr("127.0.0.1", 31012)?, peer_id()),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_12_duplicate_peer_id_is_deduped_and_safe() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let addrs = vec![
        with_p2p(ip4_addr("127.0.0.1", 31012)?, peer),
        with_p2p(ip4_addr("127.0.0.2", 31013)?, peer),
        with_p2p(memory_addr(12), peer),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_13_multiple_unique_peer_ids_are_accepted() -> TestResult {
    let mut b = behaviour()?;

    let addrs = vec![
        with_p2p(ip4_addr("127.0.0.1", 31013)?, peer_id()),
        with_p2p(ip4_addr("127.0.0.2", 31013)?, peer_id()),
        with_p2p(ip4_addr("127.0.0.3", 31013)?, peer_id()),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_14_repeated_calls_accumulate_known_peers() -> TestResult {
    let mut b = behaviour()?;

    let first = with_p2p(ip4_addr("127.0.0.1", 31014)?, peer_id());
    let second = with_p2p(ip4_addr("127.0.0.2", 31014)?, peer_id());

    add_addrs(&mut b, &[first])?;
    assert_bootstrap_can_start(&mut b)?;

    add_addrs(&mut b, &[second])?;
    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_15_valid_addr_with_p2p_suffix_is_safe_after_base_stripping() -> TestResult {
    let mut b = behaviour()?;

    let base = ip4_addr("127.0.0.1", 31015)?;
    let full = with_p2p(base.clone(), peer_id());

    assert_ne!(full, base);
    assert!(full.to_string().contains("/p2p/"));

    add_addrs(&mut b, &[full])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_16_oversized_full_multiaddr_is_rejected() -> TestResult {
    let mut b = behaviour()?;
    let addr = oversized_multiaddr();

    let result = add_peerdiscovery_peers(&mut b, &[addr], &detection());

    let text = err_text(result);
    assert!(
        text.contains("multiaddr too large"),
        "unexpected error: {text}"
    );

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_17_oversized_addr_after_valid_addr_fails_whole_call() -> TestResult {
    let mut b = behaviour()?;

    let good = with_p2p(ip4_addr("127.0.0.1", 31017)?, peer_id());
    let bad = oversized_multiaddr();

    let result = add_peerdiscovery_peers(&mut b, &[good, bad], &detection());

    let text = err_text(result);
    assert!(
        text.contains("multiaddr too large"),
        "unexpected error: {text}"
    );

    Ok(())
}

#[test]
fn e2e_18_addr_count_above_256_is_rejected() -> TestResult {
    let mut b = behaviour()?;

    let mut addrs = Vec::new();
    for i in 0..=MAX_PEERDISCOVERY_ADDRS_PER_CALL_FOR_TEST {
        addrs.push(with_p2p(memory_addr(10_000 + i as u64), peer_id()));
    }

    let result = add_peerdiscovery_peers(&mut b, &addrs, &detection());

    let text = err_text(result);
    assert!(
        text.contains("peer discovery addr list too large"),
        "unexpected error: {text}"
    );

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_19_addr_count_exactly_256_is_accepted_when_addresses_are_valid() -> TestResult {
    let mut b = behaviour()?;

    let mut addrs = Vec::new();
    for i in 0..MAX_PEERDISCOVERY_ADDRS_PER_CALL_FOR_TEST {
        addrs.push(with_p2p(memory_addr(20_000 + i as u64), peer_id()));
    }

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_20_addr_count_255_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    let mut addrs = Vec::new();
    for i in 0..255usize {
        addrs.push(with_p2p(memory_addr(30_000 + i as u64), peer_id()));
    }

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_21_all_plain_addresses_under_count_cap_are_ignored_without_error() -> TestResult {
    let mut b = behaviour()?;

    let mut addrs = Vec::new();
    for i in 0..32u64 {
        addrs.push(memory_addr(40_000 + i));
    }

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_22_many_duplicate_same_peer_under_count_cap_are_safe() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let mut addrs = Vec::new();
    for i in 0..64u64 {
        addrs.push(with_p2p(memory_addr(50_000 + i), peer));
    }

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_23_plain_addr_then_duplicate_p2p_peer_still_accepts_p2p_peer() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let addrs = vec![
        ip4_addr("127.0.0.1", 31023)?,
        with_p2p(ip4_addr("127.0.0.1", 31024)?, peer),
        with_p2p(ip4_addr("127.0.0.2", 31025)?, peer),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_24_empty_base_p2p_addr_mixed_with_valid_addr_is_ignored_not_fatal() -> TestResult {
    let mut b = behaviour()?;

    let addrs = vec![
        p2p_only(peer_id()),
        with_p2p(ip4_addr("127.0.0.1", 31024)?, peer_id()),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_25_kick_off_peerdiscovery_without_peers_is_ok() -> TestResult {
    let mut b = behaviour()?;

    kick_off_peerdiscovery(&mut b).map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_26_kick_off_peerdiscovery_after_valid_peer_is_ok() -> TestResult {
    let mut b = behaviour()?;
    let addr = with_p2p(ip4_addr("127.0.0.1", 31026)?, peer_id());

    add_addrs(&mut b, &[addr])?;

    kick_off_peerdiscovery(&mut b).map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_27_kick_off_peerdiscovery_can_be_called_repeatedly_without_peers() -> TestResult {
    let mut b = behaviour()?;

    for _ in 0..10usize {
        kick_off_peerdiscovery(&mut b).map_err(fmt_err)?;
    }

    Ok(())
}

#[test]
fn e2e_28_kick_off_peerdiscovery_can_be_called_repeatedly_with_peers() -> TestResult {
    let mut b = behaviour()?;
    let addr = with_p2p(memory_addr(28), peer_id());

    add_addrs(&mut b, &[addr])?;

    for _ in 0..10usize {
        kick_off_peerdiscovery(&mut b).map_err(fmt_err)?;
    }

    Ok(())
}

#[test]
fn e2e_29_add_peerdiscovery_peers_can_be_called_repeatedly_with_empty_lists() -> TestResult {
    let mut b = behaviour()?;

    for _ in 0..10usize {
        add_addrs(&mut b, &[])?;
    }

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_30_add_peerdiscovery_peers_can_be_called_repeatedly_with_same_peer() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = with_p2p(ip4_addr("127.0.0.1", 31030)?, peer);

    for _ in 0..10usize {
        add_addrs(&mut b, &[addr.clone()])?;
    }

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_31_ipv4_loopback_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[with_p2p(ip4_addr("127.0.0.1", 31031)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_32_ipv4_private_10_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(&mut b, &[with_p2p(ip4_addr("10.1.2.3", 31032)?, peer_id())])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_33_ipv4_private_172_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[with_p2p(ip4_addr("172.16.1.2", 31033)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_34_ipv4_private_192_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[with_p2p(ip4_addr("192.168.1.2", 31034)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_35_ipv6_loopback_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(&mut b, &[with_p2p(ip6_addr("::1", 31035)?, peer_id())])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_36_ipv6_documentation_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[with_p2p(ip6_addr("2001:db8::1", 31036)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_37_dns_localhost_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[with_p2p(dns_addr("localhost", 31037)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_38_memory_p2p_addr_with_large_memory_id_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(&mut b, &[with_p2p(memory_addr(u64::MAX), peer_id())])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_39_zero_port_ip4_p2p_addr_is_accepted_as_multiaddr() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(&mut b, &[with_p2p(ip4_addr("127.0.0.1", 0)?, peer_id())])?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_40_high_port_ip4_p2p_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[with_p2p(ip4_addr("127.0.0.1", u16::MAX)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_41_valid_addr_before_plain_addr_keeps_known_peer() -> TestResult {
    let mut b = behaviour()?;

    let addrs = vec![
        with_p2p(ip4_addr("127.0.0.1", 31041)?, peer_id()),
        ip4_addr("127.0.0.1", 31042)?,
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_42_plain_addr_before_valid_addr_keeps_known_peer() -> TestResult {
    let mut b = behaviour()?;

    let addrs = vec![
        ip4_addr("127.0.0.1", 31042)?,
        with_p2p(ip4_addr("127.0.0.1", 31043)?, peer_id()),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_43_valid_peerdiscovery_after_ignored_plain_addrs_enables_bootstrap() -> TestResult {
    let mut b = behaviour()?;

    add_addrs(
        &mut b,
        &[
            ip4_addr("127.0.0.1", 31043)?,
            memory_addr(43),
            dns_addr("localhost", 31044)?,
        ],
    )?;

    assert_bootstrap_has_no_known_peers(&mut b);

    add_addrs(
        &mut b,
        &[with_p2p(ip4_addr("127.0.0.1", 31045)?, peer_id())],
    )?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_44_error_after_previous_success_does_not_remove_existing_known_peer() -> TestResult {
    let mut b = behaviour()?;

    let good = with_p2p(ip4_addr("127.0.0.1", 31044)?, peer_id());
    add_addrs(&mut b, &[good])?;
    assert_bootstrap_can_start(&mut b)?;

    let result = add_peerdiscovery_peers(&mut b, &[oversized_multiaddr()], &detection());
    assert!(result.is_err());

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_45_too_many_addrs_after_previous_success_does_not_remove_existing_known_peer() -> TestResult
{
    let mut b = behaviour()?;

    let good = with_p2p(ip4_addr("127.0.0.1", 31045)?, peer_id());
    add_addrs(&mut b, &[good])?;
    assert_bootstrap_can_start(&mut b)?;

    let mut too_many = Vec::new();
    for i in 0..=MAX_PEERDISCOVERY_ADDRS_PER_CALL_FOR_TEST {
        too_many.push(with_p2p(memory_addr(60_000 + i as u64), peer_id()));
    }

    let result = add_peerdiscovery_peers(&mut b, &too_many, &detection());
    assert!(result.is_err());

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_46_all_duplicate_p2p_only_empty_base_addrs_are_ignored() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let addrs = vec![p2p_only(peer), p2p_only(peer), p2p_only(peer)];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_has_no_known_peers(&mut b);

    Ok(())
}

#[test]
fn e2e_47_duplicate_peer_with_first_empty_base_then_valid_base_is_accepted() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let addrs = vec![
        p2p_only(peer),
        with_p2p(ip4_addr("127.0.0.1", 31047)?, peer),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_48_valid_base_then_duplicate_empty_base_keeps_valid_base() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let addrs = vec![
        with_p2p(ip4_addr("127.0.0.1", 31048)?, peer),
        p2p_only(peer),
    ];

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_49_many_small_valid_addrs_do_not_stall_or_error() -> TestResult {
    let mut b = behaviour()?;

    let mut addrs = Vec::new();
    for i in 0..128u64 {
        addrs.push(with_p2p(memory_addr(70_000 + i), peer_id()));
    }

    add_addrs(&mut b, &addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    Ok(())
}

#[test]
fn e2e_50_full_peerdiscovery_lifecycle_ignore_plain_add_valid_dedupe_reject_abuse_and_bootstrap()
-> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    // 1. Plain addresses are ignored.
    add_addrs(&mut b, &[ip4_addr("127.0.0.1", 31050)?, memory_addr(50)])?;

    assert_bootstrap_has_no_known_peers(&mut b);

    // 2. Valid /p2p address enables peer discovery bootstrap.
    let first_valid = with_p2p(ip4_addr("127.0.0.1", 31051)?, peer);
    add_addrs(&mut b, &[first_valid.clone()])?;

    assert_bootstrap_can_start(&mut b)?;

    // 3. Duplicate same peer is safe and deterministic.
    let duplicate_same_peer = with_p2p(ip4_addr("127.0.0.2", 31052)?, peer);
    add_addrs(&mut b, &[first_valid, duplicate_same_peer])?;

    assert_bootstrap_can_start(&mut b)?;

    // 4. Valid unique peers are accepted.
    let unique_addrs = vec![
        with_p2p(ip4_addr("127.0.0.3", 31053)?, peer_id()),
        with_p2p(ip6_addr("::1", 31054)?, peer_id()),
        with_p2p(memory_addr(51), peer_id()),
    ];

    add_addrs(&mut b, &unique_addrs)?;

    assert_bootstrap_can_start(&mut b)?;

    // 5. Abuse input is rejected without destroying already known peers.
    let result = add_peerdiscovery_peers(&mut b, &[oversized_multiaddr()], &detection());
    assert!(result.is_err());

    assert_bootstrap_can_start(&mut b)?;

    // 6. kick_off_peerdiscovery ignores NoKnownPeers and succeeds with known peers too.
    kick_off_peerdiscovery(&mut b).map_err(fmt_err)?;

    Ok(())
}
