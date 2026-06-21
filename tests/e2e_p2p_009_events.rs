#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use remzar::network::p2p_009_events::{
    P2pEvent, attach_peer_to_addr, dedupe_addrs, ensure_dialable_addr_for_peer, kad_ready_addrs,
    split_multiaddr_base_and_peer,
};

type TestResult<T = ()> = Result<T, String>;

const MAX_MULTIADDR_BYTES_FOR_TEST: usize = 256;

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

fn dns_addr(host: &str, port: u16) -> TestResult<Multiaddr> {
    format!("/dns4/{host}/tcp/{port}").parse().map_err(fmt_err)
}

fn memory_addr(id: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(id));
    addr
}

fn p2p_only(peer: PeerId) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::P2p(peer));
    addr
}

fn with_p2p(mut base: Multiaddr, peer: PeerId) -> Multiaddr {
    base.push(Protocol::P2p(peer));
    base
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

fn assert_has_trailing_peer(addr: &Multiaddr, expected: PeerId) {
    let (_, peer) = split_multiaddr_base_and_peer(addr);
    assert_eq!(peer, Some(expected));
}

fn assert_has_no_trailing_peer(addr: &Multiaddr) {
    let (_, peer) = split_multiaddr_base_and_peer(addr);
    assert_eq!(peer, None);
}

#[test]
fn e2e_01_split_ip4_without_p2p_returns_same_base_and_no_peer() -> TestResult {
    let addr = ip4_addr("127.0.0.1", 31001)?;

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert_eq!(peer, None);

    Ok(())
}

#[test]
fn e2e_02_split_ip6_without_p2p_returns_same_base_and_no_peer() -> TestResult {
    let addr = ip6_addr("::1", 31002)?;

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert_eq!(peer, None);

    Ok(())
}

#[test]
fn e2e_03_split_dns_without_p2p_returns_same_base_and_no_peer() -> TestResult {
    let addr = dns_addr("localhost", 31003)?;

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert_eq!(peer, None);

    Ok(())
}

#[test]
fn e2e_04_split_memory_without_p2p_returns_same_base_and_no_peer() -> TestResult {
    let addr = memory_addr(4);

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert_eq!(peer, None);

    Ok(())
}

#[test]
fn e2e_05_split_ip4_with_p2p_returns_base_and_peer() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31005)?;
    let full = with_p2p(base.clone(), peer);

    let (actual_base, actual_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(actual_base, base);
    assert_eq!(actual_peer, Some(peer));

    Ok(())
}

#[test]
fn e2e_06_split_ip6_with_p2p_returns_base_and_peer() -> TestResult {
    let peer = peer_id();
    let base = ip6_addr("::1", 31006)?;
    let full = with_p2p(base.clone(), peer);

    let (actual_base, actual_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(actual_base, base);
    assert_eq!(actual_peer, Some(peer));

    Ok(())
}

#[test]
fn e2e_07_split_dns_with_p2p_returns_base_and_peer() -> TestResult {
    let peer = peer_id();
    let base = dns_addr("localhost", 31007)?;
    let full = with_p2p(base.clone(), peer);

    let (actual_base, actual_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(actual_base, base);
    assert_eq!(actual_peer, Some(peer));

    Ok(())
}

#[test]
fn e2e_08_split_memory_with_p2p_returns_base_and_peer() -> TestResult {
    let peer = peer_id();
    let base = memory_addr(8);
    let full = with_p2p(base.clone(), peer);

    let (actual_base, actual_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(actual_base, base);
    assert_eq!(actual_peer, Some(peer));

    Ok(())
}

#[test]
fn e2e_09_split_p2p_only_returns_empty_base_and_peer() -> TestResult {
    let peer = peer_id();
    let addr = p2p_only(peer);

    let (base, actual_peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, Multiaddr::empty());
    assert_eq!(actual_peer, Some(peer));

    Ok(())
}

#[test]
fn e2e_10_attach_peer_to_ip4_base_appends_p2p_suffix() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31010)?;

    let full = attach_peer_to_addr(base.clone(), &peer);

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_11_attach_peer_to_ip6_base_appends_p2p_suffix() -> TestResult {
    let peer = peer_id();
    let base = ip6_addr("::1", 31011)?;

    let full = attach_peer_to_addr(base.clone(), &peer);

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_12_attach_peer_to_dns_base_appends_p2p_suffix() -> TestResult {
    let peer = peer_id();
    let base = dns_addr("localhost", 31012)?;

    let full = attach_peer_to_addr(base.clone(), &peer);

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_13_attach_peer_to_memory_base_appends_p2p_suffix() -> TestResult {
    let peer = peer_id();
    let base = memory_addr(13);

    let full = attach_peer_to_addr(base.clone(), &peer);

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_14_attach_peer_to_empty_base_creates_p2p_only_addr() -> TestResult {
    let peer = peer_id();

    let full = attach_peer_to_addr(Multiaddr::empty(), &peer);

    assert_eq!(full, p2p_only(peer));

    Ok(())
}

#[test]
fn e2e_15_ensure_dialable_attaches_peer_to_ip4_base() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31015)?;

    let full = ensure_dialable_addr_for_peer(&base, &peer)
        .ok_or_else(|| "expected dialable ip4 addr".to_string())?;

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_16_ensure_dialable_attaches_peer_to_ip6_base() -> TestResult {
    let peer = peer_id();
    let base = ip6_addr("::1", 31016)?;

    let full = ensure_dialable_addr_for_peer(&base, &peer)
        .ok_or_else(|| "expected dialable ip6 addr".to_string())?;

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_17_ensure_dialable_attaches_peer_to_dns_base() -> TestResult {
    let peer = peer_id();
    let base = dns_addr("localhost", 31017)?;

    let full = ensure_dialable_addr_for_peer(&base, &peer)
        .ok_or_else(|| "expected dialable dns addr".to_string())?;

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_18_ensure_dialable_attaches_peer_to_memory_base() -> TestResult {
    let peer = peer_id();
    let base = memory_addr(18);

    let full = ensure_dialable_addr_for_peer(&base, &peer)
        .ok_or_else(|| "expected dialable memory addr".to_string())?;

    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_19_ensure_dialable_keeps_same_trailing_peer() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31019)?;
    let original = with_p2p(base.clone(), peer);

    let full = ensure_dialable_addr_for_peer(&original, &peer)
        .ok_or_else(|| "expected same-peer full addr to remain valid".to_string())?;

    assert_eq!(full, original);
    assert_eq!(split_multiaddr_base_and_peer(&full), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_20_ensure_dialable_rejects_different_trailing_peer() -> TestResult {
    let expected_peer = peer_id();
    let wrong_peer = peer_id();
    let addr = with_p2p(ip4_addr("127.0.0.1", 31020)?, wrong_peer);

    let full = ensure_dialable_addr_for_peer(&addr, &expected_peer);

    assert_eq!(full, None);

    Ok(())
}

#[test]
fn e2e_21_ensure_dialable_rejects_empty_addr() -> TestResult {
    let peer = peer_id();

    let full = ensure_dialable_addr_for_peer(&Multiaddr::empty(), &peer);

    assert_eq!(full, None);

    Ok(())
}

#[test]
fn e2e_22_ensure_dialable_rejects_p2p_only_addr() -> TestResult {
    let peer = peer_id();
    let addr = p2p_only(peer);

    let full = ensure_dialable_addr_for_peer(&addr, &peer);

    assert_eq!(full, None);

    Ok(())
}

#[test]
fn e2e_23_ensure_dialable_rejects_oversized_addr() -> TestResult {
    let peer = peer_id();
    let addr = oversized_multiaddr();

    let full = ensure_dialable_addr_for_peer(&addr, &peer);

    assert_eq!(full, None);

    Ok(())
}

#[test]
fn e2e_24_ensure_dialable_rejects_oversized_base_even_with_p2p_suffix() -> TestResult {
    let peer = peer_id();
    let addr = with_p2p(oversized_multiaddr(), peer);

    let full = ensure_dialable_addr_for_peer(&addr, &peer);

    assert_eq!(full, None);

    Ok(())
}

#[test]
fn e2e_25_ensure_dialable_does_not_append_duplicate_p2p_suffix() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31025)?;
    let full = with_p2p(base.clone(), peer);

    let ensured = ensure_dialable_addr_for_peer(&full, &peer)
        .ok_or_else(|| "expected full addr".to_string())?;

    let p2p_count = ensured
        .iter()
        .filter(|protocol| matches!(protocol, Protocol::P2p(_)))
        .count();

    assert_eq!(p2p_count, 1);
    assert_eq!(split_multiaddr_base_and_peer(&ensured), (base, Some(peer)));

    Ok(())
}

#[test]
fn e2e_26_kad_ready_empty_list_returns_empty() -> TestResult {
    let out = kad_ready_addrs(&[]);

    assert!(out.is_empty());

    Ok(())
}

#[test]
fn e2e_27_kad_ready_keeps_base_ip4_addr() -> TestResult {
    let base = ip4_addr("127.0.0.1", 31027)?;

    let out = kad_ready_addrs(&[base.clone()]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_28_kad_ready_strips_p2p_from_ip4_addr() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31028)?;
    let full = with_p2p(base.clone(), peer);

    let out = kad_ready_addrs(&[full]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_29_kad_ready_strips_p2p_from_ip6_addr() -> TestResult {
    let peer = peer_id();
    let base = ip6_addr("::1", 31029)?;
    let full = with_p2p(base.clone(), peer);

    let out = kad_ready_addrs(&[full]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_30_kad_ready_strips_p2p_from_dns_addr() -> TestResult {
    let peer = peer_id();
    let base = dns_addr("localhost", 31030)?;
    let full = with_p2p(base.clone(), peer);

    let out = kad_ready_addrs(&[full]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_31_kad_ready_strips_p2p_from_memory_addr() -> TestResult {
    let peer = peer_id();
    let base = memory_addr(31);
    let full = with_p2p(base.clone(), peer);

    let out = kad_ready_addrs(&[full]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_32_kad_ready_dedupes_same_base_from_multiple_full_addrs() -> TestResult {
    let first_peer = peer_id();
    let second_peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31032)?;

    let out = kad_ready_addrs(&[
        with_p2p(base.clone(), first_peer),
        with_p2p(base.clone(), second_peer),
    ]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_33_kad_ready_dedupes_duplicate_base_addrs() -> TestResult {
    let base = ip4_addr("127.0.0.1", 31033)?;

    let out = kad_ready_addrs(&[base.clone(), base.clone(), base.clone()]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_34_kad_ready_skips_empty_base_p2p_only_addr() -> TestResult {
    let out = kad_ready_addrs(&[p2p_only(peer_id())]);

    assert!(out.is_empty());

    Ok(())
}

#[test]
fn e2e_35_kad_ready_skips_oversized_addr() -> TestResult {
    let out = kad_ready_addrs(&[oversized_multiaddr()]);

    assert!(out.is_empty());

    Ok(())
}

#[test]
fn e2e_36_kad_ready_preserves_first_occurrence_order() -> TestResult {
    let first = ip4_addr("127.0.0.1", 31036)?;
    let second = memory_addr(36);
    let third = dns_addr("localhost", 31036)?;

    let out = kad_ready_addrs(&[
        first.clone(),
        second.clone(),
        first.clone(),
        third.clone(),
        second.clone(),
    ]);

    assert_eq!(out, vec![first, second, third]);

    Ok(())
}

#[test]
fn e2e_37_kad_ready_preserves_distinct_base_addr_families() -> TestResult {
    let ip4 = ip4_addr("127.0.0.1", 31037)?;
    let ip6 = ip6_addr("::1", 31037)?;
    let dns = dns_addr("localhost", 31037)?;
    let mem = memory_addr(37);

    let out = kad_ready_addrs(&[ip4.clone(), ip6.clone(), dns.clone(), mem.clone()]);

    assert_eq!(out, vec![ip4, ip6, dns, mem]);

    Ok(())
}

#[test]
fn e2e_38_kad_ready_dedupes_base_and_full_form_of_same_addr() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31038)?;
    let full = with_p2p(base.clone(), peer);

    let out = kad_ready_addrs(&[base.clone(), full]);

    assert_eq!(out, vec![base]);

    Ok(())
}

#[test]
fn e2e_39_dedupe_empty_vec_returns_empty() -> TestResult {
    let out = dedupe_addrs(Vec::new());

    assert!(out.is_empty());

    Ok(())
}

#[test]
fn e2e_40_dedupe_removes_exact_duplicate_ip4_addr() -> TestResult {
    let addr = ip4_addr("127.0.0.1", 31040)?;

    let out = dedupe_addrs(vec![addr.clone(), addr.clone(), addr.clone()]);

    assert_eq!(out, vec![addr]);

    Ok(())
}

#[test]
fn e2e_41_dedupe_preserves_first_occurrence_order() -> TestResult {
    let first = ip4_addr("127.0.0.1", 31041)?;
    let second = memory_addr(41);
    let third = dns_addr("localhost", 31041)?;

    let out = dedupe_addrs(vec![
        first.clone(),
        second.clone(),
        first.clone(),
        third.clone(),
        second.clone(),
    ]);

    assert_eq!(out, vec![first, second, third]);

    Ok(())
}

#[test]
fn e2e_42_dedupe_skips_oversized_addr() -> TestResult {
    let good = ip4_addr("127.0.0.1", 31042)?;
    let bad = oversized_multiaddr();

    let out = dedupe_addrs(vec![bad, good.clone()]);

    assert_eq!(out, vec![good]);

    Ok(())
}

#[test]
fn e2e_43_dedupe_treats_base_and_full_addr_as_distinct_strings() -> TestResult {
    let peer = peer_id();
    let base = ip4_addr("127.0.0.1", 31043)?;
    let full = with_p2p(base.clone(), peer);

    let out = dedupe_addrs(vec![base.clone(), full.clone()]);

    assert_eq!(out, vec![base, full]);

    Ok(())
}

#[test]
fn e2e_44_dedupe_memory_duplicates() -> TestResult {
    let addr = memory_addr(44);

    let out = dedupe_addrs(vec![addr.clone(), addr.clone()]);

    assert_eq!(out, vec![addr]);

    Ok(())
}

#[test]
fn e2e_45_dedupe_multiple_full_addrs_with_different_peers_are_distinct() -> TestResult {
    let base = ip4_addr("127.0.0.1", 31045)?;
    let first = with_p2p(base.clone(), peer_id());
    let second = with_p2p(base, peer_id());

    let out = dedupe_addrs(vec![first.clone(), second.clone()]);

    assert_eq!(out, vec![first, second]);

    Ok(())
}

#[test]
fn e2e_46_p2p_event_new_listen_addr_debug_mentions_variant() -> TestResult {
    let addr = ip4_addr("127.0.0.1", 31046)?;
    let event = P2pEvent::NewListenAddr(addr);

    let text = format!("{event:?}");

    assert!(text.contains("NewListenAddr"));

    Ok(())
}

#[test]
fn e2e_47_p2p_event_expired_listen_addr_debug_mentions_variant() -> TestResult {
    let addr = ip4_addr("127.0.0.1", 31047)?;
    let event = P2pEvent::ExpiredListenAddr(addr);

    let text = format!("{event:?}");

    assert!(text.contains("ExpiredListenAddr"));

    Ok(())
}

#[test]
fn e2e_48_p2p_event_dialing_some_peer_preserves_peer() -> TestResult {
    let peer = peer_id();
    let event = P2pEvent::Dialing {
        peer_id: Some(peer),
    };

    match event {
        P2pEvent::Dialing { peer_id } => assert_eq!(peer_id, Some(peer)),
        other => return Err(format!("unexpected event: {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_49_p2p_event_dialing_none_is_supported() -> TestResult {
    let event = P2pEvent::Dialing { peer_id: None };

    match event {
        P2pEvent::Dialing { peer_id } => assert_eq!(peer_id, None),
        other => return Err(format!("unexpected event: {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_50_full_event_address_lifecycle_dialable_peerbook_kad_ready_and_dedupe() -> TestResult {
    let peer = peer_id();
    let wrong_peer = peer_id();

    let ip4_base = ip4_addr("127.0.0.1", 31050)?;
    let ip6_base = ip6_addr("::1", 31050)?;
    let dns_base = dns_addr("localhost", 31050)?;
    let mem_base = memory_addr(50);

    // 1. PeerBook/autodial needs FULL dialable addrs.
    let ip4_full = ensure_dialable_addr_for_peer(&ip4_base, &peer)
        .ok_or_else(|| "ip4 should become dialable".to_string())?;
    let ip6_full = ensure_dialable_addr_for_peer(&ip6_base, &peer)
        .ok_or_else(|| "ip6 should become dialable".to_string())?;
    let dns_full = ensure_dialable_addr_for_peer(&dns_base, &peer)
        .ok_or_else(|| "dns should become dialable".to_string())?;
    let mem_full = ensure_dialable_addr_for_peer(&mem_base, &peer)
        .ok_or_else(|| "memory should become dialable".to_string())?;

    assert_has_trailing_peer(&ip4_full, peer);
    assert_has_trailing_peer(&ip6_full, peer);
    assert_has_trailing_peer(&dns_full, peer);
    assert_has_trailing_peer(&mem_full, peer);

    // 2. Mismatched embedded peer IDs must be rejected.
    let wrong_full = with_p2p(ip4_base.clone(), wrong_peer);
    assert_eq!(ensure_dialable_addr_for_peer(&wrong_full, &peer), None);

    // 3. Kad-ready addresses must strip /p2p and dedupe by base addr.
    let kad = kad_ready_addrs(&[
        ip4_full.clone(),
        ip4_full.clone(),
        ip6_full.clone(),
        dns_full.clone(),
        mem_full.clone(),
        p2p_only(peer),
        oversized_multiaddr(),
    ]);

    assert_eq!(kad, vec![ip4_base.clone(), ip6_base, dns_base, mem_base]);

    for addr in &kad {
        assert_has_no_trailing_peer(addr);
    }

    // 4. Simple dedupe keeps full dialable addresses distinct from base addrs.
    let deduped = dedupe_addrs(vec![ip4_base.clone(), ip4_full.clone(), ip4_full.clone()]);
    assert_eq!(deduped, vec![ip4_base, ip4_full]);

    // 5. Event wrapper supports swarm-level variants.
    let event = P2pEvent::NewListenAddr(listen_addr_for_full_lifecycle()?);
    assert!(format!("{event:?}").contains("NewListenAddr"));

    Ok(())
}

fn listen_addr_for_full_lifecycle() -> TestResult<Multiaddr> {
    ip4_addr("127.0.0.1", 31999)
}
