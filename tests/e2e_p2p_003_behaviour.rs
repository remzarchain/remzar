#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{
    Multiaddr, PeerId,
    gossipsub::{Event as GossipsubEvent, IdentTopic},
    identity,
    multiaddr::Protocol,
    swarm::Swarm,
};
use remzar::network::p2p_003_behaviour::{OutEvent, RemzarBehaviour};

type TestResult<T = ()> = Result<T, String>;

const MAX_MULTIADDR_BYTES_FOR_TEST: usize = 256;
const MAX_IDENTIFY_ADDRS_INGEST_FOR_TEST: usize = 64;

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

fn ip4_addr(port: u16) -> TestResult<Multiaddr> {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse()
        .map_err(fmt_err)
}

fn ip6_addr(port: u16) -> TestResult<Multiaddr> {
    format!("/ip6/::1/tcp/{port}").parse().map_err(fmt_err)
}

fn dns_addr(port: u16) -> TestResult<Multiaddr> {
    format!("/dns4/localhost/tcp/{port}")
        .parse()
        .map_err(fmt_err)
}

fn memory_addr(id: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(id));
    addr
}

fn p2p_addr(base: Multiaddr, peer: PeerId) -> Multiaddr {
    let mut addr = base;
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

fn has_p2p_suffix(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2p(_)))
}

fn strip_p2p_for_test(addr: &Multiaddr) -> Multiaddr {
    let mut out = Multiaddr::empty();

    for protocol in addr.iter() {
        if matches!(protocol, Protocol::P2p(_)) {
            break;
        }

        out.push(protocol);
    }

    out
}

fn build_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let kp = keypair();

    let swarm = libp2p::SwarmBuilder::with_existing_identity(kp)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(fmt_err)?
        .with_behaviour(|key| {
            RemzarBehaviour::new(key.clone()).unwrap_or_else(|err| {
                panic!("failed to build RemzarBehaviour for e2e test swarm: {err}");
            })
        })
        .map_err(fmt_err)?
        .build();

    Ok(swarm)
}

#[test]
fn e2e_01_behaviour_new_builds_all_public_components() -> TestResult {
    let mut b = behaviour()?;

    let topic = IdentTopic::new("/remzar/e2e/behaviour/01");
    let subscribed = b.gossipsub.subscribe(&topic).map_err(fmt_err)?;

    assert!(subscribed);
    assert_eq!(b.gossipsub.all_peers().count(), 0);

    Ok(())
}

#[test]
fn e2e_02_behaviour_new_can_be_called_repeatedly() -> TestResult {
    for _ in 0usize..16usize {
        let _ = behaviour()?;
    }

    Ok(())
}

#[test]
fn e2e_03_behaviour_new_with_different_keys_creates_independent_instances() -> TestResult {
    let mut first = behaviour()?;
    let mut second = behaviour()?;

    let topic = IdentTopic::new("/remzar/e2e/behaviour/03");

    assert!(first.gossipsub.subscribe(&topic).map_err(fmt_err)?);
    assert!(second.gossipsub.subscribe(&topic).map_err(fmt_err)?);

    assert_eq!(first.gossipsub.all_peers().count(), 0);
    assert_eq!(second.gossipsub.all_peers().count(), 0);

    Ok(())
}

#[test]
fn e2e_04_gossipsub_starts_with_no_known_peers() -> TestResult {
    let b = behaviour()?;

    assert_eq!(b.gossipsub.all_peers().count(), 0);

    Ok(())
}

#[test]
fn e2e_05_gossipsub_subscribe_new_topic_returns_true() -> TestResult {
    let mut b = behaviour()?;
    let topic = IdentTopic::new("/remzar/e2e/behaviour/05");

    let subscribed = b.gossipsub.subscribe(&topic).map_err(fmt_err)?;

    assert!(subscribed);

    Ok(())
}

#[test]
fn e2e_06_gossipsub_duplicate_subscribe_is_deduped() -> TestResult {
    let mut b = behaviour()?;
    let topic = IdentTopic::new("/remzar/e2e/behaviour/06");

    let first = b.gossipsub.subscribe(&topic).map_err(fmt_err)?;
    let second = b.gossipsub.subscribe(&topic).map_err(fmt_err)?;

    assert!(first);
    assert!(!second);

    Ok(())
}

#[test]
fn e2e_07_gossipsub_unsubscribe_existing_topic_succeeds() -> TestResult {
    let mut b = behaviour()?;
    let topic = IdentTopic::new("/remzar/e2e/behaviour/07");

    assert!(b.gossipsub.subscribe(&topic).map_err(fmt_err)?);

    let unsubscribed = b.gossipsub.unsubscribe(&topic);

    assert!(unsubscribed);

    Ok(())
}

#[test]
fn e2e_08_gossipsub_unsubscribe_unknown_topic_is_safe() -> TestResult {
    let mut b = behaviour()?;
    let topic = IdentTopic::new("/remzar/e2e/behaviour/08");

    let unsubscribed = b.gossipsub.unsubscribe(&topic);

    assert!(!unsubscribed);

    Ok(())
}

#[test]
fn e2e_09_gossipsub_many_topics_can_be_subscribed() -> TestResult {
    let mut b = behaviour()?;

    for i in 0usize..32usize {
        let topic = IdentTopic::new(format!("/remzar/e2e/behaviour/09/{i}"));
        assert!(b.gossipsub.subscribe(&topic).map_err(fmt_err)?);
    }

    Ok(())
}

#[test]
fn e2e_10_gossipsub_many_topics_can_be_unsubscribed() -> TestResult {
    let mut b = behaviour()?;

    let topics: Vec<IdentTopic> = (0usize..16usize)
        .map(|i| IdentTopic::new(format!("/remzar/e2e/behaviour/10/{i}")))
        .collect();

    for topic in &topics {
        assert!(b.gossipsub.subscribe(topic).map_err(fmt_err)?);
    }

    for topic in &topics {
        assert!(b.gossipsub.unsubscribe(topic));
    }

    Ok(())
}

#[test]
fn e2e_11_gossipsub_long_but_valid_topic_is_accepted() -> TestResult {
    let mut b = behaviour()?;
    let topic = IdentTopic::new(format!("/remzar/e2e/behaviour/11/{}", "a".repeat(256)));

    assert!(b.gossipsub.subscribe(&topic).map_err(fmt_err)?);

    Ok(())
}

#[test]
fn e2e_12_out_event_wraps_gossipsub_subscribed_event() -> TestResult {
    let peer = peer_id();
    let topic = IdentTopic::new("/remzar/e2e/behaviour/12");

    let event = GossipsubEvent::Subscribed {
        peer_id: peer,
        topic: topic.hash(),
    };

    let out: OutEvent = event.into();

    match out {
        OutEvent::Gossip(inner) => match *inner {
            GossipsubEvent::Subscribed { peer_id, .. } => assert_eq!(peer_id, peer),
            other => return Err(format!("unexpected gossipsub event: {other:?}")),
        },
        other => return Err(format!("unexpected out event: {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_13_out_event_wraps_gossipsub_unsubscribed_event() -> TestResult {
    let peer = peer_id();
    let topic = IdentTopic::new("/remzar/e2e/behaviour/13");

    let event = GossipsubEvent::Unsubscribed {
        peer_id: peer,
        topic: topic.hash(),
    };

    let out: OutEvent = event.into();

    match out {
        OutEvent::Gossip(inner) => match *inner {
            GossipsubEvent::Unsubscribed { peer_id, .. } => assert_eq!(peer_id, peer),
            other => return Err(format!("unexpected gossipsub event: {other:?}")),
        },
        other => return Err(format!("unexpected out event: {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_14_kad_bootstrap_checked_without_known_peers_returns_error() -> TestResult {
    let mut b = behaviour()?;

    let err = b
        .kad_bootstrap_checked()
        .expect_err("bootstrap without peers must fail");

    assert!(
        err.to_string().contains("no known peers"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn e2e_15_kad_get_closest_peers_checked_is_safe_without_known_peers() -> TestResult {
    let mut b = behaviour()?;

    let _query = b
        .kad_get_closest_peers_checked(peer_id())
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_16_kad_add_bootstrap_base_ip4_addr_is_accepted() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31016)?;

    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_17_kad_add_bootstrap_accepts_p2p_suffixed_addr_and_normalizes_internally() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr_peer = peer_id();

    let base = ip4_addr(31017)?;
    let full = p2p_addr(base.clone(), addr_peer);

    assert!(has_p2p_suffix(&full));
    assert_eq!(strip_p2p_for_test(&full), base);

    b.kad_add_bootstrap(peer, full).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_18_kad_add_bootstrap_allows_ipv6_addr() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip6_addr(31018)?;

    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_19_kad_add_bootstrap_allows_dns_addr() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = dns_addr(31019)?;

    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_20_kad_add_bootstrap_allows_memory_addr() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = memory_addr(20);

    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_21_kad_add_bootstrap_rejects_oversized_multiaddr() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = oversized_multiaddr();

    let err = b
        .kad_add_bootstrap(peer, addr)
        .expect_err("oversized multiaddr must fail");

    assert!(
        err.to_string().contains("multiaddr too large"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn e2e_22_kad_add_bootstrap_duplicate_addr_is_safe() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31022)?;

    b.kad_add_bootstrap(peer, addr.clone()).map_err(fmt_err)?;
    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_23_kad_add_bootstrap_multiple_addrs_for_same_peer_are_safe() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let first = ip4_addr(31023)?;
    let second = memory_addr(23);

    b.kad_add_bootstrap(peer, first).map_err(fmt_err)?;
    b.kad_add_bootstrap(peer, second).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_24_kad_add_bootstrap_same_addr_for_two_peers_is_safe() -> TestResult {
    let mut b = behaviour()?;

    let first_peer = peer_id();
    let second_peer = peer_id();
    let addr = ip4_addr(31024)?;

    b.kad_add_bootstrap(first_peer, addr.clone())
        .map_err(fmt_err)?;
    b.kad_add_bootstrap(second_peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_25_kad_bootstrap_checked_succeeds_after_known_bootstrap_peer() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31025)?;

    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_26_kad_get_closest_peers_checked_succeeds_after_known_bootstrap_peer() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31026)?;

    b.kad_add_bootstrap(peer, addr).map_err(fmt_err)?;

    let _query = b
        .kad_get_closest_peers_checked(peer_id())
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_27_kad_legacy_add_bootstrap_adds_valid_addr_without_panic() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31027)?;

    b.kad_add_bootstrap_legacy(peer, addr);

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_28_kad_legacy_add_bootstrap_ignores_oversized_addr_error() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    b.kad_add_bootstrap_legacy(peer, oversized_multiaddr());

    let err = b
        .kad_bootstrap_checked()
        .expect_err("legacy oversized insert should not create known peer");

    assert!(err.to_string().contains("no known peers"));

    Ok(())
}

#[test]
fn e2e_29_kad_legacy_bootstrap_without_peers_does_not_panic() -> TestResult {
    let mut b = behaviour()?;

    b.kad_bootstrap();

    Ok(())
}

#[test]
fn e2e_30_kad_legacy_get_closest_peers_does_not_panic() -> TestResult {
    let mut b = behaviour()?;

    b.kad_get_closest_peers(peer_id());

    Ok(())
}

#[test]
fn e2e_31_ingest_identify_empty_addrs_is_noop() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    b.ingest_identify_addrs(&peer, &[]).map_err(fmt_err)?;

    let err = b
        .kad_bootstrap_checked()
        .expect_err("empty identify ingest should not create known peer");

    assert!(err.to_string().contains("no known peers"));

    Ok(())
}

#[test]
fn e2e_32_ingest_identify_base_ip4_addr_adds_to_kad() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31032)?;

    b.ingest_identify_addrs(&peer, &[addr]).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_33_ingest_identify_accepts_p2p_suffixed_addr_and_normalizes_internally() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let base = ip4_addr(31033)?;
    let full = p2p_addr(base.clone(), peer_id());

    assert!(has_p2p_suffix(&full));
    assert_eq!(strip_p2p_for_test(&full), base);

    b.ingest_identify_addrs(&peer, &[full]).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_34_ingest_identify_multiple_addr_types_are_safe() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let addrs = vec![
        ip4_addr(31034)?,
        ip6_addr(31034)?,
        dns_addr(31034)?,
        memory_addr(34),
    ];

    b.ingest_identify_addrs(&peer, &addrs).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_35_ingest_identify_rejects_oversized_first_addr() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let err = b
        .ingest_identify_addrs(&peer, &[oversized_multiaddr()])
        .expect_err("oversized identify addr must fail");

    assert!(
        err.to_string().contains("multiaddr too large"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn e2e_36_ingest_identify_rejects_oversized_addr_after_valid_prefix() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let good = ip4_addr(31036)?;
    let bad = oversized_multiaddr();

    let err = b
        .ingest_identify_addrs(&peer, &[good, bad])
        .expect_err("oversized identify addr must fail");

    assert!(
        err.to_string().contains("multiaddr too large"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn e2e_37_ingest_identify_rejects_addr_count_beyond_64_before_oversize_check() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let mut addrs = Vec::new();

    for i in 0u64..MAX_IDENTIFY_ADDRS_INGEST_FOR_TEST as u64 {
        addrs.push(memory_addr(10_000 + i));
    }

    addrs.push(oversized_multiaddr());

    let err = b
        .ingest_identify_addrs(&peer, &addrs)
        .expect_err("identify ingest over 64 addresses must fail");

    assert!(
        err.to_string().contains("too many identify addrs"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn e2e_38_ingest_identify_rejects_more_than_64_addresses_without_partial_insert() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();

    let mut addrs = Vec::new();

    for i in 0u64..70u64 {
        addrs.push(memory_addr(20_000 + i));
    }

    let err = b
        .ingest_identify_addrs(&peer, &addrs)
        .expect_err("identify ingest over 64 addresses must fail");

    assert!(
        err.to_string().contains("too many identify addrs"),
        "unexpected error: {err}"
    );

    let err = b
        .kad_bootstrap_checked()
        .expect_err("rejected identify ingest must not create known peers");

    assert!(err.to_string().contains("no known peers"));

    Ok(())
}

#[test]
fn e2e_39_ingest_identify_duplicate_addrs_are_safe() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31039)?;

    b.ingest_identify_addrs(&peer, &[addr.clone(), addr.clone(), addr])
        .map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_40_ingest_identify_same_addrs_for_different_peers_are_safe() -> TestResult {
    let mut b = behaviour()?;

    let first_peer = peer_id();
    let second_peer = peer_id();
    let addr = ip4_addr(31040)?;

    b.ingest_identify_addrs(&first_peer, &[addr.clone()])
        .map_err(fmt_err)?;
    b.ingest_identify_addrs(&second_peer, &[addr])
        .map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_41_ingest_identify_then_bootstrap_checked_succeeds() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31041)?;

    b.ingest_identify_addrs(&peer, &[addr]).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_42_ingest_identify_then_get_closest_peers_checked_succeeds() -> TestResult {
    let mut b = behaviour()?;
    let peer = peer_id();
    let addr = ip4_addr(31042)?;

    b.ingest_identify_addrs(&peer, &[addr]).map_err(fmt_err)?;

    let _query = b
        .kad_get_closest_peers_checked(peer_id())
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_43_kad_add_bootstrap_with_mismatched_p2p_suffix_is_safe() -> TestResult {
    let mut b = behaviour()?;

    let argument_peer = peer_id();
    let suffix_peer = peer_id();

    let base = ip4_addr(31043)?;
    let full = p2p_addr(base.clone(), suffix_peer);

    assert!(has_p2p_suffix(&full));
    assert_eq!(strip_p2p_for_test(&full), base);

    b.kad_add_bootstrap(argument_peer, full).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_44_ingest_identify_with_mismatched_p2p_suffix_is_safe() -> TestResult {
    let mut b = behaviour()?;

    let argument_peer = peer_id();
    let suffix_peer = peer_id();

    let base = ip4_addr(31044)?;
    let full = p2p_addr(base.clone(), suffix_peer);

    assert!(has_p2p_suffix(&full));
    assert_eq!(strip_p2p_for_test(&full), base);

    b.ingest_identify_addrs(&argument_peer, &[full])
        .map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_45_normalized_kad_bootstrap_address_matches_base_transport_addr() -> TestResult {
    let mut b = behaviour()?;

    let peer = peer_id();
    let base = ip4_addr(31045)?;
    let full = p2p_addr(base.clone(), peer);

    assert!(has_p2p_suffix(&full));

    let normalized = strip_p2p_for_test(&full);
    assert_eq!(normalized, base);
    assert!(!has_p2p_suffix(&normalized));

    b.kad_add_bootstrap(peer, full).map_err(fmt_err)?;

    let _query = b.kad_bootstrap_checked().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_46_remzar_behaviour_can_be_embedded_in_real_swarm() -> TestResult {
    let swarm = build_swarm()?;

    assert_eq!(swarm.behaviour().gossipsub.all_peers().count(), 0);

    Ok(())
}

#[test]
fn e2e_47_real_swarm_can_subscribe_gossipsub_topic_through_behaviour_mut() -> TestResult {
    let mut swarm = build_swarm()?;

    let topic = IdentTopic::new("/remzar/e2e/behaviour/47");

    let subscribed = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(fmt_err)?;

    assert!(subscribed);

    Ok(())
}

#[test]
fn e2e_48_real_swarm_can_use_kad_add_bootstrap_through_behaviour_mut() -> TestResult {
    let mut swarm = build_swarm()?;

    let peer = peer_id();
    let addr = ip4_addr(31048)?;

    swarm
        .behaviour_mut()
        .kad_add_bootstrap(peer, addr)
        .map_err(fmt_err)?;

    let _query = swarm
        .behaviour_mut()
        .kad_bootstrap_checked()
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_49_real_swarm_can_use_identify_ingest_through_behaviour_mut() -> TestResult {
    let mut swarm = build_swarm()?;

    let peer = peer_id();
    let addr = ip4_addr(31049)?;

    swarm
        .behaviour_mut()
        .ingest_identify_addrs(&peer, &[addr])
        .map_err(fmt_err)?;

    let _query = swarm
        .behaviour_mut()
        .kad_bootstrap_checked()
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_50_full_behaviour_lifecycle_gossip_kad_identify_ingest_bootstrap_and_swarm_wiring()
-> TestResult {
    let mut swarm = build_swarm()?;

    let topic = IdentTopic::new("/remzar/e2e/behaviour/50");
    assert!(
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(fmt_err)?
    );

    let bootstrap_peer = peer_id();
    let identify_peer = peer_id();

    let bootstrap_base = ip4_addr(31050)?;
    let bootstrap_full = p2p_addr(bootstrap_base.clone(), peer_id());

    assert!(has_p2p_suffix(&bootstrap_full));
    assert_eq!(strip_p2p_for_test(&bootstrap_full), bootstrap_base);

    swarm
        .behaviour_mut()
        .kad_add_bootstrap(bootstrap_peer, bootstrap_full)
        .map_err(fmt_err)?;

    let identify_base = ip4_addr(31051)?;
    let identify_full = p2p_addr(identify_base.clone(), peer_id());

    assert!(has_p2p_suffix(&identify_full));
    assert_eq!(strip_p2p_for_test(&identify_full), identify_base);

    swarm
        .behaviour_mut()
        .ingest_identify_addrs(&identify_peer, &[identify_full])
        .map_err(fmt_err)?;

    let _bootstrap_query = swarm
        .behaviour_mut()
        .kad_bootstrap_checked()
        .map_err(fmt_err)?;

    let _closest_query = swarm
        .behaviour_mut()
        .kad_get_closest_peers_checked(peer_id())
        .map_err(fmt_err)?;

    assert_eq!(swarm.behaviour().gossipsub.all_peers().count(), 0);

    Ok(())
}
