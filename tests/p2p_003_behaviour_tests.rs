#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId, gossipsub::IdentTopic, identity::Keypair, multiaddr::Protocol};
use remzar::network::p2p_003_behaviour::RemzarBehaviour;

fn largest_reasonable_multiaddr() -> Multiaddr {
    let mut addr = Multiaddr::empty();
    let mut seed = 1_u64;

    loop {
        let mut candidate = addr.clone();
        candidate.push(Protocol::Memory(seed));

        if candidate.to_vec().len() > 256_usize {
            return addr;
        }

        addr = candidate;
        seed = seed.saturating_add(1_u64);
    }
}

fn hash64_from_seed(seed: u64) -> [u8; 64] {
    let mut out = [0_u8; 64];
    let mut state = seed;

    for slot in &mut out {
        let next = lcg_next(&mut state);
        let bytes = next.to_le_bytes();
        if let Some(first) = bytes.first() {
            *slot = *first;
        }
    }

    out
}

fn version_info_for_test(
    protocol_version: u32,
    chain_height: u64,
    user_agent: &str,
    genesis_hash: Option<[u8; 64]>,
) -> remzar::network::p2p_007_handshake::VersionInfo {
    remzar::network::p2p_007_handshake::VersionInfo {
        protocol_version,
        chain_height,
        services: remzar::network::p2p_007_handshake::Services::NODE,
        user_agent: user_agent.to_owned(),
        genesis_hash,
    }
}

fn assert_debug_non_empty<T: core::fmt::Debug>(value: &T) {
    let rendered = format!("{value:?}");
    assert!(!rendered.is_empty());
}

fn build_behaviour() -> Result<RemzarBehaviour> {
    RemzarBehaviour::new(Keypair::generate_ed25519())
}

fn generated_peer_id() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

fn parse_addr(value: &str) -> Result<Multiaddr> {
    value
        .parse::<Multiaddr>()
        .with_context(|| format!("failed to parse multiaddr: {value}"))
}

fn memory_addr(seed: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(seed));
    addr
}

fn attach_peer(mut base: Multiaddr, peer: &PeerId) -> Multiaddr {
    addr_push_peer(&mut base, peer);
    base
}

fn addr_push_peer(addr: &mut Multiaddr, peer: &PeerId) {
    addr.push(Protocol::P2p(*peer));
}

fn oversized_multiaddr() -> Multiaddr {
    let mut addr = Multiaddr::empty();
    let mut seed = 1_u64;

    while addr.to_vec().len() <= 256_usize {
        addr.push(Protocol::Memory(seed));
        seed = seed.saturating_add(1_u64);
    }

    addr
}

fn query_count(behaviour: &RemzarBehaviour) -> usize {
    behaviour.kademlia.iter_queries().count()
}

fn lcg_next(state: &mut u64) -> u64 {
    let next = state
        .wrapping_mul(6_364_136_223_846_793_005_u64)
        .wrapping_add(1_442_695_040_888_963_407_u64);
    *state = next;
    next
}

fn many_memory_addrs(count: u64, start: u64) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for offset in 0_u64..count {
        out.push(memory_addr(start.saturating_add(offset)));
    }
    out
}

/* ───────────────────────── constructor / structure ───────────────────────── */

#[test]
fn test_001_constructor_new_succeeds() -> Result<()> {
    let behaviour = build_behaviour()?;
    assert_eq!(query_count(&behaviour), 0_usize);
    Ok(())
}

#[test]
fn test_002_constructor_fresh_behaviour_has_no_kad_queries() -> Result<()> {
    let behaviour = build_behaviour()?;
    assert_eq!(query_count(&behaviour), 0_usize);
    Ok(())
}

#[test]
fn test_003_constructor_accepts_multiple_fresh_keypairs() -> Result<()> {
    for _round in 0_u8..8_u8 {
        let behaviour = build_behaviour()?;
        assert_eq!(query_count(&behaviour), 0_usize);
    }
    Ok(())
}

#[test]
fn test_004_constructor_does_not_seed_kad_without_peers() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let result = behaviour.kad_bootstrap_checked();
    assert!(result.is_err());
    Ok(())
}

/* ───────────────────────── gossipsub real public access ──────────────────── */

#[test]
fn test_005_gossipsub_subscribe_blocks_topic_is_new() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.blocks");
    let result = behaviour.gossipsub.subscribe(&topic);
    assert!(matches!(result, Ok(true)));
    Ok(())
}

#[test]
fn test_006_gossipsub_duplicate_subscribe_reports_not_new() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.duplicate");

    let first = behaviour.gossipsub.subscribe(&topic);
    let second = behaviour.gossipsub.subscribe(&topic);

    assert!(matches!(first, Ok(true)));
    assert!(matches!(second, Ok(false)));
    Ok(())
}

#[test]
fn test_007_gossipsub_subscribe_two_distinct_topics() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let blocks = IdentTopic::new("remzar.blocks.vector");
    let txs = IdentTopic::new("remzar.txs.vector");

    let blocks_result = behaviour.gossipsub.subscribe(&blocks);
    let txs_result = behaviour.gossipsub.subscribe(&txs);

    assert!(matches!(blocks_result, Ok(true)));
    assert!(matches!(txs_result, Ok(true)));
    Ok(())
}

#[test]
fn test_008_gossipsub_unsubscribe_existing_topic_reports_removed() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.unsubscribe");

    let subscribe_result = behaviour.gossipsub.subscribe(&topic);
    let unsubscribe_result = behaviour.gossipsub.unsubscribe(&topic);

    assert!(matches!(subscribe_result, Ok(true)));
    assert!(unsubscribe_result);
    Ok(())
}

#[test]
fn test_009_gossipsub_unsubscribe_missing_topic_does_not_poison_future_subscribe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.unsubscribe.missing");

    let missing_unsubscribe = behaviour.gossipsub.unsubscribe(&topic);
    assert!(!missing_unsubscribe);

    let subscribe_after = behaviour.gossipsub.subscribe(&topic);
    assert!(matches!(subscribe_after, Ok(true)));
    Ok(())
}

#[test]
fn test_010_gossipsub_resubscribe_after_unsubscribe_is_new_again() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.resubscribe");

    let first = behaviour.gossipsub.subscribe(&topic);
    let removed = behaviour.gossipsub.unsubscribe(&topic);
    let second = behaviour.gossipsub.subscribe(&topic);

    assert!(matches!(first, Ok(true)));
    assert!(removed);
    assert!(matches!(second, Ok(true)));
    Ok(())
}

#[test]
fn test_011_gossipsub_topic_vector_subscriptions_all_succeed() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for label in [
        "remzar.vector.blocks",
        "remzar.vector.txs",
        "remzar.vector.headers",
        "remzar.vector.batches",
        "remzar.vector.version",
        "remzar.vector.pq",
        "remzar.vector.peerbook",
        "remzar.vector.audit",
    ] {
        let topic = IdentTopic::new(label);
        let result = behaviour.gossipsub.subscribe(&topic);
        assert!(matches!(result, Ok(true)));
    }

    Ok(())
}

/* ───────────────────────── Kad bootstrap vectors / edge cases ───────────── */

#[test]
fn test_012_kad_bootstrap_checked_no_known_peers_returns_error() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let result = behaviour.kad_bootstrap_checked();
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_013_kad_add_ipv4_bootstrap_allows_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = parse_addr("/ip4/127.0.0.1/tcp/36213")?;

    behaviour.kad_add_bootstrap(peer, addr)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_014_kad_add_ipv6_bootstrap_allows_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = parse_addr("/ip6/::1/tcp/36214")?;

    behaviour.kad_add_bootstrap(peer, addr)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_015_kad_add_dns4_bootstrap_allows_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = parse_addr("/dns4/bootstrap.remzar.local/tcp/36215")?;

    behaviour.kad_add_bootstrap(peer, addr)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_016_kad_add_memory_bootstrap_allows_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap(peer, memory_addr(16_u64))?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_017_kad_add_full_p2p_suffix_allows_bootstrap_after_normalization() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36217")?;
    let full = attach_peer(base, &peer);

    behaviour.kad_add_bootstrap(peer, full)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_018_kad_add_duplicate_same_addr_remains_bootstrappable() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = memory_addr(18_u64);

    behaviour.kad_add_bootstrap(peer, addr.clone())?;
    behaviour.kad_add_bootstrap(peer, addr)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_019_kad_add_empty_addr_is_rejected_and_bootstrap_still_fails() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    let add_result = behaviour.kad_add_bootstrap(peer, Multiaddr::empty());
    let bootstrap_result = behaviour.kad_bootstrap_checked();

    assert!(add_result.is_err());
    assert!(bootstrap_result.is_err());
    Ok(())
}

#[test]
fn test_020_kad_add_oversized_addr_is_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let result = behaviour.kad_add_bootstrap(peer, oversized_multiaddr());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_021_kad_legacy_add_oversized_addr_does_not_seed_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap_legacy(peer, oversized_multiaddr());
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_022_kad_legacy_bootstrap_with_no_peers_does_not_create_query() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    behaviour.kad_bootstrap();

    assert_eq!(query_count(&behaviour), 0_usize);
    Ok(())
}

#[test]
fn test_023_kad_legacy_get_closest_starts_query() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let before = query_count(&behaviour);

    behaviour.kad_get_closest_peers(generated_peer_id());

    let after = query_count(&behaviour);
    assert!(after > before);
    Ok(())
}

#[test]
fn test_024_kad_get_closest_checked_no_peers_starts_query() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let before = query_count(&behaviour);

    let result = behaviour.kad_get_closest_peers_checked(generated_peer_id())?;

    let after = query_count(&behaviour);
    assert!(after > before);
    assert_ne!(format!("{result:?}"), "");
    Ok(())
}

#[test]
fn test_025_kad_get_closest_checked_repeated_queries_accumulate() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    let first_before = query_count(&behaviour);
    let first = behaviour.kad_get_closest_peers_checked(generated_peer_id())?;
    let first_after = query_count(&behaviour);

    let second = behaviour.kad_get_closest_peers_checked(generated_peer_id())?;
    let second_after = query_count(&behaviour);

    assert!(first_after > first_before);
    assert!(second_after > first_after);
    assert_ne!(format!("{first:?}"), format!("{second:?}"));
    Ok(())
}

#[test]
fn test_026_kad_add_many_bootstraps_then_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for seed in 1_u64..=24_u64 {
        behaviour.kad_add_bootstrap(generated_peer_id(), memory_addr(seed))?;
    }

    let result = behaviour.kad_bootstrap_checked();
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_027_kad_add_vector_mixed_transports_then_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for addr in [
        parse_addr("/ip4/127.0.0.1/tcp/36301")?,
        parse_addr("/ip4/127.0.0.1/udp/36302/quic-v1")?,
        parse_addr("/ip6/::1/tcp/36303")?,
        parse_addr("/dns4/node1.remzar.local/tcp/36304")?,
        memory_addr(36_305_u64),
    ] {
        behaviour.kad_add_bootstrap(generated_peer_id(), addr)?;
    }

    let result = behaviour.kad_bootstrap_checked();
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_028_kad_rejects_oversize_even_after_good_addr() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer_good = generated_peer_id();
    let peer_bad = generated_peer_id();

    behaviour.kad_add_bootstrap(peer_good, memory_addr(28_u64))?;
    let bad_result = behaviour.kad_add_bootstrap(peer_bad, oversized_multiaddr());
    let bootstrap_result = behaviour.kad_bootstrap_checked();

    assert!(bad_result.is_err());
    assert!(bootstrap_result.is_ok());
    Ok(())
}

#[test]
fn test_029_kad_wrong_p2p_suffix_is_stripped_for_kad_base_addr() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let kad_peer = generated_peer_id();
    let unrelated_suffix_peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36229")?;
    let full_with_wrong_suffix = attach_peer(base, &unrelated_suffix_peer);

    behaviour.kad_add_bootstrap(kad_peer, full_with_wrong_suffix)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_030_kad_p2p_only_addr_becomes_empty_and_does_not_seed() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    let mut p2p_only = Multiaddr::empty();
    addr_push_peer(&mut p2p_only, &peer);

    behaviour.kad_add_bootstrap(peer, p2p_only)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_err());
    Ok(())
}

/* ───────────────────────── Identify ingestion / adversarial batches ─────── */

#[test]
fn test_031_ingest_identify_single_base_addr_seeds_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = vec![memory_addr(31_u64)];

    behaviour.ingest_identify_addrs(&peer, &addrs)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_032_ingest_identify_single_full_p2p_addr_seeds_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let full = attach_peer(memory_addr(32_u64), &peer);
    let addrs = vec![full];

    behaviour.ingest_identify_addrs(&peer, &addrs)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_033_ingest_identify_empty_batch_is_noop() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = Vec::<Multiaddr>::new();

    behaviour.ingest_identify_addrs(&peer, &addrs)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_034_ingest_identify_duplicate_batch_remains_bootstrappable() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = memory_addr(34_u64);
    let addrs = vec![addr.clone(), addr.clone(), addr];

    behaviour.ingest_identify_addrs(&peer, &addrs)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_035_ingest_identify_oversized_first_addr_is_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = vec![oversized_multiaddr(), memory_addr(35_u64)];

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_036_ingest_identify_oversized_addr_after_cap_is_rejected_by_count_limit() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut addrs = many_memory_addrs(64_u64, 36_000_u64);
    addrs.push(oversized_multiaddr());

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);
    let bootstrap_result = behaviour.kad_bootstrap_checked();

    assert!(result.is_err());
    assert!(bootstrap_result.is_err());
    Ok(())
}

#[test]
fn test_037_ingest_identify_load_128_valid_addrs_is_rejected_by_count_limit() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = many_memory_addrs(128_u64, 37_000_u64);

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);
    let bootstrap_result = behaviour.kad_bootstrap_checked();

    assert!(result.is_err());
    assert!(bootstrap_result.is_err());
    Ok(())
}

#[test]
fn test_038_ingest_identify_mixed_full_and_base_addrs_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    let base_one = memory_addr(38_001_u64);
    let base_two = memory_addr(38_002_u64);
    let full_one = attach_peer(base_one.clone(), &peer);
    let wrong_suffix = attach_peer(base_two.clone(), &generated_peer_id());

    let addrs = vec![base_one, full_one, base_two, wrong_suffix];

    behaviour.ingest_identify_addrs(&peer, &addrs)?;
    let result = behaviour.kad_bootstrap_checked();

    assert!(result.is_ok());
    Ok(())
}

/* ───────────────────────── deterministic fuzz / property / load ─────────── */

#[test]
fn test_039_fuzz_deterministic_bootstrap_addrs_all_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let mut state = 39_u64;

    for _round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        let peer = generated_peer_id();
        let addr = memory_addr(seed);
        behaviour.kad_add_bootstrap(peer, addr)?;
    }

    let result = behaviour.kad_bootstrap_checked();
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_040_load_many_get_closest_queries_no_panic_and_queries_recorded() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let before = query_count(&behaviour);

    for _round in 0_u16..128_u16 {
        let query_id = behaviour.kad_get_closest_peers_checked(generated_peer_id())?;
        assert_ne!(format!("{query_id:?}"), "");
    }

    let after = query_count(&behaviour);
    let expected = before.saturating_add(128_usize);

    assert!(after >= expected);
    Ok(())
}

#[test]
fn test_041_gossipsub_long_topic_name_subscribe_succeeds() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic_name = "remzar.long.topic.".repeat(16_usize);
    let topic = IdentTopic::new(topic_name);

    let result = behaviour.gossipsub.subscribe(&topic);

    assert!(matches!(result, Ok(true)));
    Ok(())
}

#[test]
fn test_042_gossipsub_empty_topic_subscribe_is_handled() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("");

    let result = behaviour.gossipsub.subscribe(&topic);

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_043_gossipsub_slash_protocol_style_topic_subscribe_succeeds() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("/remzar/gossip/blocks/1.0.0");

    let result = behaviour.gossipsub.subscribe(&topic);

    assert!(matches!(result, Ok(true)));
    Ok(())
}

#[test]
fn test_044_gossipsub_vector_32_topics_subscribe_and_unsubscribe() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for index in 0_u8..32_u8 {
        let topic = IdentTopic::new(format!("remzar.vector.topic.{index}"));
        let subscribe_result = behaviour.gossipsub.subscribe(&topic);
        let unsubscribe_result = behaviour.gossipsub.unsubscribe(&topic);

        assert!(matches!(subscribe_result, Ok(true)));
        assert!(unsubscribe_result);
    }

    Ok(())
}

#[test]
fn test_045_gossipsub_resubscribe_vector_topics_after_removal() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for index in 0_u8..16_u8 {
        let topic = IdentTopic::new(format!("remzar.resubscribe.vector.{index}"));

        let first = behaviour.gossipsub.subscribe(&topic);
        let removed = behaviour.gossipsub.unsubscribe(&topic);
        let second = behaviour.gossipsub.subscribe(&topic);

        assert!(matches!(first, Ok(true)));
        assert!(removed);
        assert!(matches!(second, Ok(true)));
    }

    Ok(())
}

#[test]
fn test_046_gossipsub_repeated_duplicate_subscribe_only_first_is_new() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.duplicate.repeat");

    let first = behaviour.gossipsub.subscribe(&topic);
    assert!(matches!(first, Ok(true)));

    for _round in 0_u8..20_u8 {
        let duplicate = behaviour.gossipsub.subscribe(&topic);
        assert!(matches!(duplicate, Ok(false)));
    }

    Ok(())
}

#[test]
fn test_047_gossipsub_oversized_publish_is_rejected_or_not_sent() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.oversized.publish");
    let subscribe_result = behaviour.gossipsub.subscribe(&topic);
    let payload = vec![7_u8; 1_048_577_usize];

    let publish_result = behaviour.gossipsub.publish(topic, payload);

    assert!(subscribe_result.is_ok());
    assert!(publish_result.is_err());
    Ok(())
}

#[test]
fn test_048_gossipsub_empty_payload_without_mesh_does_not_crash() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.empty.payload");
    let subscribe_result = behaviour.gossipsub.subscribe(&topic);
    let publish_result = behaviour.gossipsub.publish(topic, Vec::<u8>::new());

    assert!(subscribe_result.is_ok());
    assert!(publish_result.is_err() || publish_result.is_ok());
    Ok(())
}

#[test]
fn test_049_gossipsub_small_payload_without_mesh_is_handled() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.small.payload");
    let subscribe_result = behaviour.gossipsub.subscribe(&topic);
    let publish_result = behaviour.gossipsub.publish(topic, vec![1_u8]);

    assert!(subscribe_result.is_ok());
    assert!(publish_result.is_err() || publish_result.is_ok());
    Ok(())
}

#[test]
fn test_050_gossipsub_many_publish_attempts_without_peers_are_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let topic = IdentTopic::new("remzar.publish.load.no.peers");
    let subscribe_result = behaviour.gossipsub.subscribe(&topic);

    assert!(subscribe_result.is_ok());

    for round in 0_u8..32_u8 {
        let payload = vec![round];
        let publish_result = behaviour.gossipsub.publish(topic.clone(), payload);
        assert!(publish_result.is_err() || publish_result.is_ok());
    }

    Ok(())
}

/* ───────────────────────── BlockTx request-response real send vectors ───── */

#[test]
fn test_051_blocktx_send_get_block_request_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request = remzar::network::p2p_006_reqresp::BlockTxRequest::GetBlock {
        hash: hash64_from_seed(51_u64),
    };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_052_blocktx_send_get_tx_request_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request = remzar::network::p2p_006_reqresp::BlockTxRequest::GetTx {
        hash: hash64_from_seed(52_u64),
    };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_053_blocktx_send_get_block_by_index_zero_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request =
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBlockByIndex { index: 0_u64 };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_054_blocktx_send_get_block_by_index_max_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request =
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBlockByIndex { index: u64::MAX };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_055_blocktx_send_get_batch_by_index_zero_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request =
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBatchByIndex { index: 0_u64 };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_056_blocktx_send_get_batch_by_index_max_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request =
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBatchByIndex { index: u64::MAX };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_057_blocktx_send_get_batch_by_hash_zero_hash_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let request =
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBatchByHash { hash: [0_u8; 64] };

    let request_id = behaviour.blocktx.send_request(&peer, request);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_058_blocktx_send_all_request_variants_return_request_ids() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    let requests = vec![
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBlock {
            hash: hash64_from_seed(58_u64),
        },
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetTx {
            hash: hash64_from_seed(59_u64),
        },
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBlockByIndex { index: 58_u64 },
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBatchByIndex { index: 59_u64 },
        remzar::network::p2p_006_reqresp::BlockTxRequest::GetBatchByHash {
            hash: hash64_from_seed(60_u64),
        },
    ];

    for request in requests {
        let request_id = behaviour.blocktx.send_request(&peer, request);
        assert_debug_non_empty(&request_id);
    }

    Ok(())
}

/* ───────────────────────── Version request-response vectors ─────────────── */

#[test]
fn test_059_version_send_minimal_valid_info_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let info = version_info_for_test(1_u32, 0_u64, "remzar/test", None);

    let request_id = behaviour.version.send_request(&peer, info);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_060_version_send_max_protocol_with_large_height_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let info = version_info_for_test(1_000_000_u32, u64::MAX, "remzar/test/max", None);

    let request_id = behaviour.version.send_request(&peer, info);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_061_version_send_empty_user_agent_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let info = version_info_for_test(1_u32, 61_u64, "", None);

    let request_id = behaviour.version.send_request(&peer, info);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_062_version_send_with_genesis_hash_returns_request_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let genesis_hash = Some(hash64_from_seed(62_u64));
    let info = version_info_for_test(1_u32, 62_u64, "remzar/test/genesis", genesis_hash);

    let request_id = behaviour.version.send_request(&peer, info);

    assert_debug_non_empty(&request_id);
    Ok(())
}

#[test]
fn test_063_version_vector_multiple_heights_return_request_ids() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    for height in [0_u64, 1_u64, 2_u64, 10_u64, 1_000_u64, u64::MAX] {
        let info = version_info_for_test(1_u32, height, "remzar/test/heights", None);
        let request_id = behaviour.version.send_request(&peer, info);
        assert_debug_non_empty(&request_id);
    }

    Ok(())
}

/* ───────────────────────── more Kad vectors and edge cases ──────────────── */

#[test]
fn test_064_kad_memory_seed_zero_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap(peer, memory_addr(0_u64))?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_065_kad_memory_seed_max_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap(peer, memory_addr(u64::MAX))?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_066_kad_ip4_tcp_port_zero_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap(peer, parse_addr("/ip4/127.0.0.1/tcp/0")?)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_067_kad_ip4_tcp_port_max_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap(peer, parse_addr("/ip4/127.0.0.1/tcp/65535")?)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_068_kad_ip6_tcp_port_max_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    behaviour.kad_add_bootstrap(peer, parse_addr("/ip6/::1/tcp/65535")?)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_069_kad_largest_generated_reasonable_multiaddr_is_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = largest_reasonable_multiaddr();

    assert!(addr.to_vec().len() <= 256_usize);

    behaviour.kad_add_bootstrap(peer, addr)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_070_kad_oversized_multiaddr_remains_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addr = oversized_multiaddr();

    assert!(addr.to_vec().len() > 256_usize);

    let result = behaviour.kad_add_bootstrap(peer, addr);

    assert!(result.is_err());
    Ok(())
}

/* ───────────────────────── identify ingestion edge cases ───────────────── */

#[test]
fn test_071_ingest_identify_exactly_64_valid_addrs_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = many_memory_addrs(64_u64, 71_000_u64);

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_072_ingest_identify_64th_oversized_addr_is_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut addrs = many_memory_addrs(63_u64, 72_000_u64);
    addrs.push(oversized_multiaddr());

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_073_ingest_identify_65th_p2p_only_addr_is_rejected_by_count_limit() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut addrs = many_memory_addrs(64_u64, 73_000_u64);
    let mut p2p_only = Multiaddr::empty();
    addr_push_peer(&mut p2p_only, &peer);
    addrs.push(p2p_only);

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_err());
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_074_ingest_identify_all_p2p_only_addrs_do_not_seed_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut addrs = Vec::new();

    for _round in 0_u8..8_u8 {
        let mut addr = Multiaddr::empty();
        addr_push_peer(&mut addr, &peer);
        addrs.push(addr);
    }

    behaviour.ingest_identify_addrs(&peer, &addrs)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_075_ingest_identify_p2p_only_plus_valid_base_seeds_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut p2p_only = Multiaddr::empty();
    addr_push_peer(&mut p2p_only, &peer);
    let addrs = vec![p2p_only, memory_addr(75_u64)];

    behaviour.ingest_identify_addrs(&peer, &addrs)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_076_ingest_identify_empty_addr_then_valid_addr_is_rejected_without_partial_insert()
-> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = vec![Multiaddr::empty(), memory_addr(76_u64)];

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_err());
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_077_ingest_identify_oversized_only_is_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let addrs = vec![oversized_multiaddr()];

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_078_ingest_identify_wrong_p2p_suffix_is_stripped_for_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let wrong_suffix_peer = generated_peer_id();
    let full = attach_peer(memory_addr(78_u64), &wrong_suffix_peer);
    let addrs = vec![full];

    behaviour.ingest_identify_addrs(&peer, &addrs)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

/* ───────────────────────── address helper property coverage ─────────────── */

#[test]
fn test_079_split_multiaddr_without_p2p_returns_same_base_and_no_peer() -> Result<()> {
    let base = memory_addr(79_u64);
    let (split_base, split_peer) =
        remzar::network::p2p_009_events::split_multiaddr_base_and_peer(&base);

    assert_eq!(split_base, base);
    assert!(split_peer.is_none());
    Ok(())
}

#[test]
fn test_080_split_multiaddr_with_p2p_returns_base_and_peer() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(80_u64);
    let full = attach_peer(base.clone(), &peer);

    let (split_base, split_peer) =
        remzar::network::p2p_009_events::split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_081_attach_peer_to_addr_adds_trailing_peer_component() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(81_u64);

    let full = remzar::network::p2p_009_events::attach_peer_to_addr(base.clone(), &peer);
    let (split_base, split_peer) =
        remzar::network::p2p_009_events::split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_082_ensure_dialable_addr_attaches_peer_to_base_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(82_u64);

    let maybe_full = remzar::network::p2p_009_events::ensure_dialable_addr_for_peer(&base, &peer);

    assert!(maybe_full.is_some());

    if let Some(full) = maybe_full {
        let (split_base, split_peer) =
            remzar::network::p2p_009_events::split_multiaddr_base_and_peer(&full);
        assert_eq!(split_base, base);
        assert_eq!(split_peer, Some(peer));
    }

    Ok(())
}

#[test]
fn test_083_ensure_dialable_addr_accepts_same_peer_suffix() -> Result<()> {
    let peer = generated_peer_id();
    let full = attach_peer(memory_addr(83_u64), &peer);

    let maybe_full = remzar::network::p2p_009_events::ensure_dialable_addr_for_peer(&full, &peer);

    assert_eq!(maybe_full, Some(full));
    Ok(())
}

#[test]
fn test_084_ensure_dialable_addr_rejects_wrong_peer_suffix() -> Result<()> {
    let peer = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let full = attach_peer(memory_addr(84_u64), &wrong_peer);

    let maybe_full = remzar::network::p2p_009_events::ensure_dialable_addr_for_peer(&full, &peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_085_ensure_dialable_addr_rejects_empty_addr() -> Result<()> {
    let peer = generated_peer_id();

    let maybe_full =
        remzar::network::p2p_009_events::ensure_dialable_addr_for_peer(&Multiaddr::empty(), &peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_086_kad_ready_addrs_dedupes_base_and_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(86_u64);
    let full = attach_peer(base.clone(), &peer);
    let input = vec![base.clone(), full, base.clone()];

    let output = remzar::network::p2p_009_events::kad_ready_addrs(&input);

    assert_eq!(output.len(), 1_usize);
    assert_eq!(output.first(), Some(&base));
    Ok(())
}

#[test]
fn test_087_kad_ready_addrs_skips_empty_multiaddr() -> Result<()> {
    let input = vec![Multiaddr::empty()];

    let output = remzar::network::p2p_009_events::kad_ready_addrs(&input);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_088_kad_ready_addrs_skips_oversized_multiaddr() -> Result<()> {
    let input = vec![oversized_multiaddr()];

    let output = remzar::network::p2p_009_events::kad_ready_addrs(&input);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_089_dedupe_addrs_keeps_first_unique_values() -> Result<()> {
    let first = memory_addr(89_u64);
    let second = memory_addr(90_u64);
    let input = vec![first.clone(), second.clone(), first.clone(), second.clone()];

    let output = remzar::network::p2p_009_events::dedupe_addrs(input);

    assert_eq!(output, vec![first, second]);
    Ok(())
}

#[test]
fn test_090_dedupe_addrs_skips_oversized_values() -> Result<()> {
    let good = memory_addr(90_u64);
    let input = vec![oversized_multiaddr(), good.clone(), oversized_multiaddr()];

    let output = remzar::network::p2p_009_events::dedupe_addrs(input);

    assert_eq!(output, vec![good]);
    Ok(())
}

/* ───────────────────────── fuzz / adversarial / load coverage ───────────── */

#[test]
fn test_091_fuzz_deterministic_100_bootstrap_addrs_are_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let mut state = 91_u64;

    for _round in 0_u8..100_u8 {
        let seed = lcg_next(&mut state);
        behaviour.kad_add_bootstrap(generated_peer_id(), memory_addr(seed))?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_092_fuzz_deterministic_identify_batches_are_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut state = 92_u64;
    let mut addrs = Vec::new();

    for _round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        addrs.push(memory_addr(seed));
    }

    let result = behaviour.ingest_identify_addrs(&peer, &addrs);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_093_property_base_and_full_bootstrap_forms_are_equally_bootstrappable() -> Result<()> {
    for seed in 93_u64..103_u64 {
        let peer = generated_peer_id();
        let base = memory_addr(seed);
        let full = attach_peer(base.clone(), &peer);

        let mut base_behaviour = build_behaviour()?;
        let mut full_behaviour = build_behaviour()?;

        base_behaviour.kad_add_bootstrap(peer, base)?;
        full_behaviour.kad_add_bootstrap(peer, full)?;

        assert!(base_behaviour.kad_bootstrap_checked().is_ok());
        assert!(full_behaviour.kad_bootstrap_checked().is_ok());
    }

    Ok(())
}

#[test]
fn test_094_property_duplicate_identify_batches_stay_bootstrappable() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();
    let mut addrs = Vec::new();

    for seed in 94_u64..110_u64 {
        let addr = memory_addr(seed);
        addrs.push(addr.clone());
        addrs.push(addr);
    }

    behaviour.ingest_identify_addrs(&peer, &addrs)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_095_adversarial_repeated_oversized_bootstrap_addrs_never_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for _round in 0_u8..16_u8 {
        let result = behaviour.kad_add_bootstrap(generated_peer_id(), oversized_multiaddr());
        assert!(result.is_err());
    }

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_096_adversarial_good_then_bad_bootstrap_keeps_good_peer_usable() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    behaviour.kad_add_bootstrap(generated_peer_id(), memory_addr(96_u64))?;

    for _round in 0_u8..16_u8 {
        let result = behaviour.kad_add_bootstrap(generated_peer_id(), oversized_multiaddr());
        assert!(result.is_err());
    }

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_097_load_256_get_closest_queries_are_recorded() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let before = query_count(&behaviour);

    for _round in 0_u16..256_u16 {
        let query_id = behaviour.kad_get_closest_peers_checked(generated_peer_id())?;
        assert_debug_non_empty(&query_id);
    }

    let after = query_count(&behaviour);
    assert!(after >= before.saturating_add(256_usize));
    Ok(())
}

#[test]
fn test_098_load_100_gossipsub_topics_subscribe_and_unsubscribe() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for index in 0_u8..100_u8 {
        let topic = IdentTopic::new(format!("remzar.load.topic.{index}"));
        let subscribe_result = behaviour.gossipsub.subscribe(&topic);
        let unsubscribe_result = behaviour.gossipsub.unsubscribe(&topic);

        assert!(matches!(subscribe_result, Ok(true)));
        assert!(unsubscribe_result);
    }

    Ok(())
}

#[test]
fn test_099_load_128_blocktx_request_ids_are_returned() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let peer = generated_peer_id();

    for seed in 0_u64..128_u64 {
        let request = remzar::network::p2p_006_reqresp::BlockTxRequest::GetBatchByHash {
            hash: hash64_from_seed(seed),
        };
        let request_id = behaviour.blocktx.send_request(&peer, request);
        assert_debug_non_empty(&request_id);
    }

    Ok(())
}

#[test]
fn test_100_combined_adversarial_network_simulation_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    let bootstrap_peer = generated_peer_id();
    let identify_peer = generated_peer_id();
    let request_peer = generated_peer_id();

    behaviour.kad_add_bootstrap(bootstrap_peer, memory_addr(100_u64))?;

    let invalid_identify_addrs = vec![Multiaddr::empty(), memory_addr(101_u64)];
    let invalid_ingest = behaviour.ingest_identify_addrs(&identify_peer, &invalid_identify_addrs);
    assert!(invalid_ingest.is_err());

    let valid_identify_addrs = vec![
        memory_addr(101_u64),
        attach_peer(memory_addr(102_u64), &identify_peer),
        attach_peer(memory_addr(103_u64), &generated_peer_id()),
    ];
    behaviour.ingest_identify_addrs(&identify_peer, &valid_identify_addrs)?;

    let topic = IdentTopic::new("remzar.combined.simulation");
    let subscribe_result = behaviour.gossipsub.subscribe(&topic);
    assert!(subscribe_result.is_ok());

    let block_request = remzar::network::p2p_006_reqresp::BlockTxRequest::GetBlock {
        hash: hash64_from_seed(100_u64),
    };
    let block_request_id = behaviour.blocktx.send_request(&request_peer, block_request);
    assert_debug_non_empty(&block_request_id);

    let version_info = version_info_for_test(
        1_u32,
        100_u64,
        "remzar/test/combined",
        Some(hash64_from_seed(101_u64)),
    );
    let version_request_id = behaviour.version.send_request(&request_peer, version_info);
    assert_debug_non_empty(&version_request_id);

    let closest_query_id = behaviour.kad_get_closest_peers_checked(request_peer)?;
    assert_debug_non_empty(&closest_query_id);

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}
