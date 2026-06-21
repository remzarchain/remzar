#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use remzar::network::p2p_003_behaviour::RemzarBehaviour;
use remzar::network::p2p_004_peerdiscovery::{add_peerdiscovery_peers, kick_off_peerdiscovery};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::alpha_003_detection_system::DetectionSystem;

fn build_behaviour() -> Result<RemzarBehaviour> {
    RemzarBehaviour::new(Keypair::generate_ed25519())
}

fn detection_system() -> DetectionSystem {
    DetectionSystem::new()
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
    base.push(Protocol::P2p(*peer));
    base
}

fn full_memory_addr(seed: u64, peer: &PeerId) -> Multiaddr {
    attach_peer(memory_addr(seed), peer)
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

fn oversized_full_multiaddr(peer: &PeerId) -> Multiaddr {
    let mut base = Multiaddr::empty();
    let mut seed = 1_u64;

    loop {
        let mut candidate_base = base.clone();
        candidate_base.push(Protocol::Memory(seed));
        let candidate_full = attach_peer(candidate_base.clone(), peer);

        if candidate_full.to_vec().len() > 256_usize {
            return candidate_full;
        }

        base = candidate_base;
        seed = seed.saturating_add(1_u64);
    }
}

fn largest_reasonable_full_multiaddr(peer: &PeerId) -> Multiaddr {
    let mut base = Multiaddr::empty();
    let mut seed = 1_u64;

    loop {
        let mut candidate_base = base.clone();
        candidate_base.push(Protocol::Memory(seed));
        let candidate_full = attach_peer(candidate_base.clone(), peer);

        if candidate_full.to_vec().len() > 256_usize {
            return attach_peer(base, peer);
        }

        base = candidate_base;
        seed = seed.saturating_add(1_u64);
    }
}

fn full_addrs(count: u64, start_seed: u64) -> Vec<Multiaddr> {
    let mut out = Vec::new();

    for offset in 0_u64..count {
        let peer = generated_peer_id();
        out.push(full_memory_addr(start_seed.saturating_add(offset), &peer));
    }

    out
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

fn assert_database_error_contains(result: Result<(), ErrorDetection>, needle: &str) -> Result<()> {
    match result {
        Err(ErrorDetection::DatabaseError { details }) => {
            assert!(details.contains(needle));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected non-database error: {other:?}")),
        Ok(()) => Err(anyhow!("expected database error containing: {needle}")),
    }
}

/* ───────────────────────── bootstrap wrapper ───────────────────────── */

#[test]
fn test_001_kick_off_peerdiscovery_no_peers_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    let result = kick_off_peerdiscovery(&mut behaviour);

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_002_kick_off_peerdiscovery_no_peers_does_not_create_query() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let before = query_count(&behaviour);

    kick_off_peerdiscovery(&mut behaviour)?;

    let after = query_count(&behaviour);
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn test_003_kick_off_peerdiscovery_repeated_empty_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;

    for _round in 0_u8..8_u8 {
        let result = kick_off_peerdiscovery(&mut behaviour);
        assert!(result.is_ok());
    }

    Ok(())
}

/* ───────────────────────── empty / ignored input vectors ───────────────── */

#[test]
fn test_004_add_empty_addr_list_is_ok_and_does_not_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = Vec::<Multiaddr>::new();

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_005_base_addr_without_p2p_is_ignored() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = vec![memory_addr(5_u64)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_006_empty_multiaddr_is_ignored() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = vec![Multiaddr::empty()];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_007_p2p_only_addr_is_ignored_because_base_is_empty() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addrs = vec![attach_peer(Multiaddr::empty(), &peer)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_008_all_base_only_addrs_are_ignored() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = vec![
        memory_addr(8_u64),
        parse_addr("/ip4/127.0.0.1/tcp/36213")?,
        parse_addr("/ip6/::1/tcp/36214")?,
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

/* ───────────────────────── valid discovery vectors ─────────────────────── */

#[test]
fn test_009_single_memory_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addrs = vec![full_memory_addr(9_u64, &peer)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_010_single_ip4_tcp_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let addrs = vec![attach_peer(base, &peer)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_011_single_ip6_tcp_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/36214")?;
    let addrs = vec![attach_peer(base, &peer)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_012_single_dns4_tcp_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/dns4/bootstrap.remzar.local/tcp/36215")?;
    let addrs = vec![attach_peer(base, &peer)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_013_single_quic_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/36216/quic-v1")?;
    let addrs = vec![attach_peer(base, &peer)];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_014_mixed_base_and_full_addr_seeds_from_full_only() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        memory_addr(14_u64),
        Multiaddr::empty(),
        full_memory_addr(15_u64, &peer),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_015_two_unique_full_addrs_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let addrs = vec![
        full_memory_addr(15_u64, &peer_one),
        full_memory_addr(16_u64, &peer_two),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_016_sixteen_unique_full_addrs_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(16_u64, 16_000_u64);

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

/* ───────────────────────── duplicate / dedupe behaviour ───────────────── */

#[test]
fn test_017_duplicate_same_peer_same_addr_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addr = full_memory_addr(17_u64, &peer);
    let addrs = vec![addr.clone(), addr];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_018_duplicate_same_peer_different_addrs_is_deduped_and_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        full_memory_addr(18_u64, &peer),
        full_memory_addr(19_u64, &peer),
        full_memory_addr(20_u64, &peer),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_019_duplicate_same_peer_does_not_trigger_sybil_after_dedupe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let mut addrs = Vec::new();

    for seed in 19_u64..27_u64 {
        addrs.push(full_memory_addr(seed, &peer));
    }

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_020_duplicate_peer_mixed_with_unique_peers_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let repeated_peer = generated_peer_id();
    let unique_one = generated_peer_id();
    let unique_two = generated_peer_id();

    let addrs = vec![
        full_memory_addr(20_u64, &repeated_peer),
        full_memory_addr(21_u64, &repeated_peer),
        full_memory_addr(22_u64, &unique_one),
        full_memory_addr(23_u64, &unique_two),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

/* ───────────────────────── defensive caps / error cases ───────────────── */

#[test]
fn test_021_exactly_256_full_addrs_is_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(256_u64, 21_000_u64);

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_022_257_full_addrs_is_rejected_by_call_cap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(257_u64, 22_000_u64);

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "addr list too large")?;
    Ok(())
}

#[test]
fn test_023_oversized_addr_without_p2p_is_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = vec![oversized_multiaddr()];

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    Ok(())
}

#[test]
fn test_024_oversized_full_addr_with_p2p_is_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addrs = vec![oversized_full_multiaddr(&peer)];

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    Ok(())
}

#[test]
fn test_025_valid_addr_then_oversized_addr_rejects_call_without_seeding() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addrs = vec![full_memory_addr(25_u64, &peer), oversized_multiaddr()];

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_026_preexisting_good_peer_survives_later_oversized_rejected_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let good_peer = generated_peer_id();
    let good_addrs = vec![full_memory_addr(26_u64, &good_peer)];
    add_peerdiscovery_peers(&mut behaviour, &good_addrs, &detection)?;

    let bad_result = add_peerdiscovery_peers(&mut behaviour, &[oversized_multiaddr()], &detection);

    assert_database_error_contains(bad_result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_027_largest_reasonable_full_addr_is_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addr = largest_reasonable_full_multiaddr(&peer);

    assert!(addr.to_vec().len() <= 256_usize);

    add_peerdiscovery_peers(&mut behaviour, &[addr], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_028_generated_oversized_full_addr_is_above_cap_and_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let addr = oversized_full_multiaddr(&peer);

    assert!(addr.to_vec().len() > 256_usize);

    let result = add_peerdiscovery_peers(&mut behaviour, &[addr], &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    Ok(())
}

/* ───────────────────────── kick-off after discovery ─────────────────────── */

#[test]
fn test_029_kick_off_after_valid_peer_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(29_u64, &peer)],
        &detection,
    )?;

    let result = kick_off_peerdiscovery(&mut behaviour);

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_030_kick_off_after_valid_peer_starts_or_keeps_query_state_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(30_u64, &peer)],
        &detection,
    )?;

    let before = query_count(&behaviour);
    kick_off_peerdiscovery(&mut behaviour)?;
    let after = query_count(&behaviour);

    assert!(after >= before);
    Ok(())
}

#[test]
fn test_031_repeated_kick_off_after_valid_peer_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(31_u64, &peer)],
        &detection,
    )?;

    for _round in 0_u8..16_u8 {
        let result = kick_off_peerdiscovery(&mut behaviour);
        assert!(result.is_ok());
    }

    Ok(())
}

/* ───────────────────────── fuzz-style deterministic coverage ───────────── */

#[test]
fn test_032_fuzz_deterministic_64_full_addrs_are_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 32_u64;
    let mut addrs = Vec::new();

    for _round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        let peer = generated_peer_id();
        addrs.push(full_memory_addr(seed, &peer));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_033_fuzz_deterministic_mixed_noise_and_full_addrs_is_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 33_u64;
    let mut addrs = Vec::new();

    for round in 0_u8..32_u8 {
        let seed = lcg_next(&mut state);
        if round % 2_u8 == 0_u8 {
            addrs.push(memory_addr(seed));
        } else {
            let peer = generated_peer_id();
            addrs.push(full_memory_addr(seed, &peer));
        }
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_034_fuzz_deterministic_duplicate_peer_many_addresses_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let mut state = 34_u64;
    let mut addrs = Vec::new();

    for _round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        addrs.push(full_memory_addr(seed, &peer));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

/* ───────────────────────── adversarial network simulation ──────────────── */

#[test]
fn test_035_adversarial_only_p2p_only_addrs_are_ignored() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for _round in 0_u8..64_u8 {
        let peer = generated_peer_id();
        addrs.push(attach_peer(Multiaddr::empty(), &peer));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_036_adversarial_empty_base_and_p2p_only_mix_is_ignored() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for seed in 36_u64..52_u64 {
        addrs.push(Multiaddr::empty());
        addrs.push(memory_addr(seed));
        let peer = generated_peer_id();
        addrs.push(attach_peer(Multiaddr::empty(), &peer));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_037_adversarial_bad_batch_after_good_batch_does_not_destroy_good_state() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let good_peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(37_u64, &good_peer)],
        &detection,
    )?;

    let mut bad_addrs = full_addrs(257_u64, 37_000_u64);
    bad_addrs.push(oversized_multiaddr());

    let bad_result = add_peerdiscovery_peers(&mut behaviour, &bad_addrs, &detection);

    assert_database_error_contains(bad_result, "addr list too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_038_adversarial_mixed_valid_duplicate_noise_and_p2p_only_still_seeds() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let repeated_peer = generated_peer_id();
    let valid_unique = generated_peer_id();

    let addrs = vec![
        Multiaddr::empty(),
        memory_addr(38_u64),
        attach_peer(Multiaddr::empty(), &generated_peer_id()),
        full_memory_addr(39_u64, &repeated_peer),
        full_memory_addr(40_u64, &repeated_peer),
        full_memory_addr(41_u64, &valid_unique),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

/* ───────────────────────── load tests ──────────────────────────────────── */

#[test]
fn test_039_load_100_valid_full_addrs_then_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(100_u64, 39_000_u64);

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_040_combined_peerdiscovery_network_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let peer_three = generated_peer_id();

    let addrs = vec![
        Multiaddr::empty(),
        memory_addr(40_u64),
        attach_peer(Multiaddr::empty(), &generated_peer_id()),
        full_memory_addr(41_u64, &peer_one),
        full_memory_addr(42_u64, &peer_two),
        full_memory_addr(43_u64, &peer_three),
        full_memory_addr(44_u64, &peer_three),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    kick_off_peerdiscovery(&mut behaviour)?;

    let query_id = behaviour.kad_get_closest_peers_checked(peer_one)?;
    let rendered_query = format!("{query_id:?}");

    assert!(!rendered_query.is_empty());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_041_257_base_only_addrs_rejected_before_filtering() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let mut addrs = Vec::new();
    for seed in 0_u64..257_u64 {
        addrs.push(memory_addr(seed));
    }

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "addr list too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_042_exactly_256_base_only_addrs_are_ignored_but_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let mut addrs = Vec::new();
    for seed in 0_u64..256_u64 {
        addrs.push(memory_addr(seed));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_043_255_base_only_plus_one_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let mut addrs = Vec::new();
    for seed in 0_u64..255_u64 {
        addrs.push(memory_addr(seed));
    }
    addrs.push(full_memory_addr(43_000_u64, &peer));

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_044_255_p2p_only_plus_one_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let valid_peer = generated_peer_id();

    let mut addrs = Vec::new();
    for _round in 0_u16..255_u16 {
        addrs.push(attach_peer(Multiaddr::empty(), &generated_peer_id()));
    }
    addrs.push(full_memory_addr(44_000_u64, &valid_peer));

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_045_exactly_256_duplicate_same_peer_full_addrs_are_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let mut addrs = Vec::new();
    for seed in 0_u64..256_u64 {
        addrs.push(full_memory_addr(seed, &peer));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_046_257_duplicate_same_peer_full_addrs_rejected_by_call_cap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let mut addrs = Vec::new();
    for seed in 0_u64..257_u64 {
        addrs.push(full_memory_addr(seed, &peer));
    }

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "addr list too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_047_memory_seed_zero_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(0_u64, &peer)],
        &detection,
    )?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_048_memory_seed_max_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(u64::MAX, &peer)],
        &detection,
    )?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_049_ip4_tcp_port_zero_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/0")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_050_ip4_tcp_port_max_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/65535")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_051_ip6_tcp_port_zero_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/0")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_052_ip6_tcp_port_max_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/65535")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_053_dns4_with_high_port_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/dns4/node.remzar.local/tcp/65535")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_054_udp_quic_port_zero_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/0/quic-v1")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_055_udp_quic_port_max_full_addr_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/65535/quic-v1")?;

    add_peerdiscovery_peers(&mut behaviour, &[attach_peer(base, &peer)], &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_056_valid_full_addr_after_empty_and_base_noise_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        Multiaddr::empty(),
        memory_addr(56_u64),
        parse_addr("/ip4/127.0.0.1/tcp/36256")?,
        full_memory_addr(56_000_u64, &peer),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_057_valid_full_addr_before_empty_and_base_noise_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        full_memory_addr(57_000_u64, &peer),
        Multiaddr::empty(),
        memory_addr(57_u64),
        parse_addr("/ip4/127.0.0.1/tcp/36257")?,
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_058_valid_full_addr_between_ignored_addrs_seeds_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        Multiaddr::empty(),
        memory_addr(58_u64),
        full_memory_addr(58_000_u64, &peer),
        memory_addr(58_001_u64),
        Multiaddr::empty(),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_059_all_ignored_mixed_noise_returns_ok_without_kad_seed() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let addrs = vec![
        Multiaddr::empty(),
        memory_addr(59_u64),
        parse_addr("/ip4/127.0.0.1/tcp/36259")?,
        parse_addr("/ip6/::1/tcp/36259")?,
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_060_repeated_empty_calls_do_not_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for _round in 0_u8..16_u8 {
        add_peerdiscovery_peers(&mut behaviour, &[], &detection)?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_061_repeated_base_only_calls_do_not_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for seed in 0_u64..16_u64 {
        add_peerdiscovery_peers(&mut behaviour, &[memory_addr(seed)], &detection)?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_062_repeated_valid_calls_keep_kad_bootstrappable() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for seed in 0_u64..16_u64 {
        let peer = generated_peer_id();
        add_peerdiscovery_peers(
            &mut behaviour,
            &[full_memory_addr(62_000_u64.saturating_add(seed), &peer)],
            &detection,
        )?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_063_duplicate_peer_first_addr_wins_but_bootstrap_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        full_memory_addr(63_000_u64, &peer),
        full_memory_addr(63_001_u64, &peer),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_064_duplicate_peer_reversed_order_is_still_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        full_memory_addr(64_001_u64, &peer),
        full_memory_addr(64_000_u64, &peer),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_065_duplicate_peer_with_base_noise_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![
        memory_addr(65_u64),
        full_memory_addr(65_000_u64, &peer),
        memory_addr(65_001_u64),
        full_memory_addr(65_002_u64, &peer),
    ];

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_066_oversized_first_rejects_entire_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![oversized_multiaddr(), full_memory_addr(66_u64, &peer)];

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_067_oversized_middle_rejects_entire_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();

    let addrs = vec![
        full_memory_addr(67_u64, &peer_one),
        oversized_multiaddr(),
        full_memory_addr(68_u64, &peer_two),
    ];

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_068_oversized_last_rejects_entire_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    let addrs = vec![full_memory_addr(68_u64, &peer), oversized_multiaddr()];

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_069_existing_seed_survives_oversized_first_in_later_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(69_u64, &peer)],
        &detection,
    )?;

    let later_result =
        add_peerdiscovery_peers(&mut behaviour, &[oversized_multiaddr()], &detection);

    assert_database_error_contains(later_result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_070_existing_seed_survives_oversized_full_in_later_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let good_peer = generated_peer_id();
    let bad_peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(70_u64, &good_peer)],
        &detection,
    )?;

    let later_result = add_peerdiscovery_peers(
        &mut behaviour,
        &[oversized_full_multiaddr(&bad_peer)],
        &detection,
    );

    assert_database_error_contains(later_result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_071_largest_reasonable_full_addr_for_many_peers_is_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for _round in 0_u8..8_u8 {
        let peer = generated_peer_id();
        let addr = largest_reasonable_full_multiaddr(&peer);
        assert!(addr.to_vec().len() <= 256_usize);
        addrs.push(addr);
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_072_oversized_full_addr_for_many_peers_rejects_first_bad_call() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for _round in 0_u8..8_u8 {
        let peer = generated_peer_id();
        let addr = oversized_full_multiaddr(&peer);
        assert!(addr.to_vec().len() > 256_usize);
        addrs.push(addr);
    }

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_073_kick_off_after_ignored_only_batch_still_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[Multiaddr::empty(), memory_addr(73_u64)],
        &detection,
    )?;

    let result = kick_off_peerdiscovery(&mut behaviour);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_074_kick_off_after_exactly_256_ignored_addrs_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let mut addrs = Vec::new();
    for seed in 0_u64..256_u64 {
        addrs.push(memory_addr(seed));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    let result = kick_off_peerdiscovery(&mut behaviour);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_075_kick_off_after_256_valid_addrs_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(256_u64, 75_000_u64);

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    let result = kick_off_peerdiscovery(&mut behaviour);

    assert!(result.is_ok());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_076_property_every_full_addr_form_seeds_but_base_form_does_not() -> Result<()> {
    for seed in 76_u64..86_u64 {
        let detection = detection_system();
        let peer = generated_peer_id();

        let mut base_behaviour = build_behaviour()?;
        let base = memory_addr(seed);
        add_peerdiscovery_peers(&mut base_behaviour, &[base], &detection)?;
        assert!(base_behaviour.kad_bootstrap_checked().is_err());

        let mut full_behaviour = build_behaviour()?;
        let full = full_memory_addr(seed, &peer);
        add_peerdiscovery_peers(&mut full_behaviour, &[full], &detection)?;
        assert!(full_behaviour.kad_bootstrap_checked().is_ok());
    }

    Ok(())
}

#[test]
fn test_077_property_full_addr_with_same_peer_dedupes_across_seeds() -> Result<()> {
    let detection = detection_system();
    let peer = generated_peer_id();

    for start_seed in 77_u64..87_u64 {
        let mut behaviour = build_behaviour()?;
        let addrs = vec![
            full_memory_addr(start_seed, &peer),
            full_memory_addr(start_seed.saturating_add(1_u64), &peer),
            full_memory_addr(start_seed.saturating_add(2_u64), &peer),
        ];

        add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
        assert!(behaviour.kad_bootstrap_checked().is_ok());
    }

    Ok(())
}

#[test]
fn test_078_property_full_addr_with_unique_peers_is_bootstrappable() -> Result<()> {
    let detection = detection_system();

    for start_seed in 78_u64..88_u64 {
        let mut behaviour = build_behaviour()?;
        let addrs = vec![
            full_memory_addr(start_seed, &generated_peer_id()),
            full_memory_addr(start_seed.saturating_add(100_u64), &generated_peer_id()),
            full_memory_addr(start_seed.saturating_add(200_u64), &generated_peer_id()),
        ];

        add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
        assert!(behaviour.kad_bootstrap_checked().is_ok());
    }

    Ok(())
}

#[test]
fn test_079_fuzz_deterministic_128_valid_full_addrs_are_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 79_u64;
    let mut addrs = Vec::new();

    for _round in 0_u8..128_u8 {
        let seed = lcg_next(&mut state);
        addrs.push(full_memory_addr(seed, &generated_peer_id()));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_080_fuzz_deterministic_256_valid_full_addrs_are_accepted() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 80_u64;
    let mut addrs = Vec::new();

    for _round in 0_u16..256_u16 {
        let seed = lcg_next(&mut state);
        addrs.push(full_memory_addr(seed, &generated_peer_id()));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_081_fuzz_deterministic_257_valid_full_addrs_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 81_u64;
    let mut addrs = Vec::new();

    for _round in 0_u16..257_u16 {
        let seed = lcg_next(&mut state);
        addrs.push(full_memory_addr(seed, &generated_peer_id()));
    }

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "addr list too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_082_fuzz_mixed_valid_base_empty_and_p2p_only_keeps_valid_peers() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 82_u64;
    let mut addrs = Vec::new();

    for round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        match round % 4_u8 {
            0_u8 => addrs.push(Multiaddr::empty()),
            1_u8 => addrs.push(memory_addr(seed)),
            2_u8 => addrs.push(attach_peer(Multiaddr::empty(), &generated_peer_id())),
            _ => addrs.push(full_memory_addr(seed, &generated_peer_id())),
        }
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_083_fuzz_mixed_without_valid_full_addrs_does_not_seed_kad() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut state = 83_u64;
    let mut addrs = Vec::new();

    for round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        match round % 3_u8 {
            0_u8 => addrs.push(Multiaddr::empty()),
            1_u8 => addrs.push(memory_addr(seed)),
            _ => addrs.push(attach_peer(Multiaddr::empty(), &generated_peer_id())),
        }
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_084_adversarial_256_p2p_only_addrs_are_ignored() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for _round in 0_u16..256_u16 {
        addrs.push(attach_peer(Multiaddr::empty(), &generated_peer_id()));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_085_adversarial_257_p2p_only_addrs_rejected_by_call_cap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for _round in 0_u16..257_u16 {
        addrs.push(attach_peer(Multiaddr::empty(), &generated_peer_id()));
    }

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "addr list too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_086_adversarial_255_p2p_only_plus_oversized_addr_rejected() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = Vec::new();

    for _round in 0_u16..255_u16 {
        addrs.push(attach_peer(Multiaddr::empty(), &generated_peer_id()));
    }
    addrs.push(oversized_multiaddr());

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_087_adversarial_255_valid_plus_oversized_addr_rejected_without_partial_seed() -> Result<()>
{
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let mut addrs = full_addrs(255_u64, 87_000_u64);
    addrs.push(oversized_multiaddr());

    let result = add_peerdiscovery_peers(&mut behaviour, &addrs, &detection);

    assert_database_error_contains(result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_088_adversarial_256_valid_then_oversized_later_call_keeps_seeded_state() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let good_addrs = full_addrs(256_u64, 88_000_u64);
    add_peerdiscovery_peers(&mut behaviour, &good_addrs, &detection)?;

    let bad_result = add_peerdiscovery_peers(&mut behaviour, &[oversized_multiaddr()], &detection);

    assert_database_error_contains(bad_result, "multiaddr too large")?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_089_load_many_small_valid_batches_keep_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for batch in 0_u64..32_u64 {
        let addrs = full_addrs(
            4_u64,
            89_000_u64.saturating_add(batch.saturating_mul(10_u64)),
        );
        add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_090_load_many_ignored_batches_never_seed_bootstrap() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for batch in 0_u64..32_u64 {
        let addrs = vec![
            Multiaddr::empty(),
            memory_addr(90_000_u64.saturating_add(batch)),
        ];
        add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_err());
    Ok(())
}

#[test]
fn test_091_load_64_batches_one_valid_each_keep_bootstrap_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for batch in 0_u64..64_u64 {
        let peer = generated_peer_id();
        let addrs = vec![
            Multiaddr::empty(),
            memory_addr(91_000_u64.saturating_add(batch)),
            full_memory_addr(91_500_u64.saturating_add(batch), &peer),
        ];
        add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    }

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_092_load_repeated_kickoff_after_many_valid_batches_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    for batch in 0_u64..16_u64 {
        let peer = generated_peer_id();
        add_peerdiscovery_peers(
            &mut behaviour,
            &[full_memory_addr(92_000_u64.saturating_add(batch), &peer)],
            &detection,
        )?;
    }

    for _round in 0_u8..32_u8 {
        let result = kick_off_peerdiscovery(&mut behaviour);
        assert!(result.is_ok());
    }

    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_093_kad_get_closest_after_peerdiscovery_returns_query_id() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(93_u64, &peer)],
        &detection,
    )?;

    let query_id = behaviour.kad_get_closest_peers_checked(peer)?;
    let rendered = format!("{query_id:?}");

    assert!(!rendered.is_empty());
    Ok(())
}

#[test]
fn test_094_kad_get_closest_many_targets_after_peerdiscovery_records_queries() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(16_u64, 94_000_u64);

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    let before = query_count(&behaviour);
    for _round in 0_u8..16_u8 {
        let query_id = behaviour.kad_get_closest_peers_checked(generated_peer_id())?;
        let rendered = format!("{query_id:?}");
        assert!(!rendered.is_empty());
    }
    let after = query_count(&behaviour);

    assert!(after >= before.saturating_add(16_usize));
    Ok(())
}

#[test]
fn test_095_kickoff_after_kad_get_closest_query_is_ok() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let peer = generated_peer_id();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(95_u64, &peer)],
        &detection,
    )?;

    let query_id = behaviour.kad_get_closest_peers_checked(peer)?;
    let rendered = format!("{query_id:?}");
    assert!(!rendered.is_empty());

    let result = kick_off_peerdiscovery(&mut behaviour);
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_096_combined_ignored_then_valid_then_bootstrap_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    add_peerdiscovery_peers(
        &mut behaviour,
        &[Multiaddr::empty(), memory_addr(96_u64)],
        &detection,
    )?;
    assert!(behaviour.kad_bootstrap_checked().is_err());

    let peer = generated_peer_id();
    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(96_000_u64, &peer)],
        &detection,
    )?;

    kick_off_peerdiscovery(&mut behaviour)?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_097_combined_valid_then_ignored_then_bootstrap_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let peer = generated_peer_id();
    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(97_000_u64, &peer)],
        &detection,
    )?;

    add_peerdiscovery_peers(
        &mut behaviour,
        &[Multiaddr::empty(), memory_addr(97_u64)],
        &detection,
    )?;

    kick_off_peerdiscovery(&mut behaviour)?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_098_combined_valid_then_rejected_then_bootstrap_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let peer = generated_peer_id();
    add_peerdiscovery_peers(
        &mut behaviour,
        &[full_memory_addr(98_000_u64, &peer)],
        &detection,
    )?;

    let rejected = add_peerdiscovery_peers(&mut behaviour, &[oversized_multiaddr()], &detection);
    assert_database_error_contains(rejected, "multiaddr too large")?;

    kick_off_peerdiscovery(&mut behaviour)?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_099_combined_max_valid_call_then_query_and_kickoff_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();
    let addrs = full_addrs(256_u64, 99_000_u64);
    let target = generated_peer_id();

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;

    let query_id = behaviour.kad_get_closest_peers_checked(target)?;
    let rendered = format!("{query_id:?}");
    assert!(!rendered.is_empty());

    kick_off_peerdiscovery(&mut behaviour)?;
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}

#[test]
fn test_100_combined_adversarial_load_peerdiscovery_path_is_safe() -> Result<()> {
    let mut behaviour = build_behaviour()?;
    let detection = detection_system();

    let first_valid_peer = generated_peer_id();
    let second_valid_peer = generated_peer_id();
    let duplicate_peer = generated_peer_id();

    let mut addrs = vec![
        Multiaddr::empty(),
        memory_addr(100_u64),
        attach_peer(Multiaddr::empty(), &generated_peer_id()),
        full_memory_addr(100_000_u64, &first_valid_peer),
        full_memory_addr(100_001_u64, &second_valid_peer),
        full_memory_addr(100_002_u64, &duplicate_peer),
        full_memory_addr(100_003_u64, &duplicate_peer),
    ];

    for seed in 100_010_u64..100_050_u64 {
        addrs.push(memory_addr(seed));
    }

    add_peerdiscovery_peers(&mut behaviour, &addrs, &detection)?;
    kick_off_peerdiscovery(&mut behaviour)?;

    let query_id = behaviour.kad_get_closest_peers_checked(first_valid_peer)?;
    let rendered = format!("{query_id:?}");

    assert!(!rendered.is_empty());
    assert!(behaviour.kad_bootstrap_checked().is_ok());
    Ok(())
}
