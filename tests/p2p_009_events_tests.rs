#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use remzar::network::p2p_009_events::{
    attach_peer_to_addr, dedupe_addrs, ensure_dialable_addr_for_peer, kad_ready_addrs,
    split_multiaddr_base_and_peer,
};

fn oversized_full_addr(peer: &PeerId) -> Multiaddr {
    attach_peer_to_addr(oversized_multiaddr(), peer)
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

fn full_memory_addr(seed: u64, peer: &PeerId) -> Multiaddr {
    attach_peer_to_addr(memory_addr(seed), peer)
}

fn p2p_only_addr(peer: &PeerId) -> Multiaddr {
    attach_peer_to_addr(Multiaddr::empty(), peer)
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

fn largest_reasonable_full_addr(peer: &PeerId) -> Multiaddr {
    let mut base = Multiaddr::empty();
    let mut seed = 1_u64;

    loop {
        let mut candidate_base = base.clone();
        candidate_base.push(Protocol::Memory(seed));
        let candidate_full = attach_peer_to_addr(candidate_base.clone(), peer);

        if candidate_full.to_vec().len() > 256_usize {
            return attach_peer_to_addr(base, peer);
        }

        base = candidate_base;
        seed = seed.saturating_add(1_u64);
    }
}

fn lcg_next(state: &mut u64) -> u64 {
    let next = state
        .wrapping_mul(6_364_136_223_846_793_005_u64)
        .wrapping_add(1_442_695_040_888_963_407_u64);
    *state = next;
    next
}

/* ───────────────────────── split_multiaddr_base_and_peer ───────────────── */

#[test]
fn test_001_split_empty_addr_returns_empty_and_no_peer() -> Result<()> {
    let addr = Multiaddr::empty();

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert!(peer.is_none());
    Ok(())
}

#[test]
fn test_002_split_base_memory_addr_returns_same_and_no_peer() -> Result<()> {
    let addr = memory_addr(2_u64);

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert!(peer.is_none());
    Ok(())
}

#[test]
fn test_003_split_base_ip4_tcp_addr_returns_same_and_no_peer() -> Result<()> {
    let addr = parse_addr("/ip4/127.0.0.1/tcp/36213")?;

    let (base, peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, addr);
    assert!(peer.is_none());
    Ok(())
}

#[test]
fn test_004_split_full_memory_addr_returns_base_and_peer() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(4_u64);
    let full = attach_peer_to_addr(base.clone(), &peer);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_005_split_full_ip4_tcp_addr_returns_base_and_peer() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let full = attach_peer_to_addr(base.clone(), &peer);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_006_split_p2p_only_addr_returns_empty_base_and_peer() -> Result<()> {
    let peer = generated_peer_id();
    let addr = p2p_only_addr(&peer);

    let (base, split_peer) = split_multiaddr_base_and_peer(&addr);

    assert_eq!(base, Multiaddr::empty());
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

/* ───────────────────────── attach_peer_to_addr ─────────────────────────── */

#[test]
fn test_007_attach_peer_to_empty_addr_creates_p2p_only_addr() -> Result<()> {
    let peer = generated_peer_id();

    let full = attach_peer_to_addr(Multiaddr::empty(), &peer);
    let (base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(base, Multiaddr::empty());
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_008_attach_peer_to_memory_addr_round_trips() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(8_u64);

    let full = attach_peer_to_addr(base.clone(), &peer);
    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_009_attach_peer_to_dns_tcp_addr_round_trips() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/dns4/bootstrap.remzar.local/tcp/36213")?;

    let full = attach_peer_to_addr(base.clone(), &peer);
    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_010_attach_peer_to_quic_addr_round_trips() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/36213/quic-v1")?;

    let full = attach_peer_to_addr(base.clone(), &peer);
    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

/* ───────────────────────── ensure_dialable_addr_for_peer ───────────────── */

#[test]
fn test_011_ensure_dialable_attaches_peer_to_base_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(11_u64);

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert!(maybe_full.is_some());

    if let Some(full) = maybe_full {
        let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);
        assert_eq!(split_base, base);
        assert_eq!(split_peer, Some(peer));
    }

    Ok(())
}

#[test]
fn test_012_ensure_dialable_keeps_same_peer_suffix() -> Result<()> {
    let peer = generated_peer_id();
    let full = full_memory_addr(12_u64, &peer);

    let maybe_full = ensure_dialable_addr_for_peer(&full, &peer);

    assert_eq!(maybe_full, Some(full));
    Ok(())
}

#[test]
fn test_013_ensure_dialable_rejects_wrong_peer_suffix() -> Result<()> {
    let wanted_peer = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let full = full_memory_addr(13_u64, &wrong_peer);

    let maybe_full = ensure_dialable_addr_for_peer(&full, &wanted_peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_014_ensure_dialable_rejects_empty_addr() -> Result<()> {
    let peer = generated_peer_id();

    let maybe_full = ensure_dialable_addr_for_peer(&Multiaddr::empty(), &peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_015_ensure_dialable_rejects_p2p_only_addr() -> Result<()> {
    let peer = generated_peer_id();
    let addr = p2p_only_addr(&peer);

    let maybe_full = ensure_dialable_addr_for_peer(&addr, &peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_016_ensure_dialable_rejects_oversized_addr() -> Result<()> {
    let peer = generated_peer_id();
    let addr = oversized_multiaddr();

    assert!(addr.to_vec().len() > 256_usize);

    let maybe_full = ensure_dialable_addr_for_peer(&addr, &peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_017_ensure_dialable_accepts_largest_reasonable_base_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = largest_reasonable_multiaddr();

    assert!(base.to_vec().len() <= 256_usize);

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert!(maybe_full.is_some());
    Ok(())
}

#[test]
fn test_018_ensure_dialable_accepts_largest_reasonable_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let full = largest_reasonable_full_addr(&peer);

    assert!(full.to_vec().len() <= 256_usize);

    let maybe_full = ensure_dialable_addr_for_peer(&full, &peer);

    assert_eq!(maybe_full, Some(full));
    Ok(())
}

/* ───────────────────────── kad_ready_addrs ─────────────────────────────── */

#[test]
fn test_019_kad_ready_empty_input_returns_empty() -> Result<()> {
    let output = kad_ready_addrs(&[]);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_020_kad_ready_skips_empty_addr() -> Result<()> {
    let output = kad_ready_addrs(&[Multiaddr::empty()]);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_021_kad_ready_keeps_base_addr() -> Result<()> {
    let base = memory_addr(21_u64);

    let output = kad_ready_addrs(&[base.clone()]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_022_kad_ready_strips_p2p_suffix() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(22_u64);
    let full = attach_peer_to_addr(base.clone(), &peer);

    let output = kad_ready_addrs(&[full]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_023_kad_ready_dedupes_base_and_full_same_transport_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(23_u64);
    let full = attach_peer_to_addr(base.clone(), &peer);

    let output = kad_ready_addrs(&[base.clone(), full, base.clone()]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_024_kad_ready_dedupes_same_base_with_different_peer_suffixes() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let base = memory_addr(24_u64);
    let full_one = attach_peer_to_addr(base.clone(), &peer_one);
    let full_two = attach_peer_to_addr(base.clone(), &peer_two);

    let output = kad_ready_addrs(&[full_one, full_two]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_025_kad_ready_skips_p2p_only_addr() -> Result<()> {
    let peer = generated_peer_id();
    let addr = p2p_only_addr(&peer);

    let output = kad_ready_addrs(&[addr]);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_026_kad_ready_skips_oversized_addr() -> Result<()> {
    let addr = oversized_multiaddr();

    let output = kad_ready_addrs(&[addr]);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_027_kad_ready_preserves_first_unique_order() -> Result<()> {
    let first = memory_addr(27_u64);
    let second = memory_addr(28_u64);
    let third = memory_addr(29_u64);

    let output = kad_ready_addrs(&[
        first.clone(),
        second.clone(),
        first.clone(),
        third.clone(),
        second.clone(),
    ]);

    assert_eq!(output, vec![first, second, third]);
    Ok(())
}

#[test]
fn test_028_kad_ready_mixed_noise_keeps_only_valid_base_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let valid_base = memory_addr(28_u64);
    let valid_full_base = memory_addr(29_u64);
    let valid_full = attach_peer_to_addr(valid_full_base.clone(), &peer);

    let output = kad_ready_addrs(&[
        Multiaddr::empty(),
        p2p_only_addr(&peer),
        oversized_multiaddr(),
        valid_base.clone(),
        valid_full,
    ]);

    assert_eq!(output, vec![valid_base, valid_full_base]);
    Ok(())
}

/* ───────────────────────── dedupe_addrs ───────────────────────────────── */

#[test]
fn test_029_dedupe_empty_input_returns_empty() -> Result<()> {
    let output = dedupe_addrs(Vec::new());

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_030_dedupe_single_addr_returns_same_addr() -> Result<()> {
    let addr = memory_addr(30_u64);

    let output = dedupe_addrs(vec![addr.clone()]);

    assert_eq!(output, vec![addr]);
    Ok(())
}

#[test]
fn test_031_dedupe_keeps_first_unique_values_in_order() -> Result<()> {
    let first = memory_addr(31_u64);
    let second = memory_addr(32_u64);
    let third = memory_addr(33_u64);

    let output = dedupe_addrs(vec![
        first.clone(),
        second.clone(),
        first.clone(),
        third.clone(),
        second.clone(),
    ]);

    assert_eq!(output, vec![first, second, third]);
    Ok(())
}

#[test]
fn test_032_dedupe_treats_base_and_full_addr_as_distinct() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(32_u64);
    let full = attach_peer_to_addr(base.clone(), &peer);

    let output = dedupe_addrs(vec![base.clone(), full.clone(), base.clone(), full.clone()]);

    assert_eq!(output, vec![base, full]);
    Ok(())
}

#[test]
fn test_033_dedupe_skips_oversized_addrs() -> Result<()> {
    let good = memory_addr(33_u64);

    let output = dedupe_addrs(vec![
        oversized_multiaddr(),
        good.clone(),
        oversized_multiaddr(),
        good.clone(),
    ]);

    assert_eq!(output, vec![good]);
    Ok(())
}

#[test]
fn test_034_dedupe_keeps_distinct_peer_suffixes_for_same_base() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let base = memory_addr(34_u64);
    let full_one = attach_peer_to_addr(base.clone(), &peer_one);
    let full_two = attach_peer_to_addr(base, &peer_two);

    let output = dedupe_addrs(vec![full_one.clone(), full_two.clone(), full_one.clone()]);

    assert_eq!(output, vec![full_one, full_two]);
    Ok(())
}

/* ───────────────────────── fuzz / adversarial / load coverage ──────────── */

#[test]
fn test_035_fuzz_deterministic_64_base_addrs_are_all_kad_ready() -> Result<()> {
    let mut state = 35_u64;
    let mut input = Vec::new();

    for _round in 0_u8..64_u8 {
        input.push(memory_addr(lcg_next(&mut state)));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 64_usize);
    Ok(())
}

#[test]
fn test_036_fuzz_deterministic_64_full_addrs_strip_to_64_kad_bases() -> Result<()> {
    let mut state = 36_u64;
    let mut input = Vec::new();

    for _round in 0_u8..64_u8 {
        let peer = generated_peer_id();
        input.push(full_memory_addr(lcg_next(&mut state), &peer));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 64_usize);
    for addr in output {
        let (_base, peer) = split_multiaddr_base_and_peer(&addr);
        assert!(peer.is_none());
    }

    Ok(())
}

#[test]
fn test_037_adversarial_64_empty_p2p_only_and_oversized_are_all_filtered() -> Result<()> {
    let peer = generated_peer_id();
    let mut input = Vec::new();

    for _round in 0_u8..64_u8 {
        input.push(Multiaddr::empty());
        input.push(p2p_only_addr(&peer));
        input.push(oversized_multiaddr());
    }

    let kad_output = kad_ready_addrs(&input);
    let dedupe_output = dedupe_addrs(input);

    assert!(kad_output.is_empty());
    assert_eq!(dedupe_output.len(), 2_usize);
    Ok(())
}

#[test]
fn test_038_property_ensure_then_split_returns_original_base_and_peer() -> Result<()> {
    for seed in 38_u64..58_u64 {
        let peer = generated_peer_id();
        let base = memory_addr(seed);

        let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);
        assert!(maybe_full.is_some());

        if let Some(full) = maybe_full {
            let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);
            assert_eq!(split_base, base);
            assert_eq!(split_peer, Some(peer));
        }
    }

    Ok(())
}

#[test]
fn test_039_load_256_unique_base_addrs_dedupe_and_kad_ready() -> Result<()> {
    let mut input = Vec::new();

    for seed in 0_u64..256_u64 {
        input.push(memory_addr(seed));
    }

    let deduped = dedupe_addrs(input.clone());
    let kad = kad_ready_addrs(&input);

    assert_eq!(deduped.len(), 256_usize);
    assert_eq!(kad.len(), 256_usize);
    Ok(())
}

#[test]
fn test_040_combined_full_address_pipeline_is_safe() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36213")?;

    let full = attach_peer_to_addr(base.clone(), &peer);
    let ensured = ensure_dialable_addr_for_peer(&full, &peer);
    assert_eq!(ensured, Some(full.clone()));

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);
    assert_eq!(split_base, base.clone());
    assert_eq!(split_peer, Some(peer));

    let deduped = dedupe_addrs(vec![full.clone(), full.clone()]);
    assert_eq!(deduped, vec![full.clone()]);

    let kad = kad_ready_addrs(&[full]);
    assert_eq!(kad, vec![base]);

    Ok(())
}

#[test]
fn test_041_split_full_ip6_tcp_addr_returns_base_and_peer() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/36213")?;
    let full = attach_peer_to_addr(base.clone(), &peer);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_042_split_full_quic_addr_returns_base_and_peer() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/36213/quic-v1")?;
    let full = attach_peer_to_addr(base.clone(), &peer);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_043_split_double_p2p_addr_removes_only_trailing_peer() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let base = memory_addr(43_u64);
    let first_full = attach_peer_to_addr(base, &peer_one);
    let double_full = attach_peer_to_addr(first_full.clone(), &peer_two);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&double_full);

    assert_eq!(split_base, first_full);
    assert_eq!(split_peer, Some(peer_two));
    Ok(())
}

#[test]
fn test_044_attach_peer_to_already_full_addr_appends_new_trailing_peer() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let base = memory_addr(44_u64);
    let first_full = attach_peer_to_addr(base, &peer_one);

    let double_full = attach_peer_to_addr(first_full.clone(), &peer_two);
    let (split_base, split_peer) = split_multiaddr_base_and_peer(&double_full);

    assert_eq!(split_base, first_full);
    assert_eq!(split_peer, Some(peer_two));
    Ok(())
}

#[test]
fn test_045_ensure_dialable_accepts_double_p2p_when_trailing_peer_matches() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let base = memory_addr(45_u64);
    let first_full = attach_peer_to_addr(base, &peer_one);
    let double_full = attach_peer_to_addr(first_full, &peer_two);

    let maybe_full = ensure_dialable_addr_for_peer(&double_full, &peer_two);

    assert_eq!(maybe_full, Some(double_full));
    Ok(())
}

#[test]
fn test_046_ensure_dialable_rejects_double_p2p_when_trailing_peer_differs() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let wanted_peer = generated_peer_id();
    let base = memory_addr(46_u64);
    let first_full = attach_peer_to_addr(base, &peer_one);
    let double_full = attach_peer_to_addr(first_full, &peer_two);

    let maybe_full = ensure_dialable_addr_for_peer(&double_full, &wanted_peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_047_attach_split_roundtrip_with_memory_zero() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(0_u64);
    let full = attach_peer_to_addr(base.clone(), &peer);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_048_attach_split_roundtrip_with_memory_max() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(u64::MAX);
    let full = attach_peer_to_addr(base.clone(), &peer);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

/* ───────────────────────── more ensure_dialable vectors ───────────────── */

#[test]
fn test_049_ensure_dialable_ip4_tcp_port_zero() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/0")?;

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(maybe_full, Some(attach_peer_to_addr(base, &peer)));
    Ok(())
}

#[test]
fn test_050_ensure_dialable_ip4_tcp_port_max() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/65535")?;

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(maybe_full, Some(attach_peer_to_addr(base, &peer)));
    Ok(())
}

#[test]
fn test_051_ensure_dialable_ip6_tcp_port_zero() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/0")?;

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(maybe_full, Some(attach_peer_to_addr(base, &peer)));
    Ok(())
}

#[test]
fn test_052_ensure_dialable_ip6_tcp_port_max() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/65535")?;

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(maybe_full, Some(attach_peer_to_addr(base, &peer)));
    Ok(())
}

#[test]
fn test_053_ensure_dialable_dns4_tcp_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/dns4/node.remzar.local/tcp/36213")?;

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(maybe_full, Some(attach_peer_to_addr(base, &peer)));
    Ok(())
}

#[test]
fn test_054_ensure_dialable_quic_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/36213/quic-v1")?;

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(maybe_full, Some(attach_peer_to_addr(base, &peer)));
    Ok(())
}

#[test]
fn test_055_ensure_dialable_rejects_oversized_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let full = oversized_full_addr(&peer);

    assert!(full.to_vec().len() > 256_usize);

    let maybe_full = ensure_dialable_addr_for_peer(&full, &peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_056_ensure_dialable_accepts_same_peer_on_dns_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/dns4/node.remzar.local/tcp/36214")?;
    let full = attach_peer_to_addr(base, &peer);

    let maybe_full = ensure_dialable_addr_for_peer(&full, &peer);

    assert_eq!(maybe_full, Some(full));
    Ok(())
}

#[test]
fn test_057_ensure_dialable_rejects_wrong_peer_on_dns_addr() -> Result<()> {
    let wanted_peer = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let base = parse_addr("/dns4/node.remzar.local/tcp/36215")?;
    let full = attach_peer_to_addr(base, &wrong_peer);

    let maybe_full = ensure_dialable_addr_for_peer(&full, &wanted_peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_058_ensure_dialable_does_not_modify_input_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(58_u64);
    let original = base.clone();

    let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);

    assert_eq!(base, original);
    assert_eq!(maybe_full, Some(attach_peer_to_addr(original, &peer)));
    Ok(())
}

/* ───────────────────────── more kad_ready_addrs vectors ───────────────── */

#[test]
fn test_059_kad_ready_strips_ip4_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let full = attach_peer_to_addr(base.clone(), &peer);

    let output = kad_ready_addrs(&[full]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_060_kad_ready_strips_ip6_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip6/::1/tcp/36213")?;
    let full = attach_peer_to_addr(base.clone(), &peer);

    let output = kad_ready_addrs(&[full]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_061_kad_ready_strips_quic_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/udp/36213/quic-v1")?;
    let full = attach_peer_to_addr(base.clone(), &peer);

    let output = kad_ready_addrs(&[full]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_062_kad_ready_keeps_largest_reasonable_base_addr() -> Result<()> {
    let base = largest_reasonable_multiaddr();

    assert!(base.to_vec().len() <= 256_usize);

    let output = kad_ready_addrs(&[base.clone()]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_063_kad_ready_strips_largest_reasonable_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let full = largest_reasonable_full_addr(&peer);
    let (base, split_peer) = split_multiaddr_base_and_peer(&full);

    assert!(full.to_vec().len() <= 256_usize);
    assert_eq!(split_peer, Some(peer));

    let output = kad_ready_addrs(&[full]);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_064_kad_ready_skips_oversized_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let full = oversized_full_addr(&peer);

    let output = kad_ready_addrs(&[full]);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_065_kad_ready_double_p2p_removes_only_last_peer_component() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let base = memory_addr(65_u64);
    let first_full = attach_peer_to_addr(base, &peer_one);
    let double_full = attach_peer_to_addr(first_full.clone(), &peer_two);

    let output = kad_ready_addrs(&[double_full]);

    assert_eq!(output, vec![first_full]);
    Ok(())
}

#[test]
fn test_066_kad_ready_order_with_base_full_and_duplicates() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();

    let first = memory_addr(66_u64);
    let second = memory_addr(67_u64);
    let third = memory_addr(68_u64);

    let first_full = attach_peer_to_addr(first.clone(), &peer_one);
    let second_full = attach_peer_to_addr(second.clone(), &peer_two);

    let output = kad_ready_addrs(&[
        first_full,
        second.clone(),
        first.clone(),
        second_full,
        third.clone(),
    ]);

    assert_eq!(output, vec![first, second, third]);
    Ok(())
}

#[test]
fn test_067_kad_ready_mixed_oversized_between_valid_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let first = memory_addr(67_u64);
    let second = memory_addr(68_u64);
    let second_full = attach_peer_to_addr(second.clone(), &peer);

    let output = kad_ready_addrs(&[
        oversized_multiaddr(),
        first.clone(),
        oversized_full_addr(&peer),
        second_full,
    ]);

    assert_eq!(output, vec![first, second]);
    Ok(())
}

#[test]
fn test_068_kad_ready_does_not_modify_input_vector() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(68_u64);
    let full = attach_peer_to_addr(base, &peer);
    let input = vec![full.clone()];
    let original = input.clone();

    let output = kad_ready_addrs(&input);

    assert_eq!(input, original);
    assert_eq!(output.len(), 1_usize);
    Ok(())
}

/* ───────────────────────── more dedupe_addrs vectors ──────────────────── */

#[test]
fn test_069_dedupe_keeps_empty_addr_once() -> Result<()> {
    let output = dedupe_addrs(vec![
        Multiaddr::empty(),
        Multiaddr::empty(),
        Multiaddr::empty(),
    ]);

    assert_eq!(output, vec![Multiaddr::empty()]);
    Ok(())
}

#[test]
fn test_070_dedupe_keeps_p2p_only_addr_once() -> Result<()> {
    let peer = generated_peer_id();
    let addr = p2p_only_addr(&peer);

    let output = dedupe_addrs(vec![addr.clone(), addr.clone(), addr.clone()]);

    assert_eq!(output, vec![addr]);
    Ok(())
}

#[test]
fn test_071_dedupe_keeps_distinct_p2p_only_peers() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let first = p2p_only_addr(&peer_one);
    let second = p2p_only_addr(&peer_two);

    let output = dedupe_addrs(vec![first.clone(), second.clone(), first.clone()]);

    assert_eq!(output, vec![first, second]);
    Ok(())
}

#[test]
fn test_072_dedupe_keeps_largest_reasonable_addr() -> Result<()> {
    let addr = largest_reasonable_multiaddr();

    assert!(addr.to_vec().len() <= 256_usize);

    let output = dedupe_addrs(vec![addr.clone(), addr.clone()]);

    assert_eq!(output, vec![addr]);
    Ok(())
}

#[test]
fn test_073_dedupe_skips_oversized_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let good = memory_addr(73_u64);
    let bad = oversized_full_addr(&peer);

    let output = dedupe_addrs(vec![bad, good.clone(), good.clone()]);

    assert_eq!(output, vec![good]);
    Ok(())
}

#[test]
fn test_074_dedupe_preserves_first_occurrence_after_noise() -> Result<()> {
    let first = memory_addr(74_u64);
    let second = memory_addr(75_u64);
    let third = memory_addr(76_u64);

    let output = dedupe_addrs(vec![
        oversized_multiaddr(),
        first.clone(),
        second.clone(),
        first.clone(),
        oversized_multiaddr(),
        third.clone(),
        second.clone(),
    ]);

    assert_eq!(output, vec![first, second, third]);
    Ok(())
}

#[test]
fn test_075_dedupe_treats_full_addresses_with_different_peers_as_distinct() -> Result<()> {
    let base = memory_addr(75_u64);
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let first = attach_peer_to_addr(base.clone(), &peer_one);
    let second = attach_peer_to_addr(base, &peer_two);

    let output = dedupe_addrs(vec![first.clone(), second.clone(), first.clone()]);

    assert_eq!(output, vec![first, second]);
    Ok(())
}

#[test]
fn test_076_dedupe_treats_double_p2p_addrs_by_full_string_identity() -> Result<()> {
    let base = memory_addr(76_u64);
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let peer_three = generated_peer_id();

    let first_full = attach_peer_to_addr(base.clone(), &peer_one);
    let double_one = attach_peer_to_addr(first_full.clone(), &peer_two);
    let double_two = attach_peer_to_addr(first_full, &peer_three);

    let output = dedupe_addrs(vec![
        double_one.clone(),
        double_two.clone(),
        double_one.clone(),
    ]);

    assert_eq!(output, vec![double_one, double_two]);
    Ok(())
}

/* ───────────────────────── property / fuzz-style tests ────────────────── */

#[test]
fn test_077_property_attach_then_split_roundtrips_for_32_memory_addrs() -> Result<()> {
    for seed in 77_u64..109_u64 {
        let peer = generated_peer_id();
        let base = memory_addr(seed);
        let full = attach_peer_to_addr(base.clone(), &peer);

        let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);

        assert_eq!(split_base, base);
        assert_eq!(split_peer, Some(peer));
    }

    Ok(())
}

#[test]
fn test_078_property_ensure_base_then_split_roundtrips_for_32_memory_addrs() -> Result<()> {
    for seed in 78_u64..110_u64 {
        let peer = generated_peer_id();
        let base = memory_addr(seed);

        let maybe_full = ensure_dialable_addr_for_peer(&base, &peer);
        assert!(maybe_full.is_some());

        if let Some(full) = maybe_full {
            let (split_base, split_peer) = split_multiaddr_base_and_peer(&full);
            assert_eq!(split_base, base);
            assert_eq!(split_peer, Some(peer));
        }
    }

    Ok(())
}

#[test]
fn test_079_property_ensure_wrong_peer_rejects_for_32_full_addrs() -> Result<()> {
    for seed in 79_u64..111_u64 {
        let real_peer = generated_peer_id();
        let wrong_peer = generated_peer_id();
        let full = full_memory_addr(seed, &real_peer);

        let maybe_full = ensure_dialable_addr_for_peer(&full, &wrong_peer);

        assert!(maybe_full.is_none());
    }

    Ok(())
}

#[test]
fn test_080_property_kad_ready_base_and_full_same_seed_dedupes_to_one() -> Result<()> {
    for seed in 80_u64..112_u64 {
        let peer = generated_peer_id();
        let base = memory_addr(seed);
        let full = attach_peer_to_addr(base.clone(), &peer);

        let output = kad_ready_addrs(&[base.clone(), full]);

        assert_eq!(output, vec![base]);
    }

    Ok(())
}

#[test]
fn test_081_fuzz_deterministic_128_base_addrs_are_kad_ready() -> Result<()> {
    let mut state = 81_u64;
    let mut input = Vec::new();

    for _round in 0_u8..128_u8 {
        input.push(memory_addr(lcg_next(&mut state)));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 128_usize);
    Ok(())
}

#[test]
fn test_082_fuzz_deterministic_128_full_addrs_are_stripped_to_bases() -> Result<()> {
    let mut state = 82_u64;
    let mut input = Vec::new();

    for _round in 0_u8..128_u8 {
        let peer = generated_peer_id();
        input.push(full_memory_addr(lcg_next(&mut state), &peer));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 128_usize);

    for addr in output {
        let (_base, peer) = split_multiaddr_base_and_peer(&addr);
        assert!(peer.is_none());
    }

    Ok(())
}

#[test]
fn test_083_fuzz_deterministic_mixed_full_and_base_addrs() -> Result<()> {
    let mut state = 83_u64;
    let mut input = Vec::new();

    for round in 0_u8..64_u8 {
        let seed = lcg_next(&mut state);
        if round % 2_u8 == 0_u8 {
            input.push(memory_addr(seed));
        } else {
            let peer = generated_peer_id();
            input.push(full_memory_addr(seed, &peer));
        }
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 64_usize);
    Ok(())
}

#[test]
fn test_084_fuzz_deterministic_repeated_same_base_with_many_peers_dedupes_to_one() -> Result<()> {
    let base = memory_addr(84_u64);
    let mut input = Vec::new();

    for _round in 0_u8..64_u8 {
        let peer = generated_peer_id();
        input.push(attach_peer_to_addr(base.clone(), &peer));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output, vec![base]);
    Ok(())
}

/* ───────────────────────── adversarial batches ────────────────────────── */

#[test]
fn test_085_adversarial_all_empty_p2p_only_and_oversized_filtered_from_kad() -> Result<()> {
    let mut input = Vec::new();

    for _round in 0_u8..64_u8 {
        let peer = generated_peer_id();
        input.push(Multiaddr::empty());
        input.push(p2p_only_addr(&peer));
        input.push(oversized_multiaddr());
        input.push(oversized_full_addr(&peer));
    }

    let output = kad_ready_addrs(&input);

    assert!(output.is_empty());
    Ok(())
}

#[test]
fn test_086_adversarial_valid_addrs_survive_between_oversized_noise() -> Result<()> {
    let first = memory_addr(86_u64);
    let second = memory_addr(87_u64);
    let third = memory_addr(88_u64);
    let peer = generated_peer_id();

    let input = vec![
        oversized_multiaddr(),
        first.clone(),
        p2p_only_addr(&peer),
        second.clone(),
        oversized_full_addr(&peer),
        attach_peer_to_addr(third.clone(), &peer),
    ];

    let output = kad_ready_addrs(&input);

    assert_eq!(output, vec![first, second, third]);
    Ok(())
}

#[test]
fn test_087_adversarial_dedupe_keeps_empty_and_p2p_only_but_skips_oversized() -> Result<()> {
    let peer = generated_peer_id();
    let empty = Multiaddr::empty();
    let p2p_only = p2p_only_addr(&peer);

    let input = vec![
        oversized_multiaddr(),
        empty.clone(),
        empty.clone(),
        p2p_only.clone(),
        p2p_only.clone(),
        oversized_full_addr(&peer),
    ];

    let output = dedupe_addrs(input);

    assert_eq!(output, vec![empty, p2p_only]);
    Ok(())
}

#[test]
fn test_088_adversarial_ensure_rejects_every_invalid_form_in_batch() -> Result<()> {
    for _round in 0_u8..32_u8 {
        let peer = generated_peer_id();

        assert!(ensure_dialable_addr_for_peer(&Multiaddr::empty(), &peer).is_none());
        assert!(ensure_dialable_addr_for_peer(&p2p_only_addr(&peer), &peer).is_none());
        assert!(ensure_dialable_addr_for_peer(&oversized_multiaddr(), &peer).is_none());
        assert!(ensure_dialable_addr_for_peer(&oversized_full_addr(&peer), &peer).is_none());
    }

    Ok(())
}

#[test]
fn test_089_adversarial_double_p2p_wrong_trailing_peer_rejected() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let wanted_peer = generated_peer_id();

    let base = memory_addr(89_u64);
    let full_one = attach_peer_to_addr(base, &peer_one);
    let double_full = attach_peer_to_addr(full_one, &peer_two);

    let maybe_full = ensure_dialable_addr_for_peer(&double_full, &wanted_peer);

    assert!(maybe_full.is_none());
    Ok(())
}

#[test]
fn test_090_adversarial_kad_ready_with_double_p2p_keeps_prior_p2p_in_base() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();

    let base = memory_addr(90_u64);
    let first_full = attach_peer_to_addr(base, &peer_one);
    let double_full = attach_peer_to_addr(first_full.clone(), &peer_two);

    let output = kad_ready_addrs(&[double_full]);

    assert_eq!(output, vec![first_full]);
    Ok(())
}

/* ───────────────────────── load tests ─────────────────────────────────── */

#[test]
fn test_091_load_512_unique_base_addrs_are_kad_ready() -> Result<()> {
    let mut input = Vec::new();

    for seed in 0_u64..512_u64 {
        input.push(memory_addr(seed));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 512_usize);
    Ok(())
}

#[test]
fn test_092_load_512_unique_full_addrs_are_kad_ready_bases() -> Result<()> {
    let mut input = Vec::new();

    for seed in 0_u64..512_u64 {
        let peer = generated_peer_id();
        input.push(full_memory_addr(seed, &peer));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output.len(), 512_usize);
    Ok(())
}

#[test]
fn test_093_load_512_full_same_base_dedupes_to_one_kad_addr() -> Result<()> {
    let base = memory_addr(93_u64);
    let mut input = Vec::new();

    for _round in 0_u16..512_u16 {
        let peer = generated_peer_id();
        input.push(attach_peer_to_addr(base.clone(), &peer));
    }

    let output = kad_ready_addrs(&input);

    assert_eq!(output, vec![base]);
    Ok(())
}

#[test]
fn test_094_load_dedupe_512_unique_base_addrs() -> Result<()> {
    let mut input = Vec::new();

    for seed in 0_u64..512_u64 {
        input.push(memory_addr(seed));
    }

    let output = dedupe_addrs(input);

    assert_eq!(output.len(), 512_usize);
    Ok(())
}

#[test]
fn test_095_load_dedupe_128_base_addrs_repeated_four_times() -> Result<()> {
    let mut input = Vec::new();

    for _repeat in 0_u8..4_u8 {
        for seed in 0_u64..128_u64 {
            input.push(memory_addr(seed));
        }
    }

    let output = dedupe_addrs(input);

    assert_eq!(output.len(), 128_usize);
    Ok(())
}

#[test]
fn test_096_load_dedupe_256_unique_p2p_only_addrs() -> Result<()> {
    let mut input = Vec::new();

    for _round in 0_u16..256_u16 {
        let peer = generated_peer_id();
        input.push(p2p_only_addr(&peer));
    }

    let output = dedupe_addrs(input);

    assert_eq!(output.len(), 256_usize);
    Ok(())
}

#[test]
fn test_097_combined_peerbook_full_to_kad_base_pipeline() -> Result<()> {
    let peer = generated_peer_id();
    let base = parse_addr("/ip4/127.0.0.1/tcp/36213")?;

    let full = ensure_dialable_addr_for_peer(&base, &peer);
    assert_eq!(full, Some(attach_peer_to_addr(base.clone(), &peer)));

    let full_addr = attach_peer_to_addr(base.clone(), &peer);
    let deduped_full = dedupe_addrs(vec![full_addr.clone(), full_addr.clone()]);
    assert_eq!(deduped_full, vec![full_addr.clone()]);

    let kad = kad_ready_addrs(&deduped_full);
    assert_eq!(kad, vec![base]);
    Ok(())
}

#[test]
fn test_098_combined_batch_normalization_with_mixed_valid_transports() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();
    let peer_three = generated_peer_id();

    let ip4 = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let ip6 = parse_addr("/ip6/::1/tcp/36214")?;
    let quic = parse_addr("/ip4/127.0.0.1/udp/36215/quic-v1")?;

    let input = vec![
        attach_peer_to_addr(ip4.clone(), &peer_one),
        attach_peer_to_addr(ip6.clone(), &peer_two),
        attach_peer_to_addr(quic.clone(), &peer_three),
    ];

    let kad = kad_ready_addrs(&input);

    assert_eq!(kad, vec![ip4, ip6, quic]);
    Ok(())
}

#[test]
fn test_099_combined_adversarial_load_keeps_only_valid_kad_bases() -> Result<()> {
    let mut input = Vec::new();
    let mut expected = Vec::new();

    for seed in 0_u64..100_u64 {
        let peer = generated_peer_id();
        let base = memory_addr(seed);
        let full = attach_peer_to_addr(base.clone(), &peer);

        input.push(Multiaddr::empty());
        input.push(p2p_only_addr(&peer));
        input.push(oversized_multiaddr());
        input.push(full);
        expected.push(base);
    }

    let kad = kad_ready_addrs(&input);

    assert_eq!(kad, expected);
    Ok(())
}

#[test]
fn test_100_combined_full_address_pipeline_with_dedupe_and_kad_ready_is_safe() -> Result<()> {
    let peer_one = generated_peer_id();
    let peer_two = generated_peer_id();

    let first_base = memory_addr(100_u64);
    let second_base = memory_addr(101_u64);

    let first_full_one = attach_peer_to_addr(first_base.clone(), &peer_one);
    let first_full_two = attach_peer_to_addr(first_base.clone(), &peer_two);
    let second_full = attach_peer_to_addr(second_base.clone(), &peer_one);

    let deduped_full = dedupe_addrs(vec![
        first_full_one.clone(),
        first_full_one,
        first_full_two,
        second_full,
        oversized_multiaddr(),
    ]);

    assert_eq!(deduped_full.len(), 3_usize);

    let kad = kad_ready_addrs(&deduped_full);

    assert_eq!(kad, vec![first_base, second_base]);
    Ok(())
}
