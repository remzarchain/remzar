#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use remzar::network::{
    p2p_009_events::split_multiaddr_base_and_peer,
    p2p_013_peer_mesh::{
        PEER_MESH_MAX_WIRE_BYTES, PEER_MESH_TOPIC_STR, PeerMeshAnnounce, PeerMeshCodecError,
        PeerMeshValidationError, build_local_peer_mesh_wire, decode_and_normalize_peer_mesh,
    },
};

fn base_that_becomes_too_large_when_peer_attached(peer: &PeerId) -> Multiaddr {
    let mut base = Multiaddr::empty();
    let mut seed = 1_u64;

    loop {
        let mut candidate = base.clone();
        candidate.push(Protocol::Memory(seed));

        if candidate.to_vec().len() > 256_usize {
            return base;
        }

        let mut full = candidate.clone();
        full.push(Protocol::P2p(*peer));

        if full.to_vec().len() > 256_usize {
            return candidate;
        }

        base = candidate;
        seed = seed.saturating_add(1_u64);
    }
}

fn assert_codec_decode_error(result: Result<PeerMeshAnnounce, PeerMeshCodecError>) -> Result<()> {
    match result {
        Err(PeerMeshCodecError::Decode(_)) => Ok(()),
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
        Ok(_) => Err(anyhow!("expected decode error")),
    }
}

fn assert_validation_variant<T>(
    result: Result<T, PeerMeshValidationError>,
    predicate: fn(&PeerMeshValidationError) -> bool,
) -> Result<()> {
    match result {
        Err(error) => {
            assert!(predicate(&error));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected validation error")),
    }
}

fn generated_peer_id() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

fn memory_addr(seed: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(seed));
    addr
}

fn full_memory_addr(seed: u64, peer: &PeerId) -> Multiaddr {
    let mut addr = memory_addr(seed);
    addr.push(Protocol::P2p(*peer));
    addr
}

fn parse_addr(value: &str) -> Result<Multiaddr> {
    value
        .parse::<Multiaddr>()
        .with_context(|| format!("failed to parse multiaddr: {value}"))
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

fn peer_announce(peer: PeerId, addrs: Vec<String>) -> PeerMeshAnnounce {
    PeerMeshAnnounce {
        peer_id: peer.to_base58(),
        listen_addrs: addrs,
        wallet: None,
        timestamp_unix: 123_u64,
    }
}

fn assert_codec_too_large<T>(result: Result<T, PeerMeshCodecError>) -> Result<()> {
    match result {
        Err(PeerMeshCodecError::TooLarge { got, max }) => {
            assert!(got > max);
            assert_eq!(max, PEER_MESH_MAX_WIRE_BYTES);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
        Ok(_) => Err(anyhow!("expected TooLarge codec error")),
    }
}

fn assert_validation_error<T>(
    result: Result<T, PeerMeshValidationError>,
    expected: &str,
) -> Result<()> {
    match result {
        Err(error) => {
            let rendered = error.to_string();
            assert!(rendered.contains(expected));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected validation error containing {expected}")),
    }
}

/* ───────────────────────── constants / local builder ───────────────────── */

#[test]
fn test_001_topic_and_wire_cap_are_expected() -> Result<()> {
    assert_eq!(PEER_MESH_TOPIC_STR, "/remzar/peer_mesh/1.0.0");
    assert_eq!(PEER_MESH_MAX_WIRE_BYTES, 64_usize * 1024_usize);
    Ok(())
}

#[test]
fn test_002_from_local_single_addr_builds_announcement() -> Result<()> {
    let peer = generated_peer_id();
    let addr = memory_addr(2_u64);

    let announce = PeerMeshAnnounce::from_local(peer, &[addr.clone()], None, 2_u64)?;

    assert_eq!(announce.peer_id, peer.to_base58());
    assert_eq!(announce.listen_addrs, vec![addr.to_string()]);
    assert!(announce.wallet.is_none());
    assert_eq!(announce.timestamp_unix, 2_u64);
    Ok(())
}

#[test]
fn test_003_from_local_empty_wallet_text_becomes_none() -> Result<()> {
    let peer = generated_peer_id();
    let addr = memory_addr(3_u64);

    let announce = PeerMeshAnnounce::from_local(peer, &[addr], Some("   "), 3_u64)?;

    assert!(announce.wallet.is_none());
    Ok(())
}

#[test]
fn test_004_from_local_dedupes_duplicate_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let addr = memory_addr(4_u64);

    let announce =
        PeerMeshAnnounce::from_local(peer, &[addr.clone(), addr.clone(), addr], None, 4_u64)?;

    assert_eq!(announce.listen_addrs.len(), 1_usize);
    Ok(())
}

#[test]
fn test_005_from_local_caps_listen_addrs_at_32() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..40_u64).map(memory_addr).collect::<Vec<_>>();

    let announce = PeerMeshAnnounce::from_local(peer, &addrs, None, 5_u64)?;

    assert_eq!(announce.listen_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_006_from_local_filters_oversized_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let good = memory_addr(6_u64);
    let bad = oversized_multiaddr();

    assert!(bad.to_vec().len() > 256_usize);

    let announce = PeerMeshAnnounce::from_local(peer, &[bad, good.clone()], None, 6_u64)?;

    assert_eq!(announce.listen_addrs, vec![good.to_string()]);
    Ok(())
}

#[test]
fn test_007_kind_str_is_peer_mesh_announce() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(7_u64).to_string()]);

    assert_eq!(announce.kind_str(), "PeerMeshAnnounce");
    Ok(())
}

#[test]
fn test_008_is_self_for_matches_local_peer() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(8_u64).to_string()]);

    assert!(announce.is_self_for(&peer));
    Ok(())
}

#[test]
fn test_009_is_self_for_rejects_different_peer() -> Result<()> {
    let peer = generated_peer_id();
    let other = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(9_u64).to_string()]);

    assert!(!announce.is_self_for(&other));
    Ok(())
}

/* ───────────────────────── encode / decode vectors ─────────────────────── */

#[test]
fn test_010_encode_decode_round_trip() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(10_u64).to_string()]);

    let wire = announce.encode_to_wire()?;
    let decoded = PeerMeshAnnounce::decode_from_wire(&wire)?;

    assert_eq!(decoded, announce);
    Ok(())
}

#[test]
fn test_011_decode_rejects_oversized_wire_payload() -> Result<()> {
    let wire = vec![0_u8; PEER_MESH_MAX_WIRE_BYTES.saturating_add(1_usize)];

    assert_codec_too_large(PeerMeshAnnounce::decode_from_wire(&wire))?;
    Ok(())
}

#[test]
fn test_012_encode_rejects_oversized_serialized_announce() -> Result<()> {
    let peer = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: peer.to_base58(),
        listen_addrs: vec!["x".repeat(PEER_MESH_MAX_WIRE_BYTES)],
        wallet: None,
        timestamp_unix: 12_u64,
    };

    assert_codec_too_large(announce.encode_to_wire())?;
    Ok(())
}

#[test]
fn test_013_decode_rejects_malformed_postcard_payload() -> Result<()> {
    let wire = vec![1_u8, 2_u8, 3_u8, 4_u8];

    match PeerMeshAnnounce::decode_from_wire(&wire) {
        Err(PeerMeshCodecError::Decode(_)) => Ok(()),
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
        Ok(_) => Err(anyhow!("expected decode error")),
    }
}

#[test]
fn test_014_json_round_trip_is_stable() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(14_u64).to_string()]);

    let encoded = serde_json::to_string(&announce)?;
    let decoded = serde_json::from_str::<PeerMeshAnnounce>(&encoded)?;

    assert_eq!(decoded, announce);
    Ok(())
}

/* ───────────────────────── normalize success vectors ───────────────────── */

#[test]
fn test_015_normalize_base_addr_attaches_announced_peer() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(15_u64);
    let announce = peer_announce(peer, vec![base.to_string()]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.peer_id, peer);
    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base.clone()]);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&normalized.full_dial_addrs[0]);
    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_016_normalize_full_addr_with_same_peer_round_trips_to_base_and_full() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(16_u64);
    let full = full_memory_addr(16_u64, &peer);
    let announce = peer_announce(peer, vec![full.to_string()]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs, vec![full]);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_017_normalize_full_addr_with_wrong_peer_rebinds_to_announced_peer() -> Result<()> {
    let announced_peer = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let base = memory_addr(17_u64);
    let wrong_full = full_memory_addr(17_u64, &wrong_peer);
    let announce = peer_announce(announced_peer, vec![wrong_full.to_string()]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.peer_id, announced_peer);
    assert_eq!(normalized.kad_base_addrs, vec![base.clone()]);

    let (split_base, split_peer) = split_multiaddr_base_and_peer(&normalized.full_dial_addrs[0]);
    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(announced_peer));
    Ok(())
}

#[test]
fn test_018_normalize_dedupes_duplicate_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let addr = memory_addr(18_u64).to_string();
    let announce = peer_announce(peer, vec![addr.clone(), addr.clone(), addr]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 1_usize);
    Ok(())
}

#[test]
fn test_019_normalize_mixed_base_and_full_same_addr_dedupes() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(19_u64);
    let full = full_memory_addr(19_u64, &peer);
    let announce = peer_announce(peer, vec![base.to_string(), full.to_string()]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_020_normalize_preserves_timestamp_and_no_wallet() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(20_u64).to_string()]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.timestamp_unix, 123_u64);
    assert!(normalized.wallet().is_none());
    Ok(())
}

#[test]
fn test_021_normalize_accepts_multiple_transport_vectors() -> Result<()> {
    let peer = generated_peer_id();
    let ip4 = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let ip6 = parse_addr("/ip6/::1/tcp/36214")?;
    let quic = parse_addr("/ip4/127.0.0.1/udp/36215/quic-v1")?;

    let announce = peer_announce(
        peer,
        vec![ip4.to_string(), ip6.to_string(), quic.to_string()],
    );

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 3_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 3_usize);
    assert!(normalized.kad_base_addrs.contains(&ip4));
    assert!(normalized.kad_base_addrs.contains(&ip6));
    assert!(normalized.kad_base_addrs.contains(&quic));
    Ok(())
}

#[test]
fn test_022_normalized_to_announce_round_trips() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(22_u64);
    let announce = peer_announce(peer, vec![base.to_string()]);

    let normalized = announce.normalize()?;
    let outbound = normalized.to_announce();
    let normalized_again = outbound.normalize()?;

    assert_eq!(normalized_again.peer_id, peer);
    assert_eq!(normalized_again.kad_base_addrs, vec![base]);
    Ok(())
}

/* ───────────────────────── normalize rejection vectors ─────────────────── */

#[test]
fn test_023_normalize_rejects_empty_peer_id() -> Result<()> {
    let announce = PeerMeshAnnounce {
        peer_id: String::new(),
        listen_addrs: vec![memory_addr(23_u64).to_string()],
        wallet: None,
        timestamp_unix: 23_u64,
    };

    assert_validation_error(announce.normalize(), "empty peer_id")?;
    Ok(())
}

#[test]
fn test_024_normalize_rejects_whitespace_peer_id() -> Result<()> {
    let announce = PeerMeshAnnounce {
        peer_id: "   ".to_owned(),
        listen_addrs: vec![memory_addr(24_u64).to_string()],
        wallet: None,
        timestamp_unix: 24_u64,
    };

    assert_validation_error(announce.normalize(), "empty peer_id")?;
    Ok(())
}

#[test]
fn test_025_normalize_rejects_peer_id_over_128_bytes() -> Result<()> {
    let announce = PeerMeshAnnounce {
        peer_id: "x".repeat(129_usize),
        listen_addrs: vec![memory_addr(25_u64).to_string()],
        wallet: None,
        timestamp_unix: 25_u64,
    };

    assert_validation_error(announce.normalize(), "peer_id too large")?;
    Ok(())
}

#[test]
fn test_026_normalize_rejects_invalid_peer_id_text() -> Result<()> {
    let announce = PeerMeshAnnounce {
        peer_id: "not-a-peer-id".to_owned(),
        listen_addrs: vec![memory_addr(26_u64).to_string()],
        wallet: None,
        timestamp_unix: 26_u64,
    };

    assert_validation_error(announce.normalize(), "invalid peer_id")?;
    Ok(())
}

#[test]
fn test_027_normalize_rejects_too_many_listen_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..33_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    assert_validation_error(announce.normalize(), "too many listen addrs")?;
    Ok(())
}

#[test]
fn test_028_normalize_rejects_invalid_multiaddr_text() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec!["not-a-multiaddr".to_owned()]);

    assert_validation_error(announce.normalize(), "invalid multiaddr text")?;
    Ok(())
}

#[test]
fn test_029_normalize_rejects_oversized_multiaddr() -> Result<()> {
    let peer = generated_peer_id();
    let oversized = oversized_multiaddr();
    let announce = peer_announce(peer, vec![oversized.to_string()]);

    assert_validation_error(announce.normalize(), "multiaddr too large")?;
    Ok(())
}

#[test]
fn test_030_normalize_rejects_empty_listen_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, Vec::new());

    assert_validation_error(announce.normalize(), "no usable listen addrs")?;
    Ok(())
}

#[test]
fn test_031_normalize_rejects_wallet_over_256_bytes() -> Result<()> {
    let peer = generated_peer_id();
    let mut announce = peer_announce(peer, vec![memory_addr(31_u64).to_string()]);
    announce.wallet = Some("x".repeat(257_usize));

    assert_validation_error(announce.normalize(), "wallet too large")?;
    Ok(())
}

/* ───────────────────────── decode_and_normalize / local wire ───────────── */

#[test]
fn test_032_decode_and_normalize_returns_none_for_self_announcement() -> Result<()> {
    let local = generated_peer_id();
    let announce = peer_announce(local, vec![memory_addr(32_u64).to_string()]);
    let wire = announce.encode_to_wire()?;

    let decoded = decode_and_normalize_peer_mesh(&wire, &local)?;

    assert!(decoded.is_none());
    Ok(())
}

#[test]
fn test_033_decode_and_normalize_returns_some_for_remote_announcement() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let base = memory_addr(33_u64);
    let announce = peer_announce(remote, vec![base.to_string()]);
    let wire = announce.encode_to_wire()?;

    let decoded = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected remote normalized announcement")?;

    assert_eq!(decoded.peer_id, remote);
    assert_eq!(decoded.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_034_decode_and_normalize_rejects_bad_wire_payload() -> Result<()> {
    let local = generated_peer_id();
    let wire = vec![1_u8, 2_u8, 3_u8];

    let result = decode_and_normalize_peer_mesh(&wire, &local);

    match result {
        Err(err) => {
            assert!(err.to_string().contains("peer mesh decode failed"));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected decode failure")),
    }
}

#[test]
fn test_035_decode_and_normalize_rejects_invalid_normalized_payload() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: remote.to_base58(),
        listen_addrs: Vec::new(),
        wallet: None,
        timestamp_unix: 35_u64,
    };
    let wire = announce.encode_to_wire()?;

    let result = decode_and_normalize_peer_mesh(&wire, &local);

    match result {
        Err(err) => {
            assert!(err.to_string().contains("peer mesh normalize failed"));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected normalize failure")),
    }
}

#[test]
fn test_036_build_local_peer_mesh_wire_round_trips_through_decode() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let base = memory_addr(36_u64);

    let wire = build_local_peer_mesh_wire(remote, &[base.clone()], None, 36_u64)?;
    let decoded =
        decode_and_normalize_peer_mesh(&wire, &local)?.context("expected decoded remote mesh")?;

    assert_eq!(decoded.peer_id, remote);
    assert_eq!(decoded.kad_base_addrs, vec![base]);
    assert_eq!(decoded.timestamp_unix, 36_u64);
    Ok(())
}

#[test]
fn test_037_build_local_peer_mesh_wire_empty_wallet_is_none() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();

    let wire = build_local_peer_mesh_wire(remote, &[memory_addr(37_u64)], Some("   "), 37_u64)?;
    let decoded =
        decode_and_normalize_peer_mesh(&wire, &local)?.context("expected decoded remote mesh")?;

    assert!(decoded.wallet().is_none());
    Ok(())
}

/* ───────────────────────── fuzz / adversarial / load coverage ─────────── */

#[test]
fn test_038_fuzz_32_distinct_base_addrs_normalize_to_32_full_and_32_kad() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..32_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_039_adversarial_wrong_peer_suffixes_all_rebind_to_announced_peer() -> Result<()> {
    let announced_peer = generated_peer_id();
    let addrs = (0_u64..16_u64)
        .map(|seed| {
            let wrong_peer = generated_peer_id();
            full_memory_addr(seed, &wrong_peer).to_string()
        })
        .collect::<Vec<_>>();
    let announce = peer_announce(announced_peer, addrs);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 16_usize);

    for addr in normalized.full_dial_addrs {
        let (_base, peer) = split_multiaddr_base_and_peer(&addr);
        assert_eq!(peer, Some(announced_peer));
    }

    Ok(())
}

#[test]
fn test_040_combined_peer_mesh_pipeline_is_safe() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let wrong_peer = generated_peer_id();

    let ip4 = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let ip6 = parse_addr("/ip6/::1/tcp/36214")?;
    let wrong_full = full_memory_addr(40_u64, &wrong_peer);

    let announce = PeerMeshAnnounce::from_local(
        remote,
        &[ip4.clone(), ip6.clone(), wrong_full],
        None,
        40_u64,
    )?;
    let wire = announce.encode_to_wire()?;
    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;
    let outbound = normalized.to_announce();
    let normalized_again = outbound.normalize()?;

    assert_eq!(normalized_again.peer_id, remote);
    assert_eq!(normalized_again.timestamp_unix, 40_u64);
    assert!(normalized_again.kad_base_addrs.contains(&ip4));
    assert!(normalized_again.kad_base_addrs.contains(&ip6));
    assert!(
        normalized_again
            .kad_base_addrs
            .contains(&memory_addr(40_u64))
    );
    Ok(())
}

#[test]
fn test_041_is_self_for_accepts_peer_id_to_string_form() -> Result<()> {
    let peer = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: peer.to_string(),
        listen_addrs: vec![memory_addr(41_u64).to_string()],
        wallet: None,
        timestamp_unix: 41_u64,
    };

    assert!(announce.is_self_for(&peer));
    Ok(())
}

#[test]
fn test_042_normalize_accepts_peer_id_to_string_form() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(42_u64);
    let announce = PeerMeshAnnounce {
        peer_id: peer.to_string(),
        listen_addrs: vec![base.to_string()],
        wallet: None,
        timestamp_unix: 42_u64,
    };

    let normalized = announce.normalize()?;

    assert_eq!(normalized.peer_id, peer);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_043_peer_id_128_bytes_is_not_too_large_but_invalid() -> Result<()> {
    let announce = PeerMeshAnnounce {
        peer_id: "x".repeat(128_usize),
        listen_addrs: vec![memory_addr(43_u64).to_string()],
        wallet: None,
        timestamp_unix: 43_u64,
    };

    assert_validation_variant(announce.normalize(), |error| {
        matches!(error, PeerMeshValidationError::InvalidPeerId(_))
    })?;
    Ok(())
}

#[test]
fn test_044_from_local_preserves_u64_max_timestamp() -> Result<()> {
    let peer = generated_peer_id();
    let addr = memory_addr(44_u64);

    let announce = PeerMeshAnnounce::from_local(peer, &[addr], None, u64::MAX)?;

    assert_eq!(announce.timestamp_unix, u64::MAX);
    Ok(())
}

#[test]
fn test_045_normalize_preserves_u64_max_timestamp() -> Result<()> {
    let peer = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: peer.to_base58(),
        listen_addrs: vec![memory_addr(45_u64).to_string()],
        wallet: None,
        timestamp_unix: u64::MAX,
    };

    let normalized = announce.normalize()?;

    assert_eq!(normalized.timestamp_unix, u64::MAX);
    Ok(())
}

#[test]
fn test_046_kind_str_after_decode_is_stable() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(46_u64).to_string()]);
    let wire = announce.encode_to_wire()?;
    let decoded = PeerMeshAnnounce::decode_from_wire(&wire)?;

    assert_eq!(decoded.kind_str(), "PeerMeshAnnounce");
    Ok(())
}

/* ───────────────────────── p2p-only and oversized-normalized cases ─────── */

#[test]
fn test_047_normalize_accepts_p2p_only_addr_for_same_peer_but_kad_is_empty() -> Result<()> {
    let peer = generated_peer_id();
    let p2p_only = full_memory_addr(0_u64, &peer);
    let (_base, split_peer) = split_multiaddr_base_and_peer(&p2p_only);
    assert_eq!(split_peer, Some(peer));

    let pure_p2p = format!("/p2p/{peer}");
    let announce = peer_announce(peer, vec![pure_p2p]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.peer_id, peer);
    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert!(normalized.kad_base_addrs.is_empty());
    Ok(())
}

#[test]
fn test_048_normalize_rebinds_wrong_p2p_only_addr_to_announced_peer() -> Result<()> {
    let announced_peer = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let wrong_p2p = format!("/p2p/{wrong_peer}");
    let announce = peer_announce(announced_peer, vec![wrong_p2p]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert!(normalized.kad_base_addrs.is_empty());

    let (_base, split_peer) = split_multiaddr_base_and_peer(&normalized.full_dial_addrs[0_usize]);
    assert_eq!(split_peer, Some(announced_peer));
    Ok(())
}

#[test]
fn test_049_normalize_rejects_only_addr_that_becomes_oversized_after_attach() -> Result<()> {
    let peer = generated_peer_id();
    let base = base_that_becomes_too_large_when_peer_attached(&peer);
    assert!(base.to_vec().len() <= 256_usize);

    let mut full = base.clone();
    full.push(Protocol::P2p(peer));
    assert!(full.to_vec().len() > 256_usize);

    let announce = peer_announce(peer, vec![base.to_string()]);

    assert_validation_error(announce.normalize(), "no usable listen addrs")?;
    Ok(())
}

#[test]
fn test_050_normalize_skips_addr_that_becomes_oversized_but_keeps_good_addr() -> Result<()> {
    let peer = generated_peer_id();
    let too_large_after_attach = base_that_becomes_too_large_when_peer_attached(&peer);
    let good = memory_addr(50_u64);

    let announce = peer_announce(
        peer,
        vec![too_large_after_attach.to_string(), good.to_string()],
    );

    let normalized = announce.normalize()?;

    assert_eq!(normalized.kad_base_addrs, vec![good]);
    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    Ok(())
}

#[test]
fn test_051_from_local_can_emit_p2p_only_addr_when_input_is_p2p_only() -> Result<()> {
    let peer = generated_peer_id();
    let p2p_only = format!("/p2p/{peer}").parse::<Multiaddr>()?;

    let announce = PeerMeshAnnounce::from_local(peer, &[p2p_only.clone()], None, 51_u64)?;

    assert_eq!(announce.listen_addrs, vec![p2p_only.to_string()]);
    Ok(())
}

#[test]
fn test_052_from_local_ignores_unique_addr_after_take_32_window() -> Result<()> {
    let peer = generated_peer_id();
    let repeated = memory_addr(52_u64);
    let ignored_unique = memory_addr(52_999_u64);
    let mut input = Vec::new();

    for _round in 0_u8..32_u8 {
        input.push(repeated.clone());
    }
    input.push(ignored_unique);

    let announce = PeerMeshAnnounce::from_local(peer, &input, None, 52_u64)?;

    assert_eq!(announce.listen_addrs, vec![repeated.to_string()]);
    Ok(())
}

/* ───────────────────────── exact cap and ordering vectors ──────────────── */

#[test]
fn test_053_normalize_accepts_exactly_32_listen_addrs() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..32_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_054_too_many_listen_addrs_takes_priority_over_invalid_addr_text() -> Result<()> {
    let peer = generated_peer_id();
    let mut addrs = (0_u64..32_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    addrs.push("not-a-multiaddr".to_owned());

    let announce = peer_announce(peer, addrs);

    assert_validation_variant(announce.normalize(), |error| {
        matches!(
            error,
            PeerMeshValidationError::TooManyListenAddrs { got: 33, max: 32 }
        )
    })?;
    Ok(())
}

#[test]
fn test_055_invalid_multiaddr_after_valid_addr_rejects_entire_normalization() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(
        peer,
        vec![
            memory_addr(55_u64).to_string(),
            "not-a-multiaddr".to_owned(),
        ],
    );

    assert_validation_error(announce.normalize(), "invalid multiaddr text")?;
    Ok(())
}

#[test]
fn test_056_oversized_multiaddr_after_valid_addr_rejects_entire_normalization() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(
        peer,
        vec![
            memory_addr(56_u64).to_string(),
            oversized_multiaddr().to_string(),
        ],
    );

    assert_validation_error(announce.normalize(), "multiaddr too large")?;
    Ok(())
}

#[test]
fn test_057_normalize_dedupes_same_base_with_many_wrong_peer_suffixes() -> Result<()> {
    let announced_peer = generated_peer_id();
    let base = memory_addr(57_u64);
    let mut addrs = Vec::new();

    for _round in 0_u8..16_u8 {
        let wrong_peer = generated_peer_id();
        let mut full = base.clone();
        full.push(Protocol::P2p(wrong_peer));
        addrs.push(full.to_string());
    }

    let announce = peer_announce(announced_peer, addrs);
    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_058_normalize_dedupes_p2p_only_duplicates_to_one_full_addr() -> Result<()> {
    let peer = generated_peer_id();
    let p2p_only = format!("/p2p/{peer}");
    let announce = peer_announce(peer, vec![p2p_only.clone(), p2p_only.clone(), p2p_only]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert!(normalized.kad_base_addrs.is_empty());
    Ok(())
}

/* ───────────────────────── codec and serde boundary vectors ────────────── */

#[test]
fn test_059_decode_empty_wire_payload_returns_decode_error() -> Result<()> {
    assert_codec_decode_error(PeerMeshAnnounce::decode_from_wire(&[]))?;
    Ok(())
}

#[test]
fn test_060_decode_exactly_max_sized_zero_wire_is_not_too_large() -> Result<()> {
    let wire = vec![0_u8; PEER_MESH_MAX_WIRE_BYTES];

    let result = PeerMeshAnnounce::decode_from_wire(&wire);

    match result {
        Err(PeerMeshCodecError::TooLarge { .. }) => {
            Err(anyhow!("exactly max-sized wire must not trigger TooLarge"))
        }
        Ok(decoded) => {
            assert!(decoded.peer_id.is_empty());
            assert!(decoded.listen_addrs.is_empty());
            assert!(decoded.wallet.is_none());
            assert_eq!(decoded.timestamp_unix, 0_u64);
            Ok(())
        }
        Err(PeerMeshCodecError::Decode(_)) => Ok(()),
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
    }
}

#[test]
fn test_061_encode_decode_with_32_addrs_round_trips() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..32_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    let wire = announce.encode_to_wire()?;
    let decoded = PeerMeshAnnounce::decode_from_wire(&wire)?;

    assert_eq!(decoded, announce);
    Ok(())
}

#[test]
fn test_062_to_announce_then_encode_decode_normalize_round_trips() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(62_u64);
    let announce = peer_announce(peer, vec![base.to_string()]);
    let normalized = announce.normalize()?;

    let outbound = normalized.to_announce();
    let wire = outbound.encode_to_wire()?;
    let decoded = PeerMeshAnnounce::decode_from_wire(&wire)?;
    let normalized_again = decoded.normalize()?;

    assert_eq!(normalized_again.peer_id, peer);
    assert_eq!(normalized_again.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_063_clone_and_eq_are_stable_for_announce() -> Result<()> {
    let peer = generated_peer_id();
    let announce = peer_announce(peer, vec![memory_addr(63_u64).to_string()]);
    let cloned = announce.clone();

    assert_eq!(cloned, announce);
    assert!(!format!("{cloned:?}").is_empty());
    Ok(())
}

#[test]
fn test_064_normalized_clone_preserves_fields() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(64_u64);
    let announce = peer_announce(peer, vec![base.to_string()]);

    let normalized = announce.normalize()?;
    let cloned = normalized.clone();

    assert_eq!(cloned.peer_id, normalized.peer_id);
    assert_eq!(cloned.full_dial_addrs, normalized.full_dial_addrs);
    assert_eq!(cloned.kad_base_addrs, normalized.kad_base_addrs);
    assert_eq!(cloned.wallet(), normalized.wallet());
    assert_eq!(cloned.timestamp_unix, normalized.timestamp_unix);
    Ok(())
}

#[test]
fn test_065_codec_too_large_display_contains_wire_payload() -> Result<()> {
    let wire = vec![0_u8; PEER_MESH_MAX_WIRE_BYTES.saturating_add(1_usize)];

    match PeerMeshAnnounce::decode_from_wire(&wire) {
        Err(error @ PeerMeshCodecError::TooLarge { .. }) => {
            let rendered = error.to_string();
            assert!(rendered.contains("wire payload too large"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
        Ok(_) => Err(anyhow!("expected too large error")),
    }
}

/* ───────────────────────── decode_and_normalize vectors ───────────────── */

#[test]
fn test_066_decode_and_normalize_self_to_string_form_returns_none() -> Result<()> {
    let local = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: local.to_string(),
        listen_addrs: vec![memory_addr(66_u64).to_string()],
        wallet: None,
        timestamp_unix: 66_u64,
    };
    let wire = announce.encode_to_wire()?;

    let decoded = decode_and_normalize_peer_mesh(&wire, &local)?;

    assert!(decoded.is_none());
    Ok(())
}

#[test]
fn test_067_decode_and_normalize_remote_p2p_only_returns_some_with_empty_kad() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let announce = peer_announce(remote, vec![format!("/p2p/{remote}")]);
    let wire = announce.encode_to_wire()?;

    let normalized =
        decode_and_normalize_peer_mesh(&wire, &local)?.context("expected remote p2p-only mesh")?;

    assert_eq!(normalized.peer_id, remote);
    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert!(normalized.kad_base_addrs.is_empty());
    Ok(())
}

#[test]
fn test_068_decode_and_normalize_remote_wrong_suffix_rebinds_to_remote() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let wrong = generated_peer_id();
    let wrong_full = full_memory_addr(68_u64, &wrong);
    let announce = peer_announce(remote, vec![wrong_full.to_string()]);
    let wire = announce.encode_to_wire()?;

    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;

    let (_base, split_peer) = split_multiaddr_base_and_peer(&normalized.full_dial_addrs[0_usize]);
    assert_eq!(split_peer, Some(remote));
    assert_eq!(normalized.kad_base_addrs, vec![memory_addr(68_u64)]);
    Ok(())
}

#[test]
fn test_069_build_local_wire_with_no_addrs_encodes_but_decode_normalize_rejects() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();

    let wire = build_local_peer_mesh_wire(remote, &[], None, 69_u64)?;
    let result = decode_and_normalize_peer_mesh(&wire, &local);

    match result {
        Err(error) => {
            assert!(error.to_string().contains("peer mesh normalize failed"));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected normalize failure")),
    }
}

#[test]
fn test_070_build_local_wire_caps_40_addrs_to_32_after_decode() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let addrs = (0_u64..40_u64).map(memory_addr).collect::<Vec<_>>();

    let wire = build_local_peer_mesh_wire(remote, &addrs, None, 70_u64)?;
    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;

    assert_eq!(normalized.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_071_build_local_wire_filters_oversized_and_keeps_good() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let good = memory_addr(71_u64);
    let bad = oversized_multiaddr();

    let wire = build_local_peer_mesh_wire(remote, &[bad, good.clone()], None, 71_u64)?;
    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;

    assert_eq!(normalized.kad_base_addrs, vec![good]);
    Ok(())
}

/* ───────────────────────── validation variant edge cases ──────────────── */

#[test]
fn test_072_empty_peer_id_takes_priority_over_too_many_addrs() -> Result<()> {
    let addrs = (0_u64..33_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = PeerMeshAnnounce {
        peer_id: String::new(),
        listen_addrs: addrs,
        wallet: None,
        timestamp_unix: 72_u64,
    };

    assert_validation_variant(announce.normalize(), |error| {
        matches!(error, PeerMeshValidationError::EmptyPeerId)
    })?;
    Ok(())
}

#[test]
fn test_073_peer_id_too_large_takes_priority_over_too_many_addrs() -> Result<()> {
    let addrs = (0_u64..33_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = PeerMeshAnnounce {
        peer_id: "x".repeat(129_usize),
        listen_addrs: addrs,
        wallet: None,
        timestamp_unix: 73_u64,
    };

    assert_validation_variant(announce.normalize(), |error| {
        matches!(error, PeerMeshValidationError::PeerIdTooLarge(129))
    })?;
    Ok(())
}

#[test]
fn test_074_too_many_addrs_takes_priority_over_wallet_too_large() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..33_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let mut announce = peer_announce(peer, addrs);
    announce.wallet = Some("x".repeat(257_usize));

    assert_validation_variant(announce.normalize(), |error| {
        matches!(
            error,
            PeerMeshValidationError::TooManyListenAddrs { got: 33, max: 32 }
        )
    })?;
    Ok(())
}

#[test]
fn test_075_wallet_too_large_takes_priority_over_invalid_multiaddr() -> Result<()> {
    let peer = generated_peer_id();
    let mut announce = peer_announce(peer, vec!["not-a-multiaddr".to_owned()]);
    announce.wallet = Some("x".repeat(257_usize));

    assert_validation_variant(announce.normalize(), |error| {
        matches!(error, PeerMeshValidationError::WalletTooLarge(257))
    })?;
    Ok(())
}

#[test]
fn test_076_invalid_multiaddr_error_carries_original_text() -> Result<()> {
    let peer = generated_peer_id();
    let raw = "not-a-multiaddr".to_owned();
    let announce = peer_announce(peer, vec![raw.clone()]);

    match announce.normalize() {
        Err(PeerMeshValidationError::InvalidMultiaddr(value)) => {
            assert_eq!(value, raw);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected validation error: {other:?}")),
        Ok(_) => Err(anyhow!("expected invalid multiaddr")),
    }
}

#[test]
fn test_077_multiaddr_too_large_reports_actual_length() -> Result<()> {
    let peer = generated_peer_id();
    let bad = oversized_multiaddr();
    let bad_len = bad.to_vec().len();
    let announce = peer_announce(peer, vec![bad.to_string()]);

    match announce.normalize() {
        Err(PeerMeshValidationError::MultiaddrTooLarge(got)) => {
            assert_eq!(got, bad_len);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected validation error: {other:?}")),
        Ok(_) => Err(anyhow!("expected multiaddr too large")),
    }
}

/* ───────────────────────── property / fuzz-style coverage ─────────────── */

#[test]
fn test_078_property_base_addr_normalizes_to_full_with_announced_peer_for_32_seeds() -> Result<()> {
    let peer = generated_peer_id();

    for seed in 78_u64..110_u64 {
        let base = memory_addr(seed);
        let announce = peer_announce(peer, vec![base.to_string()]);
        let normalized = announce.normalize()?;

        let (split_base, split_peer) =
            split_multiaddr_base_and_peer(&normalized.full_dial_addrs[0_usize]);
        assert_eq!(split_base, base);
        assert_eq!(split_peer, Some(peer));
    }

    Ok(())
}

#[test]
fn test_079_property_wrong_peer_suffix_rebinds_for_32_seeds() -> Result<()> {
    let announced_peer = generated_peer_id();

    for seed in 79_u64..111_u64 {
        let wrong_peer = generated_peer_id();
        let wrong_full = full_memory_addr(seed, &wrong_peer);
        let announce = peer_announce(announced_peer, vec![wrong_full.to_string()]);
        let normalized = announce.normalize()?;

        let (_base, split_peer) =
            split_multiaddr_base_and_peer(&normalized.full_dial_addrs[0_usize]);
        assert_eq!(split_peer, Some(announced_peer));
    }

    Ok(())
}

#[test]
fn test_080_property_to_announce_normalize_roundtrip_for_16_seeds() -> Result<()> {
    let peer = generated_peer_id();

    for seed in 80_u64..96_u64 {
        let base = memory_addr(seed);
        let announce = peer_announce(peer, vec![base.to_string()]);
        let normalized = announce.normalize()?;
        let outbound = normalized.to_announce();
        let normalized_again = outbound.normalize()?;

        assert_eq!(normalized_again.peer_id, peer);
        assert_eq!(normalized_again.kad_base_addrs, vec![base]);
    }

    Ok(())
}

#[test]
fn test_081_fuzz_mixed_base_same_peer_full_wrong_peer_full_dedupes_by_full_result() -> Result<()> {
    let announced_peer = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let base = memory_addr(81_u64);
    let same_full = full_memory_addr(81_u64, &announced_peer);
    let wrong_full = full_memory_addr(81_u64, &wrong_peer);

    let announce = peer_announce(
        announced_peer,
        vec![
            base.to_string(),
            same_full.to_string(),
            wrong_full.to_string(),
        ],
    );

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_082_fuzz_32_wrong_peer_suffixes_with_distinct_bases_keep_32_bases() -> Result<()> {
    let announced_peer = generated_peer_id();
    let addrs = (0_u64..32_u64)
        .map(|seed| {
            let wrong_peer = generated_peer_id();
            full_memory_addr(seed, &wrong_peer).to_string()
        })
        .collect::<Vec<_>>();

    let announce = peer_announce(announced_peer, addrs);
    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_083_fuzz_32_p2p_only_wrong_peers_dedupes_to_one_announced_p2p_only() -> Result<()> {
    let announced_peer = generated_peer_id();
    let addrs = (0_u64..32_u64)
        .map(|_seed| {
            let wrong_peer = generated_peer_id();
            format!("/p2p/{wrong_peer}")
        })
        .collect::<Vec<_>>();

    let announce = peer_announce(announced_peer, addrs);
    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert!(normalized.kad_base_addrs.is_empty());
    Ok(())
}

#[test]
fn test_084_fuzz_repeated_encode_decode_normalize_for_16_peers() -> Result<()> {
    let local = generated_peer_id();

    for seed in 84_u64..100_u64 {
        let remote = generated_peer_id();
        let announce = peer_announce(remote, vec![memory_addr(seed).to_string()]);
        let wire = announce.encode_to_wire()?;
        let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
            .context("expected normalized remote mesh")?;

        assert_eq!(normalized.peer_id, remote);
        assert_eq!(normalized.kad_base_addrs, vec![memory_addr(seed)]);
    }

    Ok(())
}

/* ───────────────────────── adversarial and load coverage ──────────────── */

#[test]
fn test_085_adversarial_32_duplicate_base_addrs_normalize_to_one() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(85_u64);
    let addrs = (0_u8..32_u8)
        .map(|_round| base.to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_086_adversarial_32_duplicate_full_addrs_normalize_to_one() -> Result<()> {
    let peer = generated_peer_id();
    let full = full_memory_addr(86_u64, &peer);
    let base = memory_addr(86_u64);
    let addrs = (0_u8..32_u8)
        .map(|_round| full.to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 1_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_087_adversarial_mixed_p2p_only_and_base_keeps_p2p_full_and_base_full() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(87_u64);
    let p2p_only = format!("/p2p/{peer}");
    let announce = peer_announce(peer, vec![p2p_only, base.to_string()]);

    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 2_usize);
    assert_eq!(normalized.kad_base_addrs, vec![base]);
    Ok(())
}

#[test]
fn test_088_load_32_quic_addrs_normalize_to_32_kad_bases() -> Result<()> {
    let peer = generated_peer_id();
    let mut addrs = Vec::new();

    for port in 36_200_u16..36_232_u16 {
        let addr = parse_addr(&format!("/ip4/127.0.0.1/udp/{port}/quic-v1"))?;
        addrs.push(addr.to_string());
    }

    let announce = peer_announce(peer, addrs);
    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_089_load_32_dns_addrs_normalize_to_32_kad_bases() -> Result<()> {
    let peer = generated_peer_id();
    let mut addrs = Vec::new();

    for index in 0_u8..32_u8 {
        let addr = parse_addr(&format!("/dns4/node-{index}.remzar.local/tcp/36213"))?;
        addrs.push(addr.to_string());
    }

    let announce = peer_announce(peer, addrs);
    let normalized = announce.normalize()?;

    assert_eq!(normalized.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized.kad_base_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_090_load_encode_decode_32_addr_announce_stays_below_wire_cap() -> Result<()> {
    let peer = generated_peer_id();
    let addrs = (0_u64..32_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(peer, addrs);

    let wire = announce.encode_to_wire()?;

    assert!(wire.len() <= PEER_MESH_MAX_WIRE_BYTES);
    let decoded = PeerMeshAnnounce::decode_from_wire(&wire)?;
    assert_eq!(decoded, announce);
    Ok(())
}

#[test]
fn test_091_load_build_local_wire_32_addr_announce_stays_below_wire_cap() -> Result<()> {
    let remote = generated_peer_id();
    let addrs = (0_u64..32_u64).map(memory_addr).collect::<Vec<_>>();

    let wire = build_local_peer_mesh_wire(remote, &addrs, None, 91_u64)?;

    assert!(wire.len() <= PEER_MESH_MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn test_092_adversarial_decode_too_large_wire_reports_got_len() -> Result<()> {
    let wire = vec![7_u8; PEER_MESH_MAX_WIRE_BYTES.saturating_add(17_usize)];

    match PeerMeshAnnounce::decode_from_wire(&wire) {
        Err(PeerMeshCodecError::TooLarge { got, max }) => {
            assert_eq!(got, PEER_MESH_MAX_WIRE_BYTES.saturating_add(17_usize));
            assert_eq!(max, PEER_MESH_MAX_WIRE_BYTES);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
        Ok(_) => Err(anyhow!("expected too-large decode error")),
    }
}

#[test]
fn test_093_adversarial_encode_too_large_reports_max_wire_cap() -> Result<()> {
    let peer = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: peer.to_base58(),
        listen_addrs: vec!["x".repeat(PEER_MESH_MAX_WIRE_BYTES)],
        wallet: Some("y".repeat(PEER_MESH_MAX_WIRE_BYTES)),
        timestamp_unix: 93_u64,
    };

    match announce.encode_to_wire() {
        Err(PeerMeshCodecError::TooLarge { got, max }) => {
            assert!(got > max);
            assert_eq!(max, PEER_MESH_MAX_WIRE_BYTES);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected codec error: {other:?}")),
        Ok(_) => Err(anyhow!("expected too-large encode error")),
    }
}

#[test]
fn test_094_adversarial_invalid_peer_id_after_decode_returns_normalize_failure() -> Result<()> {
    let local = generated_peer_id();
    let announce = PeerMeshAnnounce {
        peer_id: "not-a-peer-id".to_owned(),
        listen_addrs: vec![memory_addr(94_u64).to_string()],
        wallet: None,
        timestamp_unix: 94_u64,
    };
    let wire = announce.encode_to_wire()?;

    let result = decode_and_normalize_peer_mesh(&wire, &local);

    match result {
        Err(error) => {
            assert!(error.to_string().contains("peer mesh normalize failed"));
            assert!(error.to_string().contains("invalid peer_id"));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected normalize failure")),
    }
}

#[test]
fn test_095_adversarial_too_many_addrs_after_decode_returns_normalize_failure() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let addrs = (0_u64..33_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();
    let announce = peer_announce(remote, addrs);
    let wire = announce.encode_to_wire()?;

    let result = decode_and_normalize_peer_mesh(&wire, &local);

    match result {
        Err(error) => {
            assert!(error.to_string().contains("peer mesh normalize failed"));
            assert!(error.to_string().contains("too many listen addrs"));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected normalize failure")),
    }
}

#[test]
fn test_096_combined_to_announce_keeps_full_dial_addrs_not_kad_bases() -> Result<()> {
    let peer = generated_peer_id();
    let base = memory_addr(96_u64);
    let announce = peer_announce(peer, vec![base.to_string()]);
    let normalized = announce.normalize()?;

    let outbound = normalized.to_announce();

    assert_eq!(outbound.peer_id, peer.to_base58());
    assert_eq!(outbound.listen_addrs.len(), 1_usize);

    let outbound_addr = outbound.listen_addrs[0_usize].parse::<Multiaddr>()?;
    let (split_base, split_peer) = split_multiaddr_base_and_peer(&outbound_addr);

    assert_eq!(split_base, base);
    assert_eq!(split_peer, Some(peer));
    Ok(())
}

#[test]
fn test_097_combined_self_wire_from_local_is_filtered() -> Result<()> {
    let local = generated_peer_id();
    let wire = build_local_peer_mesh_wire(local, &[memory_addr(97_u64)], None, 97_u64)?;

    let decoded = decode_and_normalize_peer_mesh(&wire, &local)?;

    assert!(decoded.is_none());
    Ok(())
}

#[test]
fn test_098_combined_remote_wire_with_wrong_suffix_is_rebound_and_roundtrips() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let wrong_peer = generated_peer_id();
    let wrong_full = full_memory_addr(98_u64, &wrong_peer);

    let wire = build_local_peer_mesh_wire(remote, &[wrong_full], None, 98_u64)?;
    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;
    let outbound = normalized.to_announce();
    let normalized_again = outbound.normalize()?;

    assert_eq!(normalized_again.peer_id, remote);
    assert_eq!(normalized_again.kad_base_addrs, vec![memory_addr(98_u64)]);

    for addr in normalized_again.full_dial_addrs {
        let (_base, split_peer) = split_multiaddr_base_and_peer(&addr);
        assert_eq!(split_peer, Some(remote));
    }

    Ok(())
}

#[test]
fn test_099_combined_32_addr_remote_wire_pipeline_is_safe() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();
    let addrs = (0_u64..32_u64).map(memory_addr).collect::<Vec<_>>();

    let wire = build_local_peer_mesh_wire(remote, &addrs, None, 99_u64)?;
    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;
    let outbound = normalized.to_announce();
    let normalized_again = outbound.normalize()?;

    assert_eq!(normalized_again.peer_id, remote);
    assert_eq!(normalized_again.full_dial_addrs.len(), 32_usize);
    assert_eq!(normalized_again.kad_base_addrs.len(), 32_usize);
    assert_eq!(normalized_again.timestamp_unix, 99_u64);
    Ok(())
}

#[test]
fn test_100_combined_adversarial_peer_mesh_pipeline_is_safe() -> Result<()> {
    let local = generated_peer_id();
    let remote = generated_peer_id();

    let ip4 = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let ip6 = parse_addr("/ip6/::1/tcp/65535")?;
    let quic = parse_addr("/ip4/127.0.0.1/udp/36215/quic-v1")?;
    let wrong_peer = generated_peer_id();
    let wrong_full = full_memory_addr(100_u64, &wrong_peer);
    let duplicate = memory_addr(101_u64);

    let announce = PeerMeshAnnounce::from_local(
        remote,
        &[
            ip4.clone(),
            ip6.clone(),
            quic.clone(),
            wrong_full,
            duplicate.clone(),
            duplicate.clone(),
            oversized_multiaddr(),
        ],
        None,
        100_u64,
    )?;

    let wire = announce.encode_to_wire()?;
    let normalized = decode_and_normalize_peer_mesh(&wire, &local)?
        .context("expected normalized remote mesh")?;

    assert_eq!(normalized.peer_id, remote);
    assert_eq!(normalized.timestamp_unix, 100_u64);
    assert!(normalized.kad_base_addrs.contains(&ip4));
    assert!(normalized.kad_base_addrs.contains(&ip6));
    assert!(normalized.kad_base_addrs.contains(&quic));
    assert!(normalized.kad_base_addrs.contains(&memory_addr(100_u64)));
    assert!(normalized.kad_base_addrs.contains(&duplicate));

    for addr in normalized.full_dial_addrs {
        let (_base, split_peer) = split_multiaddr_base_and_peer(&addr);
        assert_eq!(split_peer, Some(remote));
    }

    Ok(())
}
