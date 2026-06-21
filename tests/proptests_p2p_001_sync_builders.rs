// tests/proptests_p2p_001_sync_builders.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_008_broadcast::REGISTER_TOPIC_STR;
use remzar::runtime::p2p_001_sync_builders::{
    REGISTRATION_TOPIC, REMZAR_HASH_BYTES_LEN, RemzarHashBytes,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

fn fresh_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn consensus_cap_for_test() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
}

fn exceeds_consensus_cap_model(n: usize) -> bool {
    n > consensus_cap_for_test()
}

fn usize_to_u64_saturating_model(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn zero_hash_64_model() -> RemzarHashBytes {
    [0u8; REMZAR_HASH_BYTES_LEN]
}

fn genesis_hash_bytes_64_model() -> RemzarHashBytes {
    let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX)
        .expect("GENESIS_HASH_HEX must decode as hex");

    assert_eq!(
        decoded.len(),
        REMZAR_HASH_BYTES_LEN,
        "GENESIS_HASH_HEX must decode to exactly 64 bytes"
    );

    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];
    out.copy_from_slice(&decoded);
    out
}

fn make_ipv4_addr(octets: [u8; 4], port: u16) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip4(Ipv4Addr::from(octets)));
    addr.push(Protocol::Tcp(port));
    addr
}

fn make_ipv6_addr(octets: [u8; 16], port: u16) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip6(Ipv6Addr::from(octets)));
    addr.push(Protocol::Tcp(port));
    addr
}

fn make_memory_addr(memory_id: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(memory_id));
    addr
}

fn make_p2p_only_addr() -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::P2p(fresh_peer_id()));
    addr
}

fn ip_from_multiaddr_model(addr: &Multiaddr) -> Option<IpAddr> {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }

    None
}

fn xor_hash(a: RemzarHashBytes, b: RemzarHashBytes) -> RemzarHashBytes {
    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];

    for i in 0..REMZAR_HASH_BYTES_LEN {
        out[i] = a[i] ^ b[i];
    }

    out
}

#[derive(Debug, Clone, Copy)]
enum AddrComponent {
    V4([u8; 4]),
    V6([u8; 16]),
    Tcp(u16),
    Udp(u16),
    Memory(u64),
    P2p,
}

fn addr_component_strategy() -> impl Strategy<Value = AddrComponent> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(AddrComponent::V4),
        any::<[u8; 16]>().prop_map(AddrComponent::V6),
        any::<u16>().prop_map(AddrComponent::Tcp),
        any::<u16>().prop_map(AddrComponent::Udp),
        any::<u64>().prop_map(AddrComponent::Memory),
        Just(AddrComponent::P2p),
    ]
}

fn build_multiaddr_from_components(components: &[AddrComponent]) -> Multiaddr {
    let mut addr = Multiaddr::empty();

    for component in components {
        match *component {
            AddrComponent::V4(octets) => {
                addr.push(Protocol::Ip4(Ipv4Addr::from(octets)));
            }
            AddrComponent::V6(octets) => {
                addr.push(Protocol::Ip6(Ipv6Addr::from(octets)));
            }
            AddrComponent::Tcp(port) => {
                addr.push(Protocol::Tcp(port));
            }
            AddrComponent::Udp(port) => {
                addr.push(Protocol::Udp(port));
            }
            AddrComponent::Memory(memory_id) => {
                addr.push(Protocol::Memory(memory_id));
            }
            AddrComponent::P2p => {
                addr.push(Protocol::P2p(fresh_peer_id()));
            }
        }
    }

    addr
}

fn expected_first_ip_from_components(components: &[AddrComponent]) -> Option<IpAddr> {
    for component in components {
        match *component {
            AddrComponent::V4(octets) => {
                return Some(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            AddrComponent::V6(octets) => {
                return Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            AddrComponent::Tcp(_)
            | AddrComponent::Udp(_)
            | AddrComponent::Memory(_)
            | AddrComponent::P2p => {}
        }
    }

    None
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Config::default()
    })]

    #[test]
    fn test_001_registration_topic_alias_is_stable_and_nonempty(_probe in any::<u8>()) {
        prop_assert_eq!(
            REGISTRATION_TOPIC,
            REGISTER_TOPIC_STR,
            "runtime sync builder must use the canonical broadcaster registration topic"
        );

        prop_assert!(
            !REGISTRATION_TOPIC.is_empty(),
            "registration topic must not be empty"
        );

        prop_assert!(
            !REGISTRATION_TOPIC.as_bytes().contains(&0),
            "registration topic must never contain NUL bytes"
        );
    }

    #[test]
    fn test_002_remzar_hash_type_preserves_exact_64_byte_width(hash in any::<RemzarHashBytes>()) {
        prop_assert_eq!(
            REMZAR_HASH_BYTES_LEN,
            64,
            "network/runtime hash width must remain 64 bytes"
        );

        prop_assert_eq!(
            hash.len(),
            REMZAR_HASH_BYTES_LEN,
            "RemzarHashBytes must preserve the canonical 64-byte hash width"
        );

        prop_assert_eq!(
            std::mem::size_of_val(&hash),
            REMZAR_HASH_BYTES_LEN,
            "RemzarHashBytes must not gain hidden runtime overhead"
        );
    }

    #[test]
    fn test_003_zero_hash_model_is_all_zero_and_xor_identity(hash in any::<RemzarHashBytes>()) {
        let zero = zero_hash_64_model();

        prop_assert!(
            zero.iter().all(|b| *b == 0),
            "zero hash model must be all zero bytes"
        );

        prop_assert_eq!(
            xor_hash(hash, zero),
            hash,
            "XOR with zero hash must preserve every generated hash byte"
        );
    }

    #[test]
    fn test_004_genesis_hash_matches_global_configuration_hex(_probe in any::<u8>()) {
        let genesis = genesis_hash_bytes_64_model();

        let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX)
            .expect("GENESIS_HASH_HEX must decode as hex");

        prop_assert_eq!(
            decoded.len(),
            REMZAR_HASH_BYTES_LEN,
            "configured genesis hash hex must decode to 64 bytes"
        );

        prop_assert_eq!(
            genesis.as_slice(),
            decoded.as_slice(),
            "genesis hash bytes must match GlobalConfiguration::GENESIS_HASH_HEX"
        );

        prop_assert_ne!(
            genesis,
            zero_hash_64_model(),
            "configured genesis hash must not be the zero hash"
        );
    }

    #[test]
    fn test_005_genesis_hash_return_is_copy_stable_against_caller_mutation(
        flip_index in 0usize..REMZAR_HASH_BYTES_LEN,
        flip_byte in 1u8..=255u8,
    ) {
        let original = genesis_hash_bytes_64_model();

        let mut caller_copy = genesis_hash_bytes_64_model();
        caller_copy[flip_index] ^= flip_byte;

        prop_assert_ne!(
            caller_copy,
            original,
            "mutating caller-owned hash copy must change only the caller copy"
        );

        prop_assert_eq!(
            genesis_hash_bytes_64_model(),
            original,
            "mutating caller-owned hash copy must not mutate the canonical genesis hash"
        );
    }

    #[test]
    fn test_006_global_max_block_size_is_nonzero_and_fits_test_cap(_probe in any::<u8>()) {
        let cap = consensus_cap_for_test();

        prop_assert!(
            GlobalConfiguration::MAX_BLOCK_SIZE > 0,
            "MAX_BLOCK_SIZE must be nonzero"
        );

        prop_assert!(
            cap > 0,
            "usize consensus cap must be nonzero"
        );
    }

    #[test]
    fn test_007_genesis_hash_hex_has_canonical_width_and_valid_hex(_probe in any::<u8>()) {
        prop_assert_eq!(
            GlobalConfiguration::GENESIS_HASH_HEX.len(),
            REMZAR_HASH_BYTES_LEN * 2,
            "GENESIS_HASH_HEX must be 128 hex chars for a 64-byte hash"
        );

        prop_assert!(
            hex::decode(GlobalConfiguration::GENESIS_HASH_HEX).is_ok(),
            "GENESIS_HASH_HEX must be valid hex"
        );
    }

    #[test]
    fn test_008_exceeds_consensus_cap_model_is_false_at_cap_and_true_above_boundary(
        delta in 0usize..=4096usize,
    ) {
        let cap = consensus_cap_for_test();
        let n = cap.saturating_add(delta);

        prop_assert_eq!(
            exceeds_consensus_cap_model(n),
            n > cap,
            "consensus cap model must be strict: cap allowed, above cap rejected"
        );
    }

    #[test]
    fn test_009_exceeds_consensus_cap_model_matches_strict_greater_than_for_any_usize(
        n in any::<usize>(),
    ) {
        let cap = consensus_cap_for_test();

        prop_assert_eq!(
            exceeds_consensus_cap_model(n),
            n > cap,
            "consensus cap model must exactly match n > MAX_BLOCK_SIZE"
        );
    }

    #[test]
    fn test_010_exceeds_consensus_cap_model_is_monotonic(
        a in any::<usize>(),
        b in any::<usize>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        if exceeds_consensus_cap_model(low) {
            prop_assert!(
                exceeds_consensus_cap_model(high),
                "once a smaller byte size exceeds consensus cap, every larger byte size must also exceed it"
            );
        }

        if !exceeds_consensus_cap_model(high) {
            prop_assert!(
                !exceeds_consensus_cap_model(low),
                "if a larger byte size is within cap, every smaller byte size must also be within cap"
            );
        }
    }

    #[test]
    fn test_011_usize_to_u64_saturating_model_matches_try_from_contract(n in any::<usize>()) {
        let expected = u64::try_from(n).unwrap_or(u64::MAX);

        prop_assert_eq!(
            usize_to_u64_saturating_model(n),
            expected,
            "usize->u64 saturating model must preserve representable values and saturate only on overflow"
        );
    }

    #[test]
    fn test_012_usize_to_u64_saturating_model_is_monotonic(
        a in any::<usize>(),
        b in any::<usize>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        prop_assert!(
            usize_to_u64_saturating_model(low) <= usize_to_u64_saturating_model(high),
            "saturating usize->u64 conversion must be monotonic"
        );
    }

    #[test]
    fn test_013_ip_from_multiaddr_model_extracts_exact_ipv4(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv4_addr(octets, port);

        prop_assert_eq!(
            ip_from_multiaddr_model(&addr),
            Some(IpAddr::V4(Ipv4Addr::from(octets))),
            "IPv4 multiaddr extraction must preserve exact octets"
        );
    }

    #[test]
    fn test_014_ip_from_multiaddr_model_extracts_exact_ipv6(
        octets in any::<[u8; 16]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv6_addr(octets, port);

        prop_assert_eq!(
            ip_from_multiaddr_model(&addr),
            Some(IpAddr::V6(Ipv6Addr::from(octets))),
            "IPv6 multiaddr extraction must preserve exact octets"
        );
    }

    #[test]
    fn test_015_ip_from_multiaddr_model_returns_first_ip_when_ipv4_precedes_ipv6(
        v4 in any::<[u8; 4]>(),
        v6 in any::<[u8; 16]>(),
        tcp_port in any::<u16>(),
        udp_port in any::<u16>(),
    ) {
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip4(Ipv4Addr::from(v4)));
        addr.push(Protocol::Tcp(tcp_port));
        addr.push(Protocol::Ip6(Ipv6Addr::from(v6)));
        addr.push(Protocol::Udp(udp_port));

        prop_assert_eq!(
            ip_from_multiaddr_model(&addr),
            Some(IpAddr::V4(Ipv4Addr::from(v4))),
            "IP extractor must return the first IP component, not a later IP"
        );
    }

    #[test]
    fn test_016_ip_from_multiaddr_model_returns_first_ip_when_ipv6_precedes_ipv4(
        v6 in any::<[u8; 16]>(),
        v4 in any::<[u8; 4]>(),
        tcp_port in any::<u16>(),
        udp_port in any::<u16>(),
    ) {
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip6(Ipv6Addr::from(v6)));
        addr.push(Protocol::Tcp(tcp_port));
        addr.push(Protocol::Ip4(Ipv4Addr::from(v4)));
        addr.push(Protocol::Udp(udp_port));

        prop_assert_eq!(
            ip_from_multiaddr_model(&addr),
            Some(IpAddr::V6(Ipv6Addr::from(v6))),
            "IP extractor must return the first IP component, including IPv6-first addresses"
        );
    }

    #[test]
    fn test_017_ip_from_multiaddr_model_returns_none_for_non_ip_addresses(
        memory_id in any::<u64>(),
        tcp_port in any::<u16>(),
        udp_port in any::<u16>(),
    ) {
        let empty = Multiaddr::empty();
        prop_assert_eq!(
            ip_from_multiaddr_model(&empty),
            None,
            "empty multiaddr must not produce an IP"
        );

        let memory_addr = make_memory_addr(memory_id);
        prop_assert_eq!(
            ip_from_multiaddr_model(&memory_addr),
            None,
            "memory-only multiaddr must not produce an IP"
        );

        let p2p_only = make_p2p_only_addr();
        prop_assert_eq!(
            ip_from_multiaddr_model(&p2p_only),
            None,
            "p2p-only multiaddr must not produce an IP"
        );

        let mut transport_only = Multiaddr::empty();
        transport_only.push(Protocol::Tcp(tcp_port));
        transport_only.push(Protocol::Udp(udp_port));

        prop_assert_eq!(
            ip_from_multiaddr_model(&transport_only),
            None,
            "transport-only multiaddr without IP must not produce an IP"
        );
    }

    #[test]
    fn test_018_ip_from_multiaddr_model_ignores_transport_and_p2p_suffixes(
        octets in any::<[u8; 4]>(),
        tcp_port in any::<u16>(),
        udp_port in any::<u16>(),
    ) {
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip4(Ipv4Addr::from(octets)));
        addr.push(Protocol::Tcp(tcp_port));
        addr.push(Protocol::Udp(udp_port));
        addr.push(Protocol::P2p(fresh_peer_id()));

        prop_assert_eq!(
            ip_from_multiaddr_model(&addr),
            Some(IpAddr::V4(Ipv4Addr::from(octets))),
            "transport and /p2p suffixes must not change the extracted IP"
        );
    }

    #[test]
    fn test_019_ip_from_multiaddr_model_matches_first_ip_for_arbitrary_generated_components(
        components in proptest::collection::vec(addr_component_strategy(), 0..32),
    ) {
        let addr = build_multiaddr_from_components(&components);
        let expected = expected_first_ip_from_components(&components);

        let result = std::panic::catch_unwind(|| ip_from_multiaddr_model(&addr));

        prop_assert!(
            result.is_ok(),
            "IP extractor must never panic for generated valid Multiaddr components"
        );

        prop_assert_eq!(
            result.expect("panic already checked"),
            expected,
            "IP extractor must return exactly the first IP component in iteration order"
        );
    }

    #[test]
    fn test_020_xor_hash_is_commutative(
        a in any::<RemzarHashBytes>(),
        b in any::<RemzarHashBytes>(),
    ) {
        prop_assert_eq!(
            xor_hash(a, b),
            xor_hash(b, a),
            "hash XOR must be commutative"
        );
    }

    #[test]
    fn test_021_xor_hash_self_returns_zero(hash in any::<RemzarHashBytes>()) {
        prop_assert_eq!(
            xor_hash(hash, hash),
            zero_hash_64_model(),
            "hash XOR itself must return zero hash"
        );
    }

    #[test]
    fn test_022_xor_hash_zero_is_identity(hash in any::<RemzarHashBytes>()) {
        let zero = zero_hash_64_model();

        prop_assert_eq!(
            xor_hash(hash, zero),
            hash,
            "hash XOR zero must preserve the hash"
        );

        prop_assert_eq!(
            xor_hash(zero, hash),
            hash,
            "zero XOR hash must preserve the hash"
        );
    }

    #[test]
    fn test_023_generated_ipv4_multiaddr_is_nonempty(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv4_addr(octets, port);

        prop_assert!(
            !addr.to_vec().is_empty(),
            "generated IPv4 multiaddr must serialize to nonempty bytes"
        );
    }

    #[test]
    fn test_024_generated_ipv6_multiaddr_is_nonempty(
        octets in any::<[u8; 16]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv6_addr(octets, port);

        prop_assert!(
            !addr.to_vec().is_empty(),
            "generated IPv6 multiaddr must serialize to nonempty bytes"
        );
    }

    #[test]
    fn test_025_registration_topic_matches_public_broadcast_topic_for_arbitrary_probe(
        _probe in ".{0,128}",
    ) {
        prop_assert_eq!(
            REGISTRATION_TOPIC,
            REGISTER_TOPIC_STR,
            "registration topic must remain aligned with public broadcast topic"
        );
    }
}
