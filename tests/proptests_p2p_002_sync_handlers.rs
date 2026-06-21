// tests/proptests_p2p_002_sync_handlers.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::BlockTxResponse;
use remzar::network::p2p_018_last_resort_guards::LastResortDrop;
use remzar::runtime::p2p_001_sync_builders::{REMZAR_HASH_BYTES_LEN, RemzarHashBytes};
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

fn next_retry_count_model(retries_left: u8) -> Option<u8> {
    if retries_left > 0 {
        Some(retries_left.saturating_sub(1))
    } else {
        None
    }
}

fn should_retry_block_not_found_model(retries_left: u8) -> bool {
    retries_left > 0
}

fn should_retry_batch_failure_model(
    retries_left: u8,
    expected_block_hash: Option<RemzarHashBytes>,
    idx: u64,
    applied: u64,
) -> bool {
    retries_left > 0 && (expected_block_hash.is_some() || idx > applied)
}

fn handler_batch_mode_model(expected_block_hash: Option<RemzarHashBytes>) -> &'static str {
    if expected_block_hash.is_none() {
        "canonical"
    } else {
        "hash_bound_reorg"
    }
}

fn hashes_equal_for_merkle_check_model(
    header_root: RemzarHashBytes,
    computed_root: RemzarHashBytes,
) -> bool {
    header_root == computed_root
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

fn last_resort_drop_requires_disconnect_model(drop: LastResortDrop) -> bool {
    matches!(
        drop,
        LastResortDrop::PeerCoolingDown | LastResortDrop::CounterOverflow
    )
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

fn make_memory_addr(seed: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(seed));
    addr
}

fn make_p2p_only_addr() -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::P2p(fresh_peer_id()));
    addr
}

fn response_payload_len(response: &BlockTxResponse) -> Option<usize> {
    match response {
        BlockTxResponse::BatchData(bytes) => Some(bytes.len()),
        _ => None,
    }
}

fn classify_batch_response_for_cap_model(response: &BlockTxResponse) -> Option<bool> {
    response_payload_len(response).map(exceeds_consensus_cap_model)
}

fn corrupt_one_byte(mut bytes: Vec<u8>, index_seed: usize, xor_byte: u8) -> Vec<u8> {
    if bytes.is_empty() {
        bytes.push(xor_byte.max(1));
        return bytes;
    }

    let i = index_seed % bytes.len();
    bytes[i] ^= xor_byte.max(1);
    bytes
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
    fn test_001_remzar_hash_type_preserves_exact_64_byte_width(hash in any::<RemzarHashBytes>()) {
        prop_assert_eq!(
            REMZAR_HASH_BYTES_LEN,
            64,
            "runtime hash width must stay 64 bytes"
        );

        prop_assert_eq!(
            hash.len(),
            REMZAR_HASH_BYTES_LEN,
            "RemzarHashBytes must preserve the canonical 64-byte width"
        );

        prop_assert_eq!(
            std::mem::size_of_val(&hash),
            REMZAR_HASH_BYTES_LEN,
            "RemzarHashBytes must not gain hidden runtime overhead"
        );
    }

    #[test]
    fn test_002_zero_hash_model_is_all_zero(_probe in any::<u8>()) {
        let zero = zero_hash_64_model();

        prop_assert_eq!(zero.len(), REMZAR_HASH_BYTES_LEN);
        prop_assert!(
            zero.iter().all(|b| *b == 0),
            "zero hash model must be all zero bytes"
        );
    }

    #[test]
    fn test_003_genesis_hash_bytes_match_global_configuration_hex(_probe in any::<u8>()) {
        let genesis = genesis_hash_bytes_64_model();

        let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX)
            .expect("GENESIS_HASH_HEX must be valid hex");

        prop_assert_eq!(
            decoded.len(),
            REMZAR_HASH_BYTES_LEN,
            "configured genesis hash hex must decode to 64 bytes"
        );

        prop_assert_eq!(
            genesis.as_slice(),
            decoded.as_slice(),
            "genesis model must use the same canonical genesis bytes as global config"
        );
    }

    #[test]
    fn test_004_genesis_hash_is_not_zero(_probe in any::<u8>()) {
        let genesis = genesis_hash_bytes_64_model();

        prop_assert_ne!(
            genesis,
            zero_hash_64_model(),
            "configured genesis hash must never collapse to the zero parent sentinel"
        );
    }

    #[test]
    fn test_005_retry_decrement_is_saturating_and_only_happens_when_positive(
        retries_left in any::<u8>(),
    ) {
        let next = next_retry_count_model(retries_left);

        if retries_left == 0 {
            prop_assert_eq!(
                next,
                None,
                "retry model must not enqueue another retry when retries_left is zero"
            );
        } else {
            prop_assert_eq!(
                next,
                Some(retries_left - 1),
                "retry model must decrement retry budget by exactly one"
            );
        }
    }

    #[test]
    fn test_006_block_not_found_retry_predicate_depends_only_on_retry_budget(
        retries_left in any::<u8>(),
    ) {
        let should_retry = should_retry_block_not_found_model(retries_left);

        prop_assert_eq!(
            should_retry,
            retries_left > 0,
            "BlockTxResponse::NotFound retry model should retry exactly when retry budget remains"
        );

        if should_retry {
            prop_assert_eq!(
                next_retry_count_model(retries_left),
                Some(retries_left - 1),
                "block NotFound retry must enqueue with decremented retry budget"
            );
        } else {
            prop_assert_eq!(next_retry_count_model(retries_left), None);
        }
    }

    #[test]
    fn test_007_hash_bound_batch_failure_retries_even_when_height_is_already_applied(
        idx in any::<u64>(),
        applied in any::<u64>(),
        retries_left in 1u8..=u8::MAX,
        hash in any::<RemzarHashBytes>(),
    ) {
        let should_retry = should_retry_batch_failure_model(
            retries_left,
            Some(hash),
            idx,
            applied,
        );

        prop_assert!(
            should_retry,
            "hash-bound reorg batch failures should retry while budget remains, even if idx <= applied"
        );

        prop_assert_eq!(
            next_retry_count_model(retries_left),
            Some(retries_left - 1),
            "hash-bound batch retry must decrement retry budget"
        );
    }

    #[test]
    fn test_008_canonical_batch_failure_retries_only_for_unapplied_height(
        idx in any::<u64>(),
        applied in any::<u64>(),
        retries_left in any::<u8>(),
    ) {
        let should_retry = should_retry_batch_failure_model(
            retries_left,
            None,
            idx,
            applied,
        );

        prop_assert_eq!(
            should_retry,
            retries_left > 0 && idx > applied,
            "canonical batch failures must not retry old or already-applied heights"
        );
    }

    #[test]
    fn test_009_batch_retry_predicate_never_retries_when_budget_is_zero(
        idx in any::<u64>(),
        applied in any::<u64>(),
        maybe_hash in prop::option::of(any::<RemzarHashBytes>()),
    ) {
        prop_assert!(
            !should_retry_batch_failure_model(0, maybe_hash, idx, applied),
            "batch failure retry predicate must be false when retries_left is zero"
        );
    }

    #[test]
    fn test_010_batch_mode_model_distinguishes_canonical_from_hash_bound(
        maybe_hash in prop::option::of(any::<RemzarHashBytes>()),
    ) {
        let mode = handler_batch_mode_model(maybe_hash);

        if maybe_hash.is_some() {
            prop_assert_eq!(mode, "hash_bound_reorg");
        } else {
            prop_assert_eq!(mode, "canonical");
        }
    }

    #[test]
    fn test_011_exceeds_consensus_cap_model_is_strict_at_boundary(
        extra in 0usize..=4096usize,
    ) {
        let cap = consensus_cap_for_test();
        let n = cap.saturating_add(extra);

        prop_assert_eq!(
            exceeds_consensus_cap_model(n),
            extra > 0,
            "consensus-cap model must allow exactly MAX_BLOCK_SIZE and reject MAX_BLOCK_SIZE + 1"
        );
    }

    #[test]
    fn test_012_exceeds_consensus_cap_model_matches_config_for_all_generated_sizes(
        n in any::<usize>(),
    ) {
        let cap = consensus_cap_for_test();

        prop_assert_eq!(
            exceeds_consensus_cap_model(n),
            n > cap,
            "consensus-cap model must exactly match n > GlobalConfiguration::MAX_BLOCK_SIZE"
        );
    }

    #[test]
    fn test_013_consensus_cap_check_model_is_monotonic(
        a in any::<usize>(),
        b in any::<usize>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        if exceeds_consensus_cap_model(low) {
            prop_assert!(
                exceeds_consensus_cap_model(high),
                "once a smaller response exceeds cap, all larger responses must exceed cap"
            );
        }

        if !exceeds_consensus_cap_model(high) {
            prop_assert!(
                !exceeds_consensus_cap_model(low),
                "if a larger response is accepted by cap, all smaller responses must be accepted by cap"
            );
        }
    }

    #[test]
    fn test_014_usize_to_u64_saturating_model_matches_try_from_contract(
        n in any::<usize>(),
    ) {
        let expected = u64::try_from(n).unwrap_or(u64::MAX);

        prop_assert_eq!(
            usize_to_u64_saturating_model(n),
            expected,
            "byte-budget reporting must preserve representable usize values and saturate only on overflow"
        );
    }

    #[test]
    fn test_015_batchdata_response_cap_classification_matches_payload_length(
        payload in proptest::collection::vec(any::<u8>(), 0..7_500),
    ) {
        let response = BlockTxResponse::BatchData(payload.clone());

        prop_assert_eq!(
            response_payload_len(&response),
            Some(payload.len()),
            "BatchData payload length must be exact"
        );

        prop_assert_eq!(
            classify_batch_response_for_cap_model(&response),
            Some(exceeds_consensus_cap_model(payload.len())),
            "BatchData cap classification must be based on exact payload length"
        );
    }

    #[test]
    fn test_016_batchdata_small_payload_is_not_oversized(
        payload in proptest::collection::vec(any::<u8>(), 0..7_500),
    ) {
        let response = BlockTxResponse::BatchData(payload);

        prop_assert_eq!(
            classify_batch_response_for_cap_model(&response),
            Some(false),
            "small generated BatchData payloads must be below the configured consensus cap"
        );
    }

    #[test]
    fn test_017_transaction_batch_storage_roundtrip_serializes_stably(
        index in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        let batch = TransactionBatch::new(index, timestamp, Vec::new())
            .expect("empty generated batch should construct");

        let bytes = batch.serialize()
            .expect("empty generated batch should serialize");

        prop_assert!(
            !exceeds_consensus_cap_model(bytes.len()),
            "empty batch serialization should stay within consensus cap"
        );

        let decoded = TransactionBatch::deserialize(&bytes)
            .expect("serialized batch should deserialize");

        let roundtrip = decoded.serialize()
            .expect("decoded batch should serialize again");

        prop_assert_eq!(
            roundtrip,
            bytes,
            "batch serialize -> deserialize -> serialize must be stable"
        );
    }

    #[test]
    fn test_018_transaction_batch_deserialize_never_panics_for_untrusted_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..7_500),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            TransactionBatch::deserialize(&bytes)
        }));

        prop_assert!(
            result.is_ok(),
            "batch deserialization path used by sync handlers must never panic on untrusted bytes"
        );
    }

    #[test]
    fn test_019_corrupted_serialized_batch_deserialize_or_reserialize_never_panics(
        index in any::<u64>(),
        timestamp in any::<u64>(),
        corrupt_index in any::<usize>(),
        xor_byte in 1u8..=255u8,
    ) {
        let batch = TransactionBatch::new(index, timestamp, Vec::new())
            .expect("empty generated batch should construct");

        let bytes = batch.serialize()
            .expect("empty generated batch should serialize");

        let corrupted = corrupt_one_byte(bytes, corrupt_index, xor_byte);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(decoded) = TransactionBatch::deserialize(&corrupted) {
                let _roundtrip = decoded.serialize();
            }
        }));

        prop_assert!(
            result.is_ok(),
            "corrupted batch bytes must not panic during deserialize or reserialize"
        );
    }

    #[test]
    fn test_020_merkle_root_computation_never_panics_and_success_is_64_bytes(
        index in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        let batch = TransactionBatch::new(index, timestamp, Vec::new())
            .expect("empty generated batch should construct");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            batch.compute_merkle_root()
        }));

        prop_assert!(
            result.is_ok(),
            "merkle-root computation called by batch handler must never panic"
        );

        if let Ok(Ok(root)) = result {
            prop_assert_eq!(
                root.len(),
                REMZAR_HASH_BYTES_LEN,
                "successful merkle root computation must return 64-byte chain hash"
            );
        }
    }

    #[test]
    fn test_021_merkle_mismatch_predicate_detects_any_different_64_byte_root(
        header_root in any::<RemzarHashBytes>(),
        computed_root in any::<RemzarHashBytes>(),
    ) {
        prop_assert_eq!(
            hashes_equal_for_merkle_check_model(header_root, computed_root),
            header_root == computed_root,
            "merkle acceptance predicate must be exact 64-byte equality"
        );

        if header_root != computed_root {
            prop_assert!(
                !hashes_equal_for_merkle_check_model(header_root, computed_root),
                "any different 64-byte merkle root must be treated as mismatch"
            );
        }
    }

    #[test]
    fn test_022_last_resort_disconnect_classification_is_stable(_probe in any::<u8>()) {
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::NotAdmitted));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::PeerRateLimited));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::IpRateLimited));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::PeerInflightCap));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::GlobalInflightCap));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::DuplicateRequest));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::PeerByteBudgetExceeded));
        prop_assert!(!last_resort_drop_requires_disconnect_model(LastResortDrop::GlobalByteBudgetExceeded));

        prop_assert!(last_resort_drop_requires_disconnect_model(LastResortDrop::PeerCoolingDown));
        prop_assert!(last_resort_drop_requires_disconnect_model(LastResortDrop::CounterOverflow));
    }

    #[test]
    fn test_023_ip_extraction_model_preserves_exact_ipv4_and_ipv6(
        v4 in any::<[u8; 4]>(),
        v6 in any::<[u8; 16]>(),
        tcp_port in any::<u16>(),
        udp_port in any::<u16>(),
    ) {
        let ipv4_addr = make_ipv4_addr(v4, tcp_port);
        prop_assert_eq!(
            ip_from_multiaddr_model(&ipv4_addr),
            Some(IpAddr::V4(Ipv4Addr::from(v4))),
            "IPv4 extraction must preserve exact octets"
        );

        let ipv6_addr = make_ipv6_addr(v6, udp_port);
        prop_assert_eq!(
            ip_from_multiaddr_model(&ipv6_addr),
            Some(IpAddr::V6(Ipv6Addr::from(v6))),
            "IPv6 extraction must preserve exact octets"
        );
    }

    #[test]
    fn test_024_ip_extraction_model_returns_none_for_non_ip_addresses(
        memory_id in any::<u64>(),
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
    }

    #[test]
    fn test_025_ip_extraction_model_matches_first_ip_for_arbitrary_generated_components(
        components in proptest::collection::vec(addr_component_strategy(), 0..32),
    ) {
        let addr = build_multiaddr_from_components(&components);
        let expected = expected_first_ip_from_components(&components);

        let result = std::panic::catch_unwind(|| ip_from_multiaddr_model(&addr));

        prop_assert!(
            result.is_ok(),
            "IP extraction model must never panic for generated valid Multiaddr components"
        );

        prop_assert_eq!(
            result.expect("panic already checked"),
            expected,
            "IP extraction model must return exactly the first IP component in iteration order"
        );
    }
}
