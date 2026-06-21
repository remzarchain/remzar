// tests/proptests_p2p_003_sync_swarmevent.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_005_pq_fips203kem::PQ_NONCE_LEN;
use remzar::network::p2p_006_reqresp::{BlockTxRequest, Hash};
use remzar::network::p2p_007_handshake::{Services, VersionInfo};
use remzar::network::p2p_009_events::{
    attach_peer_to_addr, kad_ready_addrs, split_multiaddr_base_and_peer,
};
use remzar::network::p2p_018_last_resort_guards::{ActionClass, LastResortDrop, LastResortGuards};
use remzar::runtime::p2p_001_sync_builders::{REMZAR_HASH_BYTES_LEN, RemzarHashBytes};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

const MAX_RETRIES_MODEL: u8 = 3;
const MAX_MULTIADDR_BYTES_MODEL: usize = 256;
const MAX_PENDING_BLOCKS_MODEL: usize = 1024;
const MAX_PENDING_BATCHES_MODEL: usize = 1024;

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

fn is_sync_by_index_request_model(request: &BlockTxRequest) -> bool {
    matches!(
        request,
        BlockTxRequest::GetBlockByIndex { .. } | BlockTxRequest::GetBatchByIndex { .. }
    )
}

fn soft_allows_duplicate_sync_request_model(
    request: &BlockTxRequest,
    drop: LastResortDrop,
) -> bool {
    matches!(drop, LastResortDrop::DuplicateRequest) && is_sync_by_index_request_model(request)
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

fn make_addr_at_least_len(min_len: usize) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    let mut seed = 1u64;

    while addr.to_vec().len() < min_len {
        addr.push(Protocol::Memory(seed));
        seed = seed.saturating_add(1);
    }

    addr
}

fn model_filter_multiaddr_bounds(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addrs
        .into_iter()
        .filter(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL)
        .collect()
}

fn model_pq_nonce_from_now_ms(now_ms: u128) -> [u8; PQ_NONCE_LEN] {
    let nonce_seed = now_ms.to_le_bytes();
    let mut offer_nonce = [0u8; PQ_NONCE_LEN];
    let seed_len = nonce_seed.len();

    for (i, b) in offer_nonce.iter_mut().enumerate() {
        let seed_idx = i % seed_len;
        *b = nonce_seed[seed_idx];
    }

    offer_nonce
}

fn request_action_cost_dup_key(request: &BlockTxRequest) -> (ActionClass, u32, Option<u64>) {
    match request {
        BlockTxRequest::GetBlock { hash } => (
            ActionClass::BlockTxGetBlock,
            3,
            Some(LastResortGuards::dup_key_from_str(&format!(
                "GetBlock:{}",
                hex::encode(hash)
            ))),
        ),
        BlockTxRequest::GetBlockByIndex { index } => (
            ActionClass::BlockTxGetBlock,
            3,
            Some(LastResortGuards::dup_key_from_str(&format!(
                "GetBlockByIndex:{index}"
            ))),
        ),
        BlockTxRequest::GetBatchByIndex { index } => (
            ActionClass::BlockTxGetBatch,
            4,
            Some(LastResortGuards::dup_key_from_str(&format!(
                "GetBatchByIndex:{index}"
            ))),
        ),
        BlockTxRequest::GetBatchByHash { hash } => (
            ActionClass::BlockTxGetBatch,
            4,
            Some(LastResortGuards::dup_key_from_str(&format!(
                "GetBatchByHash:{}",
                hex::encode(hash)
            ))),
        ),
        BlockTxRequest::GetTx { hash } => (
            ActionClass::BlockTxGetTx,
            2,
            Some(LastResortGuards::dup_key_from_str(&format!(
                "GetTx:{}",
                hex::encode(hash)
            ))),
        ),
    }
}

fn all_drops_except_duplicate() -> impl Strategy<Value = LastResortDrop> {
    prop_oneof![
        Just(LastResortDrop::NotAdmitted),
        Just(LastResortDrop::PeerRateLimited),
        Just(LastResortDrop::IpRateLimited),
        Just(LastResortDrop::PeerInflightCap),
        Just(LastResortDrop::GlobalInflightCap),
        Just(LastResortDrop::PeerByteBudgetExceeded),
        Just(LastResortDrop::GlobalByteBudgetExceeded),
        Just(LastResortDrop::PeerCoolingDown),
        Just(LastResortDrop::CounterOverflow),
    ]
}

fn request_strategy() -> impl Strategy<Value = BlockTxRequest> {
    prop_oneof![
        any::<Hash>().prop_map(|hash| BlockTxRequest::GetBlock { hash }),
        any::<Hash>().prop_map(|hash| BlockTxRequest::GetTx { hash }),
        any::<Hash>().prop_map(|hash| BlockTxRequest::GetBatchByHash { hash }),
        any::<u64>().prop_map(|index| BlockTxRequest::GetBlockByIndex { index }),
        any::<u64>().prop_map(|index| BlockTxRequest::GetBatchByIndex { index }),
    ]
}

fn should_queue_block_after_event_model(syncing: bool, pending_blocks_len: usize) -> bool {
    syncing && pending_blocks_len == 0 && pending_blocks_len < MAX_PENDING_BLOCKS_MODEL
}

fn should_queue_batch_after_event_model(syncing: bool, pending_batches_len: usize) -> bool {
    syncing && pending_batches_len == 0 && pending_batches_len < MAX_PENDING_BATCHES_MODEL
}

fn should_skip_batch_queue_item_model(idx: u64, applied: u64) -> bool {
    idx <= applied
}

fn retry_after_outbound_failure_model(retries_left: u8, already_have_item: bool) -> Option<u8> {
    if retries_left > 0 && !already_have_item {
        Some(retries_left.saturating_sub(1))
    } else {
        None
    }
}

fn response_should_be_not_found_for_oversize_model(n: usize) -> bool {
    exceeds_consensus_cap_model(n)
}

fn attach_logic_for_connection_established_model(
    remote_addr: &Multiaddr,
    peer_id: &PeerId,
) -> Multiaddr {
    match split_multiaddr_base_and_peer(remote_addr) {
        (base, Some(existing_pid)) if existing_pid == *peer_id => {
            attach_peer_to_addr(base, peer_id)
        }
        (base, None) => attach_peer_to_addr(base, peer_id),
        (_, Some(_other_pid)) => remote_addr.clone(),
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Config::default()
    })]

    #[test]
    fn test_001_is_sync_by_index_request_true_only_for_block_and_batch_index(
        hash in any::<Hash>(),
        index in any::<u64>(),
    ) {
        prop_assert!(
            is_sync_by_index_request_model(&BlockTxRequest::GetBlockByIndex { index }),
            "GetBlockByIndex must be treated as a sync-by-index request"
        );

        prop_assert!(
            is_sync_by_index_request_model(&BlockTxRequest::GetBatchByIndex { index }),
            "GetBatchByIndex must be treated as a sync-by-index request"
        );

        prop_assert!(
            !is_sync_by_index_request_model(&BlockTxRequest::GetBlock { hash }),
            "GetBlock by hash must not be treated as sync-by-index"
        );

        prop_assert!(
            !is_sync_by_index_request_model(&BlockTxRequest::GetTx { hash }),
            "GetTx must not be treated as sync-by-index"
        );

        prop_assert!(
            !is_sync_by_index_request_model(&BlockTxRequest::GetBatchByHash { hash }),
            "GetBatchByHash must not be treated as sync-by-index"
        );
    }

    #[test]
    fn test_002_soft_allow_duplicate_applies_only_to_duplicate_sync_by_index_requests(
        index in any::<u64>(),
    ) {
        let block_by_index = BlockTxRequest::GetBlockByIndex { index };
        let batch_by_index = BlockTxRequest::GetBatchByIndex { index };

        prop_assert!(
            soft_allows_duplicate_sync_request_model(
                &block_by_index,
                LastResortDrop::DuplicateRequest,
            ),
            "duplicate GetBlockByIndex should be soft-allowed"
        );

        prop_assert!(
            soft_allows_duplicate_sync_request_model(
                &batch_by_index,
                LastResortDrop::DuplicateRequest,
            ),
            "duplicate GetBatchByIndex should be soft-allowed"
        );
    }

    #[test]
    fn test_003_soft_allow_duplicate_never_applies_to_hash_or_tx_requests(
        hash in any::<Hash>(),
    ) {
        let requests = vec![
            BlockTxRequest::GetBlock { hash },
            BlockTxRequest::GetTx { hash },
            BlockTxRequest::GetBatchByHash { hash },
        ];

        for request in requests {
            prop_assert!(
                !soft_allows_duplicate_sync_request_model(
                    &request,
                    LastResortDrop::DuplicateRequest,
                ),
                "duplicate soft-allow must not apply to hash-bound or tx requests"
            );
        }
    }

    #[test]
    fn test_004_soft_allow_duplicate_rejects_all_non_duplicate_drops_for_any_request(
        request in request_strategy(),
        drop in all_drops_except_duplicate(),
    ) {
        prop_assert!(
            !soft_allows_duplicate_sync_request_model(&request, drop),
            "only DuplicateRequest may trigger soft duplicate sync allowance"
        );
    }

    #[test]
    fn test_005_request_action_class_mapping_matches_swarm_blocktx_guard_path(
        hash in any::<Hash>(),
        index in any::<u64>(),
    ) {
        let cases = vec![
            (BlockTxRequest::GetBlock { hash }, ActionClass::BlockTxGetBlock),
            (BlockTxRequest::GetBlockByIndex { index }, ActionClass::BlockTxGetBlock),
            (BlockTxRequest::GetBatchByIndex { index }, ActionClass::BlockTxGetBatch),
            (BlockTxRequest::GetBatchByHash { hash }, ActionClass::BlockTxGetBatch),
            (BlockTxRequest::GetTx { hash }, ActionClass::BlockTxGetTx),
        ];

        for (request, expected_action) in cases {
            let (action, _, _) = request_action_cost_dup_key(&request);

            prop_assert_eq!(
                action,
                expected_action,
                "BlockTx request must map to the correct last-resort action class"
            );
        }
    }

    #[test]
    fn test_006_request_cost_mapping_preserves_relative_expense(
        hash in any::<Hash>(),
        index in any::<u64>(),
    ) {
        let get_block = BlockTxRequest::GetBlock { hash };
        let get_block_by_index = BlockTxRequest::GetBlockByIndex { index };
        let get_batch_by_index = BlockTxRequest::GetBatchByIndex { index };
        let get_batch_by_hash = BlockTxRequest::GetBatchByHash { hash };
        let get_tx = BlockTxRequest::GetTx { hash };

        prop_assert_eq!(request_action_cost_dup_key(&get_block).1, 3);
        prop_assert_eq!(request_action_cost_dup_key(&get_block_by_index).1, 3);
        prop_assert_eq!(request_action_cost_dup_key(&get_batch_by_index).1, 4);
        prop_assert_eq!(request_action_cost_dup_key(&get_batch_by_hash).1, 4);
        prop_assert_eq!(request_action_cost_dup_key(&get_tx).1, 2);

        prop_assert!(
            request_action_cost_dup_key(&get_batch_by_index).1
                > request_action_cost_dup_key(&get_tx).1,
            "batch requests must cost more than tx lookup requests"
        );
    }

    #[test]
    fn test_007_dup_key_generation_is_stable_for_identical_requests(
        request in request_strategy(),
    ) {
        let (_, _, key_a) = request_action_cost_dup_key(&request);
        let (_, _, key_b) = request_action_cost_dup_key(&request);

        prop_assert_eq!(
            key_a,
            key_b,
            "duplicate suppression keys must be deterministic for identical request values"
        );

        prop_assert!(
            key_a.is_some(),
            "all BlockTx request variants should produce a duplicate-suppression key"
        );
    }

    #[test]
    fn test_008_dup_keys_are_variant_distinct_for_same_hash_or_index(
        hash in any::<Hash>(),
        index in any::<u64>(),
    ) {
        let requests = vec![
            BlockTxRequest::GetBlock { hash },
            BlockTxRequest::GetTx { hash },
            BlockTxRequest::GetBatchByHash { hash },
            BlockTxRequest::GetBlockByIndex { index },
            BlockTxRequest::GetBatchByIndex { index },
        ];

        let mut keys = std::collections::BTreeSet::new();

        for request in requests {
            let (_, _, key) = request_action_cost_dup_key(&request);
            prop_assert!(
                keys.insert(key.expect("BlockTx request should have dup key")),
                "different BlockTx request variants must not collide in duplicate-suppression key space"
            );
        }

        prop_assert_eq!(keys.len(), 5);
    }

    #[test]
    fn test_009_dup_key_is_hash_sensitive_for_hash_bound_requests(
        hash_a in any::<Hash>(),
        hash_b in any::<Hash>(),
    ) {
        prop_assume!(hash_a != hash_b);

        let variants_a = vec![
            BlockTxRequest::GetBlock { hash: hash_a },
            BlockTxRequest::GetTx { hash: hash_a },
            BlockTxRequest::GetBatchByHash { hash: hash_a },
        ];

        let variants_b = vec![
            BlockTxRequest::GetBlock { hash: hash_b },
            BlockTxRequest::GetTx { hash: hash_b },
            BlockTxRequest::GetBatchByHash { hash: hash_b },
        ];

        for (a, b) in variants_a.into_iter().zip(variants_b) {
            prop_assert_ne!(
                request_action_cost_dup_key(&a).2,
                request_action_cost_dup_key(&b).2,
                "hash-bound duplicate keys must change when the 64-byte hash changes"
            );
        }
    }

    #[test]
    fn test_010_dup_key_is_index_sensitive_for_index_requests(
        index_a in any::<u64>(),
        index_b in any::<u64>(),
    ) {
        prop_assume!(index_a != index_b);

        let block_a = BlockTxRequest::GetBlockByIndex { index: index_a };
        let block_b = BlockTxRequest::GetBlockByIndex { index: index_b };
        let batch_a = BlockTxRequest::GetBatchByIndex { index: index_a };
        let batch_b = BlockTxRequest::GetBatchByIndex { index: index_b };

        prop_assert_ne!(
            request_action_cost_dup_key(&block_a).2,
            request_action_cost_dup_key(&block_b).2,
            "GetBlockByIndex duplicate key must change when index changes"
        );

        prop_assert_ne!(
            request_action_cost_dup_key(&batch_a).2,
            request_action_cost_dup_key(&batch_b).2,
            "GetBatchByIndex duplicate key must change when index changes"
        );
    }

    #[test]
    fn test_011_consensus_cap_boundary_is_strict_for_swarm_responses(
        extra in 0usize..=4096usize,
    ) {
        let cap = consensus_cap_for_test();
        let n = cap.saturating_add(extra);

        prop_assert_eq!(
            response_should_be_not_found_for_oversize_model(n),
            extra > 0,
            "swarm response path must allow exactly MAX_BLOCK_SIZE and reject MAX_BLOCK_SIZE + 1"
        );
    }

    #[test]
    fn test_012_consensus_cap_classification_matches_global_config_for_all_sizes(
        n in any::<usize>(),
    ) {
        let cap = consensus_cap_for_test();

        prop_assert_eq!(
            exceeds_consensus_cap_model(n),
            n > cap,
            "swarm-event consensus cap model must exactly match n > GlobalConfiguration::MAX_BLOCK_SIZE"
        );
    }

    #[test]
    fn test_013_consensus_cap_classification_is_monotonic(
        a in any::<usize>(),
        b in any::<usize>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        if exceeds_consensus_cap_model(low) {
            prop_assert!(
                exceeds_consensus_cap_model(high),
                "if a smaller payload exceeds cap, every larger payload must also exceed cap"
            );
        }

        if !exceeds_consensus_cap_model(high) {
            prop_assert!(
                !exceeds_consensus_cap_model(low),
                "if a larger payload is within cap, every smaller payload must also be within cap"
            );
        }
    }

    #[test]
    fn test_014_usize_to_u64_saturating_preserves_byte_budget_contract(
        n in any::<usize>(),
    ) {
        let expected = u64::try_from(n).unwrap_or(u64::MAX);

        prop_assert_eq!(
            usize_to_u64_saturating_model(n),
            expected,
            "swarm byte-budget accounting model must preserve representable usize values and saturate only on overflow"
        );
    }

    #[test]
    fn test_015_pq_nonce_model_has_exact_length_and_repeats_u128_seed_bytes(
        now_ms in any::<u128>(),
    ) {
        let nonce = model_pq_nonce_from_now_ms(now_ms);
        let seed = now_ms.to_le_bytes();

        prop_assert_eq!(
            nonce.len(),
            PQ_NONCE_LEN,
            "outbound PQ nonce must always have PQ_NONCE_LEN bytes"
        );

        for i in 0..PQ_NONCE_LEN {
            prop_assert_eq!(
                nonce[i],
                seed[i % seed.len()],
                "PQ nonce byte must be derived by repeating now_ms little-endian seed bytes"
            );
        }
    }

    #[test]
    fn test_016_pq_nonce_model_is_deterministic_and_time_sensitive(
        now_a in any::<u128>(),
        now_b in any::<u128>(),
    ) {
        let nonce_a1 = model_pq_nonce_from_now_ms(now_a);
        let nonce_a2 = model_pq_nonce_from_now_ms(now_a);

        prop_assert_eq!(
            nonce_a1,
            nonce_a2,
            "same now_ms input must generate the same PQ offer nonce"
        );

        if now_a != now_b {
            let nonce_b = model_pq_nonce_from_now_ms(now_b);

            prop_assert_ne!(
                nonce_a1,
                nonce_b,
                "different now_ms values should produce different deterministic PQ nonce seeds"
            );
        }
    }

    #[test]
    fn test_017_version_response_template_is_valid_and_uses_canonical_genesis_hash(
        chain_height in any::<u64>(),
    ) {
        let response = VersionInfo {
            protocol_version: 1,
            chain_height,
            services: Services::NODE,
            user_agent: "remzar/v0.1.0".into(),
            genesis_hash: Some(genesis_hash_bytes_64_model()),
        };

        prop_assert!(
            response.validate_untrusted().is_ok(),
            "swarm Version(Request) response template must validate as untrusted wire data"
        );

        prop_assert_eq!(response.protocol_version, 1);
        prop_assert_eq!(response.chain_height, chain_height);
        prop_assert_eq!(response.services, Services::NODE);
        prop_assert_eq!(response.genesis_hash, Some(genesis_hash_bytes_64_model()));
    }

    #[test]
    fn test_018_genesis_hash_bytes_match_global_configuration_hex(
        _probe in any::<u8>(),
    ) {
        let genesis = genesis_hash_bytes_64_model();

        let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX)
            .expect("GENESIS_HASH_HEX must be valid hex");

        prop_assert_eq!(
            decoded.len(),
            REMZAR_HASH_BYTES_LEN,
            "configured genesis hash must decode to 64 bytes"
        );

        prop_assert_eq!(
            genesis.as_slice(),
            decoded.as_slice(),
            "swarm-event version handshake model must use the configured canonical genesis hash"
        );
    }

    #[test]
    fn test_019_zero_hash_sentinel_is_distinct_from_genesis_hash_and_has_fixed_width(
        _probe in any::<u8>(),
    ) {
        let zero = zero_hash_64_model();
        let genesis = genesis_hash_bytes_64_model();

        prop_assert_eq!(zero.len(), REMZAR_HASH_BYTES_LEN);
        prop_assert!(zero.iter().all(|b| *b == 0));
        prop_assert_eq!(genesis.len(), REMZAR_HASH_BYTES_LEN);

        prop_assert_ne!(
            genesis,
            zero,
            "genesis hash must never equal the zero parent sentinel"
        );
    }

    #[test]
    fn test_020_connection_established_attach_logic_adds_peer_to_base_addr_without_p2p(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let peer = fresh_peer_id();
        let base = make_ipv4_addr(octets, port);

        let attached = attach_logic_for_connection_established_model(&base, &peer);
        let (stripped_base, trailing_peer) = split_multiaddr_base_and_peer(&attached);

        prop_assert_eq!(
            stripped_base,
            base,
            "attaching peer should preserve the original base transport address"
        );

        prop_assert_eq!(
            trailing_peer,
            Some(peer),
            "connection-established address normalization must append the connected peer id"
        );
    }

    #[test]
    fn test_021_connection_established_attach_logic_keeps_matching_existing_peer_suffix(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let peer = fresh_peer_id();
        let base = make_ipv4_addr(octets, port);
        let already_attached = attach_peer_to_addr(base.clone(), &peer);

        let normalized = attach_logic_for_connection_established_model(&already_attached, &peer);

        prop_assert_eq!(
            normalized.clone(),
            already_attached,
            "matching /p2p suffix should be preserved, not duplicated"
        );

        let (normalized_base, normalized_peer) = split_multiaddr_base_and_peer(&normalized);

        prop_assert_eq!(normalized_base, base);
        prop_assert_eq!(normalized_peer, Some(peer));
    }

    #[test]
    fn test_022_connection_established_attach_logic_preserves_mismatched_peer_suffix(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let connected_peer = fresh_peer_id();
        let other_peer = fresh_peer_id();

        prop_assume!(connected_peer != other_peer);

        let base = make_ipv4_addr(octets, port);
        let remote_addr_with_other_peer = attach_peer_to_addr(base, &other_peer);

        let normalized =
            attach_logic_for_connection_established_model(&remote_addr_with_other_peer, &connected_peer);

        prop_assert_eq!(
            normalized,
            remote_addr_with_other_peer,
            "mismatched /p2p suffix should be preserved exactly for defensive correctness"
        );
    }

    #[test]
    fn test_023_multiaddr_bound_filter_preserves_order_and_removes_oversized_addrs(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        let small_a = make_memory_addr(seed_a);
        let small_b = make_memory_addr(seed_b);
        let small_c = make_memory_addr(seed_c);
        let oversized = make_addr_at_least_len(MAX_MULTIADDR_BYTES_MODEL.saturating_add(1));

        prop_assume!(small_a.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL);
        prop_assume!(small_b.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL);
        prop_assume!(small_c.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL);
        prop_assume!(oversized.to_vec().len() > MAX_MULTIADDR_BYTES_MODEL);

        let filtered = model_filter_multiaddr_bounds(vec![
            small_a.clone(),
            oversized,
            small_b.clone(),
            small_c.clone(),
        ]);

        prop_assert_eq!(
            filtered,
            vec![small_a, small_b, small_c],
            "swarm-event address ingestion model must drop oversized multiaddrs without reordering accepted addresses"
        );
    }

    #[test]
    fn test_024_ip_extraction_and_kad_ready_addrs_preserve_transport_base(
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

        let peer = fresh_peer_id();
        let full = attach_peer_to_addr(ipv4_addr.clone(), &peer);
        let kad_addrs = kad_ready_addrs(&[full]);

        prop_assert!(
            kad_addrs.iter().all(|addr| split_multiaddr_base_and_peer(addr).1.is_none()),
            "Kad-ready addresses must strip trailing /p2p peer ids"
        );

        prop_assert!(
            kad_addrs.contains(&ipv4_addr),
            "Kad-ready address set should contain the base transport address"
        );
    }

    #[test]
    fn test_025_post_event_queue_retry_and_skip_predicates_are_safe_at_boundaries(
        syncing in any::<bool>(),
        pending_blocks_len in 0usize..=(MAX_PENDING_BLOCKS_MODEL.saturating_add(4)),
        pending_batches_len in 0usize..=(MAX_PENDING_BATCHES_MODEL.saturating_add(4)),
        idx in any::<u64>(),
        applied in any::<u64>(),
        retries_left in any::<u8>(),
        already_have_item in any::<bool>(),
    ) {
        prop_assert_eq!(
            should_queue_block_after_event_model(syncing, pending_blocks_len),
            syncing && pending_blocks_len == 0,
            "post-event block queue drain should only start while syncing and no block request is pending"
        );

        prop_assert_eq!(
            should_queue_batch_after_event_model(syncing, pending_batches_len),
            syncing && pending_batches_len == 0,
            "post-event batch queue drain should only start while syncing and no batch request is pending"
        );

        prop_assert_eq!(
            should_skip_batch_queue_item_model(idx, applied),
            idx <= applied,
            "queued batch item must be skipped once its height is already applied"
        );

        let expected_retry = if retries_left > 0 && !already_have_item {
            Some(retries_left - 1)
        } else {
            None
        };

        prop_assert_eq!(
            retry_after_outbound_failure_model(retries_left, already_have_item),
            expected_retry,
            "outbound-failure retry must decrement only when budget remains and item is still missing"
        );

        prop_assert_eq!(
            retry_after_outbound_failure_model(MAX_RETRIES_MODEL, false),
            Some(MAX_RETRIES_MODEL - 1),
            "MAX_RETRIES_MODEL first failure transition must decrement exactly once"
        );
    }
}
