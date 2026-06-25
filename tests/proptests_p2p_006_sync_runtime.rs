// tests/proptests_p2p_006_sync_runtime.rs

use std::collections::HashSet;

use clap::Parser;
use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::runtime::p2p_006_sync_runtime::NodeOpts;

const MAX_MULTIADDR_BYTES_MODEL: usize = 256;
const MAX_CLI_BOOTSTRAPS_MODEL: usize = 256;
const MAX_STARTUP_DIALS_MODEL: usize = 256;
const MAX_KAD_SEEDS_MODEL: usize = 2048;
const HARDCODED_SEEDS_MODEL: &[(&str, &str)] = &[];
const TEST_WALLET_ADDRESS: &str = "r72656d7a6172626c6f636b636861696e6279726f6e616c6464656c616d6f7474656c61756e636865646a756e65323632303236746f323230306d61696e6e6574";

fn fresh_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn make_ipv4_addr(octets: [u8; 4], port: u16) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip4(octets.into()));
    addr.push(Protocol::Tcp(port));
    addr
}

fn make_ipv6_addr(octets: [u8; 16], port: u16) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip6(octets.into()));
    addr.push(Protocol::Tcp(port));
    addr
}

fn make_memory_addr(seed: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(seed));
    addr
}

fn make_oversized_addr(min_len: usize) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    let mut seed = 1u64;

    while addr.to_vec().len() <= min_len {
        addr.push(Protocol::Memory(seed));
        seed = seed.saturating_add(1);
    }

    addr
}

fn attach_peer_to_addr_model(mut addr: Multiaddr, peer: &PeerId) -> Multiaddr {
    addr.push(Protocol::P2p(peer.clone()));
    addr
}

fn multiaddr_within_bounds_model(addr: &Multiaddr) -> bool {
    addr.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL
}

fn filter_multiaddrs_within_bounds_model(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addrs
        .into_iter()
        .filter(multiaddr_within_bounds_model)
        .collect()
}

fn parse_cli_bootstraps_model(raw: &[String]) -> Vec<Multiaddr> {
    raw.iter()
        .take(MAX_CLI_BOOTSTRAPS_MODEL)
        .filter_map(|s| match s.parse::<Multiaddr>() {
            Ok(addr) if multiaddr_within_bounds_model(&addr) => Some(addr),
            _ => None,
        })
        .collect()
}

fn split_trailing_p2p_model(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut protocols: Vec<_> = addr.iter().collect();

    match protocols.last().cloned() {
        Some(Protocol::P2p(peer)) => {
            protocols.pop();
            let base: Multiaddr = protocols.into_iter().collect();
            Some((peer, base))
        }
        _ => None,
    }
}

fn cli_seed_pairs_model(addrs: &[Multiaddr]) -> Vec<(PeerId, Multiaddr)> {
    addrs
        .iter()
        .filter_map(|addr| {
            let (peer, _base) = split_trailing_p2p_model(addr)?;
            Some((peer, addr.clone()))
        })
        .collect()
}

fn startup_dial_list_model(
    cli_addrs: Vec<Multiaddr>,
    peerbook_addrs: Vec<Multiaddr>,
) -> Vec<Multiaddr> {
    let mut all = Vec::new();
    let mut seen = HashSet::<String>::new();

    for addr in cli_addrs.iter().chain(peerbook_addrs.iter()) {
        let key = addr.to_string();

        if seen.insert(key) {
            all.push(addr.clone());
        }

        if all.len() >= MAX_STARTUP_DIALS_MODEL {
            break;
        }
    }

    all
}

fn kad_seed_count_model(
    cli_addrs: &[Multiaddr],
    peerbook_top: &[(PeerId, Vec<Multiaddr>)],
) -> usize {
    let mut kad_seeds = 0usize;

    for addr in cli_addrs {
        if kad_seeds >= MAX_KAD_SEEDS_MODEL {
            break;
        }

        if let Some((_peer, base_addr)) = split_trailing_p2p_model(addr) {
            if multiaddr_within_bounds_model(&base_addr) {
                kad_seeds = kad_seeds.saturating_add(1);
            }
        }
    }

    for (_peer, addrs) in peerbook_top {
        for addr in addrs {
            if kad_seeds >= MAX_KAD_SEEDS_MODEL {
                break;
            }

            if multiaddr_within_bounds_model(addr) {
                kad_seeds = kad_seeds.saturating_add(1);
            }
        }

        if kad_seeds >= MAX_KAD_SEEDS_MODEL {
            break;
        }
    }

    kad_seeds
}

fn env_true_model_value(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("y")
                || v.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

fn make_bootstrap_strings(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let port = 10_000u16.saturating_add((i % 50_000) as u16);
            format!("/ip4/127.0.0.1/tcp/{port}")
        })
        .collect()
}

fn make_bootstrap_strings_with_peer(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let port = 10_000u16.saturating_add((i % 50_000) as u16);
            let peer = fresh_peer_id();
            format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
        })
        .collect()
}

fn peerbook_top_model(count: usize) -> Vec<(PeerId, Vec<Multiaddr>)> {
    (0..count)
        .map(|i| {
            let peer = fresh_peer_id();
            let addr = make_ipv4_addr(
                [127, 0, 0, 1],
                20_000u16.saturating_add((i % 40_000) as u16),
            );
            (peer, vec![addr])
        })
        .collect()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Config::default()
    })]

    #[test]
    fn test_001_node_opts_default_values_are_stable(_probe in any::<u8>()) {
        let opts = NodeOpts::default();

        prop_assert_eq!(opts.identity_file, "identity.key");
        prop_assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
        prop_assert!(opts.bootstrap.is_empty());
        prop_assert_eq!(opts.log, "info");
        prop_assert_eq!(opts.data_dir, "data");
        prop_assert_eq!(opts.wallet_address, "");
        prop_assert!(!opts.founder);
    }

    #[test]
    fn test_002_founder_flag_and_alias_parse_to_same_setting(_probe in any::<u8>()) {
        let founder = NodeOpts::try_parse_from([
            "remzar",
            "--wallet-address",
            TEST_WALLET_ADDRESS,
            "--founder",
        ])
        .expect("--founder should parse");

        let alias = NodeOpts::try_parse_from([
            "remzar",
            "--wallet-address",
            TEST_WALLET_ADDRESS,
            "--is-founder",
        ])
        .expect("--is-founder alias should parse");

        prop_assert!(founder.founder);
        prop_assert!(alias.founder);
    }

    #[test]
    fn test_003_custom_cli_fields_parse_without_touching_runtime(
        wallet in "[rR][0-9a-fA-F]{128}",
    ) {
        let opts = NodeOpts::try_parse_from([
            "remzar",
            "--identity-file",
            "test_identity.key",
            "--listen",
            "/ip4/127.0.0.1/tcp/40001",
            "--log",
            "debug",
            "--data-dir",
            "test_data",
            "--wallet-address",
            wallet.as_str(),
        ])
        .expect("custom NodeOpts should parse");

        prop_assert_eq!(opts.identity_file, "test_identity.key");
        prop_assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/40001");
        prop_assert_eq!(opts.log, "debug");
        prop_assert_eq!(opts.data_dir, "test_data");
        prop_assert_eq!(opts.wallet_address, wallet);
    }

    #[test]
    fn test_004_bootstrap_cli_arg_preserves_supplied_multiaddr(
        port in 1u16..=u16::MAX,
    ) {
        let peer = fresh_peer_id();
        let addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");

        let opts = NodeOpts::try_parse_from([
            "remzar",
            "--wallet-address",
            TEST_WALLET_ADDRESS,
            "--bootstrap",
            addr.as_str(),
        ])
        .expect("bootstrap arg should parse");

        prop_assert_eq!(opts.bootstrap.len(), 1);
        prop_assert_eq!(&opts.bootstrap[0], &addr);
    }

    #[test]
    fn test_005_env_true_model_accepts_truthy_spellings(
        value in prop::sample::select(vec![
            "1", "true", "TRUE", "True", "yes", "YES", "y", "Y", "on", "ON", "  true  ",
        ]),
    ) {
        prop_assert!(
            env_true_model_value(Some(value)),
            "truthy env strings must be accepted"
        );
    }

    #[test]
    fn test_006_env_true_model_rejects_false_or_empty_spellings(
        value in prop::sample::select(vec![
            "", "0", "false", "FALSE", "no", "NO", "n", "off", "OFF", "maybe", " founder ",
        ]),
    ) {
        prop_assert!(
            !env_true_model_value(Some(value)),
            "non-truthy env strings must be rejected"
        );

        prop_assert!(!env_true_model_value(None));
    }

    #[test]
    fn test_007_ipv4_multiaddr_is_within_defensive_bound(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv4_addr(octets, port);

        prop_assert!(
            multiaddr_within_bounds_model(&addr),
            "normal IPv4 TCP multiaddr should be within defensive bound"
        );

        prop_assert!(addr.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL);
    }

    #[test]
    fn test_008_ipv6_multiaddr_is_within_defensive_bound(
        octets in any::<[u8; 16]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv6_addr(octets, port);

        prop_assert!(
            multiaddr_within_bounds_model(&addr),
            "normal IPv6 TCP multiaddr should be within defensive bound"
        );

        prop_assert!(addr.to_vec().len() <= MAX_MULTIADDR_BYTES_MODEL);
    }

    #[test]
    fn test_009_oversized_multiaddr_is_rejected(
        extra in 1usize..=512usize,
    ) {
        let addr = make_oversized_addr(MAX_MULTIADDR_BYTES_MODEL.saturating_add(extra));

        prop_assert!(
            addr.to_vec().len() > MAX_MULTIADDR_BYTES_MODEL,
            "generated oversized multiaddr must exceed defensive bound"
        );

        prop_assert!(
            !multiaddr_within_bounds_model(&addr),
            "oversized multiaddr must be rejected"
        );
    }

    #[test]
    fn test_010_filter_multiaddrs_preserves_order_and_drops_oversized_entries(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        let small_a = make_memory_addr(seed_a);
        let small_b = make_memory_addr(seed_b);
        let small_c = make_memory_addr(seed_c);
        let oversized = make_oversized_addr(MAX_MULTIADDR_BYTES_MODEL);

        prop_assume!(multiaddr_within_bounds_model(&small_a));
        prop_assume!(multiaddr_within_bounds_model(&small_b));
        prop_assume!(multiaddr_within_bounds_model(&small_c));
        prop_assume!(!multiaddr_within_bounds_model(&oversized));

        let filtered = filter_multiaddrs_within_bounds_model(vec![
            small_a.clone(),
            oversized,
            small_b.clone(),
            small_c.clone(),
        ]);

        prop_assert_eq!(
            filtered,
            vec![small_a, small_b, small_c],
            "filtering must remove oversized addrs without reordering accepted addrs"
        );
    }

    #[test]
    fn test_011_cli_bootstrap_parser_caps_untrusted_input_volume(
        raw_count in 0usize..(MAX_CLI_BOOTSTRAPS_MODEL.saturating_mul(3).saturating_add(16)),
    ) {
        let raw = make_bootstrap_strings(raw_count);
        let parsed = parse_cli_bootstraps_model(&raw);

        prop_assert!(
            parsed.len() <= MAX_CLI_BOOTSTRAPS_MODEL,
            "CLI bootstrap parsing must cap accepted input volume"
        );

        prop_assert_eq!(
            parsed.len(),
            raw_count.min(MAX_CLI_BOOTSTRAPS_MODEL),
            "all generated valid bootstraps should parse until the cap"
        );
    }

    #[test]
    fn test_012_cli_bootstrap_parser_ignores_invalid_strings(
        port in 1u16..=u16::MAX,
    ) {
        let good = format!("/ip4/127.0.0.1/tcp/{port}");
        let raw = vec![
            "not-a-multiaddr".to_string(),
            good.clone(),
            "/ip4/999.999.999.999/tcp/abc".to_string(),
        ];

        let parsed = parse_cli_bootstraps_model(&raw);

        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(parsed[0].to_string(), good);
    }

    #[test]
    fn test_013_startup_dial_list_deduplicates_cli_duplicates(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let addr = make_ipv4_addr(octets, port);

        let all = startup_dial_list_model(
            vec![addr.clone(), addr.clone(), addr.clone()],
            Vec::new(),
        );

        prop_assert_eq!(all.len(), 1);
        prop_assert_eq!(&all[0], &addr);
    }

    #[test]
    fn test_014_startup_dial_list_preserves_cli_before_peerbook(
        cli_port in 1u16..=30_000u16,
        peerbook_port in 30_001u16..=u16::MAX,
    ) {
        let cli = make_ipv4_addr([127, 0, 0, 1], cli_port);
        let peerbook = make_ipv4_addr([127, 0, 0, 1], peerbook_port);

        let all = startup_dial_list_model(vec![cli.clone()], vec![peerbook.clone()]);

        prop_assert_eq!(all.len(), 2);
        prop_assert_eq!(&all[0], &cli);
        prop_assert_eq!(&all[1], &peerbook);
    }

    #[test]
    fn test_015_startup_dial_list_caps_total_unique_dials(
        count in MAX_STARTUP_DIALS_MODEL..(MAX_STARTUP_DIALS_MODEL.saturating_mul(3).saturating_add(16)),
    ) {
        let cli: Vec<Multiaddr> = (0..count)
            .map(|i| make_ipv4_addr([127, 0, 0, 1], 10_000u16.saturating_add((i % 50_000) as u16)))
            .collect();

        let all = startup_dial_list_model(cli, Vec::new());

        prop_assert!(
            all.len() <= MAX_STARTUP_DIALS_MODEL,
            "startup dial list must be capped"
        );

        prop_assert_eq!(all.len(), MAX_STARTUP_DIALS_MODEL);
    }

    #[test]
    fn test_016_split_trailing_p2p_extracts_peer_and_transport_base(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let peer = fresh_peer_id();
        let base = make_ipv4_addr(octets, port);
        let full = attach_peer_to_addr_model(base.clone(), &peer);

        let (parsed_peer, parsed_base) =
            split_trailing_p2p_model(&full).expect("full addr should contain trailing /p2p");

        prop_assert_eq!(parsed_peer, peer);
        prop_assert_eq!(parsed_base, base);
    }

    #[test]
    fn test_017_split_trailing_p2p_returns_none_without_peer_suffix(
        octets in any::<[u8; 4]>(),
        port in any::<u16>(),
    ) {
        let base = make_ipv4_addr(octets, port);

        prop_assert!(
            split_trailing_p2p_model(&base).is_none(),
            "addr without /p2p suffix must not produce seed pair"
        );
    }

    #[test]
    fn test_018_cli_seed_pairs_include_only_full_p2p_multiaddrs(
        port_a in 1u16..=30_000u16,
        port_b in 30_001u16..=u16::MAX,
    ) {
        let peer = fresh_peer_id();
        let with_peer = attach_peer_to_addr_model(make_ipv4_addr([127, 0, 0, 1], port_a), &peer);
        let without_peer = make_ipv4_addr([127, 0, 0, 1], port_b);

        let pairs = cli_seed_pairs_model(&[with_peer.clone(), without_peer]);

        prop_assert_eq!(pairs.len(), 1);
        prop_assert_eq!(pairs[0].0, peer);
        prop_assert_eq!(&pairs[0].1, &with_peer);
    }

    #[test]
    fn test_019_kad_seed_count_respects_global_seed_cap(
        cli_count in 0usize..(MAX_KAD_SEEDS_MODEL.saturating_mul(2).saturating_add(64)),
    ) {
        let raw = make_bootstrap_strings_with_peer(cli_count);
        let cli_addrs = parse_cli_bootstraps_model(&raw);

        let count = kad_seed_count_model(&cli_addrs, &[]);

        prop_assert!(
            count <= MAX_KAD_SEEDS_MODEL,
            "Kad seed count must never exceed the cap"
        );

        prop_assert!(
            count <= cli_addrs.len(),
            "Kad seed count from CLI cannot exceed parsed CLI addrs"
        );
    }

    #[test]
    fn test_020_kad_seed_count_includes_peerbook_after_cli_until_cap(
        cli_count in 0usize..512usize,
        peerbook_count in 0usize..512usize,
    ) {
        let raw = make_bootstrap_strings_with_peer(cli_count);
        let cli_addrs = parse_cli_bootstraps_model(&raw);
        let peerbook = peerbook_top_model(peerbook_count);

        let count = kad_seed_count_model(&cli_addrs, &peerbook);

        prop_assert!(count <= MAX_KAD_SEEDS_MODEL);
        prop_assert!(count <= cli_addrs.len().saturating_add(peerbook_count));
    }

    #[test]
    fn test_021_hardcoded_seed_model_is_safe_when_empty_or_bounded(_probe in any::<u8>()) {
        let parsed: Vec<(PeerId, Multiaddr)> = HARDCODED_SEEDS_MODEL
            .iter()
            .filter_map(|(peer_str, addr_str)| {
                let peer = peer_str.parse::<PeerId>().ok()?;
                let addr = addr_str.parse::<Multiaddr>().ok()?;

                if multiaddr_within_bounds_model(&addr) {
                    Some((peer, addr))
                } else {
                    None
                }
            })
            .collect();

        prop_assert!(
            parsed.len() <= HARDCODED_SEEDS_MODEL.len(),
            "parsed hardcoded seeds cannot exceed source seed list"
        );

        prop_assert!(
            parsed.iter().all(|(_, addr)| multiaddr_within_bounds_model(addr)),
            "all accepted hardcoded seeds must satisfy multiaddr bound"
        );
    }

    #[test]
    fn test_022_defensive_runtime_caps_have_safe_relationships(_probe in any::<u8>()) {
        prop_assert!(MAX_MULTIADDR_BYTES_MODEL >= 64);
        prop_assert!(MAX_MULTIADDR_BYTES_MODEL <= 1024);

        prop_assert!(
            MAX_CLI_BOOTSTRAPS_MODEL <= MAX_STARTUP_DIALS_MODEL,
            "CLI bootstrap cap should not exceed startup dial cap"
        );

        prop_assert!(
            MAX_STARTUP_DIALS_MODEL <= MAX_KAD_SEEDS_MODEL,
            "Kad seed cap should be at least as large as startup dial cap"
        );
    }

    #[test]
    fn test_023_default_listen_addr_parses_and_is_within_bounds(_probe in any::<u8>()) {
        let opts = NodeOpts::default();

        let listen = opts
            .listen
            .parse::<Multiaddr>()
            .expect("default listen address must parse");

        prop_assert!(
            multiaddr_within_bounds_model(&listen),
            "default listen address must be within defensive multiaddr bound"
        );

        prop_assert_eq!(listen.to_string(), "/ip4/0.0.0.0/tcp/36213");
    }

    #[test]
    fn test_024_nodeopts_bootstrap_roundtrip_with_full_p2p_addr(
        port in 1u16..=u16::MAX,
    ) {
        let peer = fresh_peer_id();
        let addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");

        let opts = NodeOpts::try_parse_from([
            "remzar",
            "--wallet-address",
            TEST_WALLET_ADDRESS,
            "--bootstrap",
            addr.as_str(),
        ])
        .expect("NodeOpts should parse full p2p bootstrap address");

        let parsed = parse_cli_bootstraps_model(&opts.bootstrap);

        prop_assert_eq!(parsed.len(), 1);

        let pair = cli_seed_pairs_model(&parsed);

        prop_assert_eq!(pair.len(), 1);
        prop_assert_eq!(pair[0].0, peer);
    }

    #[test]
    fn test_025_combined_startup_bootstrap_model_is_bounded_and_ordered(
        raw_count in 0usize..(MAX_CLI_BOOTSTRAPS_MODEL.saturating_mul(2).saturating_add(32)),
        peerbook_count in 0usize..512usize,
    ) {
        let raw = make_bootstrap_strings(raw_count);
        let cli_addrs = parse_cli_bootstraps_model(&raw);

        let peerbook_pairs = peerbook_top_model(peerbook_count);
        let peerbook_addrs: Vec<Multiaddr> = peerbook_pairs
            .iter()
            .flat_map(|(_, addrs)| addrs.clone())
            .collect();

        let all = startup_dial_list_model(cli_addrs.clone(), peerbook_addrs);

        let kad_count = kad_seed_count_model(&cli_addrs, &peerbook_pairs);

        prop_assert!(
            all.len() <= MAX_STARTUP_DIALS_MODEL,
            "combined startup dial list must stay capped"
        );

        prop_assert!(
            all.iter().all(multiaddr_within_bounds_model),
            "combined startup dial list must contain only bounded multiaddrs"
        );

        prop_assert!(
            kad_count <= MAX_KAD_SEEDS_MODEL,
            "combined Kad seed count must stay capped"
        );
    }
}
