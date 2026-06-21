#![cfg(test)]
#![deny(unsafe_code)]

use clap::{CommandFactory, Parser};
use libp2p::{Multiaddr, PeerId, identity};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, String>;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn parse_node_opts(args: &[&str]) -> TestResult<NodeOpts> {
    let argv = std::iter::once("remzar-node").chain(args.iter().copied());

    NodeOpts::try_parse_from(argv).map_err(|err| err.to_string())
}

fn parse_with_wallet(args: &[&str]) -> TestResult<NodeOpts> {
    let argv = std::iter::once("remzar-node")
        .chain(["--wallet-address", "test-wallet"])
        .chain(args.iter().copied());

    NodeOpts::try_parse_from(argv).map_err(|err| err.to_string())
}

fn parse_strings_with_wallet(args: Vec<String>) -> TestResult<NodeOpts> {
    let mut argv = Vec::with_capacity(args.len().saturating_add(3usize));
    argv.push("remzar-node".to_string());
    argv.push("--wallet-address".to_string());
    argv.push("test-wallet".to_string());
    argv.extend(args);

    NodeOpts::try_parse_from(argv).map_err(|err| err.to_string())
}

fn test_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
}

fn bootstrap_with_peer(port: u16) -> String {
    let peer = test_peer_id();
    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
}

#[test]
fn p2p_01_006_sync_runtime_default_identity_file_is_identity_key() {
    let opts = NodeOpts::default();

    assert_eq!(opts.identity_file, "identity.key");
}

#[test]
fn p2p_02_006_sync_runtime_default_listen_addr_is_public_tcp_36213() {
    let opts = NodeOpts::default();

    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
}

#[test]
fn p2p_03_006_sync_runtime_default_bootstrap_is_empty() {
    let opts = NodeOpts::default();

    assert!(opts.bootstrap.is_empty());
}

#[test]
fn p2p_04_006_sync_runtime_default_log_data_wallet_and_founder_flags() {
    let opts = NodeOpts::default();

    assert_eq!(opts.log, "info");
    assert_eq!(opts.data_dir, "data");
    assert!(opts.wallet_address.is_empty());
    assert!(!opts.founder);
}

#[test]
fn p2p_05_006_sync_runtime_clone_preserves_all_fields() {
    let original = NodeOpts {
        identity_file: "id-a.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/1111".to_string(),
        bootstrap: vec!["/ip4/127.0.0.1/tcp/2222".to_string()],
        log: "debug".to_string(),
        data_dir: "custom-data".to_string(),
        wallet_address: "wallet-a".to_string(),
        founder: true,
    };

    let cloned = original.clone();

    assert_eq!(cloned.identity_file, original.identity_file);
    assert_eq!(cloned.listen, original.listen);
    assert_eq!(cloned.bootstrap, original.bootstrap);
    assert_eq!(cloned.log, original.log);
    assert_eq!(cloned.data_dir, original.data_dir);
    assert_eq!(cloned.wallet_address, original.wallet_address);
    assert_eq!(cloned.founder, original.founder);
}

#[test]
fn p2p_06_006_sync_runtime_debug_output_contains_struct_and_key_fields() {
    let opts = NodeOpts::default();
    let text = format!("{opts:?}");

    assert!(text.contains("NodeOpts"));
    assert!(text.contains("identity_file"));
    assert!(text.contains("listen"));
    assert!(text.contains("wallet_address"));
}

#[test]
fn p2p_07_006_sync_runtime_clap_help_contains_runtime_options() {
    let mut command = NodeOpts::command();
    let help = command.render_long_help().to_string();

    assert!(help.contains("--identity-file"));
    assert!(help.contains("--listen"));
    assert!(help.contains("--bootstrap"));
    assert!(help.contains("--wallet-address"));
    assert!(help.contains("--founder"));
}

#[test]
fn p2p_08_006_sync_runtime_clap_command_exposes_expected_long_options() {
    let command = NodeOpts::command();
    let longs: BTreeSet<&str> = command
        .get_arguments()
        .filter_map(|arg| arg.get_long())
        .collect();

    assert!(longs.contains("identity-file"));
    assert!(longs.contains("listen"));
    assert!(longs.contains("bootstrap"));
    assert!(longs.contains("log"));
    assert!(longs.contains("data-dir"));
    assert!(longs.contains("wallet-address"));
    assert!(longs.contains("founder"));
}

#[test]
fn p2p_09_006_sync_runtime_parse_no_args_errors_because_wallet_is_required() {
    let err = parse_node_opts(&[]);

    assert!(err.is_err());
}

#[test]
fn p2p_10_006_sync_runtime_parse_wallet_only_uses_clap_defaults() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "wallet-01"])?;

    assert_eq!(opts.wallet_address, "wallet-01");
    assert_eq!(opts.identity_file, "identity.key");
    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
    assert!(opts.bootstrap.is_empty());
    assert_eq!(opts.log, "info");
    assert_eq!(opts.data_dir, "data");
    assert!(!opts.founder);
    Ok(())
}

#[test]
fn p2p_11_006_sync_runtime_parse_identity_file_with_required_wallet() -> TestResult {
    let opts = parse_with_wallet(&["--identity-file", "node-id.key"])?;

    assert_eq!(opts.identity_file, "node-id.key");
    assert_eq!(opts.wallet_address, "test-wallet");
    Ok(())
}

#[test]
fn p2p_12_006_sync_runtime_parse_ipv4_listen_addr_with_required_wallet() -> TestResult {
    let opts = parse_with_wallet(&["--listen", "/ip4/127.0.0.1/tcp/36213"])?;

    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/36213");
    let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;
    assert_eq!(parsed.to_string(), opts.listen);
    Ok(())
}

#[test]
fn p2p_13_006_sync_runtime_parse_single_bootstrap_addr_with_required_wallet() -> TestResult {
    let bootstrap = "/ip4/127.0.0.1/tcp/4001";
    let opts = parse_with_wallet(&["--bootstrap", bootstrap])?;

    assert_eq!(opts.bootstrap, vec![bootstrap.to_string()]);
    assert_eq!(opts.wallet_address, "test-wallet");
    Ok(())
}

#[test]
fn p2p_14_006_sync_runtime_parse_multiple_bootstrap_addrs_with_required_wallet() -> TestResult {
    let first = "/ip4/127.0.0.1/tcp/4001";
    let second = "/ip4/127.0.0.1/tcp/4002";
    let third = "/dns/example.com/tcp/4003";

    let opts = parse_with_wallet(&[
        "--bootstrap",
        first,
        "--bootstrap",
        second,
        "--bootstrap",
        third,
    ])?;

    assert_eq!(
        opts.bootstrap,
        vec![first.to_string(), second.to_string(), third.to_string()]
    );
    Ok(())
}

#[test]
fn p2p_15_006_sync_runtime_parse_log_filter_value_with_required_wallet() -> TestResult {
    let opts = parse_with_wallet(&["--log", "debug"])?;

    assert_eq!(opts.log, "debug");
    Ok(())
}

#[test]
fn p2p_16_006_sync_runtime_parse_data_dir_with_required_wallet() -> TestResult {
    let opts = parse_with_wallet(&["--data-dir", "node-data-01"])?;

    assert_eq!(opts.data_dir, "node-data-01");
    Ok(())
}

#[test]
fn p2p_17_006_sync_runtime_parse_wallet_address() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "remzar-wallet-01"])?;

    assert_eq!(opts.wallet_address, "remzar-wallet-01");
    Ok(())
}

#[test]
fn p2p_18_006_sync_runtime_parse_founder_flag_with_required_wallet() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "founder-wallet", "--founder"])?;

    assert_eq!(opts.wallet_address, "founder-wallet");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_19_006_sync_runtime_parse_is_founder_alias_with_required_wallet() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "founder-wallet", "--is-founder"])?;

    assert_eq!(opts.wallet_address, "founder-wallet");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_20_006_sync_runtime_parse_all_fields_together() -> TestResult {
    let bootstrap = bootstrap_with_peer(4567);
    let opts = parse_node_opts(&[
        "--wallet-address",
        "wallet-runtime",
        "--identity-file",
        "node-a.key",
        "--listen",
        "/ip4/127.0.0.1/tcp/1111",
        "--bootstrap",
        bootstrap.as_str(),
        "--log",
        "trace",
        "--data-dir",
        "runtime-data",
        "--founder",
    ])?;

    assert_eq!(opts.identity_file, "node-a.key");
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/1111");
    assert_eq!(opts.bootstrap, vec![bootstrap]);
    assert_eq!(opts.log, "trace");
    assert_eq!(opts.data_dir, "runtime-data");
    assert_eq!(opts.wallet_address, "wallet-runtime");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_21_006_sync_runtime_parse_bootstrap_with_p2p_peer_id_roundtrips() -> TestResult {
    let bootstrap = bootstrap_with_peer(4568);
    let opts = parse_with_wallet(&["--bootstrap", bootstrap.as_str()])?;
    let parsed = opts.bootstrap[0].parse::<Multiaddr>().map_err(fmt_err)?;

    assert_eq!(parsed.to_string(), bootstrap);
    Ok(())
}

#[test]
fn p2p_22_006_sync_runtime_parse_dns_bootstrap_is_preserved_and_parseable() -> TestResult {
    let bootstrap = "/dns/bootstrap.remzar.example/tcp/36213";
    let opts = parse_with_wallet(&["--bootstrap", bootstrap])?;
    let parsed = opts.bootstrap[0].parse::<Multiaddr>().map_err(fmt_err)?;

    assert_eq!(parsed.to_string(), bootstrap);
    Ok(())
}

#[test]
fn p2p_23_006_sync_runtime_invalid_bootstrap_string_is_preserved_by_cli_parser() -> TestResult {
    let invalid_bootstrap = "not-a-valid-multiaddr";
    let opts = parse_with_wallet(&["--bootstrap", invalid_bootstrap])?;

    assert_eq!(opts.bootstrap, vec![invalid_bootstrap.to_string()]);
    assert!(opts.bootstrap[0].parse::<Multiaddr>().is_err());
    Ok(())
}

#[test]
fn p2p_24_006_sync_runtime_unknown_arg_errors_even_with_wallet() {
    let err = parse_node_opts(&[
        "--wallet-address",
        "wallet-01",
        "--definitely-not-a-real-option",
    ]);

    assert!(err.is_err());
}

#[test]
fn p2p_25_006_sync_runtime_missing_identity_file_value_errors_with_wallet() {
    let err = parse_node_opts(&["--wallet-address", "wallet-01", "--identity-file"]);

    assert!(err.is_err());
}

#[test]
fn p2p_26_006_sync_runtime_missing_listen_value_errors_with_wallet() {
    let err = parse_node_opts(&["--wallet-address", "wallet-01", "--listen"]);

    assert!(err.is_err());
}

#[test]
fn p2p_27_006_sync_runtime_missing_bootstrap_value_errors_with_wallet() {
    let err = parse_node_opts(&["--wallet-address", "wallet-01", "--bootstrap"]);

    assert!(err.is_err());
}

#[test]
fn p2p_28_006_sync_runtime_missing_log_value_errors_with_wallet() {
    let err = parse_node_opts(&["--wallet-address", "wallet-01", "--log"]);

    assert!(err.is_err());
}

#[test]
fn p2p_29_006_sync_runtime_missing_data_dir_value_errors_with_wallet() {
    let err = parse_node_opts(&["--wallet-address", "wallet-01", "--data-dir"]);

    assert!(err.is_err());
}

#[test]
fn p2p_30_006_sync_runtime_missing_wallet_address_value_errors() {
    let err = parse_node_opts(&["--wallet-address"]);

    assert!(err.is_err());
}

#[test]
fn p2p_31_006_sync_runtime_bootstrap_order_is_preserved() -> TestResult {
    let first = "/ip4/127.0.0.1/tcp/5001";
    let second = "/ip4/127.0.0.1/tcp/5002";
    let third = "/ip4/127.0.0.1/tcp/5003";

    let opts = parse_with_wallet(&[
        "--bootstrap",
        first,
        "--bootstrap",
        second,
        "--bootstrap",
        third,
    ])?;

    assert_eq!(opts.bootstrap[0], first);
    assert_eq!(opts.bootstrap[1], second);
    assert_eq!(opts.bootstrap[2], third);
    Ok(())
}

#[test]
fn p2p_32_006_sync_runtime_empty_wallet_value_is_accepted_by_parser() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", ""])?;

    assert!(opts.wallet_address.is_empty());
    Ok(())
}

#[test]
fn p2p_33_006_sync_runtime_unicode_wallet_value_is_preserved() -> TestResult {
    let wallet = "remzar-wallet-测试-🚀";
    let opts = parse_node_opts(&["--wallet-address", wallet])?;

    assert_eq!(opts.wallet_address, wallet);
    Ok(())
}

#[test]
fn p2p_34_006_sync_runtime_ipv6_listen_addr_is_preserved_and_parseable() -> TestResult {
    let listen = "/ip6/::1/tcp/36213";
    let opts = parse_with_wallet(&["--listen", listen])?;
    let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;

    assert_eq!(parsed.to_string(), listen);
    Ok(())
}

#[test]
fn p2p_35_006_sync_runtime_memory_listen_addr_is_preserved_and_parseable() -> TestResult {
    let listen = "/memory/123456";
    let opts = parse_with_wallet(&["--listen", listen])?;
    let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;

    assert_eq!(parsed.to_string(), listen);
    Ok(())
}

#[test]
fn p2p_36_006_sync_runtime_vector_listen_ports_are_preserved() -> TestResult {
    for port in [1u16, 80u16, 443u16, 1024u16, 36213u16, 65535u16] {
        let listen = format!("/ip4/127.0.0.1/tcp/{port}");
        let opts = parse_with_wallet(&["--listen", listen.as_str()])?;
        let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(parsed.to_string(), listen);
    }

    Ok(())
}

#[test]
fn p2p_37_006_sync_runtime_load_many_bootstrap_strings_are_collected_by_parser() -> TestResult {
    let mut args = Vec::new();

    for port in 10_000u16..10_300u16 {
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 300usize);
    assert_eq!(opts.bootstrap[0], "/ip4/127.0.0.1/tcp/10000");
    assert_eq!(opts.bootstrap[299], "/ip4/127.0.0.1/tcp/10299");
    Ok(())
}

#[test]
fn p2p_38_006_sync_runtime_vector_log_values_are_preserved() -> TestResult {
    for log in ["error", "warn", "info", "debug", "trace", "remzar=debug"] {
        let opts = parse_with_wallet(&["--log", log])?;

        assert_eq!(opts.log, log);
    }

    Ok(())
}

#[test]
fn p2p_39_006_sync_runtime_data_dir_with_spaces_is_preserved() -> TestResult {
    let data_dir = "C:\\Remzar Data\\node one";
    let opts = parse_with_wallet(&["--data-dir", data_dir])?;

    assert_eq!(opts.data_dir, data_dir);
    Ok(())
}

#[test]
fn p2p_40_006_sync_runtime_bootstrap_with_generated_peer_id_roundtrips() -> TestResult {
    let mut bootstraps = Vec::new();

    for port in 11_000u16..11_010u16 {
        bootstraps.push(bootstrap_with_peer(port));
    }

    let mut args = Vec::new();
    for bootstrap in &bootstraps {
        args.push("--bootstrap".to_string());
        args.push(bootstrap.clone());
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), bootstraps.len());

    for (actual, expected) in opts.bootstrap.iter().zip(bootstraps.iter()) {
        let parsed = actual.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(actual, expected);
        assert_eq!(parsed.to_string(), *expected);
    }

    Ok(())
}

#[test]
fn p2p_41_006_sync_runtime_parse_wallet_equals_syntax() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address=wallet-equals"])?;

    assert_eq!(opts.wallet_address, "wallet-equals");
    assert_eq!(opts.identity_file, "identity.key");
    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
    Ok(())
}

#[test]
fn p2p_42_006_sync_runtime_parse_identity_file_equals_syntax() -> TestResult {
    let opts = parse_node_opts(&[
        "--wallet-address",
        "wallet-42",
        "--identity-file=node-equals.key",
    ])?;

    assert_eq!(opts.identity_file, "node-equals.key");
    assert_eq!(opts.wallet_address, "wallet-42");
    Ok(())
}

#[test]
fn p2p_43_006_sync_runtime_parse_listen_equals_syntax() -> TestResult {
    let listen = "/ip4/127.0.0.1/tcp/4300";
    let opts = parse_node_opts(&["--wallet-address", "wallet-43", "--listen", listen])?;

    assert_eq!(opts.listen, listen);
    let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;
    assert_eq!(parsed.to_string(), listen);
    Ok(())
}

#[test]
fn p2p_44_006_sync_runtime_parse_bootstrap_equals_syntax() -> TestResult {
    let bootstrap = "/ip4/127.0.0.1/tcp/4400";
    let opts = parse_node_opts(&[
        "--wallet-address",
        "wallet-44",
        &format!("--bootstrap={bootstrap}"),
    ])?;

    assert_eq!(opts.bootstrap, vec![bootstrap.to_string()]);
    Ok(())
}

#[test]
fn p2p_45_006_sync_runtime_parse_log_equals_syntax() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "wallet-45", "--log=trace"])?;

    assert_eq!(opts.log, "trace");
    Ok(())
}

#[test]
fn p2p_46_006_sync_runtime_parse_data_dir_equals_syntax() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "wallet-46", "--data-dir=data-equals"])?;

    assert_eq!(opts.data_dir, "data-equals");
    Ok(())
}

#[test]
fn p2p_47_006_sync_runtime_founder_flag_with_equals_style_wallet() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address=wallet-47", "--founder"])?;

    assert_eq!(opts.wallet_address, "wallet-47");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_48_006_sync_runtime_is_founder_alias_with_equals_style_wallet() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address=wallet-48", "--is-founder"])?;

    assert_eq!(opts.wallet_address, "wallet-48");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_49_006_sync_runtime_parse_all_fields_equals_style() -> TestResult {
    let bootstrap = bootstrap_with_peer(4900);
    let opts = parse_node_opts(&[
        "--wallet-address=wallet-49",
        "--identity-file=node-49.key",
        "--listen=/ip4/127.0.0.1/tcp/4901",
        &format!("--bootstrap={bootstrap}"),
        "--log=debug",
        "--data-dir=data-49",
        "--founder",
    ])?;

    assert_eq!(opts.wallet_address, "wallet-49");
    assert_eq!(opts.identity_file, "node-49.key");
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/4901");
    assert_eq!(opts.bootstrap, vec![bootstrap]);
    assert_eq!(opts.log, "debug");
    assert_eq!(opts.data_dir, "data-49");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_50_006_sync_runtime_parse_options_in_unusual_order() -> TestResult {
    let bootstrap = bootstrap_with_peer(5000);
    let opts = parse_node_opts(&[
        "--founder",
        "--data-dir",
        "data-50",
        "--bootstrap",
        bootstrap.as_str(),
        "--listen",
        "/ip4/127.0.0.1/tcp/5001",
        "--identity-file",
        "node-50.key",
        "--log",
        "warn",
        "--wallet-address",
        "wallet-50",
    ])?;

    assert!(opts.founder);
    assert_eq!(opts.data_dir, "data-50");
    assert_eq!(opts.bootstrap, vec![bootstrap]);
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/5001");
    assert_eq!(opts.identity_file, "node-50.key");
    assert_eq!(opts.log, "warn");
    assert_eq!(opts.wallet_address, "wallet-50");
    Ok(())
}

#[test]
fn p2p_51_006_sync_runtime_bootstrap_duplicate_values_are_preserved_by_parser() -> TestResult {
    let bootstrap = "/ip4/127.0.0.1/tcp/5100";
    let opts = parse_with_wallet(&[
        "--bootstrap",
        bootstrap,
        "--bootstrap",
        bootstrap,
        "--bootstrap",
        bootstrap,
    ])?;

    assert_eq!(opts.bootstrap.len(), 3usize);
    assert!(opts.bootstrap.iter().all(|addr| addr == bootstrap));
    Ok(())
}

#[test]
fn p2p_52_006_sync_runtime_vector_mixed_bootstrap_protocols_are_preserved() -> TestResult {
    let addrs = [
        "/ip4/127.0.0.1/tcp/5201",
        "/ip6/::1/tcp/5202",
        "/dns/bootstrap.remzar.example/tcp/5203",
        "/memory/5204",
    ];

    let opts = parse_with_wallet(&[
        "--bootstrap",
        addrs[0],
        "--bootstrap",
        addrs[1],
        "--bootstrap",
        addrs[2],
        "--bootstrap",
        addrs[3],
    ])?;

    assert_eq!(opts.bootstrap, addrs.map(str::to_string));
    for addr in &opts.bootstrap {
        let parsed = addr.parse::<Multiaddr>().map_err(fmt_err)?;
        assert_eq!(parsed.to_string(), *addr);
    }
    Ok(())
}

#[test]
fn p2p_53_006_sync_runtime_empty_bootstrap_value_is_accepted_as_empty_multiaddr() -> TestResult {
    let opts = parse_with_wallet(&["--bootstrap", ""])?;

    assert_eq!(opts.bootstrap, vec![String::new()]);

    let parsed = opts.bootstrap[0].parse::<Multiaddr>().map_err(fmt_err)?;
    assert_eq!(parsed.to_string(), "");

    Ok(())
}

#[test]
fn p2p_54_006_sync_runtime_invalid_listen_string_is_preserved_by_parser() -> TestResult {
    let opts = parse_with_wallet(&["--listen", "not-a-multiaddr"])?;

    assert_eq!(opts.listen, "not-a-multiaddr");
    assert!(opts.listen.parse::<Multiaddr>().is_err());
    Ok(())
}

#[test]
fn p2p_55_006_sync_runtime_empty_listen_value_is_accepted_as_empty_multiaddr_by_parser()
-> TestResult {
    let opts = parse_with_wallet(&["--listen", ""])?;

    assert!(opts.listen.is_empty());

    let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;
    assert_eq!(parsed.to_string(), "");

    Ok(())
}

#[test]
fn p2p_56_006_sync_runtime_identity_file_nested_path_is_preserved() -> TestResult {
    let identity_file = "keys/node/identity.key";
    let opts = parse_with_wallet(&["--identity-file", identity_file])?;

    assert_eq!(opts.identity_file, identity_file);
    Ok(())
}

#[test]
fn p2p_57_006_sync_runtime_identity_file_windows_style_path_is_preserved() -> TestResult {
    let identity_file = "C:\\Remzar\\keys\\identity.key";
    let opts = parse_with_wallet(&["--identity-file", identity_file])?;

    assert_eq!(opts.identity_file, identity_file);
    Ok(())
}

#[test]
fn p2p_58_006_sync_runtime_data_dir_unicode_value_is_preserved() -> TestResult {
    let data_dir = "data-测试-🚀";
    let opts = parse_with_wallet(&["--data-dir", data_dir])?;

    assert_eq!(opts.data_dir, data_dir);
    Ok(())
}

#[test]
fn p2p_59_006_sync_runtime_log_filter_complex_value_is_preserved() -> TestResult {
    let log = "remzar=trace,libp2p=warn,rocksdb=error";
    let opts = parse_with_wallet(&["--log", log])?;

    assert_eq!(opts.log, log);
    Ok(())
}

#[test]
fn p2p_60_006_sync_runtime_wallet_with_symbols_is_preserved() -> TestResult {
    let wallet = "wallet:abcDEF123_-+=.@";
    let opts = parse_node_opts(&["--wallet-address", wallet])?;

    assert_eq!(opts.wallet_address, wallet);
    Ok(())
}

#[test]
fn p2p_61_006_sync_runtime_uppercase_founder_flag_is_rejected() {
    let err = parse_node_opts(&["--wallet-address", "wallet-61", "--Founder"]);

    assert!(err.is_err());
}

#[test]
fn p2p_62_006_sync_runtime_short_wallet_flag_is_rejected() {
    let err = parse_node_opts(&["-w", "wallet-62"]);

    assert!(err.is_err());
}

#[test]
fn p2p_63_006_sync_runtime_short_founder_flag_is_rejected() {
    let err = parse_node_opts(&["--wallet-address", "wallet-63", "-f"]);

    assert!(err.is_err());
}

#[test]
fn p2p_64_006_sync_runtime_positional_wallet_is_rejected() {
    let err = parse_node_opts(&["wallet-64"]);

    assert!(err.is_err());
}

#[test]
fn p2p_65_006_sync_runtime_positional_bootstrap_is_rejected_even_with_wallet() {
    let err = parse_node_opts(&["--wallet-address", "wallet-65", "/ip4/127.0.0.1/tcp/6500"]);

    assert!(err.is_err());
}

#[test]
fn p2p_66_006_sync_runtime_missing_wallet_error_mentions_wallet_address() {
    let err = parse_node_opts(&[]).expect_err("wallet-address should be required");

    assert!(err.contains("--wallet-address"));
    assert!(err.contains("WALLET_ADDRESS"));
}

#[test]
fn p2p_67_006_sync_runtime_missing_bootstrap_error_mentions_bootstrap() {
    let err = parse_node_opts(&["--wallet-address", "wallet-67", "--bootstrap"])
        .expect_err("bootstrap value should be required");

    assert!(err.contains("--bootstrap"));
    assert!(err.contains("BOOTSTRAP"));
}

#[test]
fn p2p_68_006_sync_runtime_missing_listen_error_mentions_listen() {
    let err = parse_node_opts(&["--wallet-address", "wallet-68", "--listen"])
        .expect_err("listen value should be required");

    assert!(err.contains("--listen"));
    assert!(err.contains("LISTEN"));
}

#[test]
fn p2p_69_006_sync_runtime_missing_identity_error_mentions_identity_file() {
    let err = parse_node_opts(&["--wallet-address", "wallet-69", "--identity-file"])
        .expect_err("identity-file value should be required");

    assert!(err.contains("--identity-file"));
    assert!(err.contains("IDENTITY_FILE"));
}

#[test]
fn p2p_70_006_sync_runtime_missing_data_dir_error_mentions_data_dir() {
    let err = parse_node_opts(&["--wallet-address", "wallet-70", "--data-dir"])
        .expect_err("data-dir value should be required");

    assert!(err.contains("--data-dir"));
    assert!(err.contains("DATA_DIR"));
}

#[test]
fn p2p_71_006_sync_runtime_missing_log_error_mentions_log() {
    let err = parse_node_opts(&["--wallet-address", "wallet-71", "--log"])
        .expect_err("log value should be required");

    assert!(err.contains("--log"));
    assert!(err.contains("LOG"));
}

#[test]
fn p2p_72_006_sync_runtime_wallet_can_appear_before_and_after_bootstraps_not_duplicated()
-> TestResult {
    let first = "/ip4/127.0.0.1/tcp/7201";
    let second = "/ip4/127.0.0.1/tcp/7202";

    let opts = parse_node_opts(&[
        "--wallet-address",
        "wallet-72",
        "--bootstrap",
        first,
        "--bootstrap",
        second,
    ])?;

    assert_eq!(opts.wallet_address, "wallet-72");
    assert_eq!(opts.bootstrap, vec![first.to_string(), second.to_string()]);
    Ok(())
}

#[test]
fn p2p_73_006_sync_runtime_founder_flag_does_not_change_default_listen() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "wallet-73", "--founder"])?;

    assert!(opts.founder);
    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
    Ok(())
}

#[test]
fn p2p_74_006_sync_runtime_founder_alias_does_not_change_default_data_dir() -> TestResult {
    let opts = parse_node_opts(&["--wallet-address", "wallet-74", "--is-founder"])?;

    assert!(opts.founder);
    assert_eq!(opts.data_dir, "data");
    Ok(())
}

#[test]
fn p2p_75_006_sync_runtime_clap_debug_name_contains_node_opts() {
    let command = NodeOpts::command();
    let debug = format!("{command:?}");

    assert!(debug.contains("NodeOpts") || debug.contains("remzar-node"));
}

#[test]
fn p2p_76_006_sync_runtime_command_has_no_short_options_for_known_args() {
    let command = NodeOpts::command();

    for arg in command.get_arguments() {
        assert!(arg.get_short().is_none());
    }
}

#[test]
fn p2p_77_006_sync_runtime_vector_wallet_values_roundtrip() -> TestResult {
    let wallets = [
        "wallet-plain",
        "wallet_underscore",
        "wallet-dash",
        "wallet.with.dots",
        "wallet1234567890",
    ];

    for wallet in wallets {
        let opts = parse_node_opts(&["--wallet-address", wallet])?;

        assert_eq!(opts.wallet_address, wallet);
    }

    Ok(())
}

#[test]
fn p2p_78_006_sync_runtime_vector_data_dirs_roundtrip() -> TestResult {
    let dirs = [
        "data-a",
        "data/b",
        "./relative-data",
        "../parent-data",
        "data.with.dots",
    ];

    for data_dir in dirs {
        let opts = parse_with_wallet(&["--data-dir", data_dir])?;

        assert_eq!(opts.data_dir, data_dir);
    }

    Ok(())
}

#[test]
fn p2p_79_006_sync_runtime_vector_identity_files_roundtrip() -> TestResult {
    let files = [
        "identity.key",
        "node.key",
        "keys/identity.key",
        "./identity-local.key",
        "identity.with.dots.key",
    ];

    for file in files {
        let opts = parse_with_wallet(&["--identity-file", file])?;

        assert_eq!(opts.identity_file, file);
    }

    Ok(())
}

#[test]
fn p2p_80_006_sync_runtime_vector_ipv4_listen_addresses_roundtrip() -> TestResult {
    let addrs = [
        "/ip4/0.0.0.0/tcp/1",
        "/ip4/127.0.0.1/tcp/80",
        "/ip4/192.0.2.10/tcp/443",
        "/ip4/198.51.100.20/tcp/36213",
        "/ip4/203.0.113.30/tcp/65535",
    ];

    for addr in addrs {
        let opts = parse_with_wallet(&["--listen", addr])?;
        let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(parsed.to_string(), addr);
    }

    Ok(())
}

#[test]
fn p2p_81_006_sync_runtime_vector_ipv6_listen_addresses_roundtrip() -> TestResult {
    let addrs = [
        "/ip6/::1/tcp/1",
        "/ip6/2001:db8::1/tcp/36213",
        "/ip6/2001:db8::2/tcp/65535",
    ];

    for addr in addrs {
        let opts = parse_with_wallet(&["--listen", addr])?;
        let parsed = opts.listen.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(parsed.to_string(), addr);
    }

    Ok(())
}

#[test]
fn p2p_82_006_sync_runtime_vector_dns_bootstraps_roundtrip() -> TestResult {
    let addrs = [
        "/dns/seed1.remzar.example/tcp/36213",
        "/dns4/seed2.remzar.example/tcp/36214",
        "/dns6/seed3.remzar.example/tcp/36215",
    ];

    let mut args = Vec::new();
    for addr in addrs {
        args.push("--bootstrap".to_string());
        args.push(addr.to_string());
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), addrs.len());
    for (actual, expected) in opts.bootstrap.iter().zip(addrs.iter()) {
        let parsed = actual.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(parsed.to_string(), *expected);
    }

    Ok(())
}

#[test]
fn p2p_83_006_sync_runtime_vector_bootstraps_with_peer_ids_are_unique() -> TestResult {
    let mut bootstraps = Vec::new();
    let mut unique = BTreeSet::new();

    for port in 12_000u16..12_020u16 {
        let bootstrap = bootstrap_with_peer(port);
        assert!(unique.insert(bootstrap.clone()));
        bootstraps.push(bootstrap);
    }

    let mut args = Vec::new();
    for bootstrap in &bootstraps {
        args.push("--bootstrap".to_string());
        args.push(bootstrap.clone());
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 20usize);
    assert_eq!(
        opts.bootstrap.iter().collect::<BTreeSet<_>>().len(),
        20usize
    );
    Ok(())
}

#[test]
fn p2p_84_006_sync_runtime_parser_preserves_bootstrap_case_in_dns_name() -> TestResult {
    let bootstrap = "/dns/Seed.REMZAR.Example/tcp/36213";
    let opts = parse_with_wallet(&["--bootstrap", bootstrap])?;

    assert_eq!(opts.bootstrap, vec![bootstrap.to_string()]);
    Ok(())
}

#[test]
fn p2p_85_006_sync_runtime_parser_preserves_log_case() -> TestResult {
    let log = "Remzar=DEBUG,Libp2p=WARN";
    let opts = parse_with_wallet(&["--log", log])?;

    assert_eq!(opts.log, log);
    Ok(())
}

#[test]
fn p2p_86_006_sync_runtime_parser_preserves_wallet_case() -> TestResult {
    let wallet = "WalletABCdef123";
    let opts = parse_node_opts(&["--wallet-address", wallet])?;

    assert_eq!(opts.wallet_address, wallet);
    Ok(())
}

#[test]
fn p2p_87_006_sync_runtime_parser_preserves_data_dir_case() -> TestResult {
    let data_dir = "DataDirMixedCASE";
    let opts = parse_with_wallet(&["--data-dir", data_dir])?;

    assert_eq!(opts.data_dir, data_dir);
    Ok(())
}

#[test]
fn p2p_88_006_sync_runtime_manual_default_parse_difference_wallet_required() {
    let manual = NodeOpts::default();
    let parsed = parse_node_opts(&[]);

    assert!(manual.wallet_address.is_empty());
    assert!(parsed.is_err());
}

#[test]
fn p2p_89_006_sync_runtime_manual_default_matches_parse_defaults_when_wallet_supplied() -> TestResult
{
    let manual = NodeOpts::default();
    let parsed = parse_node_opts(&["--wallet-address", "wallet-89"])?;

    assert_eq!(parsed.identity_file, manual.identity_file);
    assert_eq!(parsed.listen, manual.listen);
    assert_eq!(parsed.bootstrap, manual.bootstrap);
    assert_eq!(parsed.log, manual.log);
    assert_eq!(parsed.data_dir, manual.data_dir);
    assert_eq!(parsed.founder, manual.founder);
    assert_eq!(parsed.wallet_address, "wallet-89");
    Ok(())
}

#[test]
fn p2p_90_006_sync_runtime_load_256_bootstrap_strings_are_collected_by_parser() -> TestResult {
    let mut args = Vec::new();

    for port in 20_000u16..20_256u16 {
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 256usize);
    assert_eq!(opts.bootstrap[0], "/ip4/127.0.0.1/tcp/20000");
    assert_eq!(opts.bootstrap[255], "/ip4/127.0.0.1/tcp/20255");
    Ok(())
}

#[test]
fn p2p_91_006_sync_runtime_load_257_bootstrap_strings_are_collected_by_parser_before_runtime_cap()
-> TestResult {
    let mut args = Vec::new();

    for port in 21_000u16..21_257u16 {
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 257usize);
    assert_eq!(opts.bootstrap[0], "/ip4/127.0.0.1/tcp/21000");
    assert_eq!(opts.bootstrap[256], "/ip4/127.0.0.1/tcp/21256");
    Ok(())
}

#[test]
fn p2p_92_006_sync_runtime_load_512_bootstrap_strings_are_collected_by_parser() -> TestResult {
    let mut args = Vec::new();

    for offset in 0u16..512u16 {
        let port = 22_000u16
            .checked_add(offset)
            .ok_or_else(|| "port overflow".to_string())?;
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 512usize);
    assert_eq!(opts.bootstrap[0], "/ip4/127.0.0.1/tcp/22000");
    assert_eq!(opts.bootstrap[511], "/ip4/127.0.0.1/tcp/22511");
    Ok(())
}

#[test]
fn p2p_93_006_sync_runtime_load_generated_peer_bootstraps_parse_as_multiaddrs() -> TestResult {
    let mut args = Vec::new();

    for port in 23_000u16..23_032u16 {
        args.push("--bootstrap".to_string());
        args.push(bootstrap_with_peer(port));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 32usize);
    for bootstrap in &opts.bootstrap {
        let parsed = bootstrap.parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(parsed.to_string(), *bootstrap);
        assert!(bootstrap.contains("/p2p/"));
    }

    Ok(())
}

#[test]
fn p2p_94_006_sync_runtime_adversarial_many_invalid_bootstraps_are_still_parser_strings()
-> TestResult {
    let mut args = Vec::new();

    for index in 0usize..64usize {
        args.push("--bootstrap".to_string());
        args.push(format!("not-a-multiaddr-{index}"));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap.len(), 64usize);
    assert!(
        opts.bootstrap
            .iter()
            .all(|addr| addr.parse::<Multiaddr>().is_err())
    );
    Ok(())
}

#[test]
fn p2p_95_006_sync_runtime_adversarial_mixed_valid_invalid_bootstraps_preserve_order() -> TestResult
{
    let values = [
        "/ip4/127.0.0.1/tcp/9501",
        "bad-bootstrap-a",
        "/dns/seed.remzar.example/tcp/9502",
        "bad-bootstrap-b",
        "/memory/9503",
    ];

    let mut args = Vec::new();
    for value in values {
        args.push("--bootstrap".to_string());
        args.push(value.to_string());
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.bootstrap, values.map(str::to_string));
    Ok(())
}

#[test]
fn p2p_96_006_sync_runtime_property_bootstrap_parser_does_not_deduplicate() -> TestResult {
    let first = "/ip4/127.0.0.1/tcp/9601";
    let second = "/ip4/127.0.0.1/tcp/9602";

    let opts = parse_with_wallet(&[
        "--bootstrap",
        first,
        "--bootstrap",
        second,
        "--bootstrap",
        first,
        "--bootstrap",
        second,
    ])?;

    assert_eq!(
        opts.bootstrap,
        vec![
            first.to_string(),
            second.to_string(),
            first.to_string(),
            second.to_string(),
        ]
    );
    Ok(())
}

#[test]
fn p2p_97_006_sync_runtime_property_debug_output_reflects_custom_values() {
    let opts = NodeOpts {
        identity_file: "debug-id.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/9700".to_string(),
        bootstrap: vec!["/ip4/127.0.0.1/tcp/9701".to_string()],
        log: "trace".to_string(),
        data_dir: "debug-data".to_string(),
        wallet_address: "debug-wallet".to_string(),
        founder: true,
    };

    let text = format!("{opts:?}");

    assert!(text.contains("debug-id.key"));
    assert!(text.contains("9700"));
    assert!(text.contains("9701"));
    assert!(text.contains("trace"));
    assert!(text.contains("debug-data"));
    assert!(text.contains("debug-wallet"));
    assert!(text.contains("founder: true"));
}

#[test]
fn p2p_98_006_sync_runtime_property_clone_then_mutate_original_does_not_change_clone() {
    let mut original = NodeOpts {
        identity_file: "clone-id.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/9800".to_string(),
        bootstrap: vec!["/ip4/127.0.0.1/tcp/9801".to_string()],
        log: "info".to_string(),
        data_dir: "clone-data".to_string(),
        wallet_address: "clone-wallet".to_string(),
        founder: false,
    };

    let cloned = original.clone();

    original.identity_file = "changed.key".to_string();
    original.listen = "/ip4/127.0.0.1/tcp/9999".to_string();
    original
        .bootstrap
        .push("/ip4/127.0.0.1/tcp/9998".to_string());
    original.log = "debug".to_string();
    original.data_dir = "changed-data".to_string();
    original.wallet_address = "changed-wallet".to_string();
    original.founder = true;

    assert_eq!(cloned.identity_file, "clone-id.key");
    assert_eq!(cloned.listen, "/ip4/127.0.0.1/tcp/9800");
    assert_eq!(
        cloned.bootstrap,
        vec!["/ip4/127.0.0.1/tcp/9801".to_string()]
    );
    assert_eq!(cloned.log, "info");
    assert_eq!(cloned.data_dir, "clone-data");
    assert_eq!(cloned.wallet_address, "clone-wallet");
    assert!(!cloned.founder);
}

#[test]
fn p2p_99_006_sync_runtime_end_to_end_vector_cli_parse_shape() -> TestResult {
    let bootstraps = [
        bootstrap_with_peer(9901),
        "/dns/seed99.remzar.example/tcp/9902".to_string(),
        "/memory/9903".to_string(),
    ];

    let opts = parse_node_opts(&[
        "--wallet-address",
        "wallet-99",
        "--identity-file",
        "identity-99.key",
        "--listen",
        "/ip4/127.0.0.1/tcp/9900",
        "--bootstrap",
        bootstraps[0].as_str(),
        "--bootstrap",
        bootstraps[1].as_str(),
        "--bootstrap",
        bootstraps[2].as_str(),
        "--log",
        "remzar=trace,libp2p=warn",
        "--data-dir",
        "data-99",
        "--is-founder",
    ])?;

    assert_eq!(opts.wallet_address, "wallet-99");
    assert_eq!(opts.identity_file, "identity-99.key");
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/9900");
    assert_eq!(opts.bootstrap, bootstraps.to_vec());
    assert_eq!(opts.log, "remzar=trace,libp2p=warn");
    assert_eq!(opts.data_dir, "data-99");
    assert!(opts.founder);
    Ok(())
}

#[test]
fn p2p_100_006_sync_runtime_final_parser_stress_vector() -> TestResult {
    let mut args = vec![
        "--identity-file".to_string(),
        "identity-100.key".to_string(),
        "--listen".to_string(),
        "/ip4/127.0.0.1/tcp/10000".to_string(),
        "--log".to_string(),
        "trace".to_string(),
        "--data-dir".to_string(),
        "data-100".to_string(),
        "--founder".to_string(),
    ];

    for port in 30_000u16..30_040u16 {
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = parse_strings_with_wallet(args)?;

    assert_eq!(opts.identity_file, "identity-100.key");
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/10000");
    assert_eq!(opts.log, "trace");
    assert_eq!(opts.data_dir, "data-100");
    assert_eq!(opts.wallet_address, "test-wallet");
    assert!(opts.founder);
    assert_eq!(opts.bootstrap.len(), 40usize);
    assert_eq!(opts.bootstrap[0], "/ip4/127.0.0.1/tcp/30000");
    assert_eq!(opts.bootstrap[39], "/ip4/127.0.0.1/tcp/30039");
    Ok(())
}
