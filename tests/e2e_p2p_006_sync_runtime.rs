#![cfg(test)]
#![deny(unsafe_code)]

use clap::Parser;
use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use remzar::{
    consensus::por_005_time_management::{TimeConfig, TimeManager},
    runtime::p2p_006_sync_runtime::{NodeOpts, run_node},
    storage::rocksdb_000_directory::DirectoryDB,
    utility::alpha_001_global_configuration::GlobalConfiguration,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::timeout;

type TestResult<T = ()> = Result<T, String>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn now_millis_for_test() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

fn unique_data_dir(test_name: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_e2e_p2p_006_sync_runtime_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn wallet_for_test() -> String {
    GlobalConfiguration::GENESIS_VALIDATOR.to_string()
}

fn opts_for_dir(test_name: &str) -> NodeOpts {
    let data_dir = unique_data_dir(test_name);
    let identity_file = data_dir.join("identity.key");

    NodeOpts {
        identity_file: identity_file.to_string_lossy().into_owned(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: wallet_for_test(),
        founder: false,
    }
}

fn fresh_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn full_p2p_addr(peer: PeerId, port: u16) -> String {
    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
}

fn split_full_p2p_multiaddr(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut components: Vec<_> = addr.iter().collect();

    match components.last().cloned() {
        Some(Protocol::P2p(peer_id)) => {
            components.pop();
            let base: Multiaddr = components.into_iter().collect();
            Some((peer_id, base))
        }
        _ => None,
    }
}

fn create_all_runtime_dirs(dir: &DirectoryDB) -> TestResult {
    dir.create_wallets_directory().map_err(fmt_err)?;
    dir.create_db_directory().map_err(fmt_err)?;
    dir.create_blockchain_directory().map_err(fmt_err)?;
    dir.create_registry_directory().map_err(fmt_err)?;
    dir.create_accountmodel_directory().map_err(fmt_err)?;
    dir.create_sidechain_directory().map_err(fmt_err)?;
    dir.create_log_directory().map_err(fmt_err)?;
    dir.create_audit_reports_directory().map_err(fmt_err)?;
    dir.create_peerlist_directory().map_err(fmt_err)?;
    Ok(())
}

fn assert_runtime_dirs_exist(dir: &DirectoryDB) {
    assert!(dir.wallets_path.exists());
    assert!(dir.db_path.exists());
    assert!(dir.blockchain_path.exists());
    assert!(dir.registry_path.exists());
    assert!(dir.accountmodel_path.exists());
    assert!(dir.sidechain_path.exists());
    assert!(dir.log_path.exists());
    assert!(dir.audit_reports_path.exists());
    assert!(dir.peerlist_path.exists());
}

#[test]
fn e2e_01_nodeopts_default_matches_runtime_defaults() -> TestResult {
    let opts = NodeOpts::default();

    assert_eq!(opts.identity_file, "identity.key");
    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
    assert!(opts.bootstrap.is_empty());
    assert_eq!(opts.log, "info");
    assert_eq!(opts.data_dir, "data");
    assert_eq!(opts.wallet_address, "");
    assert!(!opts.founder);

    Ok(())
}

#[test]
fn e2e_02_nodeopts_clone_preserves_all_public_fields() -> TestResult {
    let mut opts = opts_for_dir("e2e_02");
    opts.bootstrap = vec![
        "/ip4/127.0.0.1/tcp/30333".to_string(),
        "/ip4/127.0.0.1/tcp/30334".to_string(),
    ];
    opts.founder = true;

    let cloned = opts.clone();

    assert_eq!(cloned.identity_file, opts.identity_file);
    assert_eq!(cloned.listen, opts.listen);
    assert_eq!(cloned.bootstrap, opts.bootstrap);
    assert_eq!(cloned.log, opts.log);
    assert_eq!(cloned.data_dir, opts.data_dir);
    assert_eq!(cloned.wallet_address, opts.wallet_address);
    assert_eq!(cloned.founder, opts.founder);

    Ok(())
}

#[test]
fn e2e_03_nodeopts_debug_output_contains_core_field_names() -> TestResult {
    let opts = opts_for_dir("e2e_03");
    let debug = format!("{opts:?}");

    assert!(debug.contains("identity_file"));
    assert!(debug.contains("listen"));
    assert!(debug.contains("bootstrap"));
    assert!(debug.contains("wallet_address"));
    assert!(debug.contains("founder"));

    Ok(())
}

#[test]
fn e2e_04_clap_requires_wallet_address_for_cli_parse() -> TestResult {
    let parsed = NodeOpts::try_parse_from(["remzar-node"]);

    assert!(parsed.is_err());

    Ok(())
}

#[test]
fn e2e_05_clap_wallet_only_uses_runtime_defaults_for_other_fields() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.identity_file, "identity.key");
    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
    assert!(opts.bootstrap.is_empty());
    assert_eq!(opts.log, "info");
    assert_eq!(opts.data_dir, "data");
    assert_eq!(opts.wallet_address, wallet_for_test());
    assert!(!opts.founder);

    Ok(())
}

#[test]
fn e2e_06_clap_parses_all_scalar_runtime_options() -> TestResult {
    let data_dir = unique_data_dir("e2e_06");
    let identity_file = data_dir.join("node.key");

    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--identity-file",
        identity_file.to_string_lossy().as_ref(),
        "--listen",
        "/ip4/127.0.0.1/tcp/0",
        "--log",
        "trace",
        "--data-dir",
        data_dir.to_string_lossy().as_ref(),
        "--wallet-address",
        wallet_for_test().as_str(),
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.identity_file, identity_file.to_string_lossy());
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/0");
    assert_eq!(opts.log, "trace");
    assert_eq!(opts.data_dir, data_dir.to_string_lossy());
    assert_eq!(opts.wallet_address, wallet_for_test());
    assert!(!opts.founder);

    Ok(())
}

#[test]
fn e2e_07_clap_parses_founder_flag() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--founder",
    ])
    .map_err(fmt_err)?;

    assert!(opts.founder);

    Ok(())
}

#[test]
fn e2e_08_clap_parses_is_founder_alias() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--is-founder",
    ])
    .map_err(fmt_err)?;

    assert!(opts.founder);

    Ok(())
}

#[test]
fn e2e_09_clap_parses_repeated_bootstrap_values() -> TestResult {
    let peer = fresh_peer_id();
    let first = full_p2p_addr(peer, 30333);
    let second = "/ip4/127.0.0.1/tcp/30334".to_string();

    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--bootstrap",
        first.as_str(),
        "--bootstrap",
        second.as_str(),
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.bootstrap, vec![first, second]);

    Ok(())
}

#[test]
fn e2e_10_clap_preserves_bootstrap_order() -> TestResult {
    let first = "/ip4/127.0.0.1/tcp/30001".to_string();
    let second = "/ip4/127.0.0.1/tcp/30002".to_string();
    let third = "/ip4/127.0.0.1/tcp/30003".to_string();

    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--bootstrap",
        first.as_str(),
        "--bootstrap",
        second.as_str(),
        "--bootstrap",
        third.as_str(),
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.bootstrap[0], first);
    assert_eq!(opts.bootstrap[1], second);
    assert_eq!(opts.bootstrap[2], third);

    Ok(())
}

#[test]
fn e2e_11_clap_rejects_unknown_runtime_argument() -> TestResult {
    let parsed = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--unknown-runtime-option",
    ]);

    assert!(parsed.is_err());

    Ok(())
}

#[test]
fn e2e_12_clap_accepts_data_dir_with_spaces() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--data-dir",
        "tmp/remzar runtime with spaces",
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.data_dir, "tmp/remzar runtime with spaces");

    Ok(())
}

#[test]
fn e2e_13_clap_accepts_memory_listen_address_as_text() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--listen",
        "/memory/12345",
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.listen, "/memory/12345");

    Ok(())
}

#[test]
fn e2e_14_clap_accepts_custom_log_filter_string() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--log",
        "remzar=debug,libp2p=warn",
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.log, "remzar=debug,libp2p=warn");

    Ok(())
}

#[test]
fn e2e_15_clap_accepts_nested_identity_file_path() -> TestResult {
    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--identity-file",
        "runtime/keys/identity.key",
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.identity_file, "runtime/keys/identity.key");

    Ok(())
}

#[test]
fn e2e_16_directorydb_from_node_opts_maps_all_runtime_paths() -> TestResult {
    let opts = opts_for_dir("e2e_16");
    let base = PathBuf::from(&opts.data_dir);
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    assert_eq!(
        dir.wallets_path,
        base.join(GlobalConfiguration::WALLETS_DIR)
    );
    assert_eq!(
        dir.db_path,
        base.join(GlobalConfiguration::DATABASE_DIR_NAME)
    );
    assert_eq!(
        dir.blockchain_path,
        base.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert_eq!(
        dir.registry_path,
        base.join(GlobalConfiguration::REGISTRY_DIR_NAME)
    );
    assert_eq!(
        dir.accountmodel_path,
        base.join(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR)
    );
    assert_eq!(
        dir.sidechain_path,
        base.join(GlobalConfiguration::SIDECHAIN_DATABASE_DIR)
    );
    assert_eq!(
        dir.log_path,
        base.join(GlobalConfiguration::LOG_DATABASE_DIR)
    );
    assert_eq!(
        dir.audit_reports_path,
        base.join(GlobalConfiguration::AUDIT_REPORTS_DIR)
    );
    assert_eq!(
        dir.peerlist_path,
        base.join(GlobalConfiguration::PEER_LIST_DIR)
    );

    Ok(())
}

#[test]
fn e2e_17_directorydb_create_peerlist_directory() -> TestResult {
    let opts = opts_for_dir("e2e_17");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    dir.create_peerlist_directory().map_err(fmt_err)?;

    assert!(dir.peerlist_path.exists());
    assert!(dir.peerlist_path.is_dir());

    Ok(())
}

#[test]
fn e2e_18_directorydb_create_blockchain_directory() -> TestResult {
    let opts = opts_for_dir("e2e_18");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    dir.create_blockchain_directory().map_err(fmt_err)?;

    assert!(dir.blockchain_path.exists());
    assert!(dir.blockchain_path.is_dir());

    Ok(())
}

#[test]
fn e2e_19_directorydb_create_all_runtime_directories_and_validate() -> TestResult {
    let opts = opts_for_dir("e2e_19");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    create_all_runtime_dirs(&dir)?;

    assert_runtime_dirs_exist(&dir);
    dir.validate_directories().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_20_directorydb_setup_database_wallets_path() -> TestResult {
    let opts = opts_for_dir("e2e_20");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    dir.setup_database(&dir.wallets_path).map_err(fmt_err)?;

    assert!(dir.wallets_path.exists());

    Ok(())
}

#[test]
fn e2e_21_directorydb_setup_database_db_path() -> TestResult {
    let opts = opts_for_dir("e2e_21");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    dir.setup_database(&dir.db_path).map_err(fmt_err)?;

    assert!(dir.db_path.exists());

    Ok(())
}

#[test]
fn e2e_22_directorydb_setup_database_blockchain_path() -> TestResult {
    let opts = opts_for_dir("e2e_22");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    dir.setup_database(&dir.blockchain_path).map_err(fmt_err)?;

    assert!(dir.blockchain_path.exists());

    Ok(())
}

#[test]
fn e2e_23_directorydb_setup_database_all_known_paths() -> TestResult {
    let opts = opts_for_dir("e2e_23");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    let paths = [
        dir.wallets_path.clone(),
        dir.db_path.clone(),
        dir.blockchain_path.clone(),
        dir.registry_path.clone(),
        dir.accountmodel_path.clone(),
        dir.sidechain_path.clone(),
        dir.log_path.clone(),
        dir.audit_reports_path.clone(),
        dir.peerlist_path.clone(),
    ];

    for path in paths {
        dir.setup_database(&path).map_err(fmt_err)?;
        assert!(
            path.exists(),
            "missing runtime directory {}",
            path.display()
        );
    }

    Ok(())
}

#[test]
fn e2e_24_directorydb_setup_database_rejects_unknown_target() -> TestResult {
    let opts = opts_for_dir("e2e_24");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    let invalid = PathBuf::from(&opts.data_dir).join("not-a-runtime-db-dir");
    let err = dir
        .setup_database(&invalid)
        .expect_err("unknown target must fail");

    assert!(err.contains("Invalid target"));

    Ok(())
}

#[test]
fn e2e_25_directorydb_create_directories_is_idempotent() -> TestResult {
    let opts = opts_for_dir("e2e_25");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    create_all_runtime_dirs(&dir)?;
    create_all_runtime_dirs(&dir)?;

    assert_runtime_dirs_exist(&dir);
    dir.validate_directories().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_26_directorydb_from_base_dir_supports_relative_base() -> TestResult {
    let base = PathBuf::from("target/remzar_runtime_relative_test");
    let dir = DirectoryDB::from_base_dir(&base).map_err(fmt_err)?;

    assert_eq!(
        dir.blockchain_path,
        base.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert_eq!(
        dir.peerlist_path,
        base.join(GlobalConfiguration::PEER_LIST_DIR)
    );

    Ok(())
}

#[test]
fn e2e_27_directorydb_as_ref_points_to_general_db_path() -> TestResult {
    let opts = opts_for_dir("e2e_27");
    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;

    assert_eq!(dir.as_ref(), dir.db_path.as_path());

    Ok(())
}

#[test]
fn e2e_28_full_bootstrap_multiaddr_parses_with_peer_id() -> TestResult {
    let peer = fresh_peer_id();
    let addr_text = full_p2p_addr(peer, 30333);
    let addr: Multiaddr = addr_text.parse().map_err(fmt_err)?;

    let (parsed_peer, base_addr) =
        split_full_p2p_multiaddr(&addr).ok_or_else(|| "missing /p2p peer id".to_string())?;

    assert_eq!(parsed_peer, peer);
    assert_eq!(base_addr.to_string(), "/ip4/127.0.0.1/tcp/30333");

    Ok(())
}

#[test]
fn e2e_29_bootstrap_multiaddr_without_p2p_has_no_peer_id_component() -> TestResult {
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/30333".parse().map_err(fmt_err)?;

    assert!(split_full_p2p_multiaddr(&addr).is_none());

    Ok(())
}

#[test]
fn e2e_30_runtime_bootstrap_strings_can_mix_full_and_base_multiaddrs() -> TestResult {
    let peer = fresh_peer_id();
    let full = full_p2p_addr(peer, 30333);
    let base = "/ip4/127.0.0.1/tcp/30334".to_string();

    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--bootstrap",
        full.as_str(),
        "--bootstrap",
        base.as_str(),
    ])
    .map_err(fmt_err)?;

    let parsed_full: Multiaddr = opts.bootstrap[0].parse().map_err(fmt_err)?;
    let parsed_base: Multiaddr = opts.bootstrap[1].parse().map_err(fmt_err)?;

    assert!(split_full_p2p_multiaddr(&parsed_full).is_some());
    assert!(split_full_p2p_multiaddr(&parsed_base).is_none());

    Ok(())
}

#[test]
fn e2e_31_duplicate_bootstrap_strings_are_preserved_at_options_layer() -> TestResult {
    let addr = "/ip4/127.0.0.1/tcp/30333";

    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--wallet-address",
        wallet_for_test().as_str(),
        "--bootstrap",
        addr,
        "--bootstrap",
        addr,
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.bootstrap.len(), 2);
    assert_eq!(opts.bootstrap[0], addr);
    assert_eq!(opts.bootstrap[1], addr);

    Ok(())
}

#[test]
fn e2e_32_options_layer_accepts_many_bootstraps_before_runtime_filtering() -> TestResult {
    let mut args = vec![
        "remzar-node".to_string(),
        "--wallet-address".to_string(),
        wallet_for_test(),
    ];

    for port in 31000u16..31020u16 {
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = NodeOpts::try_parse_from(args.iter().map(String::as_str)).map_err(fmt_err)?;

    assert_eq!(opts.bootstrap.len(), 20);

    Ok(())
}

#[test]
fn e2e_33_default_wallet_address_is_empty_until_cli_supplies_one() -> TestResult {
    let opts = NodeOpts::default();

    assert!(opts.wallet_address.is_empty());

    Ok(())
}

#[test]
fn e2e_34_listen_ip4_multiaddr_parses_successfully() -> TestResult {
    let opts = opts_for_dir("e2e_34");
    let addr: Multiaddr = opts.listen.parse().map_err(fmt_err)?;

    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/0");

    Ok(())
}

#[test]
fn e2e_35_listen_ip6_multiaddr_parses_successfully() -> TestResult {
    let mut opts = opts_for_dir("e2e_35");
    opts.listen = "/ip6/::1/tcp/0".to_string();

    let addr: Multiaddr = opts.listen.parse().map_err(fmt_err)?;

    assert_eq!(addr.to_string(), "/ip6/::1/tcp/0");

    Ok(())
}

#[test]
fn e2e_36_invalid_listen_multiaddr_fails_before_runtime_listen() -> TestResult {
    let mut opts = opts_for_dir("e2e_36");
    opts.listen = "not-a-multiaddr".to_string();

    let parsed = opts.listen.parse::<Multiaddr>();

    assert!(parsed.is_err());

    Ok(())
}

#[test]
fn e2e_37_time_config_from_genesis_ts_has_nonzero_runtime_intervals() -> TestResult {
    let cfg = TimeConfig::from_genesis_ts(1_700_000_000);

    assert!(cfg.block_interval_secs >= 1);
    assert!(cfg.puzzle_interval_secs >= 1);
    assert!(cfg.puzzle_interval_secs <= cfg.block_interval_secs);
    assert!(cfg.failover_window_secs >= 1);
    assert!(cfg.failover_max_rounds >= 1);
    assert_eq!(cfg.genesis_time_unix, 1_700_000_000);

    Ok(())
}

#[test]
fn e2e_38_time_manager_current_slot_at_genesis_is_zero() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));

    assert_eq!(tm.current_slot(genesis), 0);

    Ok(())
}

#[test]
fn e2e_39_time_manager_slot_increments_at_block_interval() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));
    let bi = tm.block_interval_secs();

    assert_eq!(tm.current_slot(genesis.saturating_add(bi)), 1);
    assert_eq!(
        tm.current_slot(genesis.saturating_add(bi.saturating_mul(2))),
        2
    );

    Ok(())
}

#[test]
fn e2e_40_time_manager_slot_start_is_deterministic() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));
    let bi = tm.block_interval_secs();

    assert_eq!(tm.slot_start_unix(0), genesis);
    assert_eq!(
        tm.slot_start_unix(3),
        genesis.saturating_add(bi.saturating_mul(3))
    );

    Ok(())
}

#[test]
fn e2e_41_time_manager_start_after_next_slot_matches_block_interval_at_genesis() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));

    assert_eq!(
        tm.start_after_next_slot(genesis),
        Duration::from_secs(tm.block_interval_secs())
    );

    Ok(())
}

#[test]
fn e2e_42_time_manager_secs_into_slot_clamps_to_block_interval() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));
    let bi = tm.block_interval_secs();

    assert_eq!(
        tm.secs_into_slot(0, genesis.saturating_add(bi.saturating_mul(10))),
        bi
    );

    Ok(())
}

#[test]
fn e2e_43_time_manager_round_for_height_at_time_uses_failover_window() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));
    let tau = tm.failover_window_secs();

    assert_eq!(
        tm.round_for_height_at_time(0, genesis.saturating_add(tau.saturating_mul(2))),
        2
    );

    Ok(())
}

#[test]
fn e2e_44_time_manager_slot_and_round_from_block_timestamp_at_genesis() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));

    let (slot, round, into) = tm
        .slot_and_round_from_block_timestamp(genesis)
        .map_err(fmt_err)?;

    assert_eq!(slot, 0);
    assert_eq!(round, 0);
    assert_eq!(into, 0);

    Ok(())
}

#[test]
fn e2e_45_time_manager_rejects_timestamp_too_far_before_genesis() -> TestResult {
    let genesis = 1_700_000_000;
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(genesis));

    let too_early = genesis
        .saturating_sub(tm.slot_gate_drift_secs())
        .saturating_sub(10);

    let result = tm.slot_and_round_from_block_timestamp(too_early);

    assert!(result.is_err());

    Ok(())
}

#[test]
fn e2e_46_registry_heartbeat_interval_is_not_slower_than_failover() -> TestResult {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));

    let interval = tm
        .registry_heartbeat_interval(Some(999_999))
        .ok_or_else(|| "missing registry interval".to_string())?;

    assert!(interval <= Duration::from_secs(tm.failover_window_secs()));
    assert!(interval >= Duration::from_secs(1));

    Ok(())
}

#[test]
fn e2e_47_sync_poll_interval_matches_failover_cadence() -> TestResult {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));

    assert_eq!(
        tm.sync_poll_interval(),
        Duration::from_secs(tm.failover_window_secs())
    );

    Ok(())
}

#[test]
fn e2e_48_consensus_timeouts_are_positive() -> TestResult {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let timeouts = tm.consensus_timeouts();

    assert!(timeouts.propose > Duration::ZERO);
    assert!(timeouts.prevote > Duration::ZERO);
    assert!(timeouts.precommit > Duration::ZERO);

    Ok(())
}

#[tokio::test]
async fn e2e_49_run_node_with_invalid_listen_returns_error_instead_of_hanging() -> TestResult {
    let mut opts = opts_for_dir("e2e_49");
    let data_dir = PathBuf::from(&opts.data_dir);
    std::fs::create_dir_all(&data_dir).map_err(fmt_err)?;

    opts.listen = "not-a-multiaddr".to_string();
    opts.founder = false;
    opts.wallet_address = wallet_for_test();

    let result = timeout(Duration::from_secs(5), run_node(opts)).await;

    let err = match result {
        Err(_) => return Err("run_node timed out instead of rejecting invalid listen".to_string()),
        Ok(Ok(())) => return Err("run_node unexpectedly succeeded with invalid listen".to_string()),
        Ok(Err(err)) => format!("{err:?}"),
    };

    assert!(
        err.contains("Bad listen address")
            || err.contains("ValidationError")
            || err.contains("multiaddr"),
        "unexpected run_node error: {err}"
    );

    Ok(())
}

#[test]
fn e2e_50_full_public_runtime_wiring_model_opts_dirs_bootstrap_and_time() -> TestResult {
    let peer = fresh_peer_id();
    let bootstrap = full_p2p_addr(peer, 36213);
    let data_dir = unique_data_dir("e2e_50");
    let identity_file = data_dir.join("identity.key");

    let opts = NodeOpts::try_parse_from([
        "remzar-node",
        "--identity-file",
        identity_file.to_string_lossy().as_ref(),
        "--listen",
        "/ip4/127.0.0.1/tcp/0",
        "--bootstrap",
        bootstrap.as_str(),
        "--log",
        "error",
        "--data-dir",
        data_dir.to_string_lossy().as_ref(),
        "--wallet-address",
        wallet_for_test().as_str(),
    ])
    .map_err(fmt_err)?;

    assert_eq!(opts.identity_file, identity_file.to_string_lossy());
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/0");
    assert_eq!(opts.bootstrap, vec![bootstrap.clone()]);
    assert_eq!(opts.log, "error");
    assert_eq!(opts.data_dir, data_dir.to_string_lossy());
    assert_eq!(opts.wallet_address, wallet_for_test());
    assert!(!opts.founder);

    let dir = DirectoryDB::from_node_opts(&opts).map_err(fmt_err)?;
    dir.create_peerlist_directory().map_err(fmt_err)?;
    dir.create_blockchain_directory().map_err(fmt_err)?;

    assert!(dir.peerlist_path.exists());
    assert!(dir.blockchain_path.exists());

    let parsed_bootstrap: Multiaddr = opts.bootstrap[0].parse().map_err(fmt_err)?;
    let (parsed_peer, base_addr) = split_full_p2p_multiaddr(&parsed_bootstrap)
        .ok_or_else(|| "expected bootstrap peer id".to_string())?;

    assert_eq!(parsed_peer, peer);
    assert_eq!(base_addr.to_string(), "/ip4/127.0.0.1/tcp/36213");

    let listen: Multiaddr = opts.listen.parse().map_err(fmt_err)?;
    assert_eq!(listen.to_string(), "/ip4/127.0.0.1/tcp/0");

    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    assert!(tm.block_interval_secs() >= 1);
    assert!(tm.failover_window_secs() >= 1);
    assert_eq!(tm.current_slot(1_700_000_000), 0);

    Ok(())
}
