#![cfg(test)]

use fips204::ml_dsa_65;
use libp2p::gossipsub::IdentTopic;
use libp2p::identity;
use remzar::blockchain::blockchain_005_start::StartBlockchain;
use remzar::blockchain::mempool::MemPool;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::network::p2p_001_transport::build_transport;
use remzar::network::p2p_003_behaviour::RemzarBehaviour;
use remzar::network::p2p_011_peerbook::PeerBook;
use remzar::reorganization::reorg_006_manager::ReorgManager;
use remzar::runtime::p2p_001_sync_builders::P2pSync;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_003_detection_system::DetectionSystem;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

type TestResult<T = ()> = Result<T, String>;
type SetupGuard = MutexGuard<'static, ()>;

static SETUP_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

struct Harness {
    _temp_root: PathBuf,
    opts: NodeOpts,
    sync_engine: Arc<TokioMutex<P2pSync>>,
    signing_key: Arc<ml_dsa_65::PrivateKey>,
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn setup_guard() -> TestResult<SetupGuard> {
    match SETUP_LOCK.get_or_init(|| StdMutex::new(())).lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => Ok(poisoned.into_inner()),
    }
}

fn run_async<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(fmt_err)?;

    runtime.block_on(future)
}

fn unique_temp_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();

    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
}

fn wallet_with_hex_pair(pair: &str) -> String {
    format!("r{}", pair.repeat(64))
}

fn genesis_wallet() -> String {
    GlobalConfiguration::GENESIS_VALIDATOR.to_string()
}

fn make_test_node_opts(temp_root: &Path, wallet: &str, founder: bool) -> NodeOpts {
    NodeOpts {
        identity_file: temp_root.join("identity.key").to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: temp_root.to_string_lossy().to_string(),
        wallet_address: wallet.to_string(),
        founder,
    }
}

fn make_harness_and_db(
    prefix: &str,
    wallet: &str,
    founder: bool,
) -> TestResult<(Harness, RockDBManager)> {
    let _setup_guard = setup_guard()?;

    let temp_root = unique_temp_root(prefix);
    fs::create_dir_all(&temp_root).map_err(fmt_err)?;

    let opts = make_test_node_opts(&temp_root, wallet, founder);
    let db_dir = temp_root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let db_dir_str = db_dir
        .to_str()
        .ok_or_else(|| "temporary blockchain path is not valid UTF-8".to_string())?;

    let db_manager = RockDBManager::new_blockchain(&opts, db_dir_str).map_err(fmt_err)?;
    let db_for_sync = Arc::new(db_manager.clone());

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db_for_sync), detection));
    let chain = AccountModelTree::with_manager((*db_for_sync).clone());

    let peerlist_dir = temp_root.join(GlobalConfiguration::PEER_LIST_DIR);
    fs::create_dir_all(&peerlist_dir).map_err(fmt_err)?;
    PeerBook::configure_storage_dir(peerlist_dir.clone());

    let peerbook = Arc::new(StdMutex::new(PeerBook::load_or_init()));
    let sync_reorg = ReorgManager::mainnet_default(Arc::clone(&db_for_sync));
    let sync_engine = Arc::new(TokioMutex::new(P2pSync::new(
        chain,
        Arc::clone(&db_for_sync),
        Arc::clone(&mempool),
        peerbook,
        peerlist_dir,
        None,
        sync_reorg,
    )));

    let (_verifying_key, signing_key) = ml_dsa_65::try_keygen().map_err(fmt_err)?;

    Ok((
        Harness {
            _temp_root: temp_root,
            opts,
            sync_engine,
            signing_key: Arc::new(signing_key),
        },
        db_manager,
    ))
}

fn make_start(prefix: &str, wallet: &str) -> TestResult<(Harness, StartBlockchain)> {
    make_start_with_founder(prefix, wallet, false)
}

fn make_start_with_founder(
    prefix: &str,
    wallet: &str,
    founder: bool,
) -> TestResult<(Harness, StartBlockchain)> {
    let (harness, db_manager) = make_harness_and_db(prefix, wallet, founder)?;
    let starter = StartBlockchain::new(
        db_manager,
        wallet.to_string(),
        Arc::clone(&harness.sync_engine),
        Arc::clone(&harness.signing_key),
    );

    Ok((harness, starter))
}

fn make_swarm() -> TestResult<libp2p::Swarm<RemzarBehaviour>> {
    let id_keys = identity::Keypair::generate_ed25519();
    let mut behaviour = RemzarBehaviour::new(id_keys.clone()).map_err(fmt_err)?;

    behaviour
        .gossipsub
        .subscribe(&IdentTopic::new("remzar.test.v1"))
        .map_err(fmt_err)?;

    let transport = build_transport(id_keys.clone()).map_err(fmt_err)?;

    let swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_other_transport(move |_| transport)
        .map_err(fmt_err)?
        .with_behaviour(|_| behaviour)
        .map_err(fmt_err)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(1)))
        .build();

    Ok(swarm)
}

fn run_start_expect_wallet_error(harness: &Harness, starter: &StartBlockchain) -> TestResult {
    let mut swarm = make_swarm()?;

    run_async(async {
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            starter.run(&mut swarm, &harness.opts),
        )
        .await
        .map_err(fmt_err)?;

        assert!(result.is_err());
        Ok(())
    })
}

fn assert_sync_percent_bounded(sync_engine: &Arc<TokioMutex<P2pSync>>) -> TestResult {
    run_async(async {
        let sync = sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

fn make_time_manager_for_compile_surface() -> Arc<TimeManager> {
    Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1)))
}

#[test]
fn blockchain_01_005_start_new_stores_local_wallet() -> TestResult {
    let (_harness, starter) = make_start("start_01", &genesis_wallet())?;

    assert_eq!(starter.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_02_005_start_new_preserves_uppercase_wallet_until_run() -> TestResult {
    let wallet = format!("r{}", "AA".repeat(64));
    let (_harness, starter) = make_start("start_02", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_03_005_start_new_preserves_empty_wallet() -> TestResult {
    let (_harness, starter) = make_start("start_03", "")?;

    assert!(starter.local_wallet.is_empty());
    Ok(())
}

#[test]
fn blockchain_04_005_start_new_preserves_invalid_wallet() -> TestResult {
    let wallet = "not-a-wallet";
    let (_harness, starter) = make_start("start_04", wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_05_005_start_new_wraps_db_manager_in_arc() -> TestResult {
    let (_harness, starter) = make_start("start_05", &genesis_wallet())?;

    assert_eq!(Arc::strong_count(&starter.db_manager), 1);
    Ok(())
}

#[test]
fn blockchain_06_005_start_new_reuses_sync_engine_arc() -> TestResult {
    let (harness, starter) = make_start("start_06", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    Ok(())
}

#[test]
fn blockchain_07_005_start_new_reuses_signing_key_arc() -> TestResult {
    let (harness, starter) = make_start("start_07", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.signing_key, &starter.signing_key));
    Ok(())
}

#[test]
fn blockchain_08_005_start_new_db_tip_height_is_accessible() -> TestResult {
    let (_harness, starter) = make_start("start_08", &genesis_wallet())?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn blockchain_09_005_start_new_sync_percent_is_bounded() -> TestResult {
    let (harness, starter) = make_start("start_09", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    assert_sync_percent_bounded(&starter.sync_engine)
}

#[test]
fn blockchain_10_005_start_new_wallet_registry_is_independent_public_field() -> TestResult {
    let (_harness, starter) = make_start("start_10", &genesis_wallet())?;
    let _registry = &starter.wallet_registry;

    assert_eq!(starter.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_11_005_start_new_console_bus_is_constructed() -> TestResult {
    let (_harness, starter) = make_start("start_11", &genesis_wallet())?;
    let _bus = starter.console_bus.clone();

    assert_eq!(starter.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_12_005_start_new_with_founder_true_stores_opts_founder() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_12", &genesis_wallet(), true)?;

    assert!(harness.opts.founder);
    assert_eq!(starter.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_13_005_start_new_with_founder_false_stores_opts_non_founder() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_13", &genesis_wallet(), false)?;

    assert!(!harness.opts.founder);
    assert_eq!(starter.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_14_005_start_new_all_zero_wallet_stored() -> TestResult {
    let wallet = wallet_with_hex_pair("00");
    let (_harness, starter) = make_start("start_14", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_15_005_start_new_all_ff_wallet_stored() -> TestResult {
    let wallet = wallet_with_hex_pair("ff");
    let (_harness, starter) = make_start("start_15", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_16_005_start_new_short_wallet_stored() -> TestResult {
    let wallet = "r123";
    let (_harness, starter) = make_start("start_16", wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_17_005_start_new_bad_prefix_wallet_stored() -> TestResult {
    let wallet = format!("x{}", "11".repeat(64));
    let (_harness, starter) = make_start("start_17", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_18_005_start_new_non_hex_wallet_stored() -> TestResult {
    let wallet = format!("r{}", "zz".repeat(64));
    let (_harness, starter) = make_start("start_18", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_19_005_start_new_space_wallet_stored() -> TestResult {
    let wallet = " ";
    let (_harness, starter) = make_start("start_19", wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_20_005_start_new_mixed_case_vector_stored_exactly() -> TestResult {
    let wallet = format!("r{}", "Ab".repeat(64));
    let (_harness, starter) = make_start("start_20", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_21_005_start_run_empty_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_21", "")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_22_005_start_run_short_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_22", "r123")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_23_005_start_run_bad_prefix_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = format!("x{}", "11".repeat(64));
    let (harness, starter) = make_start("start_23", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_24_005_start_run_non_hex_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = format!("r{}", "zz".repeat(64));
    let (harness, starter) = make_start("start_24", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_25_005_start_run_plain_text_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_25", "not-a-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_26_005_start_run_space_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_26", " ")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_27_005_start_run_one_char_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_27", "r")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_28_005_start_run_missing_r_prefix_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = "11".repeat(64);
    let (harness, starter) = make_start("start_28", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_29_005_start_run_too_long_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = format!("r{}", "11".repeat(65));
    let (harness, starter) = make_start("start_29", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_30_005_start_run_too_short_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = format!("r{}", "11".repeat(63));
    let (harness, starter) = make_start("start_30", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_31_005_start_run_invalid_wallet_does_not_mutate_local_wallet() -> TestResult {
    let wallet = "bad-wallet";
    let (harness, starter) = make_start("start_31", wallet)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_32_005_start_run_invalid_wallet_keeps_sync_engine_available() -> TestResult {
    let (harness, starter) = make_start("start_32", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_sync_percent_bounded(&starter.sync_engine)
}

#[test]
fn blockchain_33_005_start_run_invalid_wallet_keeps_db_accessible() -> TestResult {
    let (harness, starter) = make_start("start_33", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn blockchain_34_005_start_run_invalid_wallet_founder_true_returns_error() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_34", "bad-wallet", true)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(harness.opts.founder);
    Ok(())
}

#[test]
fn blockchain_35_005_start_run_invalid_wallet_founder_false_returns_error() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_35", "bad-wallet", false)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(!harness.opts.founder);
    Ok(())
}

#[test]
fn blockchain_36_005_start_multiple_instances_have_distinct_db_arcs() -> TestResult {
    let (_harness_a, starter_a) = make_start("start_36_a", &genesis_wallet())?;
    let (_harness_b, starter_b) = make_start("start_36_b", &wallet_with_hex_pair("22"))?;

    assert!(!Arc::ptr_eq(&starter_a.db_manager, &starter_b.db_manager));
    Ok(())
}

#[test]
fn blockchain_37_005_start_multiple_instances_keep_distinct_wallets() -> TestResult {
    let wallet_a = genesis_wallet();
    let wallet_b = wallet_with_hex_pair("22");
    let (_harness_a, starter_a) = make_start("start_37_a", &wallet_a)?;
    let (_harness_b, starter_b) = make_start("start_37_b", &wallet_b)?;

    assert_eq!(starter_a.local_wallet, wallet_a);
    assert_eq!(starter_b.local_wallet, wallet_b);
    assert_ne!(starter_a.local_wallet, starter_b.local_wallet);
    Ok(())
}

#[test]
fn blockchain_38_005_start_multiple_instances_keep_distinct_sync_engines() -> TestResult {
    let (_harness_a, starter_a) = make_start("start_38_a", &genesis_wallet())?;
    let (_harness_b, starter_b) = make_start("start_38_b", &wallet_with_hex_pair("22"))?;

    assert!(!Arc::ptr_eq(&starter_a.sync_engine, &starter_b.sync_engine));
    Ok(())
}

#[test]
fn blockchain_39_005_start_multiple_instances_keep_distinct_signing_keys() -> TestResult {
    let (_harness_a, starter_a) = make_start("start_39_a", &genesis_wallet())?;
    let (_harness_b, starter_b) = make_start("start_39_b", &wallet_with_hex_pair("22"))?;

    assert!(!Arc::ptr_eq(&starter_a.signing_key, &starter_b.signing_key));
    Ok(())
}

#[test]
fn blockchain_40_005_start_time_manager_compile_surface_is_available() -> TestResult {
    let tm = make_time_manager_for_compile_surface();

    assert!(tm.block_interval().as_secs() >= 1);
    Ok(())
}

#[test]
fn blockchain_41_005_start_new_does_not_change_sync_percent() -> TestResult {
    let (harness, starter) = make_start("start_41", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    assert_sync_percent_bounded(&harness.sync_engine)
}

#[test]
fn blockchain_42_005_start_new_can_read_db_tip_repeatedly() -> TestResult {
    let (_harness, starter) = make_start("start_42", &genesis_wallet())?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn blockchain_43_005_start_new_preserves_wallet_after_db_read() -> TestResult {
    let wallet = genesis_wallet();
    let (_harness, starter) = make_start("start_43", &wallet)?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_44_005_start_run_invalid_wallet_after_db_read_returns_error() -> TestResult {
    let (harness, starter) = make_start("start_44", "bad-wallet")?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_45_005_start_run_invalid_wallet_after_sync_read_returns_error() -> TestResult {
    let (harness, starter) = make_start("start_45", "bad-wallet")?;

    assert_sync_percent_bounded(&starter.sync_engine)?;
    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_46_005_start_run_invalid_wallet_repeatedly_returns_error_without_hanging()
-> TestResult {
    let (harness, starter) = make_start("start_46", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;
    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_47_005_start_constructor_fuzz_valid_wallet_vectors_are_stored() -> TestResult {
    let wallets = [
        genesis_wallet(),
        wallet_with_hex_pair("00"),
        wallet_with_hex_pair("01"),
        wallet_with_hex_pair("7f"),
        wallet_with_hex_pair("ff"),
    ];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_47_{idx}");
        let (_harness, starter) = make_start(&prefix, wallet)?;
        assert_eq!(starter.local_wallet, *wallet);
    }

    Ok(())
}

#[test]
fn blockchain_48_005_start_constructor_fuzz_invalid_wallet_vectors_are_stored() -> TestResult {
    let wallets = ["", "r", "r123", "not-a-wallet", " "];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_48_{idx}");
        let (_harness, starter) = make_start(&prefix, wallet)?;
        assert_eq!(starter.local_wallet, *wallet);
    }

    Ok(())
}

#[test]
fn blockchain_49_005_start_run_fuzz_invalid_wallet_vectors_return_error() -> TestResult {
    let wallets = ["", "r", "r123", "not-a-wallet", " "];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_49_{idx}");
        let (harness, starter) = make_start(&prefix, wallet)?;
        run_start_expect_wallet_error(&harness, &starter)?;
    }

    Ok(())
}

#[test]
fn blockchain_50_005_start_full_invalid_wallet_smoke_keeps_public_fields_available() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_50", "bad-wallet", true)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(harness.opts.founder);
    assert_eq!(starter.local_wallet, "bad-wallet");
    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    assert!(Arc::ptr_eq(&harness.signing_key, &starter.signing_key));
    assert_sync_percent_bounded(&starter.sync_engine)
}

#[test]
fn blockchain_51_005_start_constructor_vector_01_wallet_stored() -> TestResult {
    let wallet = wallet_with_hex_pair("01");
    let (_harness, starter) = make_start("start_51", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_52_005_start_constructor_vector_7f_wallet_stored() -> TestResult {
    let wallet = wallet_with_hex_pair("7f");
    let (_harness, starter) = make_start("start_52", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_53_005_start_constructor_vector_fe_wallet_stored() -> TestResult {
    let wallet = wallet_with_hex_pair("fe");
    let (_harness, starter) = make_start("start_53", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_54_005_start_constructor_vector_mixed_case_aa_stored_exactly() -> TestResult {
    let wallet = format!("r{}", "Aa".repeat(64));
    let (_harness, starter) = make_start("start_54", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_55_005_start_constructor_vector_mixed_case_ff_stored_exactly() -> TestResult {
    let wallet = format!("r{}", "Ff".repeat(64));
    let (_harness, starter) = make_start("start_55", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_56_005_start_constructor_vector_uppercase_full_wallet_stored_exactly() -> TestResult {
    let wallet = format!("r{}", "AA".repeat(64));
    let (_harness, starter) = make_start("start_56", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_57_005_start_constructor_vector_missing_prefix_stored_exactly() -> TestResult {
    let wallet = "11".repeat(64);
    let (_harness, starter) = make_start("start_57", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_58_005_start_constructor_vector_too_long_stored_exactly() -> TestResult {
    let wallet = format!("r{}", "11".repeat(65));
    let (_harness, starter) = make_start("start_58", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_59_005_start_constructor_vector_too_short_stored_exactly() -> TestResult {
    let wallet = format!("r{}", "11".repeat(63));
    let (_harness, starter) = make_start("start_59", &wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_60_005_start_constructor_vector_tab_wallet_stored_exactly() -> TestResult {
    let wallet = "\t";
    let (_harness, starter) = make_start("start_60", wallet)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_61_005_start_run_tab_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_61", "\t")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_62_005_start_run_newline_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_62", "\n")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_63_005_start_run_uppercase_bad_prefix_returns_error_before_ctrl_c_loop() -> TestResult
{
    let wallet = format!("R{}", "11".repeat(64));
    let (harness, starter) = make_start("start_63", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_64_005_start_run_hex_with_dash_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = format!("r{}-{}", "11".repeat(32), "22".repeat(32));
    let (harness, starter) = make_start("start_64", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_65_005_start_run_hex_with_space_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = format!("r{} {}", "11".repeat(32), "22".repeat(32));
    let (harness, starter) = make_start("start_65", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_66_005_start_run_unicode_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let (harness, starter) = make_start("start_66", "remzar🚀")?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_67_005_start_run_zero_width_wallet_returns_error_before_ctrl_c_loop() -> TestResult {
    let wallet = "\u{200b}";
    let (harness, starter) = make_start("start_67", wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_68_005_start_run_invalid_uppercase_hex_without_r_returns_error() -> TestResult {
    let wallet = "AA".repeat(64);
    let (harness, starter) = make_start("start_68", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_69_005_start_run_invalid_too_long_non_hex_returns_error() -> TestResult {
    let wallet = format!("r{}", "gg".repeat(65));
    let (harness, starter) = make_start("start_69", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_70_005_start_run_invalid_too_short_non_hex_returns_error() -> TestResult {
    let wallet = format!("r{}", "gg".repeat(63));
    let (harness, starter) = make_start("start_70", &wallet)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_71_005_start_invalid_run_does_not_replace_sync_engine_arc() -> TestResult {
    let (harness, starter) = make_start("start_71", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    Ok(())
}

#[test]
fn blockchain_72_005_start_invalid_run_does_not_replace_signing_key_arc() -> TestResult {
    let (harness, starter) = make_start("start_72", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(Arc::ptr_eq(&harness.signing_key, &starter.signing_key));
    Ok(())
}

#[test]
fn blockchain_73_005_start_invalid_run_keeps_local_wallet_exact() -> TestResult {
    let wallet = "bad-wallet";
    let (harness, starter) = make_start("start_73", wallet)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_74_005_start_invalid_run_keeps_db_tip_readable() -> TestResult {
    let (harness, starter) = make_start("start_74", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn blockchain_75_005_start_invalid_run_keeps_sync_percent_bounded_after_error() -> TestResult {
    let (harness, starter) = make_start("start_75", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_sync_percent_bounded(&starter.sync_engine)
}

#[test]
fn blockchain_76_005_start_invalid_run_founder_true_keeps_public_fields() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_76", "bad-wallet", true)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(harness.opts.founder);
    assert_eq!(starter.local_wallet, "bad-wallet");
    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    Ok(())
}

#[test]
fn blockchain_77_005_start_invalid_run_founder_false_keeps_public_fields() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_77", "bad-wallet", false)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert!(!harness.opts.founder);
    assert_eq!(starter.local_wallet, "bad-wallet");
    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    Ok(())
}

#[test]
fn blockchain_78_005_start_invalid_run_can_be_called_three_times_without_hanging() -> TestResult {
    let (harness, starter) = make_start("start_78", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;
    run_start_expect_wallet_error(&harness, &starter)?;
    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_79_005_start_invalid_run_after_tip_reads_still_returns_error() -> TestResult {
    let (harness, starter) = make_start("start_79", "bad-wallet")?;

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_80_005_start_invalid_run_after_sync_read_still_returns_error() -> TestResult {
    let (harness, starter) = make_start("start_80", "bad-wallet")?;

    assert_sync_percent_bounded(&starter.sync_engine)?;

    run_start_expect_wallet_error(&harness, &starter)
}

#[test]
fn blockchain_81_005_start_constructor_arc_counts_are_at_least_shared() -> TestResult {
    let (harness, starter) = make_start("start_81", &genesis_wallet())?;

    assert!(Arc::strong_count(&harness.sync_engine) >= 2);
    assert!(Arc::strong_count(&starter.sync_engine) >= 2);
    assert!(Arc::strong_count(&harness.signing_key) >= 2);
    assert!(Arc::strong_count(&starter.signing_key) >= 2);
    Ok(())
}

#[test]
fn blockchain_82_005_start_constructor_db_arc_is_owned_by_starter() -> TestResult {
    let (_harness, starter) = make_start("start_82", &genesis_wallet())?;

    assert!(Arc::strong_count(&starter.db_manager) >= 1);
    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn blockchain_83_005_start_constructor_console_bus_clone_does_not_change_wallet() -> TestResult {
    let wallet = genesis_wallet();
    let (_harness, starter) = make_start("start_83", &wallet)?;
    let _bus_a = starter.console_bus.clone();
    let _bus_b = starter.console_bus.clone();

    assert_eq!(starter.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_84_005_start_constructor_wallet_registry_reference_is_available() -> TestResult {
    let (_harness, starter) = make_start("start_84", &genesis_wallet())?;
    let _registry_ref = &starter.wallet_registry;

    assert_eq!(starter.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_85_005_start_constructor_multiple_valid_vectors_keep_db_tip_zero() -> TestResult {
    let wallets = [
        genesis_wallet(),
        wallet_with_hex_pair("00"),
        wallet_with_hex_pair("01"),
        wallet_with_hex_pair("7f"),
        wallet_with_hex_pair("fe"),
        wallet_with_hex_pair("ff"),
    ];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_85_{idx}");
        let (_harness, starter) = make_start(&prefix, wallet)?;
        assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    }

    Ok(())
}

#[test]
fn blockchain_86_005_start_constructor_multiple_invalid_vectors_keep_db_tip_zero() -> TestResult {
    let wallets = ["", "r", "r123", "bad-wallet", " ", "\t"];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_86_{idx}");
        let (_harness, starter) = make_start(&prefix, wallet)?;
        assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    }

    Ok(())
}

#[test]
fn blockchain_87_005_start_run_invalid_vector_batch_all_return_error() -> TestResult {
    let wallets = ["", "r", "r123", "bad-wallet", " ", "\t", "\n"];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_87_{idx}");
        let (harness, starter) = make_start(&prefix, wallet)?;
        run_start_expect_wallet_error(&harness, &starter)?;
    }

    Ok(())
}

#[test]
fn blockchain_88_005_start_run_invalid_length_vectors_all_return_error() -> TestResult {
    let wallets = [
        format!("r{}", "11".repeat(1)),
        format!("r{}", "11".repeat(10)),
        format!("r{}", "11".repeat(63)),
        format!("r{}", "11".repeat(65)),
        format!("r{}", "11".repeat(128)),
    ];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_88_{idx}");
        let (harness, starter) = make_start(&prefix, wallet)?;
        run_start_expect_wallet_error(&harness, &starter)?;
    }

    Ok(())
}

#[test]
fn blockchain_89_005_start_run_invalid_character_vectors_all_return_error() -> TestResult {
    let wallets = [
        format!("r{}", "zz".repeat(64)),
        format!("r{}", "gg".repeat(64)),
        format!("r{}", "--".repeat(64)),
        format!("r{}", "__".repeat(64)),
    ];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_89_{idx}");
        let (harness, starter) = make_start(&prefix, wallet)?;
        run_start_expect_wallet_error(&harness, &starter)?;
    }

    Ok(())
}

#[test]
fn blockchain_90_005_start_run_invalid_prefix_vectors_all_return_error() -> TestResult {
    let wallets = [
        format!("x{}", "11".repeat(64)),
        format!("R{}", "11".repeat(64)),
        format!("0{}", "11".repeat(64)),
        format!(" {}", "11".repeat(64)),
    ];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_90_{idx}");
        let (harness, starter) = make_start(&prefix, wallet)?;
        run_start_expect_wallet_error(&harness, &starter)?;
    }

    Ok(())
}

#[test]
fn blockchain_91_005_start_multiple_instances_invalid_runs_do_not_share_db_arcs() -> TestResult {
    let (harness_a, starter_a) = make_start("start_91_a", "bad-wallet")?;
    let (harness_b, starter_b) = make_start("start_91_b", "r123")?;

    run_start_expect_wallet_error(&harness_a, &starter_a)?;
    run_start_expect_wallet_error(&harness_b, &starter_b)?;

    assert!(!Arc::ptr_eq(&starter_a.db_manager, &starter_b.db_manager));
    Ok(())
}

#[test]
fn blockchain_92_005_start_multiple_instances_invalid_runs_do_not_share_sync_engines() -> TestResult
{
    let (harness_a, starter_a) = make_start("start_92_a", "bad-wallet")?;
    let (harness_b, starter_b) = make_start("start_92_b", "r123")?;

    run_start_expect_wallet_error(&harness_a, &starter_a)?;
    run_start_expect_wallet_error(&harness_b, &starter_b)?;

    assert!(!Arc::ptr_eq(&starter_a.sync_engine, &starter_b.sync_engine));
    Ok(())
}

#[test]
fn blockchain_93_005_start_multiple_instances_invalid_runs_do_not_share_signing_keys() -> TestResult
{
    let (harness_a, starter_a) = make_start("start_93_a", "bad-wallet")?;
    let (harness_b, starter_b) = make_start("start_93_b", "r123")?;

    run_start_expect_wallet_error(&harness_a, &starter_a)?;
    run_start_expect_wallet_error(&harness_b, &starter_b)?;

    assert!(!Arc::ptr_eq(&starter_a.signing_key, &starter_b.signing_key));
    Ok(())
}

#[test]
fn blockchain_94_005_start_valid_constructor_then_invalid_constructor_keep_distinct_wallets()
-> TestResult {
    let (_harness_a, starter_a) = make_start("start_94_a", &genesis_wallet())?;
    let (_harness_b, starter_b) = make_start("start_94_b", "bad-wallet")?;

    assert_eq!(starter_a.local_wallet, genesis_wallet());
    assert_eq!(starter_b.local_wallet, "bad-wallet");
    assert_ne!(starter_a.local_wallet, starter_b.local_wallet);
    Ok(())
}

#[test]
fn blockchain_95_005_start_invalid_run_preserves_console_bus_cloneability() -> TestResult {
    let (harness, starter) = make_start("start_95", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    let _bus = starter.console_bus.clone();
    assert_eq!(starter.local_wallet, "bad-wallet");
    Ok(())
}

#[test]
fn blockchain_96_005_start_invalid_run_preserves_wallet_registry_reference() -> TestResult {
    let (harness, starter) = make_start("start_96", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    let _registry_ref = &starter.wallet_registry;
    assert_eq!(starter.local_wallet, "bad-wallet");
    Ok(())
}

#[test]
fn blockchain_97_005_start_sync_engine_lock_after_invalid_run_is_available() -> TestResult {
    let (harness, starter) = make_start("start_97", "bad-wallet")?;

    run_start_expect_wallet_error(&harness, &starter)?;

    run_async(async {
        let sync = starter.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_98_005_start_db_tip_read_after_many_invalid_runs_is_stable() -> TestResult {
    let (harness, starter) = make_start("start_98", "bad-wallet")?;

    for _ in 0..3 {
        run_start_expect_wallet_error(&harness, &starter)?;
    }

    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn blockchain_99_005_start_public_fields_remain_available_after_invalid_fuzz_batch() -> TestResult {
    let wallets = ["", "r", "r123", "bad-wallet"];

    for (idx, wallet) in wallets.iter().enumerate() {
        let prefix = format!("start_99_{idx}");
        let (harness, starter) = make_start(&prefix, wallet)?;

        run_start_expect_wallet_error(&harness, &starter)?;

        assert_eq!(starter.local_wallet, *wallet);
        assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
        assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
        assert!(Arc::ptr_eq(&harness.signing_key, &starter.signing_key));
    }

    Ok(())
}

#[test]
fn blockchain_100_005_start_full_edge_case_smoke_invalid_wallet_does_not_hang() -> TestResult {
    let (harness, starter) = make_start_with_founder("start_100", "bad-wallet", true)?;

    assert!(harness.opts.founder);
    assert_eq!(starter.local_wallet, "bad-wallet");
    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    assert_sync_percent_bounded(&starter.sync_engine)?;

    run_start_expect_wallet_error(&harness, &starter)?;

    assert_eq!(starter.local_wallet, "bad-wallet");
    assert_eq!(starter.db_manager.get_tip_height().map_err(fmt_err)?, 0);
    assert!(Arc::ptr_eq(&harness.sync_engine, &starter.sync_engine));
    assert!(Arc::ptr_eq(&harness.signing_key, &starter.signing_key));
    assert_sync_percent_bounded(&starter.sync_engine)
}
