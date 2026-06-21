#![cfg(test)]

use fips204::ml_dsa_65;
use libp2p::gossipsub::IdentTopic;
use libp2p::{Multiaddr, identity};
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::blockchain_004_orchestration_run::{
    OrchestrationLoop, OrchestrationLoopArgs,
};
use remzar::blockchain::mempool::MemPool;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::commandline::s_04_view_blockchain_console::ConsoleBus;
use remzar::consensus::por_000_ephemeral_registration::NodeEphemeral;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::network::p2p_001_transport::build_transport;
use remzar::network::p2p_003_behaviour::RemzarBehaviour;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::network::p2p_011_peerbook::PeerBook;
use remzar::network::p2p_013_peer_mesh::PeerMeshAnnounce;
use remzar::network::p2p_014_chat::ChatMessage;
use remzar::reorganization::reorg_006_manager::ReorgManager;
use remzar::runtime::p2p_001_sync_builders::P2pSync;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_003_detection_system::DetectionSystem;
use remzar::utility::send_file::FileChunkMessage;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot};

type TestResult<T = ()> = Result<T, String>;
type SetupGuard = MutexGuard<'static, ()>;

static SETUP_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

struct Harness {
    _temp_root: PathBuf,
    opts: NodeOpts,
    db: Arc<RockDBManager>,
    mempool: Arc<MemPool>,
    node: NodeEphemeral,
    sync_engine: Arc<TokioMutex<P2pSync>>,
    signing_key: Arc<ml_dsa_65::PrivateKey>,
    tm: Arc<TimeManager>,
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn run_loop_delayed_shutdown_ms(
    harness: &Harness,
    runner: &OrchestrationLoop,
    net_rx: Option<mpsc::Receiver<NetCmd>>,
    delay_ms: u64,
) -> TestResult {
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    run_async(async {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            let _send_result = shutdown_tx.send(());
        });

        let result = tokio::time::timeout(
            Duration::from_secs(4),
            runner.run_loop(&mut chain, &mut swarm, shutdown_rx, net_rx, &harness.opts),
        )
        .await
        .map_err(fmt_err)?;

        result.map_err(fmt_err)
    })
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

fn peer_wallet() -> String {
    let candidate = wallet_with_hex_pair("22");
    if candidate == genesis_wallet() {
        wallet_with_hex_pair("33")
    } else {
        candidate
    }
}

fn third_wallet() -> String {
    let candidate = wallet_with_hex_pair("44");
    if candidate == genesis_wallet() || candidate == peer_wallet() {
        wallet_with_hex_pair("55")
    } else {
        candidate
    }
}

fn now_secs(offset: u64) -> u64 {
    1_750_000_000u64.saturating_add(offset)
}

fn now_millis() -> TestResult<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(fmt_err)?
        .as_millis();

    u64::try_from(millis).map_err(fmt_err)
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

fn make_harness(prefix: &str, wallet: &str, founder: bool) -> TestResult<Harness> {
    let _setup_guard = setup_guard()?;

    let temp_root = unique_temp_root(prefix);
    fs::create_dir_all(&temp_root).map_err(fmt_err)?;

    let opts = make_test_node_opts(&temp_root, wallet, founder);
    let db_dir = temp_root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let db_dir_str = db_dir
        .to_str()
        .ok_or_else(|| "temporary blockchain path is not valid UTF-8".to_string())?;

    let db = Arc::new(RockDBManager::new_blockchain(&opts, db_dir_str).map_err(fmt_err)?);
    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let chain = AccountModelTree::with_manager((*db).clone());

    let peerlist_dir = temp_root.join(GlobalConfiguration::PEER_LIST_DIR);
    fs::create_dir_all(&peerlist_dir).map_err(fmt_err)?;
    PeerBook::configure_storage_dir(peerlist_dir.clone());
    let peerbook = Arc::new(StdMutex::new(PeerBook::load_or_init()));

    let sync_reorg = ReorgManager::mainnet_default(Arc::clone(&db));
    let sync_engine = Arc::new(TokioMutex::new(P2pSync::new(
        chain,
        Arc::clone(&db),
        Arc::clone(&mempool),
        peerbook,
        peerlist_dir,
        None,
        sync_reorg,
    )));

    let (_verifying_key, signing_key) = ml_dsa_65::try_keygen().map_err(fmt_err)?;
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1)));

    Ok(Harness {
        _temp_root: temp_root,
        opts,
        db,
        mempool,
        node: NodeEphemeral::new(),
        sync_engine,
        signing_key: Arc::new(signing_key),
        tm,
    })
}

fn make_loop(prefix: &str, wallet: &str) -> TestResult<(Harness, OrchestrationLoop)> {
    make_loop_with_founder(prefix, wallet, false)
}

fn make_loop_with_founder(
    prefix: &str,
    wallet: &str,
    founder: bool,
) -> TestResult<(Harness, OrchestrationLoop)> {
    let harness = make_harness(prefix, wallet, founder)?;
    let runner = OrchestrationLoop::new(OrchestrationLoopArgs {
        db: Arc::clone(&harness.db),
        node_ephemeral: harness.node.clone(),
        mempool: Arc::clone(&harness.mempool),
        sync_engine: Arc::clone(&harness.sync_engine),
        signing_key: Arc::clone(&harness.signing_key),
        tm: Arc::clone(&harness.tm),
        reorg_manager: ReorgManager::mainnet_default(Arc::clone(&harness.db)),
        local_wallet: wallet.to_string(),
        console_bus: ConsoleBus::new(),
    });

    Ok((harness, runner))
}

fn make_loop_no_mining(prefix: &str, wallet: &str) -> TestResult<(Harness, OrchestrationLoop)> {
    let (harness, mut runner) = make_loop(prefix, wallet)?;
    runner.engine.mining_intent = false;
    Ok((harness, runner))
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

fn run_loop_immediate_shutdown(
    harness: &Harness,
    runner: &OrchestrationLoop,
    net_rx: Option<mpsc::Receiver<NetCmd>>,
) -> TestResult {
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    shutdown_tx
        .send(())
        .map_err(|_| "failed to send shutdown signal".to_string())?;

    run_async(async {
        runner
            .run_loop(&mut chain, &mut swarm, shutdown_rx, net_rx, &harness.opts)
            .await
            .map_err(fmt_err)
    })
}

fn run_loop_delayed_shutdown(
    harness: &Harness,
    runner: &OrchestrationLoop,
    net_rx: Option<mpsc::Receiver<NetCmd>>,
) -> TestResult {
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    run_async(async {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let _send_result = shutdown_tx.send(());
        });

        let result = tokio::time::timeout(
            Duration::from_secs(3),
            runner.run_loop(&mut chain, &mut swarm, shutdown_rx, net_rx, &harness.opts),
        )
        .await
        .map_err(fmt_err)?;

        result.map_err(fmt_err)
    })
}

fn register_tx(wallet: &str) -> TestResult<RegisterNodeTx> {
    RegisterNodeTx::new(wallet.to_string()).map_err(fmt_err)
}

fn register_kind(wallet: &str) -> TestResult<TxKind> {
    Ok(TxKind::RegisterNode(register_tx(wallet)?))
}

fn transfer_tx() -> TestResult<Transaction> {
    Transaction::new(genesis_wallet(), peer_wallet(), 1).map_err(fmt_err)
}

fn transfer_kind() -> TestResult<TxKind> {
    Ok(TxKind::Transfer(transfer_tx()?))
}

fn make_block(index: u64) -> TestResult<Block> {
    let merkle_fill = u8::try_from(index % 251)
        .map_err(fmt_err)?
        .saturating_add(1);

    let previous_hash: Hash = if index == 0 {
        [0_u8; 64]
    } else {
        let prev_fill = u8::try_from(index.saturating_sub(1) % 251)
            .map_err(fmt_err)?
            .saturating_add(1);
        [prev_fill; 64]
    };

    let guardian_signature = [merkle_fill; ml_dsa_65::SIG_LEN];

    let metadata = BlockMetadata::new(
        index,
        now_secs(index),
        previous_hash,
        [merkle_fill; 64],
        guardian_signature,
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_{index:010}")),
        genesis_wallet(),
        0,
    )
    .map_err(fmt_err)
}

fn make_peer_mesh_announce(swarm: &libp2p::Swarm<RemzarBehaviour>) -> TestResult<PeerMeshAnnounce> {
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().map_err(fmt_err)?;
    PeerMeshAnnounce::from_local(*swarm.local_peer_id(), &[addr], Some(&genesis_wallet()), 1)
        .map_err(fmt_err)
}

fn make_puzzle_proof() -> PorPuzzleProof {
    PorPuzzleProof {
        height: 1,
        validator: genesis_wallet(),
        prev_block_hash: [7_u8; 64],
        output: 144,
    }
}

fn make_chat_message() -> TestResult<ChatMessage> {
    Ok(ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: br#"{"m":"hello"}"#.to_vec(),
        signature: vec![0_u8; ml_dsa_65::SIG_LEN],
    })
}

fn make_file_chunk() -> TestResult<FileChunkMessage> {
    let bytes = b"hello-remzar-file".to_vec();
    let digest = blake3::hash(&bytes);
    let file_id = *digest.as_bytes();

    Ok(FileChunkMessage {
        file_id,
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        chunk_index: 0,
        total_chunks: 1,
        filename: "hello.txt".to_string(),
        file_size_bytes: u64::try_from(bytes.len()).map_err(fmt_err)?,
        content_hash_hex: hex::encode(file_id),
        chunk_bytes: bytes,
        timestamp_ms: now_millis()?,
    })
}

fn wallet_count(node: &NodeEphemeral) -> TestResult<usize> {
    let registry = node.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| "ephemeral registry mutex poisoned".to_string())?;
    Ok(guard.sorted_wallets().len())
}

fn wallet_is_registered(node: &NodeEphemeral, wallet: &str) -> TestResult<bool> {
    let registry = node.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| "ephemeral registry mutex poisoned".to_string())?;
    Ok(guard.is_registered(wallet))
}

fn tip_snapshot(node: &NodeEphemeral, wallet: &str) -> TestResult<Option<u64>> {
    let registry = node.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| "ephemeral registry mutex poisoned".to_string())?;
    Ok(guard.tip_snapshot(wallet))
}

fn assert_mempool_size(mempool: &MemPool, expected: usize) -> TestResult {
    assert_eq!(mempool.mempool_size().map_err(fmt_err)?, expected);
    Ok(())
}

#[test]
fn blockchain_01_004_orchestration_run_new_wraps_engine_with_local_wallet() -> TestResult {
    let (_harness, runner) = make_loop("orchestration_run_01", &genesis_wallet())?;

    assert_eq!(runner.engine.local_wallet, genesis_wallet());
    Ok(())
}

#[test]
fn blockchain_02_004_orchestration_run_new_canonicalizes_uppercase_wallet() -> TestResult {
    let mixed = format!("r{}", "AA".repeat(64));
    let expected = wallet_with_hex_pair("aa");
    let (_harness, runner) = make_loop("orchestration_run_02", &mixed)?;

    assert_eq!(runner.engine.local_wallet, expected);
    Ok(())
}

#[test]
fn blockchain_03_004_orchestration_run_new_preserves_invalid_wallet() -> TestResult {
    let invalid = "not-a-wallet";
    let (_harness, runner) = make_loop("orchestration_run_03", invalid)?;

    assert_eq!(runner.engine.local_wallet, invalid);
    Ok(())
}

#[test]
fn blockchain_04_004_orchestration_run_new_sets_mining_intent_true() -> TestResult {
    let (_harness, runner) = make_loop("orchestration_run_04", &genesis_wallet())?;

    assert!(runner.engine.mining_intent);
    Ok(())
}

#[test]
fn blockchain_05_004_orchestration_run_new_sets_heartbeat_from_config() -> TestResult {
    let (_harness, runner) = make_loop("orchestration_run_05", &genesis_wallet())?;

    assert_eq!(
        runner.engine.registry_heartbeat_secs,
        Some(GlobalConfiguration::HEARTBEAT_TX_INTERVAL_SECS)
    );
    Ok(())
}

#[test]
fn blockchain_06_004_orchestration_run_new_sets_register_tip_sentinel() -> TestResult {
    let (_harness, runner) = make_loop("orchestration_run_06", &genesis_wallet())?;

    assert_eq!(
        runner
            .engine
            .last_canonical_register_tip
            .load(Ordering::SeqCst),
        u64::MAX
    );
    Ok(())
}

#[test]
fn blockchain_07_004_orchestration_run_new_starts_wallet_peer_latch_false() -> TestResult {
    let (_harness, runner) = make_loop("orchestration_run_07", &genesis_wallet())?;

    assert!(!runner.engine.ever_seen_wallet_peer.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn blockchain_08_004_orchestration_run_new_reuses_db_arc() -> TestResult {
    let (harness, runner) = make_loop("orchestration_run_08", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.db, &runner.engine.db));
    Ok(())
}

#[test]
fn blockchain_09_004_orchestration_run_new_reuses_mempool_arc() -> TestResult {
    let (harness, runner) = make_loop("orchestration_run_09", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.mempool, &runner.engine.mempool));
    Ok(())
}

#[test]
fn blockchain_10_004_orchestration_run_new_reuses_sync_engine_arc() -> TestResult {
    let (harness, runner) = make_loop("orchestration_run_10", &genesis_wallet())?;

    assert!(Arc::ptr_eq(
        &harness.sync_engine,
        &runner.engine.sync_engine
    ));
    Ok(())
}

#[test]
fn blockchain_11_004_orchestration_run_new_reuses_signing_key_arc() -> TestResult {
    let (harness, runner) = make_loop("orchestration_run_11", &genesis_wallet())?;

    assert!(Arc::ptr_eq(
        &harness.signing_key,
        &runner.engine.signing_key
    ));
    Ok(())
}

#[test]
fn blockchain_12_004_orchestration_run_new_reuses_time_manager_arc() -> TestResult {
    let (harness, runner) = make_loop("orchestration_run_12", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.tm, &runner.engine.tm));
    Ok(())
}

#[test]
fn blockchain_13_004_orchestration_run_no_mining_helper_disables_mining_intent() -> TestResult {
    let (_harness, runner) = make_loop_no_mining("orchestration_run_13", &genesis_wallet())?;

    assert!(!runner.engine.mining_intent);
    Ok(())
}

#[test]
fn blockchain_14_004_orchestration_run_node_clone_is_shared_with_engine() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_14", &genesis_wallet())?;

    harness
        .node
        .register_wallet_strict(&genesis_wallet(), 0)
        .map_err(fmt_err)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_15_004_orchestration_run_immediate_shutdown_returns_ok_empty_wallet() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_15", "")?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(wallet_count(&runner.engine.node)?, 0);
    Ok(())
}

#[test]
fn blockchain_16_004_orchestration_run_immediate_shutdown_registers_valid_wallet_boot_heartbeat()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_16", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert_eq!(
        tip_snapshot(&runner.engine.node, &genesis_wallet())?,
        Some(0)
    );
    Ok(())
}

#[test]
fn blockchain_17_004_orchestration_run_immediate_shutdown_rejects_invalid_wallet_boot_heartbeat()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_17", "bad-wallet")?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(wallet_count(&runner.engine.node)?, 0);
    Ok(())
}

#[test]
fn blockchain_18_004_orchestration_run_immediate_shutdown_uppercase_wallet_registers_canonical()
-> TestResult {
    let mixed = format!("r{}", "AA".repeat(64));
    let expected = wallet_with_hex_pair("aa");
    let (harness, runner) = make_loop_no_mining("orchestration_run_18", &mixed)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(runner.engine.local_wallet, expected);
    assert!(wallet_is_registered(&runner.engine.node, &expected)?);
    Ok(())
}

#[test]
fn blockchain_19_004_orchestration_run_immediate_shutdown_keeps_mempool_empty() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_19", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_20_004_orchestration_run_founder_true_immediate_shutdown_returns_ok() -> TestResult {
    let (harness, mut runner) =
        make_loop_with_founder("orchestration_run_20", &genesis_wallet(), true)?;
    runner.engine.mining_intent = false;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(harness.opts.founder);
    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_21_004_orchestration_run_registry_heartbeat_none_still_boots_and_shutdowns()
-> TestResult {
    let (harness, mut runner) = make_loop_no_mining("orchestration_run_21", &genesis_wallet())?;
    runner.engine.registry_heartbeat_secs = None;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_22_004_orchestration_run_registry_heartbeat_zero_is_bounded_by_loop() -> TestResult {
    let (harness, mut runner) = make_loop_no_mining("orchestration_run_22", &genesis_wallet())?;
    runner.engine.registry_heartbeat_secs = Some(0);

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_23_004_orchestration_run_closed_net_rx_then_shutdown_returns_ok() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_23", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_24_004_orchestration_run_net_rx_register_stages_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_24", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_25_004_orchestration_run_net_rx_txkind_transfer_stages_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_25", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendTxKind(transfer_kind()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_26_004_orchestration_run_net_rx_send_tx_does_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_26", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_27_004_orchestration_run_net_rx_send_block_does_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_27", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(1)?)))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_28_004_orchestration_run_net_rx_peer_mesh_does_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_28", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    let swarm = make_swarm()?;
    let announce = make_peer_mesh_announce(&swarm)?;

    tx.blocking_send(NetCmd::SendPeerMeshAnnounce(announce))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_29_004_orchestration_run_net_rx_puzzle_proof_does_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_29", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_30_004_orchestration_run_net_rx_chat_does_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_30", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendChat(make_chat_message()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_31_004_orchestration_run_net_rx_file_chunk_does_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_31", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendFileChunk(make_file_chunk()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_32_004_orchestration_run_net_rx_none_then_shutdown_has_no_mempool_side_effect()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_32", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_33_004_orchestration_run_shutdown_after_duplicate_registers_deduplicates_mempool()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_33", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_34_004_orchestration_run_shutdown_after_two_distinct_registers_stages_two()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_34", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&peer_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 2)
}

#[test]
fn blockchain_35_004_orchestration_run_shutdown_after_register_and_transfer_stages_two()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_35", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendTxKind(register_kind(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(transfer_kind()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 2)
}

#[test]
fn blockchain_36_004_orchestration_run_boot_snapshot_keeps_latch_false_without_wallet_peer()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_36", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(!runner.engine.ever_seen_wallet_peer.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn blockchain_37_004_orchestration_run_sync_seed_leaves_percent_bounded() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_37", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    run_async(async {
        let sync = harness.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_38_004_orchestration_run_immediate_shutdown_with_all_zero_wallet_registers()
-> TestResult {
    let wallet = wallet_with_hex_pair("00");
    let (harness, runner) = make_loop_no_mining("orchestration_run_38", &wallet)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(&runner.engine.node, &wallet)?);
    Ok(())
}

#[test]
fn blockchain_39_004_orchestration_run_immediate_shutdown_with_all_ff_wallet_registers()
-> TestResult {
    let wallet = wallet_with_hex_pair("ff");
    let (harness, runner) = make_loop_no_mining("orchestration_run_39", &wallet)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(&runner.engine.node, &wallet)?);
    Ok(())
}

#[test]
fn blockchain_40_004_orchestration_run_immediate_shutdown_short_wallet_registers_none() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_40", "rabc")?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(wallet_count(&runner.engine.node)?, 0);
    Ok(())
}

#[test]
fn blockchain_41_004_orchestration_run_immediate_shutdown_non_hex_wallet_registers_none()
-> TestResult {
    let wallet = format!("r{}", "zz".repeat(64));
    let (harness, runner) = make_loop_no_mining("orchestration_run_41", &wallet)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(wallet_count(&runner.engine.node)?, 0);
    Ok(())
}

#[test]
fn blockchain_42_004_orchestration_run_repeated_immediate_shutdown_is_idempotent_for_wallet_registry()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_42", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;
    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert_eq!(wallet_count(&runner.engine.node)?, 1);
    Ok(())
}

#[test]
fn blockchain_43_004_orchestration_run_existing_remote_wallet_survives_boot_shutdown() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_43", &genesis_wallet())?;

    runner
        .engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert!(wallet_is_registered(&runner.engine.node, &peer_wallet())?);
    Ok(())
}

#[test]
fn blockchain_44_004_orchestration_run_delayed_shutdown_remote_wallet_without_heartbeat_can_be_evicted()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_44", &genesis_wallet())?;

    runner
        .engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    run_loop_delayed_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_45_004_orchestration_run_net_rx_transfer_tag_stages_transfer() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_45", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    let kind = transfer_kind()?;

    assert_eq!(kind.tag(), "transfer");

    tx.blocking_send(NetCmd::SendTxKind(kind))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_46_004_orchestration_run_net_rx_register_tag_stages_register() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_46", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    let kind = register_kind(&genesis_wallet())?;

    assert_eq!(kind.tag(), "register_node");

    tx.blocking_send(NetCmd::SendTxKind(kind))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_47_004_orchestration_run_net_rx_register_kind_validate_before_run() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_47", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    let kind = register_kind(&genesis_wallet())?;

    kind.validate().map_err(fmt_err)?;

    tx.blocking_send(NetCmd::SendTxKind(kind))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_48_004_orchestration_run_net_rx_send_tx_then_txkind_transfer_only_txkind_stages()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_48", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let raw_tx = transfer_tx()?;
    let kind = TxKind::Transfer(raw_tx.clone());

    tx.blocking_send(NetCmd::SendTx(raw_tx)).map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(kind))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_49_004_orchestration_run_net_rx_many_none_shutdown_keeps_mempool_empty() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_49", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_50_004_orchestration_run_full_lightweight_smoke_sequence_exits_cleanly() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_50", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(transfer_kind()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown(&harness, &runner, Some(rx))?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert_mempool_size(&harness.mempool, 2)
}

#[test]
fn blockchain_51_004_orchestration_run_constructor_vector_empty_wallet() -> TestResult {
    let (_harness, runner) = make_loop_no_mining("orchestration_run_51", "")?;

    assert!(runner.engine.local_wallet.is_empty());
    assert!(!runner.engine.mining_intent);
    Ok(())
}

#[test]
fn blockchain_52_004_orchestration_run_constructor_vector_all_zero_wallet() -> TestResult {
    let wallet = wallet_with_hex_pair("00");
    let (_harness, runner) = make_loop_no_mining("orchestration_run_52", &wallet)?;

    assert_eq!(runner.engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_53_004_orchestration_run_constructor_vector_all_ff_wallet() -> TestResult {
    let wallet = wallet_with_hex_pair("ff");
    let (_harness, runner) = make_loop_no_mining("orchestration_run_53", &wallet)?;

    assert_eq!(runner.engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_54_004_orchestration_run_constructor_vector_short_wallet_preserved() -> TestResult {
    let wallet = "r123";
    let (_harness, runner) = make_loop_no_mining("orchestration_run_54", wallet)?;

    assert_eq!(runner.engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_55_004_orchestration_run_constructor_vector_bad_prefix_preserved() -> TestResult {
    let wallet = format!("x{}", "11".repeat(64));
    let (_harness, runner) = make_loop_no_mining("orchestration_run_55", &wallet)?;

    assert_eq!(runner.engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_56_004_orchestration_run_constructor_vector_non_hex_preserved() -> TestResult {
    let wallet = format!("r{}", "gg".repeat(64));
    let (_harness, runner) = make_loop_no_mining("orchestration_run_56", &wallet)?;

    assert_eq!(runner.engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_57_004_orchestration_run_immediate_shutdown_vector_01_wallet_registers() -> TestResult
{
    let wallet = wallet_with_hex_pair("01");
    let (harness, runner) = make_loop_no_mining("orchestration_run_57", &wallet)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(&runner.engine.node, &wallet)?);
    Ok(())
}

#[test]
fn blockchain_58_004_orchestration_run_immediate_shutdown_vector_7f_wallet_registers() -> TestResult
{
    let wallet = wallet_with_hex_pair("7f");
    let (harness, runner) = make_loop_no_mining("orchestration_run_58", &wallet)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(&runner.engine.node, &wallet)?);
    Ok(())
}

#[test]
fn blockchain_59_004_orchestration_run_immediate_shutdown_vector_fe_wallet_registers() -> TestResult
{
    let wallet = wallet_with_hex_pair("fe");
    let (harness, runner) = make_loop_no_mining("orchestration_run_59", &wallet)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(&runner.engine.node, &wallet)?);
    Ok(())
}

#[test]
fn blockchain_60_004_orchestration_run_immediate_shutdown_vector_space_wallet_registers_none()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_60", " ")?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(wallet_count(&runner.engine.node)?, 0);
    Ok(())
}

#[test]
fn blockchain_61_004_orchestration_run_registry_heartbeat_one_second_boots_cleanly() -> TestResult {
    let (harness, mut runner) = make_loop_no_mining("orchestration_run_61", &genesis_wallet())?;
    runner.engine.registry_heartbeat_secs = Some(1);

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_62_004_orchestration_run_registry_heartbeat_large_value_boots_cleanly() -> TestResult
{
    let (harness, mut runner) = make_loop_no_mining("orchestration_run_62", &genesis_wallet())?;
    runner.engine.registry_heartbeat_secs = Some(u64::MAX);

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_63_004_orchestration_run_immediate_shutdown_does_not_mark_wallet_peer_seen()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_63", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(!runner.engine.ever_seen_wallet_peer.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn blockchain_64_004_orchestration_run_immediate_shutdown_does_not_move_register_tip_gate()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_64", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(
        runner
            .engine
            .last_canonical_register_tip
            .load(Ordering::SeqCst),
        u64::MAX
    );
    Ok(())
}

#[test]
fn blockchain_65_004_orchestration_run_immediate_shutdown_keeps_sync_percent_bounded_for_empty_wallet()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_65", "")?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    run_async(async {
        let sync = harness.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_66_004_orchestration_run_delayed_shutdown_without_net_rx_returns_ok() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_66", &genesis_wallet())?;

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 50)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_67_004_orchestration_run_delayed_shutdown_with_registry_disabled_returns_ok()
-> TestResult {
    let (harness, mut runner) = make_loop_no_mining("orchestration_run_67", &genesis_wallet())?;
    runner.engine.registry_heartbeat_secs = None;

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 50)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_68_004_orchestration_run_net_rx_three_duplicate_registers_stage_one() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_68", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(3);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_69_004_orchestration_run_net_rx_three_distinct_registers_stage_three() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_69", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(3);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&peer_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&third_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 3)
}

#[test]
fn blockchain_70_004_orchestration_run_net_rx_txkind_register_duplicate_stage_one() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_70", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let kind = register_kind(&genesis_wallet())?;

    tx.blocking_send(NetCmd::SendTxKind(kind.clone()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(kind))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_71_004_orchestration_run_net_rx_txkind_transfer_duplicate_stage_one() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_71", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let kind = transfer_kind()?;

    tx.blocking_send(NetCmd::SendTxKind(kind.clone()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(kind))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_72_004_orchestration_run_net_rx_send_tx_duplicate_never_stages() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_72", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let raw = transfer_tx()?;

    tx.blocking_send(NetCmd::SendTx(raw.clone()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTx(raw)).map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_73_004_orchestration_run_net_rx_blocks_do_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_73", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(3);

    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(0)?)))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(1)?)))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(10_000)?)))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_74_004_orchestration_run_net_rx_peer_mesh_vectors_do_not_stage_mempool() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_74", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let swarm = make_swarm()?;
    let announce_one = make_peer_mesh_announce(&swarm)?;
    let announce_two = PeerMeshAnnounce {
        peer_id: swarm.local_peer_id().to_base58(),
        listen_addrs: Vec::new(),
        wallet: Some(genesis_wallet()),
        timestamp_unix: 1,
    };

    tx.blocking_send(NetCmd::SendPeerMeshAnnounce(announce_one))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendPeerMeshAnnounce(announce_two))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_75_004_orchestration_run_net_rx_puzzle_proof_vectors_do_not_stage_mempool()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_75", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(3);
    let mut zero_height = make_puzzle_proof();
    zero_height.height = 0;
    let mut max_height = make_puzzle_proof();
    max_height.height = u64::MAX;

    tx.blocking_send(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendAosPuzzleProof(zero_height))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendAosPuzzleProof(max_height))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_76_004_orchestration_run_net_rx_chat_vectors_do_not_stage_mempool() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_76", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let empty_chat = ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: Vec::new(),
        signature: vec![0_u8; ml_dsa_65::SIG_LEN],
    };

    tx.blocking_send(NetCmd::SendChat(make_chat_message()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendChat(empty_chat))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_77_004_orchestration_run_net_rx_file_chunk_vectors_do_not_stage_mempool() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_77", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let mut indexed_chunk = make_file_chunk()?;
    indexed_chunk.chunk_index = 2;
    indexed_chunk.total_chunks = 3;

    tx.blocking_send(NetCmd::SendFileChunk(make_file_chunk()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendFileChunk(indexed_chunk))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_78_004_orchestration_run_adversarial_non_mempool_commands_keep_mempool_empty()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_78", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(5);
    let swarm = make_swarm()?;

    tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(2)?)))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendPeerMeshAnnounce(make_peer_mesh_announce(
        &swarm,
    )?))
    .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendFileChunk(make_file_chunk()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 200)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_79_004_orchestration_run_adversarial_mixed_commands_stage_only_txkind_and_register()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_79", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(5);
    let swarm = make_swarm()?;

    tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(transfer_kind()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendPeerMeshAnnounce(make_peer_mesh_announce(
        &swarm,
    )?))
    .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 200)?;

    assert_mempool_size(&harness.mempool, 2)
}

#[test]
fn blockchain_80_004_orchestration_run_adversarial_command_channel_closed_after_commands_exits_on_shutdown()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_80", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(transfer_kind()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 200)?;

    assert_mempool_size(&harness.mempool, 2)
}

#[test]
fn blockchain_81_004_orchestration_run_load_five_duplicate_registers_stage_one() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_81", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(5);

    for _ in 0..5 {
        tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
            .map_err(fmt_err)?;
    }
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 250)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_82_004_orchestration_run_load_five_send_tx_commands_stage_none() -> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_82", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(5);

    for _ in 0..5 {
        tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
            .map_err(fmt_err)?;
    }
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 250)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_83_004_orchestration_run_load_registers_for_three_wallets_stage_three() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_83", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(6);
    let wallets = [genesis_wallet(), peer_wallet(), third_wallet()];

    for wallet in wallets {
        tx.blocking_send(NetCmd::SendRegister(register_tx(&wallet)?))
            .map_err(fmt_err)?;
        tx.blocking_send(NetCmd::SendRegister(register_tx(&wallet)?))
            .map_err(fmt_err)?;
    }
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 250)?;

    assert_mempool_size(&harness.mempool, 3)
}

#[test]
fn blockchain_84_004_orchestration_run_net_rx_raw_tx_then_register_stages_only_register()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_84", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_85_004_orchestration_run_net_rx_register_then_raw_tx_stages_only_register()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_85", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_86_004_orchestration_run_net_rx_register_then_same_register_txkind_deduplicates()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_86", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let reg = register_tx(&genesis_wallet())?;

    tx.blocking_send(NetCmd::SendRegister(reg.clone()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(TxKind::RegisterNode(reg)))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_87_004_orchestration_run_net_rx_txkind_transfer_then_raw_tx_stages_only_txkind()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_87", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let raw = transfer_tx()?;

    tx.blocking_send(NetCmd::SendTxKind(TxKind::Transfer(raw.clone())))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTx(raw)).map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_88_004_orchestration_run_net_rx_raw_tx_then_same_txkind_transfer_stages_only_txkind()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_88", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);
    let raw = transfer_tx()?;

    tx.blocking_send(NetCmd::SendTx(raw.clone()))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(TxKind::Transfer(raw)))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_89_004_orchestration_run_no_mining_shutdown_does_not_initialize_miner_state()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_89", &genesis_wallet())?;

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 50)?;

    assert!(!runner.engine.mining_intent);
    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_90_004_orchestration_run_founder_mode_no_mining_shutdown_keeps_wallet_registered()
-> TestResult {
    let (harness, mut runner) =
        make_loop_with_founder("orchestration_run_90", &genesis_wallet(), true)?;
    runner.engine.mining_intent = false;

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 50)?;

    assert!(harness.opts.founder);
    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_91_004_orchestration_run_non_founder_mode_no_mining_shutdown_keeps_wallet_registered()
-> TestResult {
    let (harness, runner) =
        make_loop_with_founder("orchestration_run_91", &genesis_wallet(), false)?;

    assert!(!harness.opts.founder);

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 50)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    Ok(())
}

#[test]
fn blockchain_92_004_orchestration_run_existing_remote_wallet_and_local_wallet_survive_immediate_shutdown()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_92", &genesis_wallet())?;

    runner
        .engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert!(wallet_is_registered(&runner.engine.node, &peer_wallet())?);
    Ok(())
}

#[test]
fn blockchain_93_004_orchestration_run_existing_two_remote_wallets_and_local_survive_immediate_shutdown()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_93", &genesis_wallet())?;

    runner
        .engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;
    runner
        .engine
        .node
        .note_heartbeat_round(&third_wallet(), 0)
        .map_err(fmt_err)?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert!(wallet_is_registered(&runner.engine.node, &peer_wallet())?);
    assert!(wallet_is_registered(&runner.engine.node, &third_wallet())?);
    Ok(())
}

#[test]
fn blockchain_94_004_orchestration_run_local_wallet_tip_snapshot_is_zero_after_boot() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_94", &genesis_wallet())?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(
        tip_snapshot(&runner.engine.node, &genesis_wallet())?,
        Some(0)
    );
    Ok(())
}

#[test]
fn blockchain_95_004_orchestration_run_empty_wallet_tip_snapshot_is_none_after_boot() -> TestResult
{
    let (harness, runner) = make_loop_no_mining("orchestration_run_95", "")?;

    run_loop_immediate_shutdown(&harness, &runner, None)?;

    assert_eq!(tip_snapshot(&runner.engine.node, "")?, None);
    Ok(())
}

#[test]
fn blockchain_96_004_orchestration_run_shutdown_after_txkind_register_preserves_wallet_boot_registration()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_96", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    tx.blocking_send(NetCmd::SendTxKind(register_kind(&genesis_wallet())?))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert_mempool_size(&harness.mempool, 1)
}

#[test]
fn blockchain_97_004_orchestration_run_shutdown_after_non_mempool_commands_preserves_wallet_boot_registration()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_97", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(2);

    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(5)?)))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 150)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_98_004_orchestration_run_load_delayed_shutdown_multiple_sync_windows_stays_bounded()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_98", &genesis_wallet())?;

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 250)?;

    run_async(async {
        let sync = harness.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_99_004_orchestration_run_load_delayed_shutdown_keeps_mempool_empty_without_net_rx()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_99", &genesis_wallet())?;

    run_loop_delayed_shutdown_ms(&harness, &runner, None, 250)?;

    assert_mempool_size(&harness.mempool, 0)
}

#[test]
fn blockchain_100_004_orchestration_run_full_vector_sequence_register_transfer_non_mempool_commands()
-> TestResult {
    let (harness, runner) = make_loop_no_mining("orchestration_run_100", &genesis_wallet())?;
    let (tx, rx) = mpsc::channel::<NetCmd>(6);
    let swarm = make_swarm()?;

    tx.blocking_send(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTxKind(transfer_kind()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendTx(transfer_tx()?))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendBlock(Box::new(make_block(7)?)))
        .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendPeerMeshAnnounce(make_peer_mesh_announce(
        &swarm,
    )?))
    .map_err(fmt_err)?;
    tx.blocking_send(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
        .map_err(fmt_err)?;
    drop(tx);

    run_loop_delayed_shutdown_ms(&harness, &runner, Some(rx), 250)?;

    assert!(wallet_is_registered(
        &runner.engine.node,
        &genesis_wallet()
    )?);
    assert_mempool_size(&harness.mempool, 2)
}
