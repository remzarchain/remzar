#![cfg(test)]

use fips204::ml_dsa_65;
use libp2p::gossipsub::IdentTopic;
use libp2p::{Multiaddr, identity};
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::blockchain_001_builder::BlockchainBuilder;
use remzar::blockchain::blockchain_003_orchestration_engine::{
    OrchestrationEngine, OrchestrationEngineArgs,
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
use tokio::sync::Mutex as TokioMutex;

type TestResult<T = ()> = Result<T, String>;
type SetupGuard = MutexGuard<'static, ()>;

static SETUP_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

struct Harness {
    _temp_root: PathBuf,
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

fn invalid_long_wallet() -> String {
    format!("x{}", "11".repeat(64))
}

fn make_test_node_opts(temp_root: &Path, wallet: &str) -> NodeOpts {
    NodeOpts {
        identity_file: temp_root.join("identity.key").to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: temp_root.to_string_lossy().to_string(),
        wallet_address: wallet.to_string(),
        founder: false,
    }
}

fn make_harness(prefix: &str, wallet: &str) -> TestResult<Harness> {
    let _setup_guard = setup_guard()?;

    let temp_root = unique_temp_root(prefix);
    fs::create_dir_all(&temp_root).map_err(fmt_err)?;

    let opts = make_test_node_opts(&temp_root, wallet);
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
        db,
        mempool,
        node: NodeEphemeral::new(),
        sync_engine,
        signing_key: Arc::new(signing_key),
        tm,
    })
}

fn make_engine(prefix: &str, wallet: &str) -> TestResult<(Harness, OrchestrationEngine)> {
    let harness = make_harness(prefix, wallet)?;
    let engine = OrchestrationEngine::new(OrchestrationEngineArgs {
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

    Ok((harness, engine))
}

fn make_engine_no_mining(prefix: &str, wallet: &str) -> TestResult<(Harness, OrchestrationEngine)> {
    let (harness, mut engine) = make_engine(prefix, wallet)?;
    engine.mining_intent = false;
    Ok((harness, engine))
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
fn blockchain_01_003_orchestration_engine_new_canonicalizes_mixed_case_wallet() -> TestResult {
    let mixed_wallet = format!("r{}", "AB".repeat(64));
    let expected_wallet = wallet_with_hex_pair("ab");
    let (_harness, engine) = make_engine("orchestration_01", &mixed_wallet)?;

    assert_eq!(engine.local_wallet, expected_wallet);
    Ok(())
}

#[test]
fn blockchain_02_003_orchestration_engine_new_preserves_invalid_wallet_without_panic() -> TestResult
{
    let invalid_wallet = "not-a-remzar-wallet";
    let (_harness, engine) = make_engine("orchestration_02", invalid_wallet)?;

    assert_eq!(engine.local_wallet, invalid_wallet);
    Ok(())
}

#[test]
fn blockchain_03_003_orchestration_engine_new_sets_mining_intent_true() -> TestResult {
    let (_harness, engine) = make_engine("orchestration_03", &genesis_wallet())?;

    assert!(engine.mining_intent);
    Ok(())
}

#[test]
fn blockchain_04_003_orchestration_engine_new_sets_registry_heartbeat_from_config() -> TestResult {
    let (_harness, engine) = make_engine("orchestration_04", &genesis_wallet())?;

    assert_eq!(
        engine.registry_heartbeat_secs,
        Some(GlobalConfiguration::HEARTBEAT_TX_INTERVAL_SECS)
    );
    Ok(())
}

#[test]
fn blockchain_05_003_orchestration_engine_new_sets_register_tip_sentinel_to_u64_max() -> TestResult
{
    let (_harness, engine) = make_engine("orchestration_05", &genesis_wallet())?;

    assert_eq!(
        engine.last_canonical_register_tip.load(Ordering::SeqCst),
        u64::MAX
    );
    Ok(())
}

#[test]
fn blockchain_06_003_orchestration_engine_new_starts_wallet_peer_latch_false() -> TestResult {
    let (_harness, engine) = make_engine("orchestration_06", &genesis_wallet())?;

    assert!(!engine.ever_seen_wallet_peer.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn blockchain_07_003_orchestration_engine_new_reuses_db_arc() -> TestResult {
    let (harness, engine) = make_engine("orchestration_07", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.db, &engine.db));
    Ok(())
}

#[test]
fn blockchain_08_003_orchestration_engine_new_reuses_mempool_arc() -> TestResult {
    let (harness, engine) = make_engine("orchestration_08", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.mempool, &engine.mempool));
    Ok(())
}

#[test]
fn blockchain_09_003_orchestration_engine_new_reuses_sync_engine_arc() -> TestResult {
    let (harness, engine) = make_engine("orchestration_09", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.sync_engine, &engine.sync_engine));
    Ok(())
}

#[test]
fn blockchain_10_003_orchestration_engine_new_reuses_signing_key_arc() -> TestResult {
    let (harness, engine) = make_engine("orchestration_10", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.signing_key, &engine.signing_key));
    Ok(())
}

#[test]
fn blockchain_11_003_orchestration_engine_new_reuses_time_manager_arc() -> TestResult {
    let (harness, engine) = make_engine("orchestration_11", &genesis_wallet())?;

    assert!(Arc::ptr_eq(&harness.tm, &engine.tm));
    Ok(())
}

#[test]
fn blockchain_12_003_orchestration_engine_new_cloned_node_shares_ephemeral_registry() -> TestResult
{
    let (harness, engine) = make_engine("orchestration_12", &genesis_wallet())?;
    harness
        .node
        .register_wallet_strict(&genesis_wallet(), 0)
        .map_err(fmt_err)?;

    assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
    Ok(())
}

#[test]
fn blockchain_13_003_orchestration_engine_new_no_mining_helper_disables_mining_intent() -> TestResult
{
    let (_harness, engine) = make_engine_no_mining("orchestration_13", &genesis_wallet())?;

    assert!(!engine.mining_intent);
    Ok(())
}

#[test]
fn blockchain_14_003_orchestration_engine_empty_wallet_constructor_keeps_empty_wallet() -> TestResult
{
    let (_harness, engine) = make_engine("orchestration_14", "")?;

    assert!(engine.local_wallet.is_empty());
    Ok(())
}

#[test]
fn blockchain_15_003_orchestration_engine_bad_prefix_wallet_is_preserved() -> TestResult {
    let wallet = invalid_long_wallet();
    let (_harness, engine) = make_engine("orchestration_15", &wallet)?;

    assert_eq!(engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_16_003_orchestration_engine_non_hex_wallet_is_preserved() -> TestResult {
    let wallet = format!("r{}", "zz".repeat(64));
    let (_harness, engine) = make_engine("orchestration_16", &wallet)?;

    assert_eq!(engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_17_003_orchestration_engine_all_zero_wallet_is_preserved_when_canonical() -> TestResult
{
    let wallet = wallet_with_hex_pair("00");
    let (_harness, engine) = make_engine("orchestration_17", &wallet)?;

    assert_eq!(engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_18_003_orchestration_engine_all_ff_wallet_is_preserved_when_canonical() -> TestResult
{
    let wallet = wallet_with_hex_pair("ff");
    let (_harness, engine) = make_engine("orchestration_18", &wallet)?;

    assert_eq!(engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_19_003_orchestration_engine_initialize_miner_returns_none_for_empty_wallet()
-> TestResult {
    let (_harness, engine) = make_engine("orchestration_19", "")?;

    assert!(engine.initialize_miner().is_none());
    Ok(())
}

#[test]
fn blockchain_20_003_orchestration_engine_initialize_miner_returns_none_when_wallet_not_ephemeral()
-> TestResult {
    let (_harness, engine) = make_engine("orchestration_20", &genesis_wallet())?;

    assert!(engine.initialize_miner().is_none());
    Ok(())
}

#[test]
fn blockchain_21_003_orchestration_engine_init_boot_heartbeat_round_registers_local_wallet()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_21", &genesis_wallet())?;

    engine.init_boot_heartbeat_round();

    assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
    assert_eq!(wallet_count(&engine.node)?, 1);
    Ok(())
}

#[test]
fn blockchain_22_003_orchestration_engine_init_boot_heartbeat_round_ignores_empty_wallet()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_22", "")?;

    engine.init_boot_heartbeat_round();

    assert_eq!(wallet_count(&engine.node)?, 0);
    Ok(())
}

#[test]
fn blockchain_23_003_orchestration_engine_init_boot_repeated_keeps_single_wallet() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_23", &genesis_wallet())?;

    for _ in 0..5 {
        engine.init_boot_heartbeat_round();
    }

    assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
    assert_eq!(wallet_count(&engine.node)?, 1);
    Ok(())
}

#[test]
fn blockchain_24_003_orchestration_engine_refresh_wallet_peer_latch_stays_false_without_wallet_peer()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_24", &genesis_wallet())?;
    let swarm = make_swarm()?;

    engine.refresh_wallet_peer_latch(&swarm);

    assert!(!engine.ever_seen_wallet_peer.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn blockchain_25_003_orchestration_engine_refresh_wallet_peer_latch_is_idempotent_once_true()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_25", &genesis_wallet())?;
    let swarm = make_swarm()?;
    engine.ever_seen_wallet_peer.store(true, Ordering::SeqCst);

    engine.refresh_wallet_peer_latch(&swarm);

    assert!(engine.ever_seen_wallet_peer.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn blockchain_26_003_orchestration_engine_handle_net_cmd_none_returns_true() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_26", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        assert!(engine.handle_net_cmd(&mut swarm, None).await);
        Ok(())
    })
}

#[test]
fn blockchain_27_003_orchestration_engine_send_tx_returns_false_and_does_not_stage_mempool()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_27", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let tx = transfer_tx()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTx(tx)))
                .await
        );
        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_28_003_orchestration_engine_send_tx_repeated_does_not_stage_mempool() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_28", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..3 {
            assert!(
                !engine
                    .handle_net_cmd(&mut swarm, Some(NetCmd::SendTx(transfer_tx()?)))
                    .await
            );
        }

        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_29_003_orchestration_engine_send_txkind_register_stages_one() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_29", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = register_kind(&genesis_wallet())?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_30_003_orchestration_engine_send_txkind_transfer_stages_one() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_30", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = transfer_kind()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_31_003_orchestration_engine_duplicate_txkind_register_deduplicates() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_31", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = register_kind(&genesis_wallet())?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind.clone())))
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_32_003_orchestration_engine_duplicate_txkind_transfer_deduplicates() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_32", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = transfer_kind()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind.clone())))
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_33_003_orchestration_engine_register_and_transfer_txkind_stage_two() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_33", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendTxKind(register_kind(&genesis_wallet())?))
                )
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(transfer_kind()?)))
                .await
        );
        assert_mempool_size(&harness.mempool, 2)
    })
}

#[test]
fn blockchain_34_003_orchestration_engine_send_register_stages_as_txkind() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_34", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let reg = register_tx(&genesis_wallet())?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendRegister(reg)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_35_003_orchestration_engine_send_register_duplicate_stages_one() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_35", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let reg = register_tx(&genesis_wallet())?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendRegister(reg.clone())))
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendRegister(reg)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_36_003_orchestration_engine_two_distinct_registers_stage_two() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_36", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
                )
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendRegister(register_tx(&peer_wallet())?))
                )
                .await
        );
        assert_mempool_size(&harness.mempool, 2)
    })
}

#[test]
fn blockchain_37_003_orchestration_engine_send_register_then_same_txkind_deduplicates() -> TestResult
{
    let (harness, engine) = make_engine_no_mining("orchestration_37", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let reg = register_tx(&genesis_wallet())?;
    let kind = TxKind::RegisterNode(reg.clone());

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendRegister(reg)))
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_38_003_orchestration_engine_send_tx_then_txkind_transfer_only_txkind_stages()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_38", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let tx = transfer_tx()?;
    let kind = TxKind::Transfer(tx.clone());

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTx(tx)))
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_39_003_orchestration_engine_send_block_returns_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_39", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let block = make_block(1)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendBlock(Box::new(block))))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_40_003_orchestration_engine_send_block_zero_height_returns_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_40", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let block = make_block(0)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendBlock(Box::new(block))))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_41_003_orchestration_engine_send_peer_mesh_returns_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_41", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let announce = make_peer_mesh_announce(&swarm)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(announce)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_42_003_orchestration_engine_peer_mesh_roundtrip_then_route_returns_false()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_42", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let announce = make_peer_mesh_announce(&swarm)?;
    let encoded = announce.encode_to_wire().map_err(fmt_err)?;
    let decoded = PeerMeshAnnounce::decode_from_wire(&encoded).map_err(fmt_err)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(decoded)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_43_003_orchestration_engine_send_aos_puzzle_proof_returns_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_43", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let proof = make_puzzle_proof();

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendAosPuzzleProof(proof)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_44_003_orchestration_engine_send_aos_puzzle_proof_zero_height_returns_false()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_44", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut proof = make_puzzle_proof();
    proof.height = 0;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendAosPuzzleProof(proof)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_45_003_orchestration_engine_send_chat_returns_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_45", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let chat = make_chat_message()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendChat(chat)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_46_003_orchestration_engine_send_file_chunk_returns_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_46", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let chunk = make_file_chunk()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendFileChunk(chunk)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_47_003_orchestration_engine_none_after_command_returns_true() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_47", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let reg = register_tx(&genesis_wallet())?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendRegister(reg)))
                .await
        );
        assert!(engine.handle_net_cmd(&mut swarm, None).await);
        Ok(())
    })
}

#[test]
fn blockchain_48_003_orchestration_engine_command_after_none_is_stateless() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_48", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let reg = register_tx(&genesis_wallet())?;

    run_async(async {
        assert!(engine.handle_net_cmd(&mut swarm, None).await);
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendRegister(reg)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_49_003_orchestration_engine_handle_sync_tick_increments_counter_once() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_49", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut sync_ticks = 0_u64;

    run_async(async {
        engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;

        assert_eq!(sync_ticks, 1);
        Ok(())
    })
}

#[test]
fn blockchain_50_003_orchestration_engine_handle_sync_tick_from_nonzero_counter_increments()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_50", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut sync_ticks = 7_u64;

    run_async(async {
        engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;

        assert_eq!(sync_ticks, 8);
        Ok(())
    })
}

#[test]
fn blockchain_51_003_orchestration_engine_handle_sync_tick_saturates_at_u64_max() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_51", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut sync_ticks = u64::MAX;

    run_async(async {
        engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;

        assert_eq!(sync_ticks, u64::MAX);
        Ok(())
    })
}

#[test]
fn blockchain_52_003_orchestration_engine_seed_sync_keeps_percent_bounded() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_52", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        engine.seed_sync(&mut swarm).await;

        let sync = harness.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_53_003_orchestration_engine_seed_sync_twice_keeps_percent_bounded() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_53", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        engine.seed_sync(&mut swarm).await;
        engine.seed_sync(&mut swarm).await;

        let sync = harness.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_54_003_orchestration_engine_registry_tick_increments_counter_once() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_54", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, 1);
        Ok(())
    })
}

#[test]
fn blockchain_55_003_orchestration_engine_registry_tick_from_nonzero_counter_increments()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_55", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 7_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, 8);
        Ok(())
    })
}

#[test]
fn blockchain_56_003_orchestration_engine_registry_tick_saturates_at_u64_max() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_56", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = u64::MAX;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, u64::MAX);
        Ok(())
    })
}

#[test]
fn blockchain_57_003_orchestration_engine_registry_tick_empty_wallet_does_not_register()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_57", "")?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, 1);
        assert_eq!(wallet_count(&engine.node)?, 0);
        Ok(())
    })
}

#[test]
fn blockchain_58_003_orchestration_engine_registry_tick_valid_wallet_registers_heartbeat()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_58", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, 1);
        assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
        assert_eq!(tip_snapshot(&engine.node, &genesis_wallet())?, Some(0));
        Ok(())
    })
}

#[test]
fn blockchain_59_003_orchestration_engine_registry_tick_invalid_wallet_does_not_register()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_59", "bad-wallet")?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, 1);
        assert_eq!(wallet_count(&engine.node)?, 0);
        Ok(())
    })
}

#[test]
fn blockchain_60_003_orchestration_engine_registry_tick_uppercase_wallet_registers_canonical()
-> TestResult {
    let mixed_wallet = format!("r{}", "AA".repeat(64));
    let expected_wallet = wallet_with_hex_pair("aa");
    let (_harness, engine) = make_engine_no_mining("orchestration_60", &mixed_wallet)?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(engine.local_wallet, expected_wallet);
        assert!(wallet_is_registered(&engine.node, &expected_wallet)?);
        Ok(())
    })
}

#[test]
fn blockchain_61_003_orchestration_engine_registry_tick_keeps_local_wallet_live_second_tick()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_61", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(registry_ticks, 2);
        assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
        Ok(())
    })
}

#[test]
fn blockchain_62_003_orchestration_engine_registry_tick_remote_wallet_drops_after_missed_round()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_62", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;
        assert!(wallet_is_registered(&engine.node, &peer_wallet())?);

        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;
        assert!(!wallet_is_registered(&engine.node, &peer_wallet())?);
        Ok(())
    })
}

#[test]
fn blockchain_63_003_orchestration_engine_registry_tick_remote_wallet_survives_when_heartbeated()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_63", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        for round in 0_u64..3 {
            engine
                .node
                .note_heartbeat_round(&peer_wallet(), round)
                .map_err(fmt_err)?;
            engine
                .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
                .await;
        }

        assert!(wallet_is_registered(&engine.node, &peer_wallet())?);
        assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
        Ok(())
    })
}

#[test]
fn blockchain_64_003_orchestration_engine_registry_tick_two_remote_wallets_drop_independently()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_64", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;
    engine
        .node
        .note_heartbeat_round(&third_wallet(), 0)
        .map_err(fmt_err)?;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        engine
            .node
            .note_heartbeat_round(&third_wallet(), 1)
            .map_err(fmt_err)?;

        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert!(!wallet_is_registered(&engine.node, &peer_wallet())?);
        assert!(wallet_is_registered(&engine.node, &third_wallet())?);
        Ok(())
    })
}

#[test]
fn blockchain_65_003_orchestration_engine_registry_tick_catchup_only_does_not_update_register_tip_gate()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_65", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(
            engine.last_canonical_register_tip.load(Ordering::SeqCst),
            u64::MAX
        );
        Ok(())
    })
}

#[test]
fn blockchain_66_003_orchestration_engine_mint_tick_none_miner_increments_without_minting()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_66", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut mint_ticks = 0_u64;

    run_async(async {
        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        assert_eq!(mint_ticks, 1);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_67_003_orchestration_engine_mint_tick_saturates_counter() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_67", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut mint_ticks = u64::MAX;

    run_async(async {
        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        assert_eq!(mint_ticks, u64::MAX);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_68_003_orchestration_engine_failover_tick_none_miner_increments_without_minting()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_68", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut failover_ticks = 0_u64;

    run_async(async {
        engine
            .handle_failover_retry_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut failover_ticks,
                false,
            )
            .await;

        assert_eq!(failover_ticks, 1);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_69_003_orchestration_engine_failover_tick_saturates_counter() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_69", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut failover_ticks = u64::MAX;

    run_async(async {
        engine
            .handle_failover_retry_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut failover_ticks,
                false,
            )
            .await;

        assert_eq!(failover_ticks, u64::MAX);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_70_003_orchestration_engine_mint_and_failover_counters_are_independent() -> TestResult
{
    let (harness, engine) = make_engine_no_mining("orchestration_70", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut mint_ticks = 0_u64;
    let mut failover_ticks = 10_u64;

    run_async(async {
        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        engine
            .handle_failover_retry_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut failover_ticks,
                false,
            )
            .await;

        assert_eq!(mint_ticks, 1);
        assert_eq!(failover_ticks, 11);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_71_003_orchestration_engine_node_update_visible_through_engine_clone() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_71", &genesis_wallet())?;

    harness
        .node
        .note_heartbeat_round(&peer_wallet(), 3)
        .map_err(fmt_err)?;

    assert!(wallet_is_registered(&engine.node, &peer_wallet())?);
    assert_eq!(tip_snapshot(&engine.node, &peer_wallet())?, Some(3));
    Ok(())
}

#[test]
fn blockchain_72_003_orchestration_engine_engine_node_update_visible_through_harness_clone()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_72", &genesis_wallet())?;

    engine
        .node
        .note_heartbeat_round(&third_wallet(), 4)
        .map_err(fmt_err)?;

    assert!(wallet_is_registered(&harness.node, &third_wallet())?);
    assert_eq!(tip_snapshot(&harness.node, &third_wallet())?, Some(4));
    Ok(())
}

#[test]
fn blockchain_73_003_orchestration_engine_two_engines_keep_distinct_wallets() -> TestResult {
    let (_harness_a, engine_a) = make_engine_no_mining("orchestration_73_a", &genesis_wallet())?;
    let (_harness_b, engine_b) = make_engine_no_mining("orchestration_73_b", &peer_wallet())?;

    assert_eq!(engine_a.local_wallet, genesis_wallet());
    assert_eq!(engine_b.local_wallet, peer_wallet());
    assert_ne!(engine_a.local_wallet, engine_b.local_wallet);
    Ok(())
}

#[test]
fn blockchain_74_003_orchestration_engine_wallet_vector_short_wallet_preserved_invalid()
-> TestResult {
    let wallet = "rabc";
    let (_harness, engine) = make_engine_no_mining("orchestration_74", wallet)?;

    assert_eq!(engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_75_003_orchestration_engine_wallet_vector_space_preserved_invalid() -> TestResult {
    let wallet = " ";
    let (_harness, engine) = make_engine_no_mining("orchestration_75", wallet)?;

    assert_eq!(engine.local_wallet, wallet);
    Ok(())
}

#[test]
fn blockchain_76_003_orchestration_engine_wallet_vector_uppercase_canonicalizes() -> TestResult {
    let wallet = format!("r{}", "Cc".repeat(64));
    let expected = wallet.to_ascii_lowercase();
    let (_harness, engine) = make_engine_no_mining("orchestration_76", &wallet)?;

    assert_eq!(engine.local_wallet, expected);
    Ok(())
}

#[test]
fn blockchain_77_003_orchestration_engine_valid_wallet_vector_01_registers_on_registry_tick()
-> TestResult {
    let wallet = wallet_with_hex_pair("01");
    let (_harness, engine) = make_engine_no_mining("orchestration_77", &wallet)?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert!(wallet_is_registered(&engine.node, &wallet)?);
        Ok(())
    })
}

#[test]
fn blockchain_78_003_orchestration_engine_valid_wallet_vector_7f_registers_on_registry_tick()
-> TestResult {
    let wallet = wallet_with_hex_pair("7f");
    let (_harness, engine) = make_engine_no_mining("orchestration_78", &wallet)?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert!(wallet_is_registered(&engine.node, &wallet)?);
        Ok(())
    })
}

#[test]
fn blockchain_79_003_orchestration_engine_invalid_wallet_vector_bad_prefix_registers_none()
-> TestResult {
    let wallet = invalid_long_wallet();
    let (_harness, engine) = make_engine_no_mining("orchestration_79", &wallet)?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(wallet_count(&engine.node)?, 0);
        Ok(())
    })
}

#[test]
fn blockchain_80_003_orchestration_engine_invalid_wallet_vector_short_registers_none() -> TestResult
{
    let (_harness, engine) = make_engine_no_mining("orchestration_80", "r123")?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert_eq!(wallet_count(&engine.node)?, 0);
        Ok(())
    })
}

#[test]
fn blockchain_81_003_orchestration_engine_peer_mesh_empty_addr_vector_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_81", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let announce = PeerMeshAnnounce {
        peer_id: swarm.local_peer_id().to_base58(),
        listen_addrs: Vec::new(),
        wallet: Some(genesis_wallet()),
        timestamp_unix: 1,
    };

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(announce)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_82_003_orchestration_engine_peer_mesh_no_wallet_vector_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_82", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().map_err(fmt_err)?;
    let announce =
        PeerMeshAnnounce::from_local(*swarm.local_peer_id(), &[addr], None, 1).map_err(fmt_err)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(announce)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_83_003_orchestration_engine_puzzle_proof_zero_prev_hash_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_83", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut proof = make_puzzle_proof();
    proof.prev_block_hash = [0_u8; 64];

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendAosPuzzleProof(proof)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_84_003_orchestration_engine_puzzle_proof_max_height_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_84", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut proof = make_puzzle_proof();
    proof.height = u64::MAX;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendAosPuzzleProof(proof)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_85_003_orchestration_engine_chat_empty_json_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_85", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let chat = ChatMessage {
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        timestamp_ms: now_millis()?,
        json: Vec::new(),
        signature: vec![0_u8; ml_dsa_65::SIG_LEN],
    };

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendChat(chat)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_86_003_orchestration_engine_file_chunk_empty_payload_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_86", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let file_id = [3_u8; 32];
    let chunk = FileChunkMessage {
        file_id,
        from_wallet: genesis_wallet(),
        to_wallet: peer_wallet(),
        chunk_index: 0,
        total_chunks: 1,
        filename: "empty.bin".to_string(),
        file_size_bytes: 0,
        content_hash_hex: hex::encode(file_id),
        chunk_bytes: Vec::new(),
        timestamp_ms: now_millis()?,
    };

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendFileChunk(chunk)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_87_003_orchestration_engine_file_chunk_nonzero_index_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_87", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chunk = make_file_chunk()?;
    chunk.chunk_index = 2;
    chunk.total_chunks = 3;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendFileChunk(chunk)))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_88_003_orchestration_engine_block_large_height_routes_false() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_88", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let block = make_block(10_000)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendBlock(Box::new(block))))
                .await
        );
        Ok(())
    })
}

#[test]
fn blockchain_89_003_orchestration_engine_fuzz_valid_wallet_constructors_canonicalize() -> TestResult
{
    let vectors = [
        format!("r{}", "AA".repeat(64)),
        format!("r{}", "Bb".repeat(64)),
        format!("r{}", "Cc".repeat(64)),
    ];

    for (idx, wallet) in vectors.iter().enumerate() {
        let prefix = format!("orchestration_89_{idx}");
        let (_harness, engine) = make_engine_no_mining(&prefix, wallet)?;
        assert_eq!(engine.local_wallet, wallet.to_ascii_lowercase());
    }

    Ok(())
}

#[test]
fn blockchain_90_003_orchestration_engine_fuzz_invalid_wallet_constructors_preserve_original()
-> TestResult {
    let vectors = ["", "r", "r123", "bad-wallet"];

    for (idx, wallet) in vectors.iter().enumerate() {
        let prefix = format!("orchestration_90_{idx}");
        let (_harness, engine) = make_engine_no_mining(&prefix, wallet)?;
        assert_eq!(engine.local_wallet, *wallet);
    }

    Ok(())
}

#[test]
fn blockchain_91_003_orchestration_engine_fuzz_none_netcmd_always_returns_true() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_91", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..5 {
            assert!(engine.handle_net_cmd(&mut swarm, None).await);
        }

        Ok(())
    })
}

#[test]
fn blockchain_92_003_orchestration_engine_fuzz_blocks_never_close_channel() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_92", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for height in 1_u64..=3 {
            assert!(
                !engine
                    .handle_net_cmd(
                        &mut swarm,
                        Some(NetCmd::SendBlock(Box::new(make_block(height)?)))
                    )
                    .await
            );
        }

        Ok(())
    })
}

#[test]
fn blockchain_93_003_orchestration_engine_fuzz_peer_mesh_never_closes_channel() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_93", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..3 {
            let announce = make_peer_mesh_announce(&swarm)?;

            assert!(
                !engine
                    .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(announce)))
                    .await
            );
        }

        Ok(())
    })
}

#[test]
fn blockchain_94_003_orchestration_engine_fuzz_registers_deduplicate_same_wallet() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_94", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..3 {
            assert!(
                !engine
                    .handle_net_cmd(
                        &mut swarm,
                        Some(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
                    )
                    .await
            );
        }

        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_95_003_orchestration_engine_fuzz_distinct_registers_stage_distinct_entries()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_95", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let wallets = [genesis_wallet(), peer_wallet(), third_wallet()];

    run_async(async {
        for wallet in wallets {
            assert!(
                !engine
                    .handle_net_cmd(
                        &mut swarm,
                        Some(NetCmd::SendRegister(register_tx(&wallet)?))
                    )
                    .await
            );
        }

        assert_mempool_size(&harness.mempool, 3)
    })
}

#[test]
fn blockchain_96_003_orchestration_engine_adversarial_alternating_none_and_register_returns_expected()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_96", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..3 {
            assert!(engine.handle_net_cmd(&mut swarm, None).await);
            assert!(
                !engine
                    .handle_net_cmd(
                        &mut swarm,
                        Some(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
                    )
                    .await
            );
        }

        Ok(())
    })
}

#[test]
fn blockchain_97_003_orchestration_engine_adversarial_mixed_netcmds_keep_open_until_none()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_97", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        let announce = make_peer_mesh_announce(&swarm)?;

        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendBlock(Box::new(make_block(1)?)))
                )
                .await
        );

        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(announce)))
                .await
        );

        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
                )
                .await
        );

        assert!(engine.handle_net_cmd(&mut swarm, None).await);
        Ok(())
    })
}

#[test]
fn blockchain_98_003_orchestration_engine_load_sync_ticks_progress_counter() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_98", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut sync_ticks = 0_u64;

    run_async(async {
        for _ in 0..5 {
            engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;
        }

        assert_eq!(sync_ticks, 5);
        Ok(())
    })
}

#[test]
fn blockchain_99_003_orchestration_engine_load_registry_ticks_progress_counter() -> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_99", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        for _ in 0..5 {
            engine
                .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
                .await;
        }

        assert_eq!(registry_ticks, 5);
        assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
        Ok(())
    })
}

#[test]
fn blockchain_100_003_orchestration_engine_load_mint_ticks_with_none_miner_progress_counter()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_100", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut mint_ticks = 0_u64;

    run_async(async {
        for _ in 0..3 {
            engine
                .handle_mint_tick(
                    &mut chain,
                    &mut swarm,
                    &mut miner,
                    &mut last_logged_tip,
                    &mut last_minted_height,
                    &mut mint_ticks,
                    false,
                )
                .await;
        }

        assert_eq!(mint_ticks, 3);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_101_003_orchestration_engine_load_failover_ticks_with_none_miner_progress_counter()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_101", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut failover_ticks = 0_u64;

    run_async(async {
        for _ in 0..3 {
            engine
                .handle_failover_retry_tick(
                    &mut chain,
                    &mut swarm,
                    &mut miner,
                    &mut last_logged_tip,
                    &mut last_minted_height,
                    &mut failover_ticks,
                    false,
                )
                .await;
        }

        assert_eq!(failover_ticks, 3);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_102_003_orchestration_engine_load_every_public_tick_counter_progress() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_102", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut registry_ticks = 0_u64;
    let mut sync_ticks = 0_u64;
    let mut mint_ticks = 0_u64;
    let mut failover_ticks = 0_u64;

    run_async(async {
        for _ in 0..2 {
            engine.seed_sync(&mut swarm).await;
            engine
                .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
                .await;
            engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;
            engine
                .handle_mint_tick(
                    &mut chain,
                    &mut swarm,
                    &mut miner,
                    &mut last_logged_tip,
                    &mut last_minted_height,
                    &mut mint_ticks,
                    false,
                )
                .await;
            engine
                .handle_failover_retry_tick(
                    &mut chain,
                    &mut swarm,
                    &mut miner,
                    &mut last_logged_tip,
                    &mut last_minted_height,
                    &mut failover_ticks,
                    false,
                )
                .await;
        }

        assert_eq!(registry_ticks, 2);
        assert_eq!(sync_ticks, 2);
        assert_eq!(mint_ticks, 2);
        assert_eq!(failover_ticks, 2);
        assert!(last_minted_height.is_none());
        Ok(())
    })
}

#[test]
fn blockchain_103_003_orchestration_engine_load_mixed_netcmd_register_and_none() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_103", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..3 {
            assert!(
                !engine
                    .handle_net_cmd(
                        &mut swarm,
                        Some(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
                    )
                    .await
            );
            assert!(engine.handle_net_cmd(&mut swarm, None).await);
        }

        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_104_003_orchestration_engine_load_mixed_txkind_register_and_transfer() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_104", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendTxKind(register_kind(&genesis_wallet())?))
                )
                .await
        );
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(transfer_kind()?)))
                .await
        );

        assert_mempool_size(&harness.mempool, 2)
    })
}

#[test]
fn blockchain_105_003_orchestration_engine_registry_load_without_remote_heartbeats_keeps_only_local()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_105", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    engine
        .node
        .note_heartbeat_round(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    run_async(async {
        for _ in 0..4 {
            engine
                .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
                .await;
        }

        assert_eq!(registry_ticks, 4);
        assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
        assert!(!wallet_is_registered(&engine.node, &peer_wallet())?);
        Ok(())
    })
}

#[test]
fn blockchain_106_003_orchestration_engine_sync_seed_and_tick_sequence_stays_bounded() -> TestResult
{
    let (harness, engine) = make_engine_no_mining("orchestration_106", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut sync_ticks = 0_u64;

    run_async(async {
        for _ in 0..3 {
            engine.seed_sync(&mut swarm).await;
            engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;
        }

        let sync = harness.sync_engine.lock().await;
        let percent = sync.sync_percent();
        assert_eq!(sync_ticks, 3);
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
        Ok(())
    })
}

#[test]
fn blockchain_107_003_orchestration_engine_send_block_does_not_change_mempool() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_107", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendBlock(Box::new(make_block(3)?)))
                )
                .await
        );
        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_108_003_orchestration_engine_send_peer_mesh_does_not_change_mempool() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_108", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        let announce = make_peer_mesh_announce(&swarm)?;

        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendPeerMeshAnnounce(announce)))
                .await
        );

        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_109_003_orchestration_engine_send_puzzle_proof_does_not_change_mempool() -> TestResult
{
    let (harness, engine) = make_engine_no_mining("orchestration_109", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendAosPuzzleProof(make_puzzle_proof()))
                )
                .await
        );
        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_110_003_orchestration_engine_send_chat_does_not_change_mempool() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_110", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let chat = make_chat_message()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendChat(chat)))
                .await
        );
        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_111_003_orchestration_engine_send_file_chunk_does_not_change_mempool() -> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_111", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let chunk = make_file_chunk()?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendFileChunk(chunk)))
                .await
        );
        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_112_003_orchestration_engine_transfer_txkind_tag_is_transfer_before_route()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_112", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = transfer_kind()?;

    assert_eq!(kind.tag(), "transfer");

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_113_003_orchestration_engine_register_txkind_tag_is_register_node_before_route()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_113", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = register_kind(&genesis_wallet())?;

    assert_eq!(kind.tag(), "register_node");

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_114_003_orchestration_engine_register_txkind_validate_succeeds_before_route()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_114", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let kind = register_kind(&genesis_wallet())?;

    kind.validate().map_err(fmt_err)?;

    run_async(async {
        assert!(
            !engine
                .handle_net_cmd(&mut swarm, Some(NetCmd::SendTxKind(kind)))
                .await
        );
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_115_003_orchestration_engine_print_new_blocks_since_does_not_mutate_minted_height()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_115", &genesis_wallet())?;
    let chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;

    engine.print_new_blocks_since(&chain, &mut last_logged_tip, &mut last_minted_height);

    assert!(last_minted_height.is_none());
    Ok(())
}

#[test]
fn blockchain_116_003_orchestration_engine_print_new_blocks_since_allows_existing_minted_height()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_116", &genesis_wallet())?;
    let chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = Some(0_u64);

    engine.print_new_blocks_since(&chain, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_minted_height, Some(0));
    Ok(())
}

#[test]
fn blockchain_117_003_orchestration_engine_initialize_miner_still_none_when_mining_disabled_and_wallet_registered()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_117", &genesis_wallet())?;

    engine
        .node
        .register_wallet_strict(&genesis_wallet(), 0)
        .map_err(fmt_err)?;

    assert!(engine.initialize_miner().is_none());
    Ok(())
}

#[test]
fn blockchain_118_003_orchestration_engine_registry_tick_with_mining_disabled_does_not_enable_miner()
-> TestResult {
    let (_harness, engine) = make_engine_no_mining("orchestration_118", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut registry_ticks = 0_u64;
    let mut miner: Option<BlockchainBuilder> = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        assert!(miner.is_none());
        assert_eq!(registry_ticks, 1);
        Ok(())
    })
}

#[test]
fn blockchain_119_003_orchestration_engine_route_many_none_commands_has_no_side_effect_on_mempool()
-> TestResult {
    let (harness, engine) = make_engine_no_mining("orchestration_119", &genesis_wallet())?;
    let mut swarm = make_swarm()?;

    run_async(async {
        for _ in 0..5 {
            assert!(engine.handle_net_cmd(&mut swarm, None).await);
        }

        assert_mempool_size(&harness.mempool, 0)
    })
}

#[test]
fn blockchain_120_003_orchestration_engine_full_lightweight_smoke_sequence_completes() -> TestResult
{
    let (harness, engine) = make_engine_no_mining("orchestration_120", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());
    let mut miner: Option<BlockchainBuilder> = None;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut registry_ticks = 0_u64;
    let mut sync_ticks = 0_u64;
    let mut mint_ticks = 0_u64;
    let mut failover_ticks = 0_u64;

    run_async(async {
        engine.seed_sync(&mut swarm).await;

        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        engine.handle_sync_tick(&mut swarm, &mut sync_ticks).await;

        assert!(
            !engine
                .handle_net_cmd(
                    &mut swarm,
                    Some(NetCmd::SendRegister(register_tx(&genesis_wallet())?))
                )
                .await
        );

        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        engine
            .handle_failover_retry_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut failover_ticks,
                false,
            )
            .await;

        assert_eq!(registry_ticks, 1);
        assert_eq!(sync_ticks, 1);
        assert_eq!(mint_ticks, 1);
        assert_eq!(failover_ticks, 1);
        assert!(wallet_is_registered(&engine.node, &genesis_wallet())?);
        assert_mempool_size(&harness.mempool, 1)
    })
}

#[test]
fn blockchain_121_003_orchestration_engine_v2_preflight_rejects_height_zero_without_staging_proof()
-> TestResult {
    let harness = make_harness("orchestration_121", &genesis_wallet())?;

    let miner = BlockchainBuilder::new(
        Arc::clone(&harness.db),
        Arc::clone(&harness.mempool),
        genesis_wallet(),
        Arc::clone(&harness.tm),
        Arc::clone(&harness.signing_key),
    )
    .map_err(fmt_err)?;

    let result = miner
        .consensus()
        .local_wallet_can_attempt_mint_at(0, [1_u8; 64]);

    assert!(result.is_err());
    assert!(miner.pending_puzzle_proof().is_none());
    Ok(())
}

#[test]
fn blockchain_122_003_orchestration_engine_v2_preflight_rejects_zero_prev_hash_without_staging_proof()
-> TestResult {
    let harness = make_harness("orchestration_122", &genesis_wallet())?;

    let miner = BlockchainBuilder::new(
        Arc::clone(&harness.db),
        Arc::clone(&harness.mempool),
        genesis_wallet(),
        Arc::clone(&harness.tm),
        Arc::clone(&harness.signing_key),
    )
    .map_err(fmt_err)?;

    let result = miner
        .consensus()
        .local_wallet_can_attempt_mint_at(1, [0_u8; 64]);

    assert!(result.is_err());
    assert!(miner.pending_puzzle_proof().is_none());
    Ok(())
}

#[test]
fn blockchain_123_003_orchestration_engine_v2_preflight_rejects_unknown_parent_without_staging_proof()
-> TestResult {
    let harness = make_harness("orchestration_123", &genesis_wallet())?;

    let miner = BlockchainBuilder::new(
        Arc::clone(&harness.db),
        Arc::clone(&harness.mempool),
        genesis_wallet(),
        Arc::clone(&harness.tm),
        Arc::clone(&harness.signing_key),
    )
    .map_err(fmt_err)?;

    let unknown_parent = [9_u8; 64];

    let result = miner
        .consensus()
        .local_wallet_can_attempt_mint_at(1, unknown_parent);

    assert!(result.is_err());
    assert!(miner.pending_puzzle_proof().is_none());
    Ok(())
}

#[test]
fn blockchain_124_003_orchestration_engine_v2_preflight_unknown_parent_is_idempotent() -> TestResult
{
    let harness = make_harness("orchestration_124", &genesis_wallet())?;

    let miner = BlockchainBuilder::new(
        Arc::clone(&harness.db),
        Arc::clone(&harness.mempool),
        genesis_wallet(),
        Arc::clone(&harness.tm),
        Arc::clone(&harness.signing_key),
    )
    .map_err(fmt_err)?;

    let unknown_parent = [17_u8; 64];

    for _ in 0..5 {
        let result = miner
            .consensus()
            .local_wallet_can_attempt_mint_at(1, unknown_parent);

        assert!(result.is_err());
        assert!(miner.pending_puzzle_proof().is_none());
    }

    Ok(())
}

#[test]
fn blockchain_125_003_orchestration_engine_v2_preflight_is_read_only_across_distinct_denials()
-> TestResult {
    let harness = make_harness("orchestration_125", &genesis_wallet())?;

    let miner = BlockchainBuilder::new(
        Arc::clone(&harness.db),
        Arc::clone(&harness.mempool),
        genesis_wallet(),
        Arc::clone(&harness.tm),
        Arc::clone(&harness.signing_key),
    )
    .map_err(fmt_err)?;

    assert!(
        miner
            .consensus()
            .local_wallet_can_attempt_mint_at(0, [1_u8; 64])
            .is_err()
    );

    assert!(
        miner
            .consensus()
            .local_wallet_can_attempt_mint_at(1, [0_u8; 64])
            .is_err()
    );

    assert!(
        miner
            .consensus()
            .local_wallet_can_attempt_mint_at(1, [33_u8; 64])
            .is_err()
    );

    assert!(miner.pending_puzzle_proof().is_none());
    assert_mempool_size(&harness.mempool, 0)?;
    Ok(())
}

#[test]
fn blockchain_126_003_orchestration_engine_v2_builder_rejects_invalid_local_wallet_before_preflight()
-> TestResult {
    let harness = make_harness("orchestration_126", &genesis_wallet())?;

    let result = BlockchainBuilder::new(
        Arc::clone(&harness.db),
        Arc::clone(&harness.mempool),
        invalid_long_wallet(),
        Arc::clone(&harness.tm),
        Arc::clone(&harness.signing_key),
    );

    assert!(result.is_err());
    assert_mempool_size(&harness.mempool, 0)?;
    Ok(())
}

#[test]
fn blockchain_127_003_orchestration_engine_v2_mint_tick_with_real_miner_does_not_mint_while_not_ready()
-> TestResult {
    let (harness, engine) = make_engine("orchestration_127", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());

    let mut miner = Some(
        BlockchainBuilder::new(
            Arc::clone(&harness.db),
            Arc::clone(&harness.mempool),
            genesis_wallet(),
            Arc::clone(&harness.tm),
            Arc::clone(&harness.signing_key),
        )
        .map_err(fmt_err)?,
    );

    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut mint_ticks = 0_u64;

    run_async(async {
        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        assert_eq!(mint_ticks, 1);
        assert!(last_minted_height.is_none());
        assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);

        if let Some(m) = miner.as_ref() {
            assert!(m.pending_puzzle_proof().is_none());
        }

        Ok(())
    })
}

#[test]
fn blockchain_128_003_orchestration_engine_v2_mint_tick_with_ephemeral_quorum_still_does_not_bypass_consensus()
-> TestResult {
    let (harness, engine) = make_engine("orchestration_128", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());

    engine
        .node
        .register_wallet_strict(&genesis_wallet(), 0)
        .map_err(fmt_err)?;

    engine
        .node
        .register_wallet_strict(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    let mut miner = Some(
        BlockchainBuilder::new(
            Arc::clone(&harness.db),
            Arc::clone(&harness.mempool),
            genesis_wallet(),
            Arc::clone(&harness.tm),
            Arc::clone(&harness.signing_key),
        )
        .map_err(fmt_err)?,
    );

    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut mint_ticks = 0_u64;

    run_async(async {
        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        assert_eq!(mint_ticks, 1);
        assert!(last_minted_height.is_none());
        assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);

        if let Some(m) = miner.as_ref() {
            assert!(m.pending_puzzle_proof().is_none());
        }

        Ok(())
    })
}

#[test]
fn blockchain_129_003_orchestration_engine_v2_failover_retry_with_ephemeral_quorum_still_does_not_bypass_consensus()
-> TestResult {
    let (harness, engine) = make_engine("orchestration_129", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());

    engine
        .node
        .register_wallet_strict(&genesis_wallet(), 0)
        .map_err(fmt_err)?;

    engine
        .node
        .register_wallet_strict(&peer_wallet(), 0)
        .map_err(fmt_err)?;

    engine
        .node
        .register_wallet_strict(&third_wallet(), 0)
        .map_err(fmt_err)?;

    let mut miner = Some(
        BlockchainBuilder::new(
            Arc::clone(&harness.db),
            Arc::clone(&harness.mempool),
            genesis_wallet(),
            Arc::clone(&harness.tm),
            Arc::clone(&harness.signing_key),
        )
        .map_err(fmt_err)?,
    );

    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;
    let mut failover_ticks = 0_u64;

    run_async(async {
        engine
            .handle_failover_retry_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut failover_ticks,
                false,
            )
            .await;

        assert_eq!(failover_ticks, 1);
        assert!(last_minted_height.is_none());
        assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);

        if let Some(m) = miner.as_ref() {
            assert!(m.pending_puzzle_proof().is_none());
        }

        Ok(())
    })
}

#[test]
fn blockchain_130_003_orchestration_engine_v2_registry_then_mint_does_not_create_block_without_canonical_preflight()
-> TestResult {
    let (harness, engine) = make_engine("orchestration_130", &genesis_wallet())?;
    let mut swarm = make_swarm()?;
    let mut chain = AccountModelTree::with_manager((*harness.db).clone());

    let mut miner = Some(
        BlockchainBuilder::new(
            Arc::clone(&harness.db),
            Arc::clone(&harness.mempool),
            genesis_wallet(),
            Arc::clone(&harness.tm),
            Arc::clone(&harness.signing_key),
        )
        .map_err(fmt_err)?,
    );

    let mut registry_ticks = 0_u64;
    let mut mint_ticks = 0_u64;
    let mut last_logged_tip = 0_u64;
    let mut last_minted_height = None;

    run_async(async {
        engine
            .handle_registry_tick(&mut swarm, &mut miner, &mut registry_ticks)
            .await;

        engine
            .handle_mint_tick(
                &mut chain,
                &mut swarm,
                &mut miner,
                &mut last_logged_tip,
                &mut last_minted_height,
                &mut mint_ticks,
                false,
            )
            .await;

        assert_eq!(registry_ticks, 1);
        assert_eq!(mint_ticks, 1);
        assert!(last_minted_height.is_none());
        assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);

        if let Some(m) = miner.as_ref() {
            assert!(m.pending_puzzle_proof().is_none());
        }

        Ok(())
    })
}
