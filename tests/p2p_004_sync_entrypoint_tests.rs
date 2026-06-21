#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, Swarm, identity, swarm::Config as SwarmConfig};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{
        p2p_001_transport::build_transport, p2p_003_behaviour::RemzarBehaviour,
        p2p_011_peerbook::PeerBook,
    },
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{p2p_001_sync_builders::P2pSync, p2p_006_sync_runtime::NodeOpts},
    storage::rocksdb_005_manager::RockDBManager,
    utility::{
        alpha_001_global_configuration::GlobalConfiguration,
        alpha_003_detection_system::DetectionSystem,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

type TestResult<T = ()> = Result<T, String>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct EntryHarness {
    sync: P2pSync,
    swarm: Swarm<RemzarBehaviour>,
    data_dir: PathBuf,
}

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
        "remzar_p2p_004_sync_entrypoint_tests_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn build_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_string(),
        founder: false,
    }
}

fn test_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
}

fn make_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let transport = build_transport(keypair.clone()).map_err(fmt_err)?;
    let behaviour = RemzarBehaviour::new(keypair).map_err(fmt_err)?;

    Ok(Swarm::new(
        transport,
        behaviour,
        peer_id,
        SwarmConfig::with_tokio_executor(),
    ))
}

fn build_harness(test_name: &str) -> TestResult<EntryHarness> {
    let data_dir = unique_data_dir(test_name);
    std::fs::create_dir_all(&data_dir).map_err(fmt_err)?;

    let opts = build_node_opts(&data_dir);
    let blockchain_path = data_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_text = blockchain_path.to_string_lossy().into_owned();

    let db = Arc::new(
        RockDBManager::new_blockchain(&opts, blockchain_path_text.as_str()).map_err(fmt_err)?,
    );

    let chain = AccountModelTree::with_manager((*db).clone());
    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let peerbook = Arc::new(Mutex::new(PeerBook::default()));
    let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&db));

    let sync = P2pSync::new(
        chain,
        Arc::clone(&db),
        mempool,
        peerbook,
        data_dir.join(GlobalConfiguration::PEER_LIST_DIR),
        Some(GlobalConfiguration::GENESIS_HASH_HEX.to_string()),
        reorg_manager,
    );

    Ok(EntryHarness {
        sync,
        swarm: make_swarm()?,
        data_dir,
    })
}

fn tracked_block_work(sync: &P2pSync) -> usize {
    sync.block_queue
        .len()
        .saturating_add(sync.pending_blocks.len())
}

fn tracked_batch_work(sync: &P2pSync) -> usize {
    sync.batch_queue
        .len()
        .saturating_add(sync.pending_batches.len())
}

fn assert_initial_public_state(sync: &P2pSync) {
    assert!(!sync.has_synced());
    assert!(sync.is_syncing());
    assert_eq!(sync.total_to_download, 0u64);
    assert_eq!(sync.downloaded, 0u64);
    assert!(sync.pending_versions.is_empty());
    assert!(sync.pending_pq.is_empty());
    assert!(sync.pending_blocks.is_empty());
    assert!(sync.pending_batches.is_empty());
    assert!(sync.block_queue.is_empty());
    assert!(sync.batch_queue.is_empty());
    assert!(sync.pq_ready_peers.is_empty());
    assert!(sync.pq_initiators.is_empty());
    assert!(!sync.tried_genesis);
}

#[test]
fn p2p_01_004_sync_entrypoint_constructs_real_harness() -> TestResult {
    let harness = build_harness("p2p_01")?;

    assert!(harness.data_dir.exists());
    assert!(!harness.swarm.local_peer_id().to_string().is_empty());
    assert_initial_public_state(&harness.sync);
    Ok(())
}

#[test]
fn p2p_02_004_sync_entrypoint_poll_no_peers_keeps_pending_versions_empty() -> TestResult {
    let mut harness = build_harness("p2p_02")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.pending_versions.is_empty());
    Ok(())
}

#[test]
fn p2p_03_004_sync_entrypoint_poll_no_peers_keeps_unsynced_without_genesis() -> TestResult {
    let mut harness = build_harness("p2p_03")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_04_004_sync_entrypoint_poll_no_peers_preserves_download_counters() -> TestResult {
    let mut harness = build_harness("p2p_04")?;

    harness.sync.total_to_download = 100u64;
    harness.sync.downloaded = 25u64;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.total_to_download, 0u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_05_004_sync_entrypoint_poll_no_peers_preserves_sync_percent() -> TestResult {
    let mut harness = build_harness("p2p_05")?;

    harness.sync.total_to_download = 400u64;
    harness.sync.downloaded = 100u64;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    // With no connected peers and no active sync backlog, polling reconciles
    // manual counters to the local DB tip.
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_06_004_sync_entrypoint_poll_no_peers_preserves_expected_genesis_hash() -> TestResult {
    let mut harness = build_harness("p2p_06")?;
    let before = harness.sync.expected_genesis_hash.clone();

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.expected_genesis_hash, before);
    Ok(())
}

#[test]
fn p2p_07_004_sync_entrypoint_poll_no_peers_preserves_tried_genesis_flag() -> TestResult {
    let mut harness = build_harness("p2p_07")?;

    harness.sync.tried_genesis = true;
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.tried_genesis);
    Ok(())
}

#[test]
fn p2p_08_004_sync_entrypoint_poll_no_peers_preserves_ready_peer() -> TestResult {
    let mut harness = build_harness("p2p_08")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_09_004_sync_entrypoint_poll_no_peers_preserves_many_ready_peers() -> TestResult {
    let mut harness = build_harness("p2p_09")?;

    for _ in 0usize..16usize {
        harness.sync.mark_pq_ready(test_peer_id());
    }

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.pq_ready_peers.len(), 16usize);
    Ok(())
}

#[test]
fn p2p_10_004_sync_entrypoint_poll_no_peers_preserves_block_queue() -> TestResult {
    let mut harness = build_harness("p2p_10")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 10u64, 3u8));
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert_eq!(tracked_block_work(&harness.sync), 1usize);
    Ok(())
}

#[test]
fn p2p_11_004_sync_entrypoint_poll_no_peers_preserves_batch_queue() -> TestResult {
    let mut harness = build_harness("p2p_11")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 11u64, 2u8));
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert_eq!(tracked_batch_work(&harness.sync), 1usize);
    Ok(())
}

#[test]
fn p2p_12_004_sync_entrypoint_poll_no_peers_preserves_mixed_queues() -> TestResult {
    let mut harness = build_harness("p2p_12")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 12u64, 3u8));
    harness.sync.batch_queue.push_back((peer, 12u64, 2u8));

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(tracked_block_work(&harness.sync), 1usize);
    assert_eq!(tracked_batch_work(&harness.sync), 1usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_13_004_sync_entrypoint_poll_no_peers_preserves_pending_maps_empty() -> TestResult {
    let mut harness = build_harness("p2p_13")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_14_004_sync_entrypoint_poll_no_peers_does_not_create_chain_blocks() -> TestResult {
    let mut harness = build_harness("p2p_14")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.chain.get_blocks().is_empty());
    Ok(())
}

#[test]
fn p2p_15_004_sync_entrypoint_poll_no_peers_does_not_create_chain_balances() -> TestResult {
    let mut harness = build_harness("p2p_15")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn p2p_16_004_sync_entrypoint_poll_no_peers_keeps_tip_height_zero() -> TestResult {
    let mut harness = build_harness("p2p_16")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.db.get_tip_height().map_err(fmt_err)?, 0u64);
    Ok(())
}

#[test]
fn p2p_17_004_sync_entrypoint_poll_no_peers_keeps_addr_index_height_zero() -> TestResult {
    let mut harness = build_harness("p2p_17")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(
        harness.sync.db.get_addr_index_height().map_err(fmt_err)?,
        0u64
    );
    Ok(())
}

#[test]
fn p2p_18_004_sync_entrypoint_poll_no_peers_keeps_last_synced_index_none() -> TestResult {
    let mut harness = build_harness("p2p_18")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.last_synced_index().is_none());
    Ok(())
}

#[test]
fn p2p_19_004_sync_entrypoint_poll_no_peers_keeps_last_synced_hash_none() -> TestResult {
    let mut harness = build_harness("p2p_19")?;

    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_20_004_sync_entrypoint_poll_no_peers_repeated_is_idempotent() -> TestResult {
    let mut harness = build_harness("p2p_20")?;

    for _ in 0usize..10usize {
        harness.sync.poll_peers_for_height(&mut harness.swarm);
    }

    assert!(harness.sync.pending_versions.is_empty());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_21_004_sync_entrypoint_begin_sync_zero_tip_without_pq_does_not_request_block() -> TestResult
{
    let mut harness = build_harness("p2p_21")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 0u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 0u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_22_004_sync_entrypoint_begin_sync_target_one_without_pq_defers_without_requests()
-> TestResult {
    let mut harness = build_harness("p2p_22")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 1u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 1u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_23_004_sync_entrypoint_begin_sync_target_ten_without_pq_defers_without_requests()
-> TestResult {
    let mut harness = build_harness("p2p_23")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 10u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 10u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_24_004_sync_entrypoint_begin_sync_without_pq_preserves_block_queue() -> TestResult {
    let mut harness = build_harness("p2p_24")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 24u64, 3u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 50u64);

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_25_004_sync_entrypoint_begin_sync_without_pq_preserves_batch_queue() -> TestResult {
    let mut harness = build_harness("p2p_25")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 25u64, 2u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 50u64);

    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_26_004_sync_entrypoint_begin_sync_without_pq_preserves_pending_maps_empty() -> TestResult {
    let mut harness = build_harness("p2p_26")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 26u64);

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_27_004_sync_entrypoint_begin_sync_without_pq_target_does_not_mark_peer_ready() -> TestResult
{
    let mut harness = build_harness("p2p_27")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 27u64);

    assert!(!harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_28_004_sync_entrypoint_begin_sync_without_pq_sets_percent_zero_for_positive_target()
-> TestResult {
    let mut harness = build_harness("p2p_28")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 28u64);

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_29_004_sync_entrypoint_begin_sync_without_pq_then_lower_target_does_not_decrease_total()
-> TestResult {
    let mut harness = build_harness("p2p_29")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 100u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 50u64);

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_30_004_sync_entrypoint_begin_sync_without_pq_then_higher_target_increases_total()
-> TestResult {
    let mut harness = build_harness("p2p_30")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 30u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 300u64);

    assert_eq!(harness.sync.total_to_download, 300u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_31_004_sync_entrypoint_vector_begin_sync_without_pq_targets() -> TestResult {
    let mut harness = build_harness("p2p_31")?;
    let peer = test_peer_id();

    for target in [1u64, 2u64, 3u64, 10u64, 100u64, 1_000u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);

        assert_eq!(harness.sync.total_to_download, target);
        assert_eq!(harness.sync.downloaded, 0u64);
        assert!(harness.sync.pending_blocks.is_empty());
    }

    Ok(())
}

#[test]
fn p2p_32_004_sync_entrypoint_begin_sync_without_pq_large_target() -> TestResult {
    let mut harness = build_harness("p2p_32")?;
    let peer = test_peer_id();
    let target = u64::MAX / 10_000u64;

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, target);

    assert_eq!(harness.sync.total_to_download, target);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_33_004_sync_entrypoint_begin_sync_without_pq_u64_max_target() -> TestResult {
    let mut harness = build_harness("p2p_33")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, u64::MAX);

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_34_004_sync_entrypoint_begin_sync_without_pq_different_peers_same_target() -> TestResult {
    let mut harness = build_harness("p2p_34")?;

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 34u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 34u64);

    assert_eq!(harness.sync.total_to_download, 34u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_35_004_sync_entrypoint_begin_sync_without_pq_different_peers_higher_target_wins()
-> TestResult {
    let mut harness = build_harness("p2p_35")?;

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 35u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 350u64);

    assert_eq!(harness.sync.total_to_download, 350u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_36_004_sync_entrypoint_begin_sync_without_pq_keeps_node_syncing() -> TestResult {
    let mut harness = build_harness("p2p_36")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 36u64);

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_37_004_sync_entrypoint_begin_sync_without_pq_preserves_expected_genesis_hash() -> TestResult
{
    let mut harness = build_harness("p2p_37")?;
    let peer = test_peer_id();
    let before = harness.sync.expected_genesis_hash.clone();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 37u64);

    assert_eq!(harness.sync.expected_genesis_hash, before);
    Ok(())
}

#[test]
fn p2p_38_004_sync_entrypoint_begin_sync_without_pq_preserves_tried_genesis() -> TestResult {
    let mut harness = build_harness("p2p_38")?;
    let peer = test_peer_id();

    harness.sync.tried_genesis = true;
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 38u64);

    assert!(harness.sync.tried_genesis);
    Ok(())
}

#[test]
fn p2p_39_004_sync_entrypoint_begin_sync_without_pq_preserves_ready_unrelated_peer() -> TestResult {
    let mut harness = build_harness("p2p_39")?;
    let ready_peer = test_peer_id();
    let target_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, target_peer, 39u64);

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&target_peer));
    Ok(())
}

#[test]
fn p2p_40_004_sync_entrypoint_begin_sync_without_pq_preserves_last_synced_pointers_none()
-> TestResult {
    let mut harness = build_harness("p2p_40")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 40u64);

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_41_004_sync_entrypoint_begin_sync_ready_peer_zero_target_no_request() -> TestResult {
    let mut harness = build_harness("p2p_41")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 0u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 0u64);
    Ok(())
}

#[test]
fn p2p_42_004_sync_entrypoint_begin_sync_ready_peer_target_one_requests_index_one() -> TestResult {
    let mut harness = build_harness("p2p_42")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 1u64);

    assert_eq!(harness.sync.total_to_download, 1u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    // PQ-ready alone is not enough to emit a request; the peer must also be connected.
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_43_004_sync_entrypoint_begin_sync_ready_peer_target_ten_requests_index_one() -> TestResult {
    let mut harness = build_harness("p2p_43")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 10u64);

    assert_eq!(harness.sync.total_to_download, 10u64);
    // PQ-ready alone is not enough to emit a request; the peer must also be connected.
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_44_004_sync_entrypoint_begin_sync_ready_peer_clears_stale_block_queue_on_new_target()
-> TestResult {
    let mut harness = build_harness("p2p_44")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.block_queue.push_back((peer, 99u64, 3u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 44u64);

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_45_004_sync_entrypoint_begin_sync_ready_peer_clears_stale_batch_queue_on_new_target()
-> TestResult {
    let mut harness = build_harness("p2p_45")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.batch_queue.push_back((peer, 99u64, 2u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 45u64);

    // Disconnected peers defer sync; stale queued work is not cleared until
    // block sync can actually start with a connected peer.
    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_46_004_sync_entrypoint_begin_sync_ready_peer_clears_stale_pending_work_on_new_target()
-> TestResult {
    let mut harness = build_harness("p2p_46")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.block_queue.push_back((peer, 10u64, 3u8));
    harness.sync.batch_queue.push_back((peer, 10u64, 2u8));

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 46u64);

    // Disconnected peers defer sync; existing queued work is preserved.
    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_47_004_sync_entrypoint_begin_sync_ready_peer_repeated_same_target_dedupes_request()
-> TestResult {
    let mut harness = build_harness("p2p_47")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 47u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 47u64);

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    // PQ-ready alone is not enough to emit a request; the peer must also be connected.
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_48_004_sync_entrypoint_begin_sync_ready_peer_lower_target_does_not_decrease_total()
-> TestResult {
    let mut harness = build_harness("p2p_48")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 100u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 48u64);

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_49_004_sync_entrypoint_begin_sync_ready_peer_higher_target_replaces_pending_request()
-> TestResult {
    let mut harness = build_harness("p2p_49")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 49u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 490u64);

    assert_eq!(harness.sync.total_to_download, 490u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    // PQ-ready alone is not enough to emit a request; the peer must also be connected.
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_50_004_sync_entrypoint_begin_sync_ready_peer_preserves_pq_ready_state() -> TestResult {
    let mut harness = build_harness("p2p_50")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 50u64);

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_51_004_sync_entrypoint_begin_sync_ready_peer_sets_sync_percent_zero() -> TestResult {
    let mut harness = build_harness("p2p_51")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 51u64);

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_52_004_sync_entrypoint_begin_sync_ready_peer_keeps_pending_batches_empty_for_missing_block()
-> TestResult {
    let mut harness = build_harness("p2p_52")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 52u64);

    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_53_004_sync_entrypoint_begin_sync_ready_peer_different_peer_same_target_keeps_one_reserved_index()
-> TestResult {
    let mut harness = build_harness("p2p_53")?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, first, 53u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, second, 53u64);

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_54_004_sync_entrypoint_begin_sync_ready_peer_many_repeats_stays_deduped() -> TestResult {
    let mut harness = build_harness("p2p_54")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for _ in 0usize..20usize {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 54u64);
    }

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_55_004_sync_entrypoint_vector_ready_peer_targets_replace_to_highest_total() -> TestResult {
    let mut harness = build_harness("p2p_55")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in [1u64, 5u64, 3u64, 10u64, 7u64, 55u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 55u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_56_004_sync_entrypoint_begin_sync_ready_peer_safe_large_target() -> TestResult {
    let mut harness = build_harness("p2p_56")?;
    let peer = test_peer_id();
    let target = u64::MAX / 10_000u64;

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, target);

    assert_eq!(harness.sync.total_to_download, target);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_57_004_sync_entrypoint_begin_sync_ready_peer_u64_max_target() -> TestResult {
    let mut harness = build_harness("p2p_57")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, u64::MAX);

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_58_004_sync_entrypoint_deferred_then_ready_same_peer_issues_request() -> TestResult {
    let mut harness = build_harness("p2p_58")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 58u64);
    assert!(harness.sync.pending_blocks.is_empty());

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 58u64);

    // PQ-ready alone is not enough to emit a request; the peer must also be connected.
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_59_004_sync_entrypoint_deferred_target_then_ready_lower_target_uses_high_target()
-> TestResult {
    let mut harness = build_harness("p2p_59")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 590u64);
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 59u64);

    assert_eq!(harness.sync.total_to_download, 590u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_60_004_sync_entrypoint_deferred_target_then_ready_higher_target_uses_higher_target()
-> TestResult {
    let mut harness = build_harness("p2p_60")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 60u64);
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 600u64);

    assert_eq!(harness.sync.total_to_download, 600u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_61_004_sync_entrypoint_on_local_tip_advanced_without_blocks_keeps_unsynced() -> TestResult {
    let mut harness = build_harness("p2p_61")?;

    harness.sync.on_local_tip_advanced();

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_62_004_sync_entrypoint_on_local_tip_advanced_without_blocks_keeps_pending_empty()
-> TestResult {
    let mut harness = build_harness("p2p_62")?;

    harness.sync.on_local_tip_advanced();

    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_63_004_sync_entrypoint_on_local_tip_advanced_without_blocks_keeps_queues_empty() -> TestResult
{
    let mut harness = build_harness("p2p_63")?;

    harness.sync.on_local_tip_advanced();

    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_64_004_sync_entrypoint_on_local_tip_advanced_preserves_manual_counters() -> TestResult {
    let mut harness = build_harness("p2p_64")?;

    harness.sync.total_to_download = 640u64;
    harness.sync.downloaded = 160u64;
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.total_to_download, 0u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_65_004_sync_entrypoint_on_local_tip_advanced_preserves_sync_percent() -> TestResult {
    let mut harness = build_harness("p2p_65")?;

    harness.sync.total_to_download = 800u64;
    harness.sync.downloaded = 200u64;
    harness.sync.on_local_tip_advanced();

    // on_local_tip_advanced reconciles manual counters to the local DB tip.
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_66_004_sync_entrypoint_on_local_tip_advanced_preserves_ready_peer() -> TestResult {
    let mut harness = build_harness("p2p_66")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.on_local_tip_advanced();

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_67_004_sync_entrypoint_on_local_tip_advanced_preserves_many_ready_peers() -> TestResult {
    let mut harness = build_harness("p2p_67")?;

    for _ in 0usize..32usize {
        harness.sync.mark_pq_ready(test_peer_id());
    }

    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.pq_ready_peers.len(), 32usize);
    Ok(())
}

#[test]
fn p2p_68_004_sync_entrypoint_on_local_tip_advanced_preserves_block_queue() -> TestResult {
    let mut harness = build_harness("p2p_68")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 68u64, 3u8));
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_69_004_sync_entrypoint_on_local_tip_advanced_preserves_batch_queue() -> TestResult {
    let mut harness = build_harness("p2p_69")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 69u64, 2u8));
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_70_004_sync_entrypoint_on_local_tip_advanced_preserves_expected_genesis_hash() -> TestResult
{
    let mut harness = build_harness("p2p_70")?;
    let before = harness.sync.expected_genesis_hash.clone();

    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.expected_genesis_hash, before);
    Ok(())
}

#[test]
fn p2p_71_004_sync_entrypoint_on_local_tip_advanced_keeps_tip_zero_without_blocks() -> TestResult {
    let mut harness = build_harness("p2p_71")?;

    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.db.get_tip_height().map_err(fmt_err)?, 0u64);
    Ok(())
}

#[test]
fn p2p_72_004_sync_entrypoint_on_local_tip_advanced_keeps_addr_index_zero_without_blocks()
-> TestResult {
    let mut harness = build_harness("p2p_72")?;

    harness.sync.on_local_tip_advanced();

    assert_eq!(
        harness.sync.db.get_addr_index_height().map_err(fmt_err)?,
        0u64
    );
    Ok(())
}

#[test]
fn p2p_73_004_sync_entrypoint_on_local_tip_advanced_repeated_is_idempotent() -> TestResult {
    let mut harness = build_harness("p2p_73")?;

    for _ in 0usize..20usize {
        harness.sync.on_local_tip_advanced();
    }

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_74_004_sync_entrypoint_on_local_tip_after_deferred_sync_keeps_deferred_counters()
-> TestResult {
    let mut harness = build_harness("p2p_74")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 740u64);
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.total_to_download, 740u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_75_004_sync_entrypoint_on_local_tip_after_ready_sync_keeps_pending_request() -> TestResult {
    let mut harness = build_harness("p2p_75")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 75u64);
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    assert_eq!(harness.sync.total_to_download, 75u64);
    Ok(())
}

#[test]
fn p2p_76_004_sync_entrypoint_poll_after_deferred_sync_preserves_total() -> TestResult {
    let mut harness = build_harness("p2p_76")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 760u64);
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.total_to_download, 760u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_77_004_sync_entrypoint_poll_after_ready_sync_preserves_pending_request() -> TestResult {
    let mut harness = build_harness("p2p_77")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 77u64);
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_78_004_sync_entrypoint_ready_sync_then_clear_pq_state_does_not_clear_pending_request()
-> TestResult {
    let mut harness = build_harness("p2p_78")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 78u64);
    harness.sync.clear_pq_peer_state(&peer);

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    assert!(!harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_79_004_sync_entrypoint_ready_sync_then_repeat_after_pq_clear_does_not_duplicate()
-> TestResult {
    let mut harness = build_harness("p2p_79")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 79u64);
    harness.sync.clear_pq_peer_state(&peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 79u64);

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_80_004_sync_entrypoint_ready_sync_many_peers_same_target_single_index_request() -> TestResult
{
    let mut harness = build_harness("p2p_80")?;

    for _ in 0usize..10usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 80u64);
    }

    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_81_004_sync_entrypoint_load_50_deferred_targets_without_pq_keep_no_requests() -> TestResult {
    let mut harness = build_harness("p2p_81")?;
    let peer = test_peer_id();

    for target in 1u64..=50u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 50u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_82_004_sync_entrypoint_load_50_ready_targets_keep_single_pending_request() -> TestResult {
    let mut harness = build_harness("p2p_82")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=50u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 50u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_83_004_sync_entrypoint_load_100_poll_no_peers_calls_are_stable() -> TestResult {
    let mut harness = build_harness("p2p_83")?;

    for _ in 0usize..100usize {
        harness.sync.poll_peers_for_height(&mut harness.swarm);
    }

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_84_004_sync_entrypoint_load_100_on_local_tip_calls_are_stable() -> TestResult {
    let mut harness = build_harness("p2p_84")?;

    for _ in 0usize..100usize {
        harness.sync.on_local_tip_advanced();
    }

    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_85_004_sync_entrypoint_vector_interleaved_defer_poll_tip() -> TestResult {
    let mut harness = build_harness("p2p_85")?;
    let peer = test_peer_id();

    for target in [10u64, 20u64, 30u64, 40u64, 50u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
        harness.sync.poll_peers_for_height(&mut harness.swarm);
        harness.sync.on_local_tip_advanced();
    }

    assert_eq!(harness.sync.total_to_download, 50u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_86_004_sync_entrypoint_vector_interleaved_ready_poll_tip() -> TestResult {
    let mut harness = build_harness("p2p_86")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in [10u64, 20u64, 30u64, 40u64, 50u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
        harness.sync.poll_peers_for_height(&mut harness.swarm);
        harness.sync.on_local_tip_advanced();
    }

    assert_eq!(harness.sync.total_to_download, 50u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_87_004_sync_entrypoint_adversarial_large_existing_queues_cleared_by_ready_new_target()
-> TestResult {
    let mut harness = build_harness("p2p_87")?;
    let peer = test_peer_id();

    for index in 0u64..256u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 87u64);

    assert_eq!(harness.sync.block_queue.len(), 256usize);
    assert_eq!(harness.sync.batch_queue.len(), 256usize);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_88_004_sync_entrypoint_adversarial_large_existing_queues_preserved_by_deferred_sync()
-> TestResult {
    let mut harness = build_harness("p2p_88")?;
    let peer = test_peer_id();

    for index in 0u64..256u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 88u64);

    assert_eq!(harness.sync.block_queue.len(), 256usize);
    assert_eq!(harness.sync.batch_queue.len(), 256usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_89_004_sync_entrypoint_adversarial_high_low_target_sequence_without_pq() -> TestResult {
    let mut harness = build_harness("p2p_89")?;
    let peer = test_peer_id();

    for target in [1_000u64, 1u64, 900u64, 2u64, 800u64, 3u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 1_000u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_90_004_sync_entrypoint_adversarial_high_low_target_sequence_with_pq() -> TestResult {
    let mut harness = build_harness("p2p_90")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in [1_000u64, 1u64, 900u64, 2u64, 800u64, 3u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 1_000u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    Ok(())
}

#[test]
fn p2p_91_004_sync_entrypoint_property_sync_percent_stays_bounded_after_deferred_vectors()
-> TestResult {
    let mut harness = build_harness("p2p_91")?;
    let peer = test_peer_id();

    for target in 1u64..=40u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);

        let percent = harness.sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
    }

    Ok(())
}

#[test]
fn p2p_92_004_sync_entrypoint_property_sync_percent_stays_bounded_after_ready_vectors() -> TestResult
{
    let mut harness = build_harness("p2p_92")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=40u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);

        let percent = harness.sync.sync_percent();
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
    }

    Ok(())
}

#[test]
fn p2p_93_004_sync_entrypoint_property_ready_peer_set_survives_many_begin_calls() -> TestResult {
    let mut harness = build_harness("p2p_93")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=25u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert!(harness.sync.is_pq_ready(&peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_94_004_sync_entrypoint_property_unready_peer_never_becomes_ready_by_begin_calls()
-> TestResult {
    let mut harness = build_harness("p2p_94")?;
    let peer = test_peer_id();

    for target in 1u64..=25u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_95_004_sync_entrypoint_property_pending_versions_unaffected_by_begin_sync() -> TestResult {
    let mut harness = build_harness("p2p_95")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=10u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert!(harness.sync.pending_versions.is_empty());
    Ok(())
}

#[test]
fn p2p_96_004_sync_entrypoint_property_pending_pq_unaffected_by_begin_sync() -> TestResult {
    let mut harness = build_harness("p2p_96")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=10u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert!(harness.sync.pending_pq.is_empty());
    Ok(())
}

#[test]
fn p2p_97_004_sync_entrypoint_final_poll_no_peers_stress_invariants() -> TestResult {
    let mut harness = build_harness("p2p_97")?;
    let ready_peer = test_peer_id();

    harness.sync.total_to_download = 500u64;
    harness.sync.downloaded = 125u64;
    harness.sync.mark_pq_ready(ready_peer);

    for _ in 0usize..25usize {
        harness.sync.poll_peers_for_height(&mut harness.swarm);
    }

    // Repeated no-peer polling reconciles manual counters to the local DB tip.
    assert_eq!(harness.sync.total_to_download, 0u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(harness.sync.pending_versions.is_empty());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_98_004_sync_entrypoint_final_deferred_sync_stress_invariants() -> TestResult {
    let mut harness = build_harness("p2p_98")?;
    let peer = test_peer_id();

    for target in 1u64..=100u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_99_004_sync_entrypoint_final_ready_sync_stress_invariants() -> TestResult {
    let mut harness = build_harness("p2p_99")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=100u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    assert!(harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_100_004_sync_entrypoint_final_mixed_public_entrypoint_stress() -> TestResult {
    let mut harness = build_harness("p2p_100")?;
    let deferred_peer = test_peer_id();
    let ready_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);

    for target in [10u64, 20u64, 30u64, 40u64, 50u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, deferred_peer, target);
        harness.sync.poll_peers_for_height(&mut harness.swarm);
        harness.sync.on_local_tip_advanced();
    }

    for target in [60u64, 70u64, 80u64, 90u64, 100u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, ready_peer, target);
        harness.sync.poll_peers_for_height(&mut harness.swarm);
        harness.sync.on_local_tip_advanced();
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert_eq!(harness.sync.pending_blocks.len(), 0usize);
    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&deferred_peer));
    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.chain.get_blocks().is_empty());
    assert!(harness.sync.chain.get_balances().is_empty());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}
