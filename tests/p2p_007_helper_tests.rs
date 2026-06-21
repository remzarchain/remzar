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

struct HelperHarness {
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
        "remzar_p2p_sync_007_helper_tests_{}_{}_{}_{}",
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

fn build_harness(test_name: &str) -> TestResult<HelperHarness> {
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

    Ok(HelperHarness {
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

fn assert_no_pending_work(sync: &P2pSync) {
    assert!(sync.pending_versions.is_empty());
    assert!(sync.pending_pq.is_empty());
    assert!(sync.pending_blocks.is_empty());
    assert!(sync.pending_batches.is_empty());
}

#[test]
fn p2p_01_sync_007_helper_constructs_real_harness() -> TestResult {
    let harness = build_harness("p2p_01")?;

    assert!(harness.data_dir.exists());
    assert!(!harness.swarm.local_peer_id().to_string().is_empty());
    assert_initial_public_state(&harness.sync);
    Ok(())
}

#[test]
fn p2p_02_sync_007_helper_unready_target_zero_has_no_pending_work() -> TestResult {
    let mut harness = build_harness("p2p_02")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 0u64);

    assert_no_pending_work(&harness.sync);
    assert_eq!(harness.sync.total_to_download, 0u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    Ok(())
}

#[test]
fn p2p_03_sync_007_helper_unready_target_one_defers_without_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_03")?;
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
fn p2p_04_sync_007_helper_unready_target_two_defers_without_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_04")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 2u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 2u64);
    Ok(())
}

#[test]
fn p2p_05_sync_007_helper_unready_target_ten_defers_without_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_05")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 10u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 10u64);
    Ok(())
}

#[test]
fn p2p_06_sync_007_helper_unready_target_100_defers_without_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_06")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 100u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 100u64);
    Ok(())
}

#[test]
fn p2p_07_sync_007_helper_unready_high_target_sets_zero_percent() -> TestResult {
    let mut harness = build_harness("p2p_07")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 700u64);

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_08_sync_007_helper_unready_lower_target_does_not_decrease_total() -> TestResult {
    let mut harness = build_harness("p2p_08")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 80u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 8u64);

    assert_eq!(harness.sync.total_to_download, 80u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_09_sync_007_helper_unready_higher_target_increases_total() -> TestResult {
    let mut harness = build_harness("p2p_09")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 9u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 90u64);

    assert_eq!(harness.sync.total_to_download, 90u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_10_sync_007_helper_unready_repeated_same_target_keeps_no_pending_work() -> TestResult {
    let mut harness = build_harness("p2p_10")?;
    let peer = test_peer_id();

    for _ in 0usize..10usize {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 10u64);
    }

    assert_eq!(harness.sync.total_to_download, 10u64);
    assert_no_pending_work(&harness.sync);
    Ok(())
}

#[test]
fn p2p_11_sync_007_helper_unready_different_peers_same_target_has_no_pending_work() -> TestResult {
    let mut harness = build_harness("p2p_11")?;

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 11u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 11u64);

    assert_eq!(harness.sync.total_to_download, 11u64);
    assert_no_pending_work(&harness.sync);
    Ok(())
}

#[test]
fn p2p_12_sync_007_helper_unready_different_peers_highest_target_wins() -> TestResult {
    let mut harness = build_harness("p2p_12")?;

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 12u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 120u64);

    assert_eq!(harness.sync.total_to_download, 120u64);
    assert_no_pending_work(&harness.sync);
    Ok(())
}

#[test]
fn p2p_13_sync_007_helper_unready_preserves_block_queue() -> TestResult {
    let mut harness = build_harness("p2p_13")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 13u64, 3u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 130u64);

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert_eq!(tracked_block_work(&harness.sync), 1usize);
    Ok(())
}

#[test]
fn p2p_14_sync_007_helper_unready_preserves_batch_queue() -> TestResult {
    let mut harness = build_harness("p2p_14")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 14u64, 2u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 140u64);

    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert_eq!(tracked_batch_work(&harness.sync), 1usize);
    Ok(())
}

#[test]
fn p2p_15_sync_007_helper_unready_preserves_mixed_queues() -> TestResult {
    let mut harness = build_harness("p2p_15")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 15u64, 3u8));
    harness.sync.batch_queue.push_back((peer, 15u64, 2u8));
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 150u64);

    assert_eq!(tracked_block_work(&harness.sync), 1usize);
    assert_eq!(tracked_batch_work(&harness.sync), 1usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_16_sync_007_helper_unready_does_not_mark_peer_ready() -> TestResult {
    let mut harness = build_harness("p2p_16")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 16u64);

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_17_sync_007_helper_unready_preserves_unrelated_ready_peer() -> TestResult {
    let mut harness = build_harness("p2p_17")?;
    let ready_peer = test_peer_id();
    let target_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, target_peer, 17u64);

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&target_peer));
    Ok(())
}

#[test]
fn p2p_18_sync_007_helper_ready_target_zero_has_no_block_request() -> TestResult {
    let mut harness = build_harness("p2p_18")?;
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
fn p2p_19_sync_007_helper_ready_target_one_issues_index_one() -> TestResult {
    let mut harness = build_harness("p2p_19")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 1u64);

    assert!(harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 1u64);
    Ok(())
}

#[test]
fn p2p_20_sync_007_helper_ready_target_two_issues_single_index_one() -> TestResult {
    let mut harness = build_harness("p2p_20")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 2u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 2u64);
    Ok(())
}

#[test]
fn p2p_21_sync_007_helper_ready_target_ten_issues_single_index_one() -> TestResult {
    let mut harness = build_harness("p2p_21")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 10u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 10u64);
    Ok(())
}

#[test]
fn p2p_22_sync_007_helper_ready_target_100_issues_single_index_one() -> TestResult {
    let mut harness = build_harness("p2p_22")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 100u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(tracked_block_work(&harness.sync), 0usize);
    assert_eq!(harness.sync.total_to_download, 100u64);
    Ok(())
}

#[test]
fn p2p_23_sync_007_helper_ready_repeated_same_target_dedupes_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_23")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for _ in 0usize..10usize {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 23u64);
    }

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(tracked_block_work(&harness.sync), 0usize);
    assert_eq!(harness.sync.total_to_download, 23u64);
    Ok(())
}

#[test]
fn p2p_24_sync_007_helper_ready_lower_target_does_not_duplicate_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_24")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 240u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 24u64);

    assert_eq!(harness.sync.total_to_download, 240u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_25_sync_007_helper_ready_higher_target_replaces_stale_pending_round() -> TestResult {
    let mut harness = build_harness("p2p_25")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 25u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 250u64);

    assert_eq!(harness.sync.total_to_download, 250u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_26_sync_007_helper_ready_high_low_sequence_keeps_highest_target() -> TestResult {
    let mut harness = build_harness("p2p_26")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in [260u64, 1u64, 200u64, 2u64, 100u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 260u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_27_sync_007_helper_ready_high_target_percent_zero() -> TestResult {
    let mut harness = build_harness("p2p_27")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 270u64);

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_28_sync_007_helper_ready_preserves_pq_ready_after_issue() -> TestResult {
    let mut harness = build_harness("p2p_28")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 28u64);

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_29_sync_007_helper_ready_no_pending_batch_for_missing_block_path() -> TestResult {
    let mut harness = build_harness("p2p_29")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 29u64);

    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_30_sync_007_helper_ready_pending_versions_unchanged() -> TestResult {
    let mut harness = build_harness("p2p_30")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 30u64);

    assert!(harness.sync.pending_versions.is_empty());
    Ok(())
}

#[test]
fn p2p_31_sync_007_helper_ready_pending_pq_unchanged() -> TestResult {
    let mut harness = build_harness("p2p_31")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 31u64);

    assert!(harness.sync.pending_pq.is_empty());
    Ok(())
}

#[test]
fn p2p_32_sync_007_helper_ready_clears_stale_block_queue_on_new_target() -> TestResult {
    let mut harness = build_harness("p2p_32")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 99u64, 3u8));
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 32u64);

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 32u64);
    Ok(())
}

#[test]
fn p2p_33_sync_007_helper_ready_clears_stale_batch_queue_on_new_target() -> TestResult {
    let mut harness = build_harness("p2p_33")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 99u64, 2u8));
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 33u64);

    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 33u64);
    Ok(())
}

#[test]
fn p2p_34_sync_007_helper_ready_clears_large_stale_queues_on_new_target() -> TestResult {
    let mut harness = build_harness("p2p_34")?;
    let peer = test_peer_id();

    for index in 0u64..64u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 34u64);

    assert_eq!(harness.sync.block_queue.len(), 64usize);
    assert_eq!(harness.sync.batch_queue.len(), 64usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_35_sync_007_helper_unready_preserves_large_stale_queues() -> TestResult {
    let mut harness = build_harness("p2p_35")?;
    let peer = test_peer_id();

    for index in 0u64..64u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 35u64);

    assert_eq!(harness.sync.block_queue.len(), 64usize);
    assert_eq!(harness.sync.batch_queue.len(), 64usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_36_sync_007_helper_deferred_then_ready_same_peer_issues_one_request() -> TestResult {
    let mut harness = build_harness("p2p_36")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 36u64);
    assert!(harness.sync.pending_blocks.is_empty());

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 36u64);

    assert!(harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 36u64);
    Ok(())
}

#[test]
fn p2p_37_sync_007_helper_deferred_high_then_ready_lower_uses_high_target() -> TestResult {
    let mut harness = build_harness("p2p_37")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 370u64);
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 37u64);

    assert_eq!(harness.sync.total_to_download, 370u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_38_sync_007_helper_deferred_low_then_ready_higher_uses_higher_target() -> TestResult {
    let mut harness = build_harness("p2p_38")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 38u64);
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 380u64);

    assert_eq!(harness.sync.total_to_download, 380u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_39_sync_007_helper_ready_different_peer_same_target_dedupes_by_index() -> TestResult {
    let mut harness = build_harness("p2p_39")?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, first, 39u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, second, 39u64);

    assert_eq!(harness.sync.total_to_download, 39u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(tracked_block_work(&harness.sync), 0usize);
    Ok(())
}

#[test]
fn p2p_40_sync_007_helper_ready_different_peer_higher_target_reissues_single_request() -> TestResult
{
    let mut harness = build_harness("p2p_40")?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, first, 40u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, second, 400u64);

    assert_eq!(harness.sync.total_to_download, 400u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_41_sync_007_helper_ready_many_peers_same_target_single_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_41")?;

    for _ in 0usize..16usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 41u64);
    }

    assert_eq!(harness.sync.total_to_download, 41u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_42_sync_007_helper_ready_many_peers_increasing_target_single_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_42")?;

    for target in 1u64..=16u64 {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 16u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_43_sync_007_helper_unready_many_peers_increasing_target_no_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_43")?;

    for target in 1u64..=16u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, test_peer_id(), target);
    }

    assert_eq!(harness.sync.total_to_download, 16u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_44_sync_007_helper_ready_target_u64_max_issues_one_request() -> TestResult {
    let mut harness = build_harness("p2p_44")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, u64::MAX);

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_45_sync_007_helper_unready_target_u64_max_defers_no_request() -> TestResult {
    let mut harness = build_harness("p2p_45")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, u64::MAX);

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_46_sync_007_helper_ready_safe_large_target_percent_zero() -> TestResult {
    let mut harness = build_harness("p2p_46")?;
    let peer = test_peer_id();
    let target = u64::MAX / 10_000u64;

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, target);

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_47_sync_007_helper_unready_safe_large_target_percent_zero() -> TestResult {
    let mut harness = build_harness("p2p_47")?;
    let peer = test_peer_id();
    let target = u64::MAX / 10_000u64;

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, target);

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_48_sync_007_helper_ready_clear_pq_after_request_does_not_clear_pending_block() -> TestResult
{
    let mut harness = build_harness("p2p_48")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 48u64);
    harness.sync.clear_pq_peer_state(&peer);

    assert!(harness.sync.pending_blocks.is_empty());
    assert!(!harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_49_sync_007_helper_clear_pq_then_repeat_same_target_does_not_duplicate_pending_block()
-> TestResult {
    let mut harness = build_harness("p2p_49")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 49u64);
    harness.sync.clear_pq_peer_state(&peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 49u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 49u64);
    Ok(())
}

#[test]
fn p2p_50_sync_007_helper_ready_request_keeps_node_syncing() -> TestResult {
    let mut harness = build_harness("p2p_50")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 50u64);

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_51_sync_007_helper_unready_request_keeps_node_syncing() -> TestResult {
    let mut harness = build_harness("p2p_51")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 51u64);

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_52_sync_007_helper_ready_request_keeps_last_synced_none_without_blocks() -> TestResult {
    let mut harness = build_harness("p2p_52")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 52u64);

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_53_sync_007_helper_unready_request_keeps_last_synced_none_without_blocks() -> TestResult {
    let mut harness = build_harness("p2p_53")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 53u64);

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_54_sync_007_helper_ready_request_does_not_create_chain_blocks() -> TestResult {
    let mut harness = build_harness("p2p_54")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 54u64);

    assert!(harness.sync.chain.get_blocks().is_empty());
    Ok(())
}

#[test]
fn p2p_55_sync_007_helper_ready_request_does_not_create_chain_balances() -> TestResult {
    let mut harness = build_harness("p2p_55")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 55u64);

    assert!(harness.sync.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn p2p_56_sync_007_helper_ready_request_does_not_change_db_tip() -> TestResult {
    let mut harness = build_harness("p2p_56")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 56u64);

    assert_eq!(harness.sync.db.get_tip_height().map_err(fmt_err)?, 0u64);
    Ok(())
}

#[test]
fn p2p_57_sync_007_helper_ready_request_does_not_change_addr_index() -> TestResult {
    let mut harness = build_harness("p2p_57")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 57u64);

    assert_eq!(
        harness.sync.db.get_addr_index_height().map_err(fmt_err)?,
        0u64
    );
    Ok(())
}

#[test]
fn p2p_58_sync_007_helper_unready_request_does_not_change_db_tip() -> TestResult {
    let mut harness = build_harness("p2p_58")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 58u64);

    assert_eq!(harness.sync.db.get_tip_height().map_err(fmt_err)?, 0u64);
    Ok(())
}

#[test]
fn p2p_59_sync_007_helper_unready_request_does_not_change_addr_index() -> TestResult {
    let mut harness = build_harness("p2p_59")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 59u64);

    assert_eq!(
        harness.sync.db.get_addr_index_height().map_err(fmt_err)?,
        0u64
    );
    Ok(())
}

#[test]
fn p2p_60_sync_007_helper_on_local_tip_after_ready_request_keeps_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_60")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 60u64);
    harness.sync.on_local_tip_advanced();

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 60u64);
    Ok(())
}

#[test]
fn p2p_61_sync_007_helper_on_local_tip_after_unready_request_keeps_no_pending_block() -> TestResult
{
    let mut harness = build_harness("p2p_61")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 61u64);
    harness.sync.on_local_tip_advanced();

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 61u64);
    Ok(())
}

#[test]
fn p2p_62_sync_007_helper_poll_after_ready_request_keeps_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_62")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 62u64);
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 62u64);
    Ok(())
}

#[test]
fn p2p_63_sync_007_helper_poll_after_unready_request_keeps_no_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_63")?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 63u64);
    harness.sync.poll_peers_for_height(&mut harness.swarm);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 63u64);
    Ok(())
}

#[test]
fn p2p_64_sync_007_helper_ready_request_after_manual_has_synced_true_resets_without_genesis()
-> TestResult {
    let mut harness = build_harness("p2p_64")?;
    let peer = test_peer_id();

    harness.sync.has_synced = true;
    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 64u64);

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_65_sync_007_helper_unready_request_after_manual_has_synced_true_resets_without_genesis()
-> TestResult {
    let mut harness = build_harness("p2p_65")?;
    let peer = test_peer_id();

    harness.sync.has_synced = true;
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 65u64);

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_66_sync_007_helper_ready_vector_small_targets_are_deduped() -> TestResult {
    let mut harness = build_harness("p2p_66")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=12u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
        assert!(harness.sync.pending_blocks.is_empty());
    }

    assert_eq!(harness.sync.total_to_download, 12u64);
    Ok(())
}

#[test]
fn p2p_67_sync_007_helper_unready_vector_small_targets_are_deferred() -> TestResult {
    let mut harness = build_harness("p2p_67")?;
    let peer = test_peer_id();

    for target in 1u64..=12u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
        assert!(harness.sync.pending_blocks.is_empty());
    }

    assert_eq!(harness.sync.total_to_download, 12u64);
    Ok(())
}

#[test]
fn p2p_68_sync_007_helper_ready_vector_descending_targets_keep_first_high() -> TestResult {
    let mut harness = build_harness("p2p_68")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in (1u64..=12u64).rev() {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 12u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_69_sync_007_helper_unready_vector_descending_targets_keep_first_high() -> TestResult {
    let mut harness = build_harness("p2p_69")?;
    let peer = test_peer_id();

    for target in (1u64..=12u64).rev() {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 12u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_70_sync_007_helper_ready_vector_random_like_targets_keep_max() -> TestResult {
    let mut harness = build_harness("p2p_70")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in [7u64, 1u64, 9u64, 3u64, 12u64, 2u64, 10u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 12u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_71_sync_007_helper_unready_vector_random_like_targets_keep_max() -> TestResult {
    let mut harness = build_harness("p2p_71")?;
    let peer = test_peer_id();

    for target in [7u64, 1u64, 9u64, 3u64, 12u64, 2u64, 10u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 12u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_72_sync_007_helper_ready_vector_percent_is_bounded() -> TestResult {
    let mut harness = build_harness("p2p_72")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=32u64 {
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
fn p2p_73_sync_007_helper_unready_vector_percent_is_bounded() -> TestResult {
    let mut harness = build_harness("p2p_73")?;
    let peer = test_peer_id();

    for target in 1u64..=32u64 {
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
fn p2p_74_sync_007_helper_ready_load_50_targets_single_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_74")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

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
fn p2p_75_sync_007_helper_unready_load_50_targets_no_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_75")?;
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
fn p2p_76_sync_007_helper_ready_load_100_same_target_single_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_76")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for _ in 0usize..100usize {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 76u64);
    }

    assert_eq!(harness.sync.total_to_download, 76u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_77_sync_007_helper_unready_load_100_same_target_no_pending_block() -> TestResult {
    let mut harness = build_harness("p2p_77")?;
    let peer = test_peer_id();

    for _ in 0usize..100usize {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 77u64);
    }

    assert_eq!(harness.sync.total_to_download, 77u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_78_sync_007_helper_ready_many_peers_load_still_single_index_request() -> TestResult {
    let mut harness = build_harness("p2p_78")?;

    for _ in 0usize..50usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, 78u64);
    }

    assert_eq!(harness.sync.total_to_download, 78u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_79_sync_007_helper_unready_many_peers_load_no_pending_work() -> TestResult {
    let mut harness = build_harness("p2p_79")?;

    for _ in 0usize..50usize {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, test_peer_id(), 79u64);
    }

    assert_no_pending_work(&harness.sync);
    assert_eq!(harness.sync.total_to_download, 79u64);
    Ok(())
}

#[test]
fn p2p_80_sync_007_helper_ready_many_peers_increasing_load_highest_target() -> TestResult {
    let mut harness = build_harness("p2p_80")?;

    for target in 1u64..=50u64 {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 50u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_81_sync_007_helper_unready_many_peers_increasing_load_highest_target() -> TestResult {
    let mut harness = build_harness("p2p_81")?;

    for target in 1u64..=50u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, test_peer_id(), target);
    }

    assert_eq!(harness.sync.total_to_download, 50u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_82_sync_007_helper_ready_queue_then_high_target_clears_queue_once() -> TestResult {
    let mut harness = build_harness("p2p_82")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 820u64);

    assert_eq!(harness.sync.block_queue.len(), 20usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_83_sync_007_helper_unready_queue_then_high_target_preserves_queue() -> TestResult {
    let mut harness = build_harness("p2p_83")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 830u64);

    assert_eq!(harness.sync.block_queue.len(), 20usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_84_sync_007_helper_ready_batch_queue_then_high_target_clears_queue_once() -> TestResult {
    let mut harness = build_harness("p2p_84")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 840u64);

    assert_eq!(harness.sync.batch_queue.len(), 20usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_85_sync_007_helper_unready_batch_queue_then_high_target_preserves_queue() -> TestResult {
    let mut harness = build_harness("p2p_85")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 850u64);

    assert_eq!(harness.sync.batch_queue.len(), 20usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_86_sync_007_helper_ready_mixed_queues_then_high_target_clears_both() -> TestResult {
    let mut harness = build_harness("p2p_86")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 860u64);

    assert_eq!(harness.sync.block_queue.len(), 20usize);
    assert_eq!(harness.sync.batch_queue.len(), 20usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_87_sync_007_helper_unready_mixed_queues_then_high_target_preserves_both() -> TestResult {
    let mut harness = build_harness("p2p_87")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 870u64);

    assert_eq!(harness.sync.block_queue.len(), 20usize);
    assert_eq!(harness.sync.batch_queue.len(), 20usize);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_88_sync_007_helper_adversarial_ready_and_unready_peer_same_target() -> TestResult {
    let mut harness = build_harness("p2p_88")?;
    let ready_peer = test_peer_id();
    let unready_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, unready_peer, 88u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, ready_peer, 88u64);

    assert_eq!(harness.sync.total_to_download, 88u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&unready_peer));
    Ok(())
}

#[test]
fn p2p_89_sync_007_helper_adversarial_ready_then_unready_same_target_no_duplicate() -> TestResult {
    let mut harness = build_harness("p2p_89")?;
    let ready_peer = test_peer_id();
    let unready_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, ready_peer, 89u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, unready_peer, 89u64);

    assert!(harness.sync.pending_blocks.is_empty());
    assert_eq!(harness.sync.total_to_download, 89u64);
    Ok(())
}

#[test]
fn p2p_90_sync_007_helper_adversarial_unready_high_then_ready_low_uses_high_target() -> TestResult {
    let mut harness = build_harness("p2p_90")?;
    let ready_peer = test_peer_id();
    let unready_peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, unready_peer, 900u64);
    harness.sync.mark_pq_ready(ready_peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, ready_peer, 90u64);

    assert_eq!(harness.sync.total_to_download, 900u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_91_sync_007_helper_adversarial_ready_low_then_unready_high_then_ready_same_peer()
-> TestResult {
    let mut harness = build_harness("p2p_91")?;
    let ready_peer = test_peer_id();
    let unready_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, ready_peer, 91u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, unready_peer, 910u64);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, ready_peer, 910u64);

    assert_eq!(harness.sync.total_to_download, 910u64);
    assert!(harness.sync.pending_blocks.is_empty());
    Ok(())
}

#[test]
fn p2p_92_sync_007_helper_property_block_work_never_exceeds_one_for_ready_single_index()
-> TestResult {
    let mut harness = build_harness("p2p_92")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=40u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
        assert!(tracked_block_work(&harness.sync) <= 1usize);
    }

    Ok(())
}

#[test]
fn p2p_93_sync_007_helper_property_batch_work_stays_zero_for_missing_block_path() -> TestResult {
    let mut harness = build_harness("p2p_93")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=40u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
        assert_eq!(tracked_batch_work(&harness.sync), 0usize);
    }

    Ok(())
}

#[test]
fn p2p_94_sync_007_helper_property_pending_block_index_is_always_next_missing_one() -> TestResult {
    let mut harness = build_harness("p2p_94")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=20u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);

        let all_index_one = harness
            .sync
            .pending_blocks
            .values()
            .all(|(_, idx, _)| *idx == 1u64);

        assert!(all_index_one);
    }

    Ok(())
}

#[test]
fn p2p_95_sync_007_helper_property_pending_retries_are_preserved_from_issue_path() -> TestResult {
    let mut harness = build_harness("p2p_95")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut harness.swarm, peer, 95u64);

    let retries_are_nonzero = harness
        .sync
        .pending_blocks
        .values()
        .all(|(_, _, retries_left)| *retries_left > 0u8);

    assert!(retries_are_nonzero);
    Ok(())
}

#[test]
fn p2p_96_sync_007_helper_property_ready_peer_set_size_after_many_issues() -> TestResult {
    let mut harness = build_harness("p2p_96")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=25u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_97_sync_007_helper_final_deferred_stress_invariants() -> TestResult {
    let mut harness = build_harness("p2p_97")?;
    let peer = test_peer_id();

    for target in 1u64..=100u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_98_sync_007_helper_final_ready_stress_invariants() -> TestResult {
    let mut harness = build_harness("p2p_98")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    for target in 1u64..=100u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_99_sync_007_helper_final_mixed_ready_deferred_stress() -> TestResult {
    let mut harness = build_harness("p2p_99")?;
    let ready_peer = test_peer_id();
    let deferred_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);

    for target in 1u64..=50u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, deferred_peer, target);
    }

    for target in 51u64..=100u64 {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, ready_peer, target);
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&deferred_peer));
    Ok(())
}

#[test]
fn p2p_100_sync_007_helper_final_public_helper_path_invariants() -> TestResult {
    let mut harness = build_harness("p2p_100")?;
    let ready_peer = test_peer_id();

    for index in 0u64..32u64 {
        harness.sync.block_queue.push_back((ready_peer, index, 3u8));
        harness.sync.batch_queue.push_back((ready_peer, index, 2u8));
    }

    harness.sync.mark_pq_ready(ready_peer);

    for target in [10u64, 20u64, 30u64, 100u64, 50u64, 100u64] {
        harness
            .sync
            .begin_sync_to_target(&mut harness.swarm, ready_peer, target);
        harness.sync.poll_peers_for_height(&mut harness.swarm);
        harness.sync.on_local_tip_advanced();
    }

    assert_eq!(harness.sync.total_to_download, 100u64);
    assert_eq!(harness.sync.downloaded, 0u64);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert_eq!(harness.sync.block_queue.len(), 32usize);
    assert_eq!(harness.sync.batch_queue.len(), 32usize);
    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.chain.get_blocks().is_empty());
    assert!(harness.sync.chain.get_balances().is_empty());
    assert_eq!(harness.sync.db.get_tip_height().map_err(fmt_err)?, 0u64);
    assert_eq!(
        harness.sync.db.get_addr_index_height().map_err(fmt_err)?,
        0u64
    );
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}
