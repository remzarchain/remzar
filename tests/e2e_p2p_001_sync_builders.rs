#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, identity};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::p2p_011_peerbook::PeerBook,
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{
        p2p_001_sync_builders::{
            P2pSync, PendingBatchRequest, REMZAR_HASH_BYTES_LEN, RemzarHashBytes,
        },
        p2p_006_sync_runtime::NodeOpts,
    },
    storage::rocksdb_005_manager::RockDBManager,
    utility::{
        alpha_001_global_configuration::GlobalConfiguration,
        alpha_003_detection_system::DetectionSystem,
    },
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, timeout};

type TestResult<T = ()> = Result<T, String>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct SyncHarness {
    sync: P2pSync,
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
        "remzar_e2e_p2p_001_sync_builders_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn test_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn filled_hash(byte: u8) -> RemzarHashBytes {
    [byte; REMZAR_HASH_BYTES_LEN]
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

fn build_sync_harness(test_name: &str) -> TestResult<SyncHarness> {
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

    Ok(SyncHarness { sync, data_dir })
}

fn assert_clean_initial_core_state(sync: &P2pSync) {
    assert!(!sync.has_synced());
    assert!(sync.is_syncing());

    assert_eq!(sync.total_to_download, 0);
    assert_eq!(sync.downloaded, 0);
    assert_eq!(format!("{:.2}", sync.sync_percent()), "0.00");

    assert!(sync.pending_versions.is_empty());
    assert!(sync.pending_pq.is_empty());
    assert!(sync.pending_blocks.is_empty());
    assert!(sync.pending_batches.is_empty());

    assert!(sync.block_queue.is_empty());
    assert!(sync.batch_queue.is_empty());

    assert!(sync.pq_ready_peers.is_empty());
    assert!(sync.pq_initiators.is_empty());

    assert!(!sync.tried_genesis);
    assert!(sync.last_synced_index().is_none());
    assert!(sync.last_synced_hash().is_none());
}

fn cleanup_peer_public_backlog(sync: &mut P2pSync, peer: &PeerId) {
    sync.block_queue.retain(|(p, _, _)| p != peer);
    sync.batch_queue.retain(|(p, _, _)| p != peer);
    sync.clear_pq_peer_state(peer);
}

async fn wait_until<F>(limit: Duration, mut predicate: F, label: &str) -> TestResult
where
    F: FnMut() -> bool,
{
    let started = std::time::Instant::now();

    while started.elapsed() < limit {
        if predicate() {
            return Ok(());
        }

        sleep(Duration::from_millis(5)).await;
    }

    Err(format!("timed out waiting for {label}"))
}

fn push_block_backlog(sync: &mut P2pSync, peer: PeerId, start: u64, count: u64, retries: u8) {
    for offset in 0..count {
        sync.block_queue
            .push_back((peer, start.saturating_add(offset), retries));
    }
}

fn push_batch_backlog(sync: &mut P2pSync, peer: PeerId, start: u64, count: u64, retries: u8) {
    for offset in 0..count {
        sync.batch_queue
            .push_back((peer, start.saturating_add(offset), retries));
    }
}

fn drain_block_queue_with_retry_budget(sync: &mut P2pSync, max_steps: usize) -> usize {
    let mut steps = 0usize;

    while steps < max_steps {
        let Some((peer, idx, retries_left)) = sync.block_queue.pop_front() else {
            break;
        };

        if retries_left > 0 {
            sync.block_queue
                .push_back((peer, idx, retries_left.saturating_sub(1)));
        }

        steps = steps.saturating_add(1);
    }

    steps
}

fn drain_batch_queue_with_retry_budget(sync: &mut P2pSync, max_steps: usize) -> usize {
    let mut steps = 0usize;

    while steps < max_steps {
        let Some((peer, idx, retries_left)) = sync.batch_queue.pop_front() else {
            break;
        };

        if retries_left > 0 {
            sync.batch_queue
                .push_back((peer, idx, retries_left.saturating_sub(1)));
        }

        steps = steps.saturating_add(1);
    }

    steps
}

#[tokio::test]
async fn e2e_01_real_sync_engine_boots_with_real_db_mempool_and_reorg_manager() -> TestResult {
    let harness = build_sync_harness("e2e_01")?;

    assert!(harness.data_dir.exists());
    assert_clean_initial_core_state(&harness.sync);

    Ok(())
}

#[tokio::test]
async fn e2e_02_two_real_sync_engines_are_isolated_and_do_not_share_peer_state() -> TestResult {
    let mut first = build_sync_harness("e2e_02_first")?;
    let second = build_sync_harness("e2e_02_second")?;

    let peer = test_peer_id();
    first.sync.mark_pq_ready(peer);

    assert_ne!(first.data_dir, second.data_dir);
    assert!(first.sync.is_pq_ready(&peer));
    assert!(!second.sync.is_pq_ready(&peer));
    assert!(second.sync.pq_ready_peers.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_03_delayed_pq_handshake_marks_peer_ready_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_03")?;
    let peer = test_peer_id();

    timeout(Duration::from_millis(250), async {
        sleep(Duration::from_millis(25)).await;
        harness.sync.mark_pq_ready(peer);

        wait_until(
            Duration::from_millis(100),
            || harness.sync.is_pq_ready(&peer),
            "PQ peer readiness",
        )
        .await
    })
    .await
    .map_err(|_| "PQ readiness flow exceeded outer timeout".to_string())??;

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[tokio::test]
async fn e2e_04_delayed_disconnect_clears_pq_ready_state_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_04")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    assert!(harness.sync.is_pq_ready(&peer));

    timeout(Duration::from_millis(250), async {
        sleep(Duration::from_millis(25)).await;
        harness.sync.clear_pq_peer_state(&peer);

        wait_until(
            Duration::from_millis(100),
            || !harness.sync.is_pq_ready(&peer),
            "PQ peer disconnect cleanup",
        )
        .await
    })
    .await
    .map_err(|_| "PQ disconnect cleanup exceeded outer timeout".to_string())??;

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[tokio::test]
async fn e2e_05_disconnect_of_one_peer_does_not_clear_other_ready_peers() -> TestResult {
    let mut harness = build_sync_harness("e2e_05")?;
    let disconnected = test_peer_id();
    let survivor = test_peer_id();

    harness.sync.mark_pq_ready(disconnected);
    harness.sync.mark_pq_ready(survivor);

    cleanup_peer_public_backlog(&mut harness.sync, &disconnected);

    assert!(!harness.sync.is_pq_ready(&disconnected));
    assert!(harness.sync.is_pq_ready(&survivor));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_06_delayed_block_backlog_sets_background_work_and_then_clears() -> TestResult {
    let mut harness = build_sync_harness("e2e_06")?;
    let peer = test_peer_id();

    timeout(Duration::from_millis(500), async {
        sleep(Duration::from_millis(20)).await;
        push_block_backlog(&mut harness.sync, peer, 1, 16, 3);

        assert!(harness.sync.has_background_sync_work());
        assert_eq!(harness.sync.block_queue.len(), 16);

        sleep(Duration::from_millis(20)).await;
        harness.sync.block_queue.clear();

        wait_until(
            Duration::from_millis(100),
            || !harness.sync.has_background_sync_work(),
            "block backlog clear",
        )
        .await
    })
    .await
    .map_err(|_| "block backlog flow exceeded outer timeout".to_string())??;

    assert!(harness.sync.block_queue.is_empty());
    Ok(())
}

#[tokio::test]
async fn e2e_07_delayed_batch_backlog_sets_background_work_and_then_clears() -> TestResult {
    let mut harness = build_sync_harness("e2e_07")?;
    let peer = test_peer_id();

    timeout(Duration::from_millis(500), async {
        sleep(Duration::from_millis(20)).await;
        push_batch_backlog(&mut harness.sync, peer, 100, 16, 2);

        assert!(harness.sync.has_background_sync_work());
        assert_eq!(harness.sync.batch_queue.len(), 16);

        sleep(Duration::from_millis(20)).await;
        harness.sync.batch_queue.clear();

        wait_until(
            Duration::from_millis(100),
            || !harness.sync.has_background_sync_work(),
            "batch backlog clear",
        )
        .await
    })
    .await
    .map_err(|_| "batch backlog flow exceeded outer timeout".to_string())??;

    assert!(harness.sync.batch_queue.is_empty());
    Ok(())
}

#[tokio::test]
async fn e2e_08_interleaved_block_and_batch_queues_preserve_fifo_order() -> TestResult {
    let mut harness = build_sync_harness("e2e_08")?;
    let peer = test_peer_id();

    for index in 0u64..10u64 {
        harness.sync.block_queue.push_back((peer, index, 3));
        harness.sync.batch_queue.push_back((peer, index + 100, 2));
    }

    for expected in 0u64..10u64 {
        let (_, block_idx, block_retry) = harness
            .sync
            .block_queue
            .pop_front()
            .ok_or_else(|| "missing block queue item".to_string())?;

        let (_, batch_idx, batch_retry) = harness
            .sync
            .batch_queue
            .pop_front()
            .ok_or_else(|| "missing batch queue item".to_string())?;

        assert_eq!(block_idx, expected);
        assert_eq!(batch_idx, expected + 100);
        assert_eq!(block_retry, 3);
        assert_eq!(batch_retry, 2);
    }

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[tokio::test]
async fn e2e_09_disconnect_cleanup_removes_only_the_disconnected_peer_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_09")?;
    let bad_peer = test_peer_id();
    let good_peer = test_peer_id();

    push_block_backlog(&mut harness.sync, bad_peer, 0, 8, 3);
    push_batch_backlog(&mut harness.sync, bad_peer, 0, 8, 3);
    push_block_backlog(&mut harness.sync, good_peer, 100, 5, 3);
    push_batch_backlog(&mut harness.sync, good_peer, 100, 5, 3);

    harness.sync.mark_pq_ready(bad_peer);
    harness.sync.mark_pq_ready(good_peer);

    cleanup_peer_public_backlog(&mut harness.sync, &bad_peer);

    assert!(!harness.sync.is_pq_ready(&bad_peer));
    assert!(harness.sync.is_pq_ready(&good_peer));

    assert_eq!(harness.sync.block_queue.len(), 5);
    assert_eq!(harness.sync.batch_queue.len(), 5);

    assert!(
        harness
            .sync
            .block_queue
            .iter()
            .all(|(peer, _, _)| *peer == good_peer)
    );

    assert!(
        harness
            .sync
            .batch_queue
            .iter()
            .all(|(peer, _, _)| *peer == good_peer)
    );

    Ok(())
}

#[tokio::test]
async fn e2e_10_retry_budget_drain_eventually_clears_block_and_batch_backlogs() -> TestResult {
    let mut harness = build_sync_harness("e2e_10")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 0, 4, 2);
    push_batch_backlog(&mut harness.sync, peer, 0, 4, 2);

    let block_steps = drain_block_queue_with_retry_budget(&mut harness.sync, 32);
    let batch_steps = drain_batch_queue_with_retry_budget(&mut harness.sync, 32);

    assert!(block_steps > 4);
    assert!(batch_steps > 4);
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_11_sync_percent_advances_monotonically_during_download_flow() -> TestResult {
    let mut harness = build_sync_harness("e2e_11")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 100;
    harness.sync.downloaded = 0;

    let mut previous = harness.sync.sync_percent();

    for downloaded in [1u64, 10, 25, 50, 75, 99, 100] {
        sleep(Duration::from_millis(2)).await;

        harness.sync.downloaded = downloaded;
        let current = harness.sync.sync_percent();

        assert!(
            current >= previous,
            "sync percent regressed: previous={previous}, current={current}"
        );

        previous = current;
    }

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");
    Ok(())
}

#[tokio::test]
async fn e2e_12_sync_percent_caps_at_hundred_when_peer_over_reports_downloaded() -> TestResult {
    let mut harness = build_sync_harness("e2e_12")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 3;
    harness.sync.downloaded = u64::MAX;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    Ok(())
}

#[tokio::test]
async fn e2e_13_zero_total_download_reports_zero_or_hundred_based_on_synced_flag() -> TestResult {
    let mut harness = build_sync_harness("e2e_13")?;

    harness.sync.total_to_download = 0;
    harness.sync.downloaded = 0;

    harness.sync.has_synced = false;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");

    harness.sync.has_synced = true;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    Ok(())
}

#[tokio::test]
async fn e2e_14_hash_bound_pending_batch_request_survives_delayed_lifecycle() -> TestResult {
    let peer = test_peer_id();
    let expected_hash = filled_hash(0x44);

    let request = PendingBatchRequest {
        peer,
        idx: 77,
        retries_left: 3,
        expected_block_hash: Some(expected_hash),
    };

    sleep(Duration::from_millis(10)).await;

    let cloned = request.clone();

    assert_eq!(cloned.peer, peer);
    assert_eq!(cloned.idx, 77);
    assert_eq!(cloned.retries_left, 3);
    assert_eq!(cloned.expected_block_hash, Some(expected_hash));

    Ok(())
}

#[tokio::test]
async fn e2e_15_legacy_index_only_pending_batch_request_survives_delay() -> TestResult {
    let peer = test_peer_id();

    let request = PendingBatchRequest {
        peer,
        idx: 88,
        retries_left: 1,
        expected_block_hash: None,
    };

    sleep(Duration::from_millis(10)).await;

    assert_eq!(request.peer, peer);
    assert_eq!(request.idx, 88);
    assert_eq!(request.retries_left, 1);
    assert!(request.expected_block_hash.is_none());

    Ok(())
}

#[tokio::test]
async fn e2e_16_many_pq_ready_peers_can_be_marked_then_cleared_without_leak() -> TestResult {
    let mut harness = build_sync_harness("e2e_16")?;
    let mut peers = Vec::new();

    for _ in 0usize..128usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        peers.push(peer);
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 128);

    for peer in peers {
        harness.sync.clear_pq_peer_state(&peer);
    }

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[tokio::test]
async fn e2e_17_unknown_peer_disconnect_does_not_damage_ready_peer_set() -> TestResult {
    let mut harness = build_sync_harness("e2e_17")?;
    let stable_peer = test_peer_id();

    harness.sync.mark_pq_ready(stable_peer);

    for _ in 0usize..64usize {
        let unknown_peer = test_peer_id();
        cleanup_peer_public_backlog(&mut harness.sync, &unknown_peer);
    }

    assert!(harness.sync.is_pq_ready(&stable_peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_18_alternating_delay_queue_push_and_clear_cycles_do_not_leave_background_work()
-> TestResult {
    let mut harness = build_sync_harness("e2e_18")?;
    let peer = test_peer_id();

    for cycle in 0u64..20u64 {
        sleep(Duration::from_millis(1)).await;

        harness.sync.block_queue.push_back((peer, cycle, 3));
        harness.sync.batch_queue.push_back((peer, cycle, 2));
        assert!(harness.sync.has_background_sync_work());

        sleep(Duration::from_millis(1)).await;

        harness.sync.block_queue.clear();
        harness.sync.batch_queue.clear();
        assert!(!harness.sync.has_background_sync_work());
    }

    Ok(())
}

#[tokio::test]
async fn e2e_19_background_queue_work_does_not_clear_pq_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_19")?;
    let ready_peer = test_peer_id();
    let queue_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);

    push_block_backlog(&mut harness.sync, queue_peer, 0, 32, 3);
    push_batch_backlog(&mut harness.sync, queue_peer, 0, 32, 3);

    assert!(harness.sync.has_background_sync_work());
    assert!(harness.sync.is_pq_ready(&ready_peer));

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    assert!(!harness.sync.has_background_sync_work());
    assert!(harness.sync.is_pq_ready(&ready_peer));

    Ok(())
}

#[tokio::test]
async fn e2e_20_repeated_update_sync_state_is_stable_without_genesis_even_with_backlog_changes()
-> TestResult {
    let mut harness = build_sync_harness("e2e_20")?;
    let peer = test_peer_id();

    for round in 0u64..10u64 {
        harness.sync.update_sync_state();

        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());

        harness.sync.block_queue.push_back((peer, round, 3));
        harness.sync.update_sync_state();

        assert!(harness.sync.has_background_sync_work());
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());

        harness.sync.block_queue.clear();
        harness.sync.update_sync_state();

        assert!(!harness.sync.has_background_sync_work());
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
    }

    Ok(())
}

#[tokio::test]
async fn e2e_21_repeated_update_sync_pointers_without_blocks_stays_none_and_non_panicking()
-> TestResult {
    let mut harness = build_sync_harness("e2e_21")?;

    for _ in 0usize..25usize {
        harness.sync.update_sync_pointers();

        assert!(harness.sync.last_synced_index().is_none());
        assert!(harness.sync.last_synced_hash().is_none());

        sleep(Duration::from_millis(1)).await;
    }

    Ok(())
}

#[tokio::test]
async fn e2e_22_real_arc_wiring_keeps_db_and_mempool_alive_through_sync_lifecycle() -> TestResult {
    let mut harness = build_sync_harness("e2e_22")?;

    let db_before = Arc::strong_count(&harness.sync.db);
    let mempool_before = Arc::strong_count(&harness.sync.mempool);

    let db_clone = Arc::clone(&harness.sync.db);
    let mempool_clone = Arc::clone(&harness.sync.mempool);

    assert_eq!(
        Arc::strong_count(&harness.sync.db),
        db_before.saturating_add(1)
    );
    assert_eq!(
        Arc::strong_count(&harness.sync.mempool),
        mempool_before.saturating_add(1)
    );

    harness.sync.update_sync_state();
    harness.sync.update_sync_pointers();

    drop(db_clone);
    drop(mempool_clone);

    assert_eq!(Arc::strong_count(&harness.sync.db), db_before);
    assert_eq!(Arc::strong_count(&harness.sync.mempool), mempool_before);

    Ok(())
}

#[tokio::test]
async fn e2e_23_public_hash_alias_supports_deduped_ordered_sync_collections() -> TestResult {
    let mut hashes = BTreeSet::<RemzarHashBytes>::new();

    for byte in [9u8, 1, 9, 3, 7, 3, 2, 2] {
        hashes.insert(filled_hash(byte));
    }

    assert_eq!(hashes.len(), 5);
    assert_eq!(hashes.iter().next().copied(), Some(filled_hash(1)));
    assert_eq!(hashes.iter().next_back().copied(), Some(filled_hash(9)));

    Ok(())
}

#[tokio::test]
async fn e2e_24_simulated_desync_due_to_one_node_backlog_converges_after_cleanup() -> TestResult {
    let mut node_a = build_sync_harness("e2e_24_a")?;
    let mut node_b = build_sync_harness("e2e_24_b")?;

    let peer_a = test_peer_id();
    let peer_b = test_peer_id();

    node_a.sync.mark_pq_ready(peer_b);
    node_b.sync.mark_pq_ready(peer_a);

    push_block_backlog(&mut node_b.sync, peer_a, 0, 24, 3);
    push_batch_backlog(&mut node_b.sync, peer_a, 0, 24, 3);

    assert!(!node_a.sync.has_background_sync_work());
    assert!(node_b.sync.has_background_sync_work());

    timeout(Duration::from_millis(500), async {
        sleep(Duration::from_millis(25)).await;

        node_b.sync.block_queue.clear();
        node_b.sync.batch_queue.clear();

        wait_until(
            Duration::from_millis(100),
            || !node_b.sync.has_background_sync_work(),
            "node B backlog convergence",
        )
        .await
    })
    .await
    .map_err(|_| "desync convergence exceeded timeout".to_string())??;

    assert!(!node_a.sync.has_background_sync_work());
    assert!(!node_b.sync.has_background_sync_work());
    assert!(node_a.sync.is_pq_ready(&peer_b));
    assert!(node_b.sync.is_pq_ready(&peer_a));

    Ok(())
}

#[tokio::test]
async fn e2e_25_full_core_lifecycle_connect_delay_backlog_disconnect_reconnect_and_converge()
-> TestResult {
    let mut node_a = build_sync_harness("e2e_25_a")?;
    let mut node_b = build_sync_harness("e2e_25_b")?;

    let peer_a = test_peer_id();
    let peer_b = test_peer_id();

    timeout(Duration::from_millis(1_000), async {
        // 1. Delayed connection / PQ readiness.
        sleep(Duration::from_millis(20)).await;
        node_a.sync.mark_pq_ready(peer_b);
        node_b.sync.mark_pq_ready(peer_a);

        assert!(node_a.sync.is_pq_ready(&peer_b));
        assert!(node_b.sync.is_pq_ready(&peer_a));

        // 2. Network pressure: queues build up on both sides.
        push_block_backlog(&mut node_a.sync, peer_b, 0, 12, 3);
        push_batch_backlog(&mut node_a.sync, peer_b, 0, 12, 2);
        push_block_backlog(&mut node_b.sync, peer_a, 100, 12, 3);
        push_batch_backlog(&mut node_b.sync, peer_a, 100, 12, 2);

        assert!(node_a.sync.has_background_sync_work());
        assert!(node_b.sync.has_background_sync_work());

        // 3. Simulated disconnect of B from A.
        sleep(Duration::from_millis(20)).await;
        cleanup_peer_public_backlog(&mut node_a.sync, &peer_b);

        assert!(!node_a.sync.is_pq_ready(&peer_b));
        assert!(!node_a.sync.has_background_sync_work());

        // 4. B finishes its old backlog.
        node_b.sync.block_queue.clear();
        node_b.sync.batch_queue.clear();

        assert!(!node_b.sync.has_background_sync_work());

        // 5. Simulated reconnect.
        sleep(Duration::from_millis(20)).await;
        node_a.sync.mark_pq_ready(peer_b);
        node_b.sync.mark_pq_ready(peer_a);

        wait_until(
            Duration::from_millis(100),
            || {
                node_a.sync.is_pq_ready(&peer_b)
                    && node_b.sync.is_pq_ready(&peer_a)
                    && !node_a.sync.has_background_sync_work()
                    && !node_b.sync.has_background_sync_work()
            },
            "reconnect convergence",
        )
        .await
    })
    .await
    .map_err(|_| "full core lifecycle exceeded timeout".to_string())??;

    assert!(node_a.sync.is_pq_ready(&peer_b));
    assert!(node_b.sync.is_pq_ready(&peer_a));
    assert!(!node_a.sync.has_background_sync_work());
    assert!(!node_b.sync.has_background_sync_work());

    // Without a real genesis block in these temp DBs, both engines should remain
    // in syncing mode, but with no background backlog left.
    node_a.sync.update_sync_state();
    node_b.sync.update_sync_state();

    assert!(!node_a.sync.has_synced());
    assert!(!node_b.sync.has_synced());
    assert!(node_a.sync.is_syncing());
    assert!(node_b.sync.is_syncing());

    Ok(())
}

#[tokio::test]
async fn e2e_26_expected_genesis_hash_is_wired_into_real_sync_engine() -> TestResult {
    let harness = build_sync_harness("e2e_26")?;

    assert_eq!(
        harness.sync.expected_genesis_hash.as_deref(),
        Some(GlobalConfiguration::GENESIS_HASH_HEX)
    );

    assert_eq!(
        GlobalConfiguration::GENESIS_HASH_HEX.len(),
        REMZAR_HASH_BYTES_LEN * 2
    );

    Ok(())
}

#[tokio::test]
async fn e2e_27_fresh_sync_engine_can_issue_pq_requests_repeatedly_without_state_drift()
-> TestResult {
    let mut harness = build_sync_harness("e2e_27")?;

    for _ in 0usize..50usize {
        assert!(harness.sync.can_issue_more_pq_requests());

        harness.sync.update_sync_state();
        harness.sync.update_sync_pointers();

        assert!(harness.sync.can_issue_more_pq_requests());
        assert!(harness.sync.pending_pq.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn e2e_28_pq_disconnect_cleanup_is_idempotent_under_repeated_network_events() -> TestResult {
    let mut harness = build_sync_harness("e2e_28")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    assert!(harness.sync.is_pq_ready(&peer));

    for _ in 0usize..25usize {
        harness.sync.clear_pq_peer_state(&peer);
        assert!(!harness.sync.is_pq_ready(&peer));
        assert!(harness.sync.pq_ready_peers.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn e2e_29_duplicate_peer_ready_events_are_deduped_before_sync_work_begins() -> TestResult {
    let mut harness = build_sync_harness("e2e_29")?;
    let peer = test_peer_id();

    for _ in 0usize..100usize {
        harness.sync.mark_pq_ready(peer);
    }

    assert!(harness.sync.is_pq_ready(&peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);

    push_block_backlog(&mut harness.sync, peer, 0, 4, 3);
    assert!(harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_30_zero_retry_block_and_batch_items_drop_after_one_drain_pass() -> TestResult {
    let mut harness = build_sync_harness("e2e_30")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 10, 8, 0);
    push_batch_backlog(&mut harness.sync, peer, 20, 8, 0);

    assert!(harness.sync.has_background_sync_work());

    let block_steps = drain_block_queue_with_retry_budget(&mut harness.sync, 8);
    let batch_steps = drain_batch_queue_with_retry_budget(&mut harness.sync, 8);

    assert_eq!(block_steps, 8);
    assert_eq!(batch_steps, 8);
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_31_mixed_retry_budget_eventually_drains_without_losing_fifo_safety() -> TestResult {
    let mut harness = build_sync_harness("e2e_31")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 1, 0));
    harness.sync.block_queue.push_back((peer, 2, 1));
    harness.sync.block_queue.push_back((peer, 3, 2));

    harness.sync.batch_queue.push_back((peer, 11, 0));
    harness.sync.batch_queue.push_back((peer, 12, 1));
    harness.sync.batch_queue.push_back((peer, 13, 2));

    let block_steps = drain_block_queue_with_retry_budget(&mut harness.sync, 16);
    let batch_steps = drain_batch_queue_with_retry_budget(&mut harness.sync, 16);

    assert!(block_steps >= 3);
    assert!(batch_steps >= 3);
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_32_small_drain_budget_leaves_background_work_visible_instead_of_hiding_stall()
-> TestResult {
    let mut harness = build_sync_harness("e2e_32")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 0, 20, 3);
    push_batch_backlog(&mut harness.sync, peer, 0, 20, 3);

    let block_steps = drain_block_queue_with_retry_budget(&mut harness.sync, 5);
    let batch_steps = drain_batch_queue_with_retry_budget(&mut harness.sync, 5);

    assert_eq!(block_steps, 5);
    assert_eq!(batch_steps, 5);
    assert!(harness.sync.has_background_sync_work());
    assert!(!harness.sync.block_queue.is_empty());
    assert!(!harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_33_disconnect_after_partial_retry_clears_requeued_work_for_that_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_33")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    push_block_backlog(&mut harness.sync, peer, 0, 10, 3);
    push_batch_backlog(&mut harness.sync, peer, 0, 10, 3);

    let _ = drain_block_queue_with_retry_budget(&mut harness.sync, 5);
    let _ = drain_batch_queue_with_retry_budget(&mut harness.sync, 5);

    assert!(harness.sync.has_background_sync_work());

    cleanup_peer_public_backlog(&mut harness.sync, &peer);

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_34_sync_percent_handles_near_u64_max_without_overflow_or_nan() -> TestResult {
    let mut harness = build_sync_harness("e2e_34")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = u64::MAX;
    harness.sync.downloaded = u64::MAX - 1;

    let percent = harness.sync.sync_percent();

    assert!(percent.is_finite());
    assert!(percent >= 99.0);
    assert!(percent <= 100.0);
    assert_eq!(format!("{percent:.2}"), "99.99");

    Ok(())
}

#[tokio::test]
async fn e2e_35_sync_percent_preserves_fractional_progress_for_small_downloads() -> TestResult {
    let mut harness = build_sync_harness("e2e_35")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 3;
    harness.sync.downloaded = 1;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "33.33");

    harness.sync.downloaded = 2;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "66.66");

    harness.sync.downloaded = 3;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    Ok(())
}

#[tokio::test]
async fn e2e_36_many_real_sync_engines_boot_with_unique_database_directories() -> TestResult {
    let mut dirs = BTreeSet::new();

    for index in 0usize..12usize {
        let harness = build_sync_harness(&format!("e2e_36_{index}"))?;

        assert!(harness.data_dir.exists());
        assert!(dirs.insert(harness.data_dir.clone()));
        assert_clean_initial_core_state(&harness.sync);
    }

    assert_eq!(dirs.len(), 12);

    Ok(())
}

#[tokio::test]
async fn e2e_37_blockchain_database_subdirectory_exists_after_real_bootstrap() -> TestResult {
    let harness = build_sync_harness("e2e_37")?;

    let blockchain_dir = harness
        .data_dir
        .join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    assert!(harness.data_dir.exists());
    assert!(blockchain_dir.exists());

    Ok(())
}

#[tokio::test]
async fn e2e_38_update_sync_state_does_not_mutate_queue_lengths() -> TestResult {
    let mut harness = build_sync_harness("e2e_38")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 100, 7, 3);
    push_batch_backlog(&mut harness.sync, peer, 200, 9, 2);

    let block_len_before = harness.sync.block_queue.len();
    let batch_len_before = harness.sync.batch_queue.len();

    for _ in 0usize..20usize {
        harness.sync.update_sync_state();

        assert_eq!(harness.sync.block_queue.len(), block_len_before);
        assert_eq!(harness.sync.batch_queue.len(), batch_len_before);
    }

    Ok(())
}

#[tokio::test]
async fn e2e_39_update_sync_pointers_does_not_mutate_pq_or_backlog_state() -> TestResult {
    let mut harness = build_sync_harness("e2e_39")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    push_block_backlog(&mut harness.sync, peer, 1, 6, 3);
    push_batch_backlog(&mut harness.sync, peer, 1, 6, 3);

    for _ in 0usize..20usize {
        harness.sync.update_sync_pointers();

        assert!(harness.sync.is_pq_ready(&peer));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1);
        assert_eq!(harness.sync.block_queue.len(), 6);
        assert_eq!(harness.sync.batch_queue.len(), 6);
    }

    Ok(())
}

#[tokio::test]
async fn e2e_40_same_peer_can_reconnect_after_full_cleanup_and_resume_new_work() -> TestResult {
    let mut harness = build_sync_harness("e2e_40")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    push_block_backlog(&mut harness.sync, peer, 0, 5, 3);
    push_batch_backlog(&mut harness.sync, peer, 0, 5, 3);

    cleanup_peer_public_backlog(&mut harness.sync, &peer);

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.has_background_sync_work());

    sleep(Duration::from_millis(10)).await;

    harness.sync.mark_pq_ready(peer);
    push_block_backlog(&mut harness.sync, peer, 100, 3, 2);

    assert!(harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 3);
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_41_cleanup_peer_with_backlog_but_no_pq_ready_state_is_safe() -> TestResult {
    let mut harness = build_sync_harness("e2e_41")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 50, 4, 3);
    push_batch_backlog(&mut harness.sync, peer, 60, 4, 3);

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.has_background_sync_work());

    cleanup_peer_public_backlog(&mut harness.sync, &peer);

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_42_clearing_pq_peer_state_does_not_touch_sync_progress_counters() -> TestResult {
    let mut harness = build_sync_harness("e2e_42")?;
    let peer = test_peer_id();

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 500;
    harness.sync.downloaded = 125;

    harness.sync.mark_pq_ready(peer);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");

    harness.sync.clear_pq_peer_state(&peer);

    assert_eq!(harness.sync.total_to_download, 500);
    assert_eq!(harness.sync.downloaded, 125);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");

    Ok(())
}

#[tokio::test]
async fn e2e_43_large_queue_pressure_remains_visible_until_explicitly_cleared() -> TestResult {
    let mut harness = build_sync_harness("e2e_43")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 0, 512, 3);
    push_batch_backlog(&mut harness.sync, peer, 10_000, 512, 3);

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 512);
    assert_eq!(harness.sync.batch_queue.len(), 512);

    harness.sync.update_sync_state();

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 512);
    assert_eq!(harness.sync.batch_queue.len(), 512);

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_44_multi_peer_backlog_cleanup_removes_middle_peer_only() -> TestResult {
    let mut harness = build_sync_harness("e2e_44")?;

    let first = test_peer_id();
    let second = test_peer_id();
    let third = test_peer_id();

    push_block_backlog(&mut harness.sync, first, 0, 3, 3);
    push_block_backlog(&mut harness.sync, second, 100, 5, 3);
    push_block_backlog(&mut harness.sync, third, 200, 7, 3);

    push_batch_backlog(&mut harness.sync, first, 0, 3, 3);
    push_batch_backlog(&mut harness.sync, second, 100, 5, 3);
    push_batch_backlog(&mut harness.sync, third, 200, 7, 3);

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);
    harness.sync.mark_pq_ready(third);

    cleanup_peer_public_backlog(&mut harness.sync, &second);

    assert!(harness.sync.is_pq_ready(&first));
    assert!(!harness.sync.is_pq_ready(&second));
    assert!(harness.sync.is_pq_ready(&third));

    assert_eq!(harness.sync.block_queue.len(), 10);
    assert_eq!(harness.sync.batch_queue.len(), 10);

    assert!(
        harness
            .sync
            .block_queue
            .iter()
            .all(|(peer, _, _)| *peer == first || *peer == third)
    );

    assert!(
        harness
            .sync
            .batch_queue
            .iter()
            .all(|(peer, _, _)| *peer == first || *peer == third)
    );

    Ok(())
}

#[tokio::test]
async fn e2e_45_hash_bound_and_legacy_batch_requests_remain_distinguishable() -> TestResult {
    let peer = test_peer_id();
    let hash_a = filled_hash(0xaa);
    let hash_b = filled_hash(0xbb);

    let requests = vec![
        PendingBatchRequest {
            peer,
            idx: 1,
            retries_left: 3,
            expected_block_hash: Some(hash_a),
        },
        PendingBatchRequest {
            peer,
            idx: 1,
            retries_left: 3,
            expected_block_hash: Some(hash_b),
        },
        PendingBatchRequest {
            peer,
            idx: 1,
            retries_left: 3,
            expected_block_hash: None,
        },
    ];

    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].expected_block_hash, Some(hash_a));
    assert_eq!(requests[1].expected_block_hash, Some(hash_b));
    assert!(requests[2].expected_block_hash.is_none());
    assert_ne!(
        requests[0].expected_block_hash,
        requests[1].expected_block_hash
    );
    assert_ne!(
        requests[0].expected_block_hash,
        requests[2].expected_block_hash
    );

    Ok(())
}

#[tokio::test]
async fn e2e_46_pending_batch_debug_output_exposes_core_diagnostics() -> TestResult {
    let peer = test_peer_id();

    let request = PendingBatchRequest {
        peer,
        idx: 999,
        retries_left: 2,
        expected_block_hash: Some(filled_hash(0x5a)),
    };

    let debug = format!("{request:?}");

    assert!(debug.contains("PendingBatchRequest"));
    assert!(debug.contains("idx"));
    assert!(debug.contains("retries_left"));
    assert!(debug.contains("expected_block_hash"));

    Ok(())
}

#[tokio::test]
async fn e2e_47_hash_values_are_copied_not_accidentally_shared_between_requests() -> TestResult {
    let peer = test_peer_id();

    let original_hash = filled_hash(0x11);
    let mut caller_mutated_hash = original_hash;

    let request = PendingBatchRequest {
        peer,
        idx: 1,
        retries_left: 3,
        expected_block_hash: Some(original_hash),
    };

    caller_mutated_hash[0] = 0x99;
    caller_mutated_hash[63] = 0x88;

    assert_eq!(request.expected_block_hash, Some(filled_hash(0x11)));
    assert_ne!(request.expected_block_hash, Some(caller_mutated_hash));

    Ok(())
}

#[tokio::test]
async fn e2e_48_timeout_detects_persistent_background_work_as_stall_signal() -> TestResult {
    let mut harness = build_sync_harness("e2e_48")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 0, 1, 3);

    let result = timeout(Duration::from_millis(75), async {
        wait_until(
            Duration::from_millis(200),
            || !harness.sync.has_background_sync_work(),
            "background work to clear without cleanup",
        )
        .await
    })
    .await;

    assert!(
        result.is_err(),
        "persistent queue work should trigger timeout-based stall detection"
    );

    assert!(harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_49_timeout_succeeds_when_background_work_clears_before_deadline() -> TestResult {
    let mut harness = build_sync_harness("e2e_49")?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 0, 1, 3);
    assert!(harness.sync.has_background_sync_work());

    timeout(Duration::from_millis(250), async {
        sleep(Duration::from_millis(25)).await;
        harness.sync.batch_queue.clear();

        wait_until(
            Duration::from_millis(100),
            || !harness.sync.has_background_sync_work(),
            "background work clear before deadline",
        )
        .await
    })
    .await
    .map_err(|_| "background work did not clear before timeout".to_string())??;

    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_50_five_node_core_mesh_disconnect_reconnect_and_backlog_convergence() -> TestResult {
    let mut nodes = Vec::new();

    for index in 0usize..5usize {
        nodes.push(build_sync_harness(&format!("e2e_50_node_{index}"))?);
    }

    let peers: Vec<PeerId> = (0usize..5usize).map(|_| test_peer_id()).collect();

    timeout(Duration::from_millis(1_500), async {
        // Simulated mesh readiness: each node becomes ready for the next peer.
        for index in 0usize..nodes.len() {
            let next_peer = peers[(index + 1) % peers.len()];
            nodes[index].sync.mark_pq_ready(next_peer);
            assert!(nodes[index].sync.is_pq_ready(&next_peer));
        }

        // Simulated network pressure across the mesh.
        for index in 0usize..nodes.len() {
            let next_peer = peers[(index + 1) % peers.len()];
            let base = u64::try_from(index).unwrap_or(0).saturating_mul(100);

            push_block_backlog(&mut nodes[index].sync, next_peer, base, 8, 3);
            push_batch_backlog(&mut nodes[index].sync, next_peer, base + 50, 8, 2);

            assert!(nodes[index].sync.has_background_sync_work());
        }

        sleep(Duration::from_millis(25)).await;

        // Simulated disconnect cleanup across all links.
        for index in 0usize..nodes.len() {
            let next_peer = peers[(index + 1) % peers.len()];
            cleanup_peer_public_backlog(&mut nodes[index].sync, &next_peer);

            assert!(!nodes[index].sync.is_pq_ready(&next_peer));
            assert!(!nodes[index].sync.has_background_sync_work());
        }

        sleep(Duration::from_millis(25)).await;

        // Simulated reconnect across all links.
        for index in 0usize..nodes.len() {
            let next_peer = peers[(index + 1) % peers.len()];
            nodes[index].sync.mark_pq_ready(next_peer);
        }

        wait_until(
            Duration::from_millis(250),
            || {
                nodes.iter().enumerate().all(|(index, node)| {
                    let next_peer = peers[(index + 1) % peers.len()];

                    node.sync.is_pq_ready(&next_peer)
                        && !node.sync.has_background_sync_work()
                        && node.sync.block_queue.is_empty()
                        && node.sync.batch_queue.is_empty()
                })
            },
            "five node core mesh convergence",
        )
        .await
    })
    .await
    .map_err(|_| "five node mesh convergence exceeded timeout".to_string())??;

    for index in 0usize..nodes.len() {
        let next_peer = peers[(index + 1) % peers.len()];

        assert!(nodes[index].sync.is_pq_ready(&next_peer));
        assert!(!nodes[index].sync.has_background_sync_work());

        nodes[index].sync.update_sync_state();

        // No real genesis block was inserted in these temp DBs, so the engine
        // should remain syncing, but with clean P2P background state.
        assert!(!nodes[index].sync.has_synced());
        assert!(nodes[index].sync.is_syncing());
    }

    Ok(())
}
